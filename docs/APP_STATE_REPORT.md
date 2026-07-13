# SentinelNet — Report sullo Stato dell'Applicazione

> Documento tecnico di riferimento per lo sviluppo evolutivo.
> Base: commit `3778ea6` (2026-07-13) — codebase in italiano, 104 file tracciati.

---

## 1. Panoramica e scopo

**SentinelNet** è una piattaforma **self-hosted** per la gestione centralizzata, l'osservabilità e la messa in sicurezza di infrastrutture di rete **multivendor**. È pensata per system administrator e piccoli team IT che devono governare parchi apparati eterogenei (switch, router, firewall, wireless controller) distribuiti su più sedi.

Obiettivi principali:

- **Backup automatico** delle configurazioni running degli apparati, organizzato per gruppo e vendor.
- **Triage firmware & vulnerabilità**: rilevazione della versione installata e confronto in tempo reale con il database europeo **ENISA EUVD**, con classificazione CVSS (CRITICAL/HIGH/MEDIUM/LOW).
- **Console di gestione unificata** via browser: inventario, mappa topologica, terminale SSH, threat intelligence.
- **Analisi delle configurazioni** multivendor (config analyzer) e **provisioning day-0** di switch e FortiGate.
- **Gestione multi-sito** su VPN in modalità *central poll* o *site agent*.
- **Integrazione AI**: assistente integrato nella dashboard e **server MCP** per client LLM esterni.

Il valore differenziante è la combinazione di *backup + threat intelligence europea (EUVD) + gestione multivendor + assistenza AI* in un singolo pacchetto self-hosted.

---

## 2. Architettura

### 2.1 Componenti principali

| Componente | Modulo | Responsabilità |
|------------|--------|----------------|
| **Web/API server** | `app_server.py` | Entrypoint FastAPI: rotte HTTP, API REST, WebSocket (terminale), proxy ENISA EUVD, middleware di sicurezza. Refactoring parziale in corso verso router modulari. |
| **Router modulari** | `routers/` (`fortigate.py`, `wlc.py`, `observability.py`, `deps.py`) | Endpoint FortiGate/WLC/observability estratti da `app_server.py`; `deps.py` centralizza le dipendenze DI di autenticazione (`get_current_user`, `require_admin`, `require_operator`). |
| **Observability / flussi live** | `db.py`, `observability/` (`ingesters/`, `storage/schema.sql`, `correlator.py`, `summary.py`, `metrics.py`, `rollup.py`) | Writer SQLite asincrono WAL (`db.py`), ingestori IPFIX/NetFlow/sFlow/syslog, correlazione flussi↔dispositivi, aggregazione top-talker e rollup storico. |
| **Motore SSH/backup** | `core_engine.py` | Backup, triage firmware, registro driver, parsing CDP/LLDP, generazione mappa topologica, esecuzione comandi. |
| **Inventario** | `inventory_manager.py` | Persistenza inventario CSV, gruppi/vendor JSON, cache versioni rilevate (scritture serializzate). |
| **Scanner** | `network_scanner.py` | Parsing subnet e discovery concorrente (ping + probe SSH). |
| **Sicurezza** | `security_manager.py` | JWT, audit log, rate-limiting, lockout anti brute-force, blacklist CLI. |
| **Cifratura** | `crypto_vault.py` / `secure_key_store.py` | Fernet per credenziali a riposo; storage chiavi con DPAPI su Windows. |
| **Utenti** | `user_manager.py` | Account locali, bcrypt (cost 12), ruoli, scope tenant/gruppo. |
| **Config paths** | `data_config.py` | Risoluzione percorsi file di stato, `SENTINELNET_DATA_DIR`, migrazione legacy. |
| **Driver vendor** | `drivers/*.py` | Astrazione per Cisco IOS/CBS/WLC, HPE ProCurve, Juniper, Aruba, Fortinet, Palo Alto. |
| **Servizi specializzati** | `fortigate_service.py`, `wlc_service.py`, `arp_collector.py`, `mac_collector.py`, `mac_history.py` | Integrazioni REST/SSH e raccolta dati di rete. |
| **Provisioning** | `switch_provisioner.py`, `fortigate_provisioner.py` | Generazione e push (SSH/seriale) di config day-0. |
| **AI / MCP** | `ai_assistant.py`, `mcp_server.py` | Assistente multi-provider e server MCP su stdio. |
| **Multi-sito** | `site_manager.py`, `site_agent.py` | Coda job, autenticazione agente, gestione sedi remote. |
| **Export** | `visio_export.py` | Generazione file `.vsdx` della topologia. |
| **UI** | `templates/dashboard.html` | Single-page web UI. |

### 2.2 Interazioni e flussi dati

**Flusso backup + triage (core):**
```
UI/API → run_backup_and_triage() → resolve_driver() → _connect() (netmiko/REST)
       → get_backup_command()/get_version() → salvataggio in backup-config/<gruppo>/<vendor>/
       → classify → confronto ENISA EUVD (proxy) → detected_versions.json
```

**Flusso FortiGate (nota recente):** il triage FortiGate usa la **REST `get_full_config`** con **fallback SSH**, salvando la config nel `backup-config` con la stessa nomenclatura degli altri vendor. `fortigate_service.py` centralizza `_api_or_ssh()`, `_fgt_call()`, `_fgt_device()`.

**Flusso mappa topologica:**
```
backup running-config → parsing CDP/LLDP → generate_network_map()
       → uplink detection (_mac_topology_uplinks) → nodi/edge → Vis.js (UI) / visio_export
```

**Flusso terminale SSH:** UI (Xterm.js) → WebSocket → token OTP monouso → sessione SSH live, con blacklist CLI applicata.

**Flusso multi-sito:**
- *Central poll*: il server centrale apre SSH diretto via VPN.
- *Site agent*: l'agente remoto (`site_agent.py`) fa polling in uscita (`agent_poll_jobs`), esegue e restituisce risultati (`agent_post_job_result`); il centrale mantiene una coda job (`enqueue_job`, `claim_pending_jobs`, `complete_job`).

**Flusso AI/MCP:** `ai_assistant.py` costruisce il contesto (`build_tenant_context`, `_device_running_config_context`, `_fortigate_live_context`, `top_flows_context`) e chiama il provider (`_chat_openai/_chat_anthropic/_chat_gemini/_chat_ollama`). `mcp_server.py` espone i tool su stdio con autorizzazione lato server. La chat supporta l'allegato di IP multipli via checkbox (`attach_device_ips`) e un riassunto server-side dei top flow (`attach_top_flows`); ogni contesto passa per il choke-point di redazione (`redaction.py`) prima di uscire verso il provider LLM.

**Flusso proposta di config via AI:** quando sono allegati IP dispositivo, il modello può emettere un blocco recintato ```` ```sentinelnet-config ```` (JSON: `device_ip`, `commands`, `config_mode`, `save_after`). Il modello **propone**, non esegue: la UI mostra la proposta e solo dopo conferma esplicita dell'utente invoca `/api/bulk-command`, che applica invariati blacklist CLI, RBAC e audit log.

**Flusso flussi live (NetFlow/IPFIX/sFlow):** i collector in `observability/ingesters/` ricevono i pacchetti UDP dagli apparati, li scrivono in SQLite (WAL) tramite `db.py`, il `correlator.py` li associa ai dispositivi noti, `summary.py`/`metrics.py`/`rollup.py` producono le viste top-talker/anomalie esposte da `routers/observability.py` (`/top`, `/anomalies`, `/health`, `/config`) e renderizzate nel tab **Flussi Live** della dashboard.

> **Nota strutturale (dal graph report):** nessun ciclo di import rilevato. I nodi più connessi (`user_group_scope`, `_fgt_device`, `BaseDriver`, `_connect`, `get_users`) confermano che scope tenant, FortiGate e driver sono le astrazioni centrali.

---

## 3. Funzionalità per area

### 3.1 Backup & Triage
- Salvataggio automatico della running-config in file di testo.
- **Nuova organizzazione**: `backup-config/<gruppo>/<vendor>/<hostname>-<ip>.txt`.
- `remove_stale_backups()` elimina i backup precedenti dello stesso IP in **qualunque** sottocartella (evita duplicati dopo riassegnazione gruppo/vendor).
- Triage: `get_version()` → `_clean_version()` → confronto EUVD → cache in `detected_versions.json`.

### 3.2 Analisi config (config_analyzer.py)
- `analyze_config`, `analyze_device`, `analyze_all`, con detection del tipo (`detect_config_type`).
- Analizzatori dedicati: `analyze_fortios_config`, `analyze_wlc_config`.
- Utility di parsing VLAN (`_expand_vlan_list`) e ricerca backup più recente (`_find_freshest_backup`).

### 3.3 FortiGate (REST/SSH)
- `fortigate_service.py`: `api_get()`, `_api_or_ssh()`, `_fgt_call()`, `get_full_config`, `get_arp_table`, `fgt_dhcp_leases`, `fgt_interfaces`, `diagnose_client`.
- Endpoint API: `fgt_arp`, `fgt_device_inventory`, `fgt_full_config`, `fgt_diagnose_client`, ecc.
- Provisioning day-0 FortiOS (`fortigate_provisioner.py`): `build_config()` con quoting CLI (`_q`), push via SSH/seriale.

### 3.4 WLC (wireless)
- `wlc_service.py`: risoluzione controller da inventario, diagnosi client wireless aggregata (client + AP + WLAN + roaming).
- Endpoint: `wlc_ap_summary`, `wlc_client_detail`, `wlc_client_summary`, `wlc_interfaces`, `wlc_diagnose_client`.
- Driver `CiscoWlcDriver` (AireOS 2500/3500/5500/8500, vWLC).

### 3.5 Client map / MAC history
- `arp_collector.py`: raccolta ARP (`arp_scan`, `arp_search`, `arp_client_map`, `arp_stats`).
- `mac_collector.py`: raccolta MAC/interfacce via **CLI, NETCONF e RESTCONF** (`collect_if_macs_via_cli/netconf/restconf`, `collect_mac_table`).
- `mac_history.py`: `mac_locate`, `mac_search`, riclassificazione avvistamenti (`_reclassify_sightings`), rilevamento uplink (`_mac_topology_uplinks`), override manuali (`mac_set_override`, `mac_delete_override`).

### 3.6 AI Assistant / MCP
- Assistente integrato multi-provider (OpenAI, Anthropic, Gemini, Ollama) con profili configurabili (`create_ai_profile`, `activate_ai_profile`).
- Contesto scoped per tenant/sede; allegato multi-dispositivo via checkbox (`attach_device_ips`, tab AI) e riassunto top-flow (`attach_top_flows`) dal tab Flussi Live.
- **Redazione segreti** (`redaction.py`): il contesto inviato al provider LLM passa da un choke-point unico che maschera credenziali/segreti prima dell'invio.
- **Proposta config via chat**: blocco recintato `sentinelnet-config` (JSON), applicato solo dopo conferma esplicita dell'utente via `/api/bulk-command` (blacklist/RBAC/audit invariati).
- **Server MCP** (`mcp_server.py`) su stdio: tool `list_devices`, `get_network_map`, `get_port_channels`, `locate_mac`, `search_mac`, `analyze_config`, `get_triage_status`, `send_cli_command`, `list_sites`, `generate_switch_config`.
- Autorizzazione per ruolo (viewer read-only, operator write) e selezione tool esposti dal tab **MCP Server** (admin).

### 3.7 Osservabilità di rete (Flussi Live)
- Ingestori per **IPFIX, NetFlow, sFlow e syslog** (`observability/ingesters/`) che scrivono su SQLite in modalità WAL tramite un writer asincrono dedicato (`db.py`).
- `correlator.py` associa i flussi ai dispositivi noti in inventario; `summary.py`/`metrics.py` calcolano top-talker e indicatori; `rollup.py` gestisce l'aggregazione storica.
- Schema dati in `observability/storage/schema.sql`.
- API dedicate in `routers/observability.py`: `/top`, `/anomalies`, `/health`, `/config`.
- Tab **Flussi Live** nella dashboard con refresh automatico opzionale.

### 3.8 Sicurezza / Utenti
- JWT (fail-closed sul segreto) veicolato via **cookie `HttpOnly`** (browser) o header `Bearer` (script/API); il token non transita più da `sessionStorage` (risolve L-1, vedi §6.2). `Secure` attivo quando è configurato TLS.
- Opzione **TLS nativo** via `data_config.resolve_tls_config()` (`SENTINELNET_SSL_CERTFILE`/`SENTINELNET_SSL_KEYFILE`): se entrambe presenti e leggibili, Uvicorn si avvia in HTTPS (risolve H-1); se ne è impostata una sola, l'avvio fallisce con errore esplicito.
- Audit log rotante (`log_audit`), rate-limiting + lockout (`is_locked_out`).
- Credenziali apparati cifrate Fernet; chiavi locali protette (DPAPI su Windows).
- Utenti locali bcrypt (cost 12), ruoli e scope gruppo (`user_group_scope`, `get_allowed_tabs`, `assert_group_allowed`, `assert_device_allowed`).
- Blacklist CLI (`is_command_safe`, `command_allowed`) applicata sia all'API one-shot che al terminale interattivo; bypass admin auditato.

### 3.9 Siti / VPN (multi-sito)
- `site_manager.py`: creazione/gestione sedi (`create_site`, `delete_site`, `_default_sites`), coda job, auth agente.
- `site_agent.py`: processo leggero lato sede (Mode B), polling in uscita.
- Endpoint agente: `agent_poll_jobs`, `agent_post_job_result`, `agent_push_inventory`, `agent_push_mac`, autenticazione `X-Site-Token`/`X-Site-Id`.

### 3.10 Mappa topologica
- `generate_network_map()` da tabelle CDP/LLDP nei backup.
- Report port-channel (`get_portchannel_report`).
- Rendering 2D via Vis.js con tooltip; export `.vsdx` (`build_vsdx`, `_collect_bounds`, `_hex_to_rgb_fraction`).

---

## 4. Stack tecnico e deployment

**Stack:**
- **Linguaggio:** Python 3.11+
- **Web framework:** FastAPI + Uvicorn
- **SSH:** Netmiko (multivendor via `device_type`)
- **Crittografia:** `cryptography` (Fernet), bcrypt, DPAPI (Windows)
- **Frontend:** single-page HTML + Vis.js + Xterm.js (WebSocket)
- **AI:** provider multipli via API
- **Export:** generazione `.vsdx`

**Gestione dipendenze:** `uv` (consigliato) o `pip` standard, da `requirements.txt`.

**Deployment:**
| Modalità | Note |
|----------|------|
| **Locale** | `uv run app_server.py` / `python app_server.py`; apre il browser su `http://localhost:8765/`. Setup wizard al primo avvio (crea admin in `users.json`). |
| **PyInstaller exe** | Distribuzione standalone; risoluzione risorse bundled (`get_path`, resource path). |
| **Docker** | `docker compose up -d` o immagine ufficiale `claudiovidhi/sentinelnet:latest`; volume `./data:/app/data` + `SENTINELNET_DATA_DIR`. |

**Configurazione via env** (tutte opzionali): `SENTINELNET_MASTER_KEY`, `SENTINELNET_JWT_SECRET`, `SENTINELNET_ADMIN_USER/PASS/SECRET`, `SENTINELNET_DATA_DIR`, `SENTINELNET_HOST/PORT`, `SENTINELNET_NO_BROWSER`, `SENTINELNET_CORS_ORIGINS`, `SENTINELNET_SSL_CERTFILE`/`SENTINELNET_SSL_KEYFILE` (TLS nativo).

---

## 5. Struttura dati su disco

I file di stato sono risolti da `data_config.py` (con supporto `SENTINELNET_DATA_DIR` e migrazione una-tantum dei file legacy da CWD).

```
data/ (o CWD / SENTINELNET_DATA_DIR)
├── network_hosts.csv        # inventario con credenziali CIFRATE (Fernet) — git-ignored
├── detected_versions.json   # cache stato triage / versioni rilevate
├── groups.json              # gruppi/sedi configurati
├── users.json               # account locali (bcrypt)
├── secret.key               # chiave Fernet (o derivata da MASTER_KEY)
├── jwt_secret.key           # segreto firma JWT
├── audit.log                # registro sicurezza rotante
└── backup-config/
    └── <gruppo>/
        └── <vendor>/
            └── <hostname>-<ip>.txt   # running-config (incl. FortiGate via REST/SSH)
```

**Note:**
- La cartella di backup per gruppo/sede è creata on-demand (`group_backup_dir`).
- I FortiGate salvano la config nel `backup-config` come gli altri vendor (nota recente).
- File sensibili esclusi da Git via `.gitignore`: `network_hosts.csv`, `backup-config/`, `detected_versions.json`, `groups.json`, `secret.key`, `jwt_secret.key`, `users.json`.

---

## 6. Punti di forza, debiti tecnici e aree di sviluppo

### 6.1 Punti di forza
- **Architettura multivendor pluggabile**: registro driver centralizzato (`resolve_driver`, `driver_factory`, `BaseDriver`) facilmente estendibile.
- **Sicurezza matura**: JWT fail-closed, Fernet a riposo, bcrypt, audit log, rate-limiting/lockout, blacklist CLI su tutti i canali, scope tenant/gruppo pervasivo.
- **Nessun import cycle** e buona modularità dei servizi specializzati (FortiGate, WLC, MAC, ARP).
- **Threat intelligence europea** (ENISA EUVD) integrata nel triage.
- **Estensibilità AI**: doppio canale (assistente in-app + server MCP) con autorizzazione coerente lato server.
- **Copertura test presente**: suite dedicate (`test_ai_assistant`, `test_fortigate_service`, `test_wlc_service`, `test_config_analyzer_multivendor`, `test_sites`, `test_remote_site`, `test_switch_provisioner`, `test_arp_collector`, `test_observability_ui`, `test_redaction`).
- **Deployment flessibile**: locale, exe PyInstaller e Docker con persistenza dati chiara; build locale via `scripts/build.ps1` (pyinstaller + smoke test), nessuna pipeline CI (rimossa deliberatamente).
- **Osservabilità di rete nativa**: ingestori NetFlow/IPFIX/sFlow/syslog con storage SQLite WAL dedicato (`db.py`, `observability/`), primo passo verso la migrazione da file JSON/CSV a datastore transazionale.
- **Refactoring in corso verso router modulari** (`routers/fortigate.py`, `routers/wlc.py`, `routers/observability.py`, `routers/deps.py`), con DI centralizzata per l'autenticazione.

### 6.2 Debiti tecnici (evidenziati dal graph report e dai security findings)
- **Bassa coesione in alcune community core**: `Application API Endpoints` (0.04), `Vendor Device Drivers` (0.09), `Network Discovery and Triage` (0.10). `app_server.py` concentra ~51 endpoint eterogenei: candidato a suddivisione in router modulari.
- **God nodes**: `user_group_scope()` (27 edge), `_fgt_device()`, `BaseDriver`, `_connect()` — alta responsabilità concentrata, rischio di accoppiamento.
- **Nodi isolati / gap documentazione**: 112 nodi con ≤1 connessione; molti riguardano documentazione security/ZTP/FortiOS non collegata al codice.
- **Findings di sicurezza — stato aggiornato** (verificato su codice, non solo su report interni):
  - *H-1* (TLS): **risolto** — opzione TLS nativo (`SENTINELNET_SSL_CERTFILE`/`KEYFILE`, `data_config.resolve_tls_config()`); reverse proxy resta comunque un'opzione valida per deployment complessi.
  - *L-1* (JWT in `sessionStorage`): **risolto** — token veicolato via cookie `HttpOnly` (`Secure` quando TLS attivo), vedi `app_server.py` `_set_session_cookie`/`routers/deps.py`.
  - *I-1* (contesto AI verso LLM terzi): **mitigato** — introdotto `redaction.py` come choke-point di redazione segreti prima dell'invio al provider; resta by-design che config/flow summary vengano inviati a LLM esterni (policy utente necessaria per governare quali provider usare).
  - *I-2* (config day-0 del provisioner con segreti in chiaro): **non risolto** — `fortigate_provisioner.py` e `switch_provisioner.py` generano ancora config con password in chiaro nei parametri (es. default `changeme`, esempio hardcoded `S3cret!`); nessun placeholder/redazione applicata a questo flusso.
  - Diversi finding minori risultano già risolti (*H-2* password policy, *M-1* blacklist bypass, *DF-1* file sensibili in CWD).
- **8 edge INFERRED su `BaseDriver`** (confidence 0.5): da verificare la correttezza delle relazioni driver.

### 6.3 Aree di sviluppo — stato Sezione 11 (implementata 2026-07-13)

Tutti gli item della Sezione 11 del Master Implementation Plan risultano **implementati e verificati** (suite test completa verde):

- **11.1 Filtro tenant Flussi Live** — dropdown multi-selezione a checkbox, filtro client-side sui dati già scoped dal server (`renderFlowsTable`).
- **11.2 Selezione righe + pannello dettaglio flusso** — checkbox per riga (chiave = tupla flow), slide panel con salto in topologia, lookup client-map della sorgente e link alle anomalie filtrate per IP.
- **11.3 Analisi AI dei flussi selezionati** — `attach_flow_keys` (max 20) in `AiChatSchema`; il server ri-deriva i totali da `flow_aggregates` con scope tenant invariato; redazione nel choke-point `chat()` intatta.
- **11.4 GUI token FortiGate** — pannello admin nel tab provisioner: tabella stato, salva/rimuovi/test contro gli endpoint esistenti.
- **11.5a GUI impostazioni observability** — pannello in tab-settings su `GET/POST /api/observability/config`, banner "riavvio richiesto".
- **11.5b Modifica credenziali dispositivo** — azione "Modifica" in inventario che riusa l'upsert `/api/add-device`; password/secret richiedono re-inserimento (l'upsert sovrascrive sempre i campi cifrati).
- **11.6 Trasporti multi-protocollo** — colonna `Transports` JSON in `network_hosts.csv` (ssh/telnet/netconf/restconf + porta, migrazione lazy dai vecchi record SSH-only); collector e `_connect()` rispettano i trasporti dichiarati; Telnet con warning cleartext + audit.

**Debiti residui (dal graph report, ancora validi):**
- Refactoring di `app_server.py` da completare (`routers/` copre solo FortiGate/WLC/observability; inventario, mac, sites, ai/mcp restano nel monolite).
- Consolidare l'astrazione driver e verificare gli edge inferred su `BaseDriver`.
- *I-2* segreti in chiaro nelle config day-0 del provisioner (vedi §6.2) — da correggere con placeholder/redazione dedicata.
- Ampliamento copertura test sulle community a bassa coesione (endpoint API, discovery/triage).

---

*Report aggiornato al commit `3778ea6` (2026-07-13), verificato riga per riga sul codice corrente (non sul solo git log). Verificare la freschezza del knowledge graph con `git rev-parse --short HEAD` rispetto a questo commit ed eseguire `graphify update .` dopo modifiche al codice. Le aree di sviluppo in §6.3 fanno riferimento a `docs/MASTER-IMPLEMENTATION-PLAN.md`, Sezione 11.*