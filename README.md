# SentinelNet

> SentinelNet — self-hosted network management, backup automation and vulnerability intelligence for sysadmins and small IT teams.

**SentinelNet** è una piattaforma self-hosted per la gestione centralizzata dell'infrastruttura di rete. Automatizza il backup delle configurazioni, rileva le versioni firmware degli apparati attivi e le confronta in tempo reale con il database europeo delle vulnerabilità ENISA EUVD, offrendo una console di gestione unificata accessibile via browser.

---

## Caratteristiche Principali

* 🔄 **Backup Automatico**: Salva automaticamente la configurazione running degli apparati in file di testo locali con nomenclatura per hostname e IP.
* 🧩 **Architettura Multi-Vendor**: Driver pluggabili guidati dal registro vendor — supporto integrato per Cisco IOS, HPE ProCurve, Juniper Junos, Aruba OS, Fortinet FortiOS e Palo Alto PAN-OS. L'associazione vendor → driver → `device_type` netmiko è centralizzata e facilmente estendibile.
* 🛡️ **Triage Firmware & Vulnerabilità**: Rileva la versione firmware installata e la confronta con il database europeo ENISA EUVD, con classificazione CVSS per severità (CRITICAL / HIGH / MEDIUM / LOW).
* 📡 **Scansione Subnet**: Discovery automatico di host su una subnet (ping + probe SSH) con triage opzionale e registrazione in inventario.
* 🗺️ **Mappa Topologica Interattiva**: Genera automaticamente la mappa di rete 2D da tabelle CDP/LLDP presenti nei backup, con nodi dinamici via Vis.js e tooltip avanzati.
* 🖥️ **Terminale SSH Interattivo**: Console WebSocket/Xterm.js per sessioni SSH live direttamente da browser, autenticata via token OTP monouso.
* 👥 **Gestione Gruppi e Sedi**: Organizza i dispositivi in gruppi logici (sedi, clienti) con riassegnazione drag-and-drop e filtro per gruppo su tutte le viste.
* 📥 **Importazione CSV**: Caricamento massivo di inventario da file CSV con validazione per riga e report dettagliato degli errori.
* 🔒 **Sicurezza Integrata**: Autenticazione JWT (fail-closed sul segreto), cifratura Fernet delle credenziali a riposo, audit log rotante, rate-limiting con lockout anti brute-force e blacklist comandi CLI pericolosi applicata sia all'API one-shot che al terminale interattivo.

---

## Struttura del Progetto

| File | Responsabilità |
|------|---------------|
| `app_server.py` | Entrypoint FastAPI: rotte HTTP, API REST, WebSocket e proxy verso ENISA EUVD. |
| `core_engine.py` | Motore SSH: backup, triage firmware, registro driver, parsing CDP/LLDP e generazione mappa topologica. |
| `inventory_manager.py` | Persistenza inventario CSV, gruppi/vendor JSON e cache versioni rilevate (scritture serializzate). |
| `network_scanner.py` | Parsing subnet e discovery concorrente (ping + probe SSH) degli host. |
| `security_manager.py` | JWT, audit log, rate-limiting e lockout per brute-force. |
| `crypto_vault.py` | Cifratura/decifratura Fernet delle credenziali degli apparati. |
| `user_manager.py` | Gestione account locali con hashing bcrypt (cost factor 12). |
| `data_config.py` | Risoluzione dei percorsi dei file di stato (supporto `SENTINELNET_DATA_DIR`). |
| `drivers/base_driver.py` | Classe base astratta dei driver (`get_version`, `get_backup_command`). |
| `drivers/cisco_ios.py` | Driver Cisco IOS. |
| `drivers/hp_procurve.py` | Driver HPE ProCurve. |
| `drivers/juniper_junos.py` | Driver Juniper Junos. |
| `drivers/aruba_os.py` | Driver Aruba OS. |
| `drivers/fortinet.py` | Driver Fortinet FortiOS. |
| `drivers/paloalto_panos.py` | Driver Palo Alto PAN-OS. |
| `templates/dashboard.html` | Single-page Web UI: inventario, topologia, threat intel, terminale SSH. |
| `Dockerfile` / `docker-compose.yml` | Build e orchestrazione del container. |
| `requirements.txt` | Dipendenze Python del progetto. |

---

## Contribuire

Regole per lo sviluppo (lingua, doppio artefatto, regola async-DB, scope multi-gruppo): [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Requisiti e Installazione

Il progetto richiede **Python 3.11+** e utilizza `netmiko` per le sessioni SSH, `fastapi`/`uvicorn` per il server web e `cryptography` per la cifratura delle credenziali.

### Con `uv` (Consigliato)

```bash
uv venv
uv pip install -r requirements.txt
```

### Con `pip` standard

```bash
pip install -r requirements.txt
```

---

## Avvio dell'Applicazione

### Esecuzione Locale (PC)

```bash
# Con uv
uv run app_server.py

# Con Python standard
python app_server.py
```

SentinelNet avvierà automaticamente il browser predefinito all'indirizzo **`http://localhost:8765/`**.

Al primo avvio, un setup wizard guidato richiede la creazione dell'account amministratore locale. Le credenziali sono archiviate in `users.json` con hash bcrypt e non vengono mai trasmesse in chiaro.

### Esecuzione con Docker

Puoi compilare ed eseguire SentinelNet all'interno di un container isolato. Le configurazioni, le credenziali e i backup verranno salvati in una directory locale `data` per garantire la persistenza dei dati.

#### Con Docker Compose

```bash
# Avvio in background
docker compose up -d
```

#### Esecuzione standalone (Immagine ufficiale pre-compilata)

Se si desidera eseguire l'applicazione immediatamente senza scaricare il codice sorgente o compilarlo localmente, è possibile scaricare l'immagine ufficiale pre-compilata da Docker Hub (pubblicata dall'autore):

```bash
docker run -d \
  -p 8765:8765 \
  -v ./data:/app/data \
  -e SENTINELNET_DATA_DIR=/app/data \
  --name sentinelnet \
  claudiovidhi/sentinelnet:latest
```

> [!NOTE]
> `claudiovidhi/sentinelnet` è l'immagine pubblica ufficiale ospitata sul registro dell'autore. Se compili e pubblichi autonomamente la tua versione personalizzata dell'immagine su Docker Hub, sostituisci `claudiovidhi` con il tuo username Docker.

L'applicazione sarà accessibile su **`http://localhost:8765/`**.

---

## Variabili d'Ambiente

Tutte le variabili sono opzionali. Se non definite, SentinelNet genera e persiste automaticamente chiavi sicure sui file locali (`secret.key`, `jwt_secret.key`).

| Variabile | Descrizione | Default |
|-----------|-------------|---------|
| `SENTINELNET_MASTER_KEY` | Passphrase da cui derivare (via SHA-256) la chiave Fernet per la cifratura delle credenziali degli apparati. | file `secret.key` |
| `SENTINELNET_JWT_SECRET` | Segreto per la firma dei token JWT di sessione. | file `jwt_secret.key` |
| `SENTINELNET_ADMIN_USER` | Username usato dal profilo credenziali `default` e come fallback per i dispositivi senza username. | `Admin` |
| `SENTINELNET_ADMIN_PASS` | Password usata dal profilo credenziali `default` e come fallback. | `admin` |
| `SENTINELNET_ADMIN_SECRET` | Enable secret usato dal profilo credenziali `default` e come fallback. | `admin` |
| `SENTINELNET_DATA_DIR` | Percorso della directory dati (inventario, log e chiavi) per esecuzione Docker. | directory corrente |
| `SENTINELNET_HOST` | Indirizzo di bind del server. | `127.0.0.1` |
| `SENTINELNET_PORT` | Porta di ascolto del server. | `8765` |
| `SENTINELNET_NO_BROWSER` | Se `true`, non apre il browser all'avvio (impostato automaticamente quando host è `0.0.0.0`). | `false` |
| `SENTINELNET_CORS_ORIGINS` | Lista (separata da virgole) delle origini CORS consentite. | `http://localhost:8765,http://127.0.0.1:8765` |
| `SENTINELNET_SSL_CERTFILE` | Certificato TLS (PEM) per HTTPS nativo; richiede anche `SENTINELNET_SSL_KEYFILE`. Percorsi relativi risolti in `SENTINELNET_DATA_DIR`. Vedi [docs/HARDENING.md](docs/HARDENING.md). | HTTP |
| `SENTINELNET_SSL_KEYFILE` | Chiave privata TLS (PEM) per HTTPS nativo. | HTTP |

> ⚠️ **Esposizione del pannello**: non esporre mai il pannello in HTTP su reti non fidate. Guida completa a TLS nativo e reverse proxy: [docs/HARDENING.md](docs/HARDENING.md).

---

## Sedi Remote (multi-sito)

SentinelNet gestisce più sedi su VPN da un unico centrale, in modalità
**central poll** (SSH diretto via VPN) o **site agent** (agente remoto che si
connette in uscita e riceve i comandi da una coda). Guida completa alla
creazione e gestione: [docs/REMOTE-SITES.md](docs/REMOTE-SITES.md).

---

## Server MCP — usare SentinelNet da un client LLM esterno

Oltre all'AI Assistant integrato nella dashboard, SentinelNet espone i propri
dati come **server MCP** (Model Context Protocol) su stdio: qualunque client
compatibile (Claude Desktop, LM Studio, Cline, ecc.) può interrogare
inventario, mappa di rete, MAC tracker e config analyzer, eseguire comandi CLI
e generare config day-0, con autorizzazione (ruoli, tenant, blacklist comandi)
applicata sempre lato server.

Esempio di configurazione per Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "sentinelnet": {
      "command": "python",
      "args": ["/percorso/SentinelNet/mcp_server.py"],
      "env": {
        "SENTINELNET_URL": "http://127.0.0.1:8765",
        "SENTINELNET_USERNAME": "admin",
        "SENTINELNET_PASSWORD": "..."
      }
    }
  }
}
```

Il server centrale deve essere in esecuzione. Tool disponibili: `list_devices`,
`get_network_map`, `get_port_channels`, `locate_mac`, `search_mac`,
`analyze_config`, `get_triage_status`, `send_cli_command`, `list_sites`,
`generate_switch_config`. I tool di scrittura richiedono un account con ruolo
*operator*; usare un account *viewer* per accesso in sola lettura.

Dalla dashboard, tab **MCP Server** (admin): guida alla configurazione, snippet
JSON pronto da copiare e selezione dei tool esposti ai client (i tool
disattivati spariscono dall'elenco e ogni chiamata viene rifiutata).

---

## Sicurezza delle Credenziali

Il file `network_hosts.csv` contiene le credenziali cifrate degli apparati fisici ed è escluso dal tracciamento Git tramite `.gitignore`. Prima di pubblicare il repository, verificare che i seguenti file siano esclusi:

* `network_hosts.csv` — inventario con credenziali cifrate
* `backup-config/` — configurazioni running degli apparati
* `detected_versions.json` — cache dello stato di triage
* `groups.json` — gruppi/sedi configurati
* `secret.key` / `jwt_secret.key` — chiavi crittografiche locali
* `users.json` — account amministratore locale
