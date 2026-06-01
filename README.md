# SentinelNet

> SentinelNet — self-hosted network management, backup automation and vulnerability intelligence for sysadmins and small IT teams.

**SentinelNet** è una piattaforma self-hosted per la gestione centralizzata dell'infrastruttura di rete. Automatizza il backup delle configurazioni, rileva le versioni firmware degli apparati attivi e le confronta in tempo reale con il database europeo delle vulnerabilità ENISA EUVD, offrendo una console di gestione unificata accessibile via browser.

---

## Caratteristiche Principali

* 🔄 **Backup Automatico**: Salva automaticamente la configurazione running degli switch Cisco IOS e HPE ProCurve in file di testo locali con nomenclatura per hostname e IP.
* 🛡️ **Triage Firmware & Vulnerabilità**: Rileva la versione firmware installata e la confronta con il database europeo ENISA EUVD, con classificazione CVSS per severità (CRITICAL / HIGH / MEDIUM / LOW).
* 🗺️ **Mappa Topologica Interattiva**: Genera automaticamente la mappa di rete 2D da tabelle CDP/LLDP presenti nei backup, con nodi dinamici via Vis.js e tooltip avanzati.
* 🖥️ **Terminale SSH Interattivo**: Console WebSocket/Xterm.js per sessioni SSH live direttamente da browser, autenticata via token OTP monouso.
* 👥 **Gestione Gruppi e Sedi**: Organizza i dispositivi in gruppi logici (sedi, clienti) con riassegnazione drag-and-drop e filtro per gruppo su tutte le viste.
* 📥 **Importazione CSV**: Caricamento massivo di inventario da file CSV con validazione per riga e report dettagliato degli errori.
* 🔒 **Sicurezza Integrata**: Autenticazione JWT, cifratura Fernet delle credenziali a riposo, audit log rotante e blacklist comandi CLI pericolosi.

---

## Struttura del Progetto

| File | Responsabilità |
|------|---------------|
| `app_server.py` | Entrypoint FastAPI: rotte HTTP, API REST, WebSocket e proxy verso ENISA EUVD. |
| `core_engine.py` | Motore SSH: backup, triage firmware, parsing CDP/LLDP e generazione mappa topologica. |
| `inventory_manager.py` | Persistenza inventario CSV, gruppi JSON e cache versioni rilevate. |
| `security_manager.py` | JWT, audit log, rate-limiting e lockout per brute-force. |
| `crypto_vault.py` | Cifratura/decifratura Fernet delle credenziali degli apparati. |
| `user_manager.py` | Gestione account locali con hashing bcrypt (cost factor 12). |
| `drivers/cisco_ios.py` | Driver Cisco IOS: versione firmware e comando di backup. |
| `drivers/hp_procurve.py` | Driver HPE ProCurve: versione firmware e comando di backup. |
| `templates/dashboard.html` | Single-page Web UI: inventario, topologia, threat intel, terminale SSH. |
| `requirements.txt` | Dipendenze Python del progetto. |

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

```bash
# Con uv
uv run app_server.py

# Con Python standard
python app_server.py
```

SentinelNet avvierà automaticamente il browser predefinito all'indirizzo **`http://localhost:8765/`**.

Al primo avvio, un setup wizard guidato richiede la creazione dell'account amministratore locale. Le credenziali sono archiviate in `users.json` con hash bcrypt e non vengono mai trasmesse in chiaro.

---

## Variabili d'Ambiente

Tutte le variabili sono opzionali. Se non definite, SentinelNet genera e persiste automaticamente chiavi sicure sui file locali (`secret.key`, `jwt_secret.key`).

| Variabile | Descrizione |
|-----------|-------------|
| `SENTINELNET_MASTER_KEY` | Chiave Fernet per la cifratura delle credenziali degli apparati. |
| `SENTINELNET_JWT_SECRET` | Segreto per la firma dei token JWT di sessione. |
| `SENTINELNET_ADMIN_USER` | Username predefinito per il profilo credenziali "Standard". |
| `SENTINELNET_ADMIN_PASS` | Password predefinita per il profilo credenziali "Standard". |
| `SENTINELNET_ADMIN_SECRET` | Enable secret predefinito per il profilo credenziali "Standard". |

---

## Sicurezza delle Credenziali

Il file `network_hosts.csv` contiene le credenziali cifrate degli apparati fisici ed è escluso dal tracciamento Git tramite `.gitignore`. Prima di pubblicare il repository, verificare che i seguenti file siano esclusi:

* `network_hosts.csv` — inventario con credenziali cifrate
* `backup-config/` — configurazioni running degli apparati
* `detected_versions.json` — cache dello stato di triage
* `secret.key` / `jwt_secret.key` — chiavi crittografiche locali
* `users.json` — account amministratore locale
