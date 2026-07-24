# Gestione Sedi Remote & Remote Site Agent (Multi-Sito)

SentinelNet gestisce più sedi remote (collegate via VPN o Internet) da un unico server centrale.
Ogni sede ha una **modalità di collegamento** che determina come il centrale interagisce con gli apparati di quella sede:

| Modalità | Come funziona | Quando usarla |
|----------|---------------|---------------|
| **Central poll** (Mode A) | Il centrale apre connessioni SSH direttamente verso i dispositivi remoti attraverso il routing VPN site-to-site. Nessun processo aggiuntivo. | VPN site-to-site stabile, subnet remote direttamente raggiungibili dal centrale. |
| **Site agent** (Mode B) | Un processo leggero (`site_agent.py`) gira in un server/VM nella sede e si connette **in uscita** al centrale (HTTPS). Spinge inventario, MAC-table e stato; i comandi CLI passano via coda di job. | NAT/firewall che impedisce connessioni entranti verso la sede, VPN instabile, o per isolare le credenziali dentro la sede. |

La sede predefinita `central` esiste sempre nel sistema e non è eliminabile.

---

## Architecture: How Site Agent (Mode B) Works

```
┌─────────────────────────────────────────┐               ┌───────────────────────────────────────────────┐
│         CENTRAL SENTINELNET             │               │            REMOTE SITE (VM / AGENT)          │
│                                         │  HTTPS (443)  │                                               │
│  - Web Dashboard & API                  │ ◄───────────  │  - site_agent.py                              │
│  - Site Registry & Token Hash           │  Outbound     │  - Local inventory (network_hosts.csv)        │
│  - Job Queue (SQLite)                   │  Polling      │  - Credentials stored locally                 │
│  - Consolidated Inventory & MAC Tracker │               │  - Direct local SSH to switches/firewalls     │
└─────────────────────────────────────────┘               └───────────────────────┬───────────────────────┘
                                                                                  │ Local SSH
                                                                                  ▼
                                                                  ┌───────────────────────────────┐
                                                                  │ Local Remote Switch/Firewall  │
                                                                  └───────────────────────────────┘
```

### Principi chiave dell'agente remoto:
1. **Connessione Outbound-Only**: L'agente si connette dal basso verso l'alto (da remoto verso il centrale). Nessuna porta aperta in ingresso nella sede remota.
2. **Isolamento delle credenziali**: Le password SSH/enable degli apparati remoti risiedono esclusivamente nella directory dati locale dell'agente (`network_hosts.csv`). Al centrale vengono inviati solo metadata (IP, Hostname, Vendor, MAC table).
3. **Relay dei Comandi CLI**: Quando un amministratore invia un comando CLI dalla dashboard verso un apparato della sede agent, il centrale accoda un job. L'agente preleva il job durante il polling, lo esegue localmente via SSH e restituisce l'output.

---

## 1. Creazione di una Sede sul Centrale

Dalla Dashboard (account **admin**): tab **Sedi multi-sito** → *Nuova sede*.

1. **Nome** — es. `Milano-VM` (l'id alfanumerico derivato sarà `milano-vm`).
2. **Modalità** — Seleziona `Site agent`.
3. **Subnet** — Reti della sede, es. `192.168.56.0/24` (per riferimento/documentazione).

> [!IMPORTANT]
> Per le sedi **agent**, al momento della creazione viene mostrato **una sola volta** il Token di Autenticazione dell'agente (es. `agent_tok_...`). Copialo subito.
> Sul centrale viene salvato soltanto l'hash SHA-256 del token.

### Creazione via API / cURL:

```bash
# 1. Autenticazione admin per ottenere il JWT
TOKEN=$(curl -s -X POST http://<CENTRAL_IP>:8765/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<ADMIN_PASSWORD>"}' | jq -r .access_token)

# 2. Creazione della sede agent
curl -X POST http://<CENTRAL_IP>:8765/api/sites \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Milano-VM", "mode": "agent", "subnets": ["192.168.56.0/24"]}'
```

---

## 2. Guida Passo-Passo per Test in Ambiente VM

Questa guida mostra come testare l'agente remoto su una Virtual Machine (Ubuntu/Debian o Windows VM in VirtualBox/VMware/Proxmox/Hyper-V).

### Passo 1: Preparazione della VM Remota
Sulla VM che rappresenterà la sede remota:

```bash
# Clona il repository o copia il codice
git clone https://github.com/Claudio-Vidhi/SentinelNet.git && cd SentinelNet

# Crea l'ambiente virtuale Python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Passo 2: Configurazione Automatica con Helper Script
Usa lo script di supporto [scripts/vm_agent_test_helper.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/scripts/vm_agent_test_helper.py) per generare la configurazione `agent.json` e l'inventario locale:

```bash
python scripts/vm_agent_test_helper.py setup \
  --central-url http://<CENTRAL_IP>:8765 \
  --site-id milano-vm \
  --token <IL_TOKEN_MOSTRATO_ALLA_CREAZIONE> \
  --interval 15 \
  --no-verify-tls
```

Questo comando crea:
- `agent.json`
- `agent-data/network_hosts.csv` (inventario locale apparati)

### Passo 3: Aggiunta Apparati all'Inventario Locale della VM
Aggiungi un apparato reale o di lab presente nella rete della VM:

```bash
python scripts/vm_agent_test_helper.py add-device \
  --ip 192.168.56.10 \
  --hostname sw-milano-01 \
  --vendor cisco \
  --username admin \
  --password adminpw \
  --site-id milano-vm
```

*(In alternativa, puoi editare direttamente il file `agent-data/network_hosts.csv` con le credenziali dei tuoi apparati).*

### Passo 4: Verifica Connessione e Autenticazione (Diagnostica)
Prima di avviare l'agente, esegui un test di diagnosi:

```bash
python scripts/vm_agent_test_helper.py check --config agent.json
```

Se l'output mostra `[OK] Heartbeat riuscito!`, il centrale ha validato con successo `X-Site-Id` e `X-Site-Token`.

### Passo 5: Avvio dell'Agente in Primo Piano
```bash
python services/site_agent.py --config agent.json
```

Output atteso:
```text
[agent] avviato: centrale=http://192.168.1.100:8765 sede=milano-vm intervallo=15s
[heartbeat] sede 'milano-vm' ok, 1 dispositivi locali
```

### Passo 6: Verifica Risultati sul Centrale
1. **Stato Sede**: Nella dashboard centrale, tab **Sedi multi-sito**, la riga `Milano-VM` mostra **Ultimo contatto** aggiornato in tempo reale.
2. **Inventario Rispecchiato**: Nella tab **Inventario Apparati**, il dispositivo `192.168.56.10` compaia automaticamente taggato con la sede `milano-vm`.
3. **Esecuzione Comandi CLI Relay**:
   - Dalla dashboard, seleziona l'apparato `192.168.56.10` e invia un comando CLI (es. `show version` o `show ip int brief`).
   - Il centrale accoda il job e l'agente sulla VM lo preleva, lo esegue via SSH locale e restituisce il risultato alla dashboard in pochissimi secondi.

---

## 3. Installazione dell'Agente come Servizio di Sistema

### Linux (Systemd)
Crea il file `/etc/systemd/system/sentinelnet-agent.service`:

```ini
[Unit]
Description=SentinelNet Site Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/SentinelNet
ExecStart=/opt/SentinelNet/.venv/bin/python services/site_agent.py --config /opt/SentinelNet/agent.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Abilita e avvia:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelnet-agent
sudo systemctl status sentinelnet-agent
```

### Windows (NSSM - Non-Sucking Service Manager)
```cmd
nssm install SentinelNetAgent C:\SentinelNet\.venv\Scripts\python.exe C:\SentinelNet\services\site_agent.py --config C:\SentinelNet\agent.json
nssm set SentinelNetAgent AppDirectory C:\SentinelNet
nssm start SentinelNetAgent
```

---

## 4. Esecuzione Comandi CLI e API Job Queue (Relay)

- `POST /api/send-command` (ruolo operator/admin): Rileva automaticamente se il dispositivo appartiene a una sede agent. Accoda il job e attende la risposta dell'agente fino a ~90 secondi.
- Se l'agente impiega più tempo, la risposta HTTP ritorna:
  ```json
  {"status": "queued", "job_id": "job_1234567890_abc"}
  ```
- L'esito può essere consultato in qualsiasi momento con:
  ```bash
  curl -H "Authorization: Bearer $JWT" http://<CENTRAL_IP>:8765/api/command-jobs/job_1234567890_abc
  ```
- I comandi distruttivi presenti nella blacklist di sicurezza vengono bloccati anche durante il relay.

---

## 5. Risoluzione Problemi (Troubleshooting)

| Sintomo | Causa Probabile | Soluzione |
|---------|-----------------|-----------|
| **HTTP 401 (Heartbeat fallito)** | Token o Site ID non corretti | Verifica `agent.json`. Se il token è andato perso, usa **Rigenera token** dalla Dashboard e aggiorna `agent.json`. |
| **Apparati non compaiono sul centrale** | `network_hosts.csv` vuoto o errato sulla VM | Verifica che `data_dir` in `agent.json` punti alla cartella contenente `network_hosts.csv`. Esegui `python scripts/vm_agent_test_helper.py add-device ...`. |
| **Comando CLI in stato `queued` permanente** | L'agente VM non è in esecuzione o l'IP dell'apparato non corrisponde all'inventario locale dell'agente | Assicurati che `python services/site_agent.py` sia attivo sulla VM e che l'IP richiesto sia presente nell'inventario locale della VM. |
| **SSL / TLS Certificate Error** | Certificato self-signed sul server centrale | Imposta `"verify_tls": false` in `agent.json` (solo per ambienti di test/lab) oppure importa la CA nel sistema della VM. |
