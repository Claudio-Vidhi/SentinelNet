# Gestione Sedi Remote (multi-sito)

SentinelNet gestisce più sedi collegate via VPN da un unico server centrale.
Ogni sede ha una **modalità** che determina come il centrale raggiunge gli
apparati:

| Modalità | Come funziona | Quando usarla |
|----------|---------------|---------------|
| **Central poll** | Il centrale apre SSH direttamente verso i dispositivi remoti attraverso il routing VPN. Nessun processo remoto. | VPN site-to-site stabile, subnet remote raggiungibili dal centrale. |
| **Site agent** | Un processo leggero (`site_agent.py`) gira nella sede e si connette **in uscita** al centrale (HTTPS): spinge inventario, MAC-table e stato; i comandi CLI arrivano tramite una coda di job. | NAT/firewall che impedisce connessioni entranti verso la sede, VPN instabile, o per non esporre credenziali degli apparati fuori sede. |

La sede predefinita `central` esiste sempre e non è eliminabile.

---

## 1. Creare una sede

Dalla dashboard (account **admin**): tab **Sedi multi-sito** → *Nuova sede*.

1. **Nome** — es. `Milano` (l'id è derivato: `milano`).
2. **Modalità** — `Central poll` o `Site agent`.
3. **Subnet** — le reti della sede, es. `10.10.0.0/24, 10.10.1.0/24`
   (documentazione/riferimento per la scansione).

Per le sedi **agent** al momento della creazione viene mostrato **una sola
volta** il token di autenticazione dell'agente: copialo subito. Sul server
resta solo l'hash SHA-256; se lo perdi usa *Rigenera token* (il vecchio smette
di funzionare).

Equivalente via API:

```bash
curl -X POST https://central:8765/api/sites \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d '{"name": "Milano", "mode": "agent", "subnets": ["10.10.0.0/24"]}'
```

---

## 2. Sede in modalità Central poll

Non serve nulla nella sede remota. Sul centrale:

1. Verifica che il routing VPN raggiunga le subnet della sede (`ping`/SSH).
2. Aggiungi i dispositivi all'inventario (tab *Provisioning Apparato* o
   *Scansione Subnet* selezionando il Gruppo/Sede corretto).
3. Triage, backup, MAC tracker e terminale funzionano come per la sede locale:
   il traffico SSH parte dal centrale e attraversa la VPN.

---

## 3. Sede in modalità Site agent

### Installazione dell'agente

Nella sede remota (una VM/mini-PC Linux o Windows con Python 3.11+ e accesso
SSH agli apparati locali):

```bash
git clone <repo> SentinelNet && cd SentinelNet
pip install -r requirements.txt        # oppure: uv sync
```

Crea `agent.json`:

```json
{
  "central_url": "https://central:8765",
  "site_id": "milano",
  "token": "<TOKEN mostrato alla creazione della sede>",
  "interval": 60,
  "verify_tls": true,
  "data_dir": "./agent-data"
}
```

Avvio:

```bash
python site_agent.py --config agent.json
```

L'agente mantiene un **proprio inventario locale** (`network_hosts.csv` nella
`data_dir`) con le credenziali degli apparati della sede: popolalo con gli
stessi strumenti del centrale (CSV import o `inventory_manager`). Le
credenziali **non lasciano mai la sede**: al centrale arrivano solo IP,
hostname e vendor.

### Cosa fa ad ogni ciclo (default 60s)

1. **Heartbeat** — aggiorna *Ultimo contatto* nella tabella sedi.
2. **Push inventario** — i dispositivi compaiono sul centrale taggati con la sede.
3. **Push MAC-table** — alimenta il MAC tracker centrale.
4. **Esecuzione job** — preleva i comandi CLI accodati, li esegue via SSH in
   locale e ne posta l'esito.

### Esecuzione come servizio

Linux (systemd, `/etc/systemd/system/sentinelnet-agent.service`):

```ini
[Unit]
Description=SentinelNet Site Agent
After=network-online.target

[Service]
WorkingDirectory=/opt/SentinelNet
ExecStart=/usr/bin/python3 site_agent.py --config agent.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Windows: `nssm install SentinelNetAgent python C:\SentinelNet\site_agent.py
--config C:\SentinelNet\agent.json`.

---

## 4. Comandi CLI verso una sede agent (relay)

Il centrale non apre SSH verso le sedi agent: i comandi passano da una coda
persistente (SQLite) e vengono eseguiti dall'agente.

- `POST /api/send-command` (ruolo *operator*) rileva da solo che il
  dispositivo appartiene a una sede agent: accoda il job e attende l'esito
  fino a ~90 secondi, restituendo l'output come per un dispositivo locale.
  Se l'agente non risponde in tempo, la risposta è `{"status": "queued",
  "job_id": ...}`: recupera l'esito con `GET /api/command-jobs/{job_id}`.
- In alternativa `POST /api/sites/{site_id}/command` accoda senza attendere.
- La blacklist dei comandi distruttivi si applica anche al relay.

---

## 5. Manutenzione e sicurezza

- **Ultimo contatto** nella tabella sedi: se resta fermo, l'agente è giù o il
  token non è più valido (controlla i log dell'agente).
- **Rotazione token**: *Rigenera token* → aggiorna `agent.json` → riavvia
  l'agente. Fai ruotare i token periodicamente e dopo ogni cambio di personale.
- **TLS**: esponi il centrale in HTTPS (reverse proxy) e lascia
  `verify_tls: true`. `--no-verify-tls` solo per test.
- **Eliminare una sede** rimuove la definizione e invalida il token; i
  dispositivi già rispecchiati restano in inventario finché non li elimini.
- I job restano nello storico (`GET /api/sites/{site_id}/command-jobs`) con
  utente richiedente, esito e timestamp — utile per audit.
