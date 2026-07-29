# SentinelNet — Guida all'hardening del pannello di gestione

> Riferimento per il finding **H-1** (assenza di TLS built-in) e per la
> configurazione sicura dell'esposizione del pannello web.

**Regola fondamentale: il pannello di gestione non deve MAI essere esposto a
reti non fidate in HTTP.** Le opzioni supportate sono due, in ordine di
preferenza:

1. **Reverse proxy con terminazione TLS** (consigliata)
2. **TLS nativo** (integrato in SentinelNet, per installazioni semplici)

---

## 1. Reverse proxy (consigliato)

Un reverse proxy (nginx, Caddy, Traefik) davanti a SentinelNet gestisce
certificati, rinnovo automatico (ACME/Let's Encrypt), security header e
terminazione TLS. SentinelNet resta in ascolto solo su localhost o sulla rete
interna Docker.

### Requisiti obbligatori del proxy

- Terminazione TLS (certificato valido, TLS ≥ 1.2).
- Security header:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
  - `X-Frame-Options: DENY`
- **Passthrough WebSocket** per il terminale SSH integrato (upgrade su `/ws/...`).

### Esempio nginx

```nginx
server {
    listen 443 ssl;
    server_name sentinelnet.esempio.it;

    ssl_certificate     /etc/ssl/sentinelnet.crt;
    ssl_certificate_key /etc/ssl/sentinelnet.key;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header X-Frame-Options DENY always;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        # WebSocket (terminale SSH)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }
}
```

### Esempio Caddy (TLS automatico)

```
sentinelnet.esempio.it {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        Referrer-Policy no-referrer
        X-Frame-Options DENY
    }
    reverse_proxy sentinelnet:8765
}
```

Caddy gestisce automaticamente certificato, rinnovo e upgrade WebSocket. In
`docker-compose.yml` è presente una stanza `proxy` commentata pronta all'uso.

---

## 2. TLS nativo

SentinelNet può servire HTTPS direttamente, senza proxy. Impostare **entrambe**
le variabili d'ambiente:

| Variabile | Significato |
|---|---|
| `SENTINELNET_SSL_CERTFILE` | Percorso del certificato (PEM, catena completa) |
| `SENTINELNET_SSL_KEYFILE`  | Percorso della chiave privata (PEM) |

- I percorsi **relativi** sono risolti rispetto a `SENTINELNET_DATA_DIR`
  (identico tra sorgente, exe e Docker).
- Se è impostata **una sola** variabile, o un file non è leggibile, il server
  **rifiuta di avviarsi** (fail-closed) con un errore esplicito: nessun
  fallback silenzioso a HTTP.
- Se nessuna delle due è impostata il comportamento resta HTTP invariato
  (adatto solo a localhost/laboratorio).

**Il rinnovo del certificato è responsabilità dell'operatore**: SentinelNet non
genera né rinnova certificati. Dopo la sostituzione dei file è necessario
riavviare il servizio.

Esempio (Docker):

```yaml
environment:
  - SENTINELNET_SSL_CERTFILE=certs/server.crt   # → /app/data/certs/server.crt
  - SENTINELNET_SSL_KEYFILE=certs/server.key
```

Esempio (exe/sorgente, PowerShell):

```powershell
$env:SENTINELNET_SSL_CERTFILE = "C:\sentinelnet\data\certs\server.crt"
$env:SENTINELNET_SSL_KEYFILE  = "C:\sentinelnet\data\certs\server.key"
```

---

## 3. Sessione browser: cookie HttpOnly + anti-CSRF

Dal fix del finding **L-1** la sessione browser non usa più `sessionStorage`:

- Al login il server imposta il cookie **`net_session`**: `HttpOnly`,
  `SameSite=Strict`, e `Secure` quando la richiesta arriva su HTTPS (TLS
  nativo o reverse proxy con `X-Forwarded-Proto: https`).
- Le richieste che **modificano stato** (POST/PUT/PATCH/DELETE) autenticate
  via cookie devono includere l'header **`X-Requested-With`** (la dashboard lo
  invia sempre). Un form cross-site non può impostare header custom: insieme a
  `SameSite=Strict` questo costituisce la difesa anti-CSRF.
- I **client programmatici** (server MCP, script, agent) continuano a usare
  `Authorization: Bearer <token>`: il Bearer esplicito non è forgiabile
  cross-site e non richiede l'header anti-CSRF.
- Il logout (`POST /api/auth/logout`) cancella il cookie; il JWT è stateless e
  scade comunque entro 60 minuti.

## 4. Listener di osservabilità (IPFIX/sFlow/syslog)

Spenti di default ovunque (exe e Docker). Abilitazione via env:

```
SENTINELNET_OBS_ENABLE=1          # master switch
SENTINELNET_OBS_BIND=127.0.0.1    # 0.0.0.0 solo con opt-in esplicito
SENTINELNET_OBS_IPFIX_PORT=4739   SENTINELNET_OBS_IPFIX_ENABLE=1
SENTINELNET_OBS_SFLOW_PORT=6343   SENTINELNET_OBS_SFLOW_ENABLE=1
SENTINELNET_OBS_SYSLOG_PORT=5514  SENTINELNET_OBS_SYSLOG_ENABLE=1
SENTINELNET_OBS_RETENTION_FLOWS_DAYS=30   # _SYSLOG_DAYS=7, _EVENTS_DAYS=90
```

- **Mai la porta 514 in-process**: usare 5514 e, se serve la 514 standard,
  mapparla solo dal Docker compose (`"514:5514/udp"`).
- L'ingest UDP non è autenticato: esporlo SOLO su reti di management fidate.
  I datagrammi da IP non presenti in inventario sono scartati e messi in
  quarantena (tabella `quarantined_exporters`, voce di audit oraria).
- **Limite noto (NAT)**: l'attribuzione tenant usa l'IP sorgente del
  datagramma; exporter dietro NAT verrebbero attribuiti male e vanno gestiti
  con il relay di sede (fase 6.3 del piano), non esponendo l'UDP sulla VPN.
- Diagnostica: `GET /api/observability/health` (solo admin).

## 5. Altre raccomandazioni

- Non pubblicare mai la porta 8765 direttamente su Internet.
- Limitare l'accesso al pannello a VPN/rete di gestione.
- Impostare `SENTINELNET_JWT_SECRET` e `SENTINELNET_MASTER_KEY` espliciti in
  produzione (altrimenti generati e salvati in `SENTINELNET_DATA_DIR`).
- Proteggere `SENTINELNET_DATA_DIR` (credenziali apparati cifrate, chiavi).
