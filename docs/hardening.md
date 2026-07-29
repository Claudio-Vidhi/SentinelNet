# Hardening

How to expose the management panel safely, and how the observability listeners
should be reachable.

**Core rule: the management panel must NEVER be exposed to untrusted networks
over HTTP.** Two supported options, in order of preference:

1. Reverse proxy with TLS termination (recommended)
2. Native TLS, built into SentinelNet, for simple installations

---

## 1. Reverse proxy (recommended)

A reverse proxy (nginx, Caddy, Traefik) in front of SentinelNet handles
certificates, automatic renewal (ACME/Let's Encrypt), security headers and TLS
termination. SentinelNet keeps listening on localhost or on the internal Docker
network only.

### Mandatory proxy requirements

- TLS termination (valid certificate, TLS ≥ 1.2).
- Security headers:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
  - `X-Frame-Options: DENY`
- **WebSocket passthrough** for the built-in SSH terminal (upgrade on `/ws/...`).

### nginx example

```nginx
server {
    listen 443 ssl;
    server_name sentinelnet.example.com;

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
        # WebSocket (SSH terminal)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }
}
```

### Caddy example (automatic TLS)

```
sentinelnet.example.com {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        Referrer-Policy no-referrer
        X-Frame-Options DENY
    }
    reverse_proxy sentinelnet:8765
}
```

Caddy handles the certificate, its renewal and the WebSocket upgrade
automatically. `docker-compose.yml` ships a commented-out `proxy` stanza ready
to use.

---

## 2. Native TLS

SentinelNet can serve HTTPS directly, without a proxy. Set **both** environment
variables:

| Variable | Meaning |
|---|---|
| `SENTINELNET_SSL_CERTFILE` | Certificate path (PEM, full chain) |
| `SENTINELNET_SSL_KEYFILE` | Private key path (PEM) |

- **Relative** paths resolve against `SENTINELNET_DATA_DIR` — identical
  behaviour across source, exe and Docker.
- If only **one** variable is set, or a file is unreadable, the server **refuses
  to start** (fail-closed) with an explicit error. There is no silent fallback
  to HTTP.
- If neither is set, behaviour stays HTTP — suitable for localhost and lab use
  only.

**Certificate renewal is the operator's responsibility**: SentinelNet neither
generates nor renews certificates. Restart the service after replacing the
files.

Docker example:

```yaml
environment:
  - SENTINELNET_SSL_CERTFILE=certs/server.crt   # → /app/data/certs/server.crt
  - SENTINELNET_SSL_KEYFILE=certs/server.key
```

Exe / source example (PowerShell):

```powershell
$env:SENTINELNET_SSL_CERTFILE = "C:\sentinelnet\data\certs\server.crt"
$env:SENTINELNET_SSL_KEYFILE  = "C:\sentinelnet\data\certs\server.key"
```

---

## 3. Browser session: HttpOnly cookie and CSRF defence

The browser session does not use `sessionStorage`:

- On login the server sets the **`net_session`** cookie: `HttpOnly`,
  `SameSite=Strict`, and `Secure` when the request arrives over HTTPS (native
  TLS, or a reverse proxy sending `X-Forwarded-Proto: https`).
- **State-changing requests** (POST/PUT/PATCH/DELETE) authenticated by cookie
  must carry the **`X-Requested-With`** header — the dashboard always sends it.
  A cross-site form cannot set custom headers; together with `SameSite=Strict`
  that constitutes the CSRF defence.
- **Programmatic clients** (MCP server, scripts, agents) keep using
  `Authorization: Bearer <token>`: an explicit bearer token cannot be forged
  cross-site and needs no anti-CSRF header.
- Logout (`POST /api/auth/logout`) clears the cookie; the JWT is stateless and
  expires within 60 minutes regardless.

---

## 4. Observability listeners (IPFIX/sFlow/syslog)

Off by default everywhere, in both the exe and Docker. Enable via environment:

```
SENTINELNET_OBS_ENABLE=1          # master switch
SENTINELNET_OBS_BIND=127.0.0.1    # 0.0.0.0 requires explicit opt-in
SENTINELNET_OBS_IPFIX_PORT=4739   SENTINELNET_OBS_IPFIX_ENABLE=1
SENTINELNET_OBS_SFLOW_PORT=6343   SENTINELNET_OBS_SFLOW_ENABLE=1
SENTINELNET_OBS_SYSLOG_PORT=5514  SENTINELNET_OBS_SYSLOG_ENABLE=1
SENTINELNET_OBS_RETENTION_FLOWS_DAYS=30   # _SYSLOG_DAYS=7, _EVENTS_DAYS=90
```

- **Never port 514 in-process**: use 5514, and if the standard port is required,
  map it from Docker Compose (`"514:5514/udp"`).
- **UDP ingest is unauthenticated.** Expose it ONLY on trusted management
  networks. Datagrams from IPs absent from the inventory are dropped and
  quarantined (`quarantined_exporters` table, hourly audit entry) — see
  [ADR-0005](adr/0005-strict-tenant-attribution.md).
- **Known limitation (NAT)**: tenant attribution uses the datagram's source IP,
  so exporters behind NAT would be misattributed. Handle them with a site relay,
  not by exposing UDP over the VPN.
- Diagnostics: `GET /api/observability/health` (admin only).

---

## 5. Other recommendations

- Never publish port 8765 directly on the Internet.
- Restrict panel access to a VPN or management network.
- Set `SENTINELNET_JWT_SECRET` and `SENTINELNET_MASTER_KEY` explicitly in
  production; otherwise they are generated and stored in
  `SENTINELNET_DATA_DIR`.
- Protect `SENTINELNET_DATA_DIR` — it holds encrypted device credentials and
  the keys that decrypt them.

Current security findings and their status: [security-audit.md](security-audit.md)
and [security-semgrep.md](security-semgrep.md).
