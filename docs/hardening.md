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
        proxy_pass http://127.0.0.1:8000;
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
    reverse_proxy sentinelnet:8000
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

**Certificate renewal is the operator's responsibility**: SentinelNet does not
renew certificates. It can *generate* a self-signed one for a single host from
the Settings tab (Python's `cryptography`, so no `openssl` binary is needed on
any platform), with the address in the `subjectAltName` — without which modern
clients reject the certificate whatever its CN. That is a starting point for a
lab or an isolated management network, not a substitute for a real CA. Restart
the service after replacing the files.

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
- Logout (`POST /api/auth/logout`) clears the cookie and revokes the token.
- **Session lifetime** is set by an administrator in *Settings → Sessions*:
  an idle timeout (5–1440 minutes, default 60) and a maximum length (1–720
  hours, default 12). Every token lives the idle timeout. While the operator
  is using the page, the dashboard marks its requests with
  `X-SentinelNet-Active` (only within 2 minutes of real keyboard/pointer input,
  never for background polling) and the server re-issues the cookie at most
  once a minute, so a session ends one idle timeout after the last input. No
  renewal reaches past the maximum length from the sign-in. Changes apply from
  the next token issued, without restart.

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

## 5. FortiGate REST: an accepted risk, stated

Per-device TLS certificate verification for the FortiGate REST API defaults to
**off**, because a FortiGate almost always presents a self-signed certificate
and verifying it out of the box would leave every new install unable to poll
anything.

What that costs, so the decision is made with open eyes: the API token travels
as a `Bearer` header over a connection whose peer is not authenticated. Anyone
positioned on the path between SentinelNet and the firewall's management
interface can read that token and then use it directly against the FortiGate.

- Keep the management path a network you trust. This is the same assumption the
  panel itself makes (see the core rule at the top of this document).
- Where the FortiGate carries a certificate from a CA you run, **turn
  verification on** for that device: the checkbox is per-target, in the token
  dialog of the FortiGate Management tab.
- Treat a stolen API token as a full compromise of that firewall, and rotate it
  from the FortiGate side, not from here.

## 6. Restarting the application from the dashboard

The Settings tab can restart SentinelNet, so a changed listening port or a new
certificate can be applied without a shell. Two properties make that safe, and
both are worth stating explicitly.

**The application never kills itself.** The endpoint starts a separate oneshot
unit, `sentinelnet-restart.service`, whose only job is
`systemctl restart sentinelnet.service`. If the restart fails, the old process
is still running and still serving the panel. An app that exited on its own
would leave the machine with no panel and no way back in.

**The endpoint runs one fixed command line.** Nothing from the request body
reaches it — there is no unit-name parameter, no path, no arguments. The argv
is literally:

```
sudo -n systemctl start --no-block sentinelnet-restart.service
```

Install the two files from `docs/deploy/`:

```sh
sudo cp docs/deploy/sentinelnet-restart.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo install -m 0440 docs/deploy/sentinelnet-restart.sudoers      /etc/sudoers.d/sentinelnet-restart
sudo visudo -c
```

The sudoers fragment grants exactly that one command, with its exact arguments:

```
sentinelnet ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block sentinelnet-restart.service
```

It names one command rather than `systemctl` with a wildcard because a wildcard
would hand the application control of every service on the host — including the
firewall and the SSH daemon — and `ALL` would hand it the host. The blast radius
of a bug in the panel should be "the panel restarts", not "anything restarts".

### Windows service

On Windows there is no oneshot unit, and no environment variable that tells a
process it is running as a service — a service and a double-clicked exe look
identical from the inside. So the supervisor declares itself: set
`SENTINELNET_WINDOWS_SERVICE=1` in the service's environment when you install
it. With NSSM that is `nssm set SentinelNet AppEnvironmentExtra
SENTINELNET_WINDOWS_SERVICE=1`.

The service must be named `SentinelNet` — the name is fixed in the code
precisely because it ends up on a command line. The restart then runs, detached
and unwaited:

```
powershell -NoProfile -NonInteractive -Command Restart-Service -Name SentinelNet
```

Detached because `Restart-Service` stops this very process: a call that waited
for the result would never return. The account running the service needs
permission to stop and start it (grant it with `sc.exe sdset`, or run the
service as an account that already has it).

Without the variable the endpoint answers 409 rather than guessing — a wrong
guess here means "the panel stopped and did not come back".

### Neither supervisor

With no systemd and no declared Windows service (a PyInstaller exe, or a
process started by hand) the endpoint answers 409 instead of pretending: with
nothing to bring the process back, "restart" would only mean "stop".

## 7. MCP tools: least privilege

The MCP bridge exposes 46 tools to whatever model the operator points at it.
They all run **as the authenticated user**: `ai/mcp_server.py` calls the REST
API with that user's token, so RBAC, tenant scoping and the redaction
choke-point apply exactly as they do in the browser. An MCP client therefore
cannot read a tenant its user cannot read.

What it *can* do is act without a human reading the screen first, and that is
the risk this section is about. Decide per tool, not per bridge.

### Three tiers

| Tier | Tools | Why |
|---|---|---|
| **Read-only, safe to enable** | `list_devices`, `get_network_map`, `get_port_channels`, `locate_mac`, `search_mac`, `mac_to_ip`, `client_map`, `endpoint_inventory`, `analyze_config`, `get_triage_status`, `list_sites`, every `fortigate_*` and `wlc_*` read, `diagnose_client`, `policy_trace`, `policy_findings` | They read what the panel already shows to that user. The worst case is a model summarising data the user could open in two clicks |
| **Touches devices — enable deliberately** | `send_cli_command`, `arp_scan`, `generate_fortigate_config`, `generate_switch_config` | `send_cli_command` opens an SSH session and runs a string: the CLI blacklist still applies (admins bypass it, audited — see §M-1 in the code), but a model chooses the command. `arp_scan` interrogates gateways. The two generators produce configuration that someone may paste without reading |
| **Disabled by default** | `get_top_talkers`, `get_anomalies`, `linux_health` | `routers/mcp.py:_MCP_DEFAULT_DISABLED`. They stay off until an admin saves an explicit MCP setting: absent settings mean off, not "all on" |

### Rules that hold whatever you enable

- **Give the bridge its own account**, at the lowest role that answers the
  questions you want asked — `viewer` for a read-only assistant. A tool list
  is not an authorisation boundary; the account is.
- **Scope that account to the tenants the assistant is for.** An MCP user with
  no tenant restriction reads the whole estate, by design
  (`tests/test_rbac_scope.py` documents that empty means unrestricted).
- **`send_cli_command` deserves its own decision.** If the assistant only ever
  needs to read, leave it off: every vendor's `show` output is already
  reachable through the read-only tools above.
- **The audit log says who, and which client.** Calls carry
  `X-SentinelNet-Client: mcp/<tool>`, which is a *claim* by the caller, not
  proof — identity stays the token's. Read it as "which client says it made
  this call", which is what tells an MCP run apart from the dashboard.
- **A local model is still a third party** unless it runs on the same host:
  outbound messages pass through `redaction.redact()` first (finding I-1), and
  that choke-point is what keeps credentials and public addresses out of the
  prompt — not the tool selection.

---

## 8. Roles, tenants and tabs

Four roles, ranked `viewer` < `operator` < `admin` < `super_admin`
(`security/user_manager.py`), checked server-side by the dependencies in
`routers/deps.py`:

- **`super_admin`** is the only role that creates, changes, disables or
  deletes admin-level accounts, and it is never limited by tenant or tab. At
  least one must stay active; the break-glass reset (README) exists for when
  none is.
- **`admin`** manages operators and viewers. An admin can be limited to some
  tenants, and then manages only users inside them. Global settings — SMTP,
  SSO, public URL, certificates, updates, tenants, sites, cloud backup, MCP —
  need an admin with no tenant limit (`is_unscoped_admin`).
- **Tenant scope** (`user_group_scope`) filters every list and
  `assert_device_allowed` guards every device route: a device outside the
  caller's tenants answers the same as one that does not exist.
- **Tab permissions** (`require_tab`) are not a UI hint. Every `/api/*` route
  belongs to a tab and returns 403 to a user who does not hold it, so hiding a
  tab also closes its API.
- **SSO** maps IdP groups to at most `admin`. `super_admin` is assigned only
  locally, and role synchronisation never touches it.

Upgrading from a release before 0.40.0 promotes every existing admin to
`super_admin` (only if no super_admin exists yet, recorded in the audit log)
so nobody loses access. Demote the accounts that should not manage other
admins; with SSO role sync on, demote the ones that must keep following the
IdP.

---

## 9. Other recommendations

- Never publish port 8000 directly on the Internet.
- Restrict panel access to a VPN or management network.
- Set `SENTINELNET_JWT_SECRET` and `SENTINELNET_MASTER_KEY` explicitly in
  production; otherwise they are generated and stored in
  `SENTINELNET_DATA_DIR`.
- Protect `SENTINELNET_DATA_DIR` — it holds encrypted device credentials and
  the keys that decrypt them.

Audit and scan findings are tracked in `data/security/`, outside the public tree
— see [CONTRIBUTING.md](../CONTRIBUTING.md) §6.
