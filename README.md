# SentinelNet

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg)](pyproject.toml)
[![Docker image](https://img.shields.io/badge/Docker-claudiovidhi%2Fsentinelnet-2496ED.svg)](https://hub.docker.com/r/claudiovidhi/sentinelnet)

> Self-hosted network management, observability, backup automation and
> vulnerability intelligence for sysadmins and small IT teams.

**SentinelNet** is a self-hosted platform for centralized management of network
infrastructure. It automates configuration backup, detects the firmware versions
running on active devices and compares them in real time against the
NIST NVD vulnerability database — and it collects passive network telemetry
(NetFlow, IPFIX, sFlow, syslog, SNMP), correlates it with deterministic rules,
and turns it into explainable incidents. Everything is reachable from a single
browser console.

---

## Key features

- **Automatic backup** — saves device running-configs to local text files,
  organized by group and vendor.
- **Multi-vendor architecture** — pluggable drivers driven by a vendor registry:
  Cisco IOS, HPE ProCurve, Juniper Junos, Aruba OS, Fortinet FortiOS and Palo
  Alto PAN-OS. The vendor → driver → netmiko `device_type` mapping is
  centralized and easy to extend.
- **Firmware and vulnerability triage** — detects the installed firmware version
  and checks it against NIST NVD, with CVSS severity classification
  (CRITICAL / HIGH / MEDIUM / LOW).
- **Network observability** — passive collectors for IPFIX, NetFlow, sFlow and
  syslog, plus active FortiGate REST and SNMP polling, feeding a deterministic
  correlation engine that produces evidence-backed incidents.
- **Client diagnosis (L2 + L3)** — one report for a single client: access
  switch and port, port VLAN, link state and error-counter delta, whether its
  VLAN is allowed on the switch trunks, the logical traffic path, the firewall
  policy that would match a given destination, and blocks in the last hour
  grouped by policy. Across sites it also checks the far end's policy, live
  IPsec tunnel state and whether a route to the destination exists at all.
  Sections that cannot be answered say why rather than being omitted.
- **Subnet scanning** — automatic host discovery (ping + SSH probe) with
  optional triage and inventory registration.
- **Interactive topology map** — generates the 2D network map from CDP/LLDP
  tables found in backups, rendered with Vis.js. Three views (classic, new,
  layered); the layered one derives each device's tier from the topology and
  lets an operator name the core switch when the deduction does not match the
  rack, re-layering the map from that node.
- **Interactive SSH terminal** — WebSocket/Xterm.js console for live SSH
  sessions from the browser, authenticated with a single-use OTP token.
- **Groups and sites** — organize devices into logical groups (sites, customers)
  with drag-and-drop reassignment and per-group filtering across every view.
- **CSV import** — bulk inventory upload with per-row validation and a detailed
  error report.
- **Built-in security** — JWT authentication (fail-closed on the secret), Fernet
  encryption of credentials at rest, rotating audit log, rate limiting with
  brute-force lockout, and a dangerous-CLI-command blacklist enforced on both the
  one-shot API and the interactive terminal.

---

## Documentation

Full index: [docs/README.md](docs/README.md).

| Topic | Document |
|---|---|
| Engineering principles | [docs/principles.md](docs/principles.md) |
| Architecture, data pipeline, event/evidence/incident model | [docs/architecture.md](docs/architecture.md) |
| Data sources (NetFlow, IPFIX, sFlow, syslog, SNMP, REST) | [docs/collectors.md](docs/collectors.md) |
| Operations runbook (logs, diagnostics, retention, backup) | [docs/operations.md](docs/operations.md) |
| Secure exposure (TLS, reverse proxy) | [docs/hardening.md](docs/hardening.md) |
| Multi-site deployment | [docs/remote-sites.md](docs/remote-sites.md) |
| Layout, tests, build | [docs/development.md](docs/development.md) |
| Architecture decisions and their rationale | [docs/adr/](docs/adr/) |

Development rules (language convention, dual artifact, async-DB rule,
multi-group scope): [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Project layout

| Path | Responsibility |
|---|---|
| `app_server.py` | FastAPI entrypoint: lifespan, router mounting, static files |
| `core/` | SQLite writer, path/config resolution, SSH engine |
| `observability/` | Ingest → events → rules → evidence → incidents pipeline |
| `collectors/` | ARP, MAC tables, MAC history, subnet scanner |
| `routers/` | One FastAPI router per functional area |
| `services/` | FortiGate, WLC, inventory, provisioners, sites, site agent |
| `security/` | JWT/RBAC/audit, credential encryption, keystore, redaction |
| `ai/` | LLM assistant, config analyzer, MCP server and client |
| `drivers/` | One driver per vendor, `BaseDriver` as the contract |
| `templates/`, `static/` | Single-page web UI |

Detailed map with responsibilities: [docs/architecture.md](docs/architecture.md) §9.

---

## Requirements and installation

Python **3.11+** (`requires-python` in `pyproject.toml` is authoritative). The
Docker image ships 3.11; development happens on 3.14. Key dependencies:
`netmiko` for SSH
sessions, `fastapi`/`uvicorn` for the web server, `cryptography` for credential
encryption, `pysnmp` for the SNMP poller.

### With `uv` (recommended)

```bash
uv venv
uv pip install -r requirements.txt
```

### With standard `pip`

```bash
pip install -r requirements.txt
```

---

## Running the application

### Locally

```bash
uv run app_server.py     # with uv
python app_server.py     # with standard Python
```

SentinelNet opens the default browser at **`http://localhost:8000/`**.

On first start a setup wizard asks you to create the local administrator
account. Credentials are stored in `users.json` as bcrypt hashes and are never
transmitted in clear text.

Starting a second time while SentinelNet is already running does not fail on
the busy port: it opens the interface of the running instance and exits.

### Password recovery by email

Optional, and off until an SMTP server is configured under **Settings → Mail
server**. Each account can carry a recovery address, set from the Users tab;
an account without one simply cannot use this path — the link is never sent to
a fallback address such as the SMTP sender.

The link is built from the configured public base URL (`SENTINELNET_BASE_URL`,
or *Public base URL* in the advanced settings), never from the request's `Host`
header. When the server binds to `0.0.0.0` and no base URL is configured, no
mail is sent: there is no reachable host name to put in the link.

Tokens are single-use, valid 15 minutes, and held in memory only — restarting
the server invalidates any pending link. The reply to a recovery request is
identical whether or not the account exists.

### User invitations by email

With SMTP configured, an administrator can invite a colleague from the Users
tab instead of choosing an initial password for them and passing it along. The
invitee opens a link valid for 24 hours and picks their own password.

The account is created only when the invitation is accepted — an invitation
that is never accepted expires and leaves nothing behind. Username and role
come from the invitation, not from the request that redeems it: the address
invited becomes the username, and a redeemer cannot claim a role they were not
offered.

### Single Sign-On (OpenID Connect)

Optional, configured under **Settings -> Single Sign-On**. Local accounts keep
working: SSO is added alongside them, so a provider outage never locks everyone
out. The issuer must be HTTPS — discovery and the signing keys come from it.

The flow is authorization code with PKCE. Every id_token is verified against
the provider's published keys before any claim is used: signature, issuer,
audience, expiry and the per-login nonce, accepting asymmetric algorithms only.

Two switches default to off, deliberately:

- *Create the account on first sign-in* — with it on, anyone the provider can
  authenticate gets an account, which on a corporate directory is the whole
  address book. Off, an unknown identity is refused and told to contact an
  administrator.
- *Realign the role on every sign-in* — with it on, IdP groups are the source
  of truth and a role set locally is rewritten at the next login.

### Emergency administrator recovery (break-glass)

When every administrator account is locked out or disabled, reset one from the
machine that hosts the installation:

```bash
uv run app_server.py --reset-admin              # first administrator found
uv run app_server.py --reset-admin --user NAME  # a specific account
```

The password is typed interactively and never appears in the shell history.
The account is re-enabled and a password change is forced at the next login, so
whoever ran the recovery keeps no usable credentials. Every reset is written to
`audit.log`. The command needs local read/write access to `users.json` — the
same privilege that would allow editing that file by hand.

### With Docker

Configurations, credentials and backups are stored in a local `data` directory
for persistence.

```bash
docker compose up -d
```

Or run the pre-built official image without cloning the source:

```bash
docker run -d \
  -p 8000:8000 \
  -v ./data:/app/data \
  -e SENTINELNET_DATA_DIR=/app/data \
  --name sentinelnet \
  claudiovidhi/sentinelnet:latest
```

> [!NOTE]
> `claudiovidhi/sentinelnet` is the author's official public image. If you build
> and publish your own customized image, replace `claudiovidhi` with your Docker
> username.

The application is available at **`http://localhost:8000/`**.

---

## Environment variables

All variables are optional. When unset, SentinelNet generates and persists secure
keys in local files (`secret.key`, `jwt_secret.key`).

| Variable | Description | Default |
|---|---|---|
| `SENTINELNET_MASTER_KEY` | Passphrase from which the Fernet key for device-credential encryption is derived (via SHA-256). | `secret.key` file |
| `SENTINELNET_JWT_SECRET` | Secret used to sign session JWTs. | `jwt_secret.key` file |
| `SENTINELNET_ADMIN_USER` | Username used by the `default` credential profile and as a fallback for devices without one. | `Admin` |
| `SENTINELNET_ADMIN_PASS` | Password used by the `default` credential profile and as a fallback. | `admin` |
| `SENTINELNET_ADMIN_SECRET` | Enable secret used by the `default` credential profile and as a fallback. | `admin` |
| `SENTINELNET_DATA_DIR` | Data directory path (inventory, logs, keys). | `./data` |
| `SENTINELNET_HOST` | Server bind address. | `127.0.0.1` |
| `SENTINELNET_PORT` | Listening port. | `8000` |
| `SENTINELNET_NO_BROWSER` | If `true`, does not open the browser at startup (set automatically when the host is `0.0.0.0`). | `false` |
| `SENTINELNET_CORS_ORIGINS` | Comma-separated list of allowed CORS origins. | `http://localhost:8000,http://127.0.0.1:8000` |
| `SENTINELNET_SSL_CERTFILE` | TLS certificate (PEM) for native HTTPS; also requires `SENTINELNET_SSL_KEYFILE`. Relative paths resolve inside `SENTINELNET_DATA_DIR`. | HTTP |
| `SENTINELNET_SSL_KEYFILE` | TLS private key (PEM) for native HTTPS. | HTTP |

Observability listener variables (`SENTINELNET_OBS_*`) are documented in
[docs/operations.md](docs/operations.md) §3.

> **Panel exposure:** never expose the management panel over HTTP on untrusted
> networks. Full guidance on native TLS and reverse proxies:
> [docs/hardening.md](docs/hardening.md).

---

## Remote sites (multi-site)

SentinelNet manages multiple sites over VPN from a single central server, in
**central poll** mode (direct SSH over VPN) or **site agent** mode (a remote
agent that connects outbound and receives commands from a queue). Full
deployment guide: [docs/remote-sites.md](docs/remote-sites.md).

---

## MCP server — using SentinelNet from an external LLM client

Besides the AI assistant built into the dashboard, SentinelNet exposes its data
as an **MCP server** (Model Context Protocol) over stdio. Any compatible client
(Claude Desktop, LM Studio, Cline, …) can query the inventory, network map, MAC
tracker and config analyzer, run CLI commands and generate day-0 configuration —
with authorization (roles, tenants, command blacklist) always enforced
server-side.

Example Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "sentinelnet": {
      "command": "python",
      "args": ["/path/to/SentinelNet/ai/mcp_server.py"],
      "env": {
        "SENTINELNET_URL": "http://127.0.0.1:8000",
        "SENTINELNET_USERNAME": "admin",
        "SENTINELNET_PASSWORD": "..."
      }
    }
  }
}
```

The central server must be running. Available tools, by area:

| Area | Tools |
|---|---|
| **Diagnosis** | `diagnose_client` — the L2+L3 report for one client; prefer it over the per-device tools when the question is about a client rather than about one box |
| Inventory & topology | `list_devices`, `get_network_map`, `get_port_channels`, `list_sites` |
| Identity & location | `locate_mac`, `search_mac`, `mac_to_ip`, `client_map`, `arp_scan` |
| FortiGate | `fortigate_status`, `_interfaces`, `_arp`, `_dhcp_leases`, `_device_inventory`, `_policies`, `_policy_stats`, `_firewall_addresses`, `_firewall_policy_objects`, `_firewall_services`, `_policy_lookup`, `_sessions`, `_routes`, `_traffic_logs`, `_wifi_clients`, `_managed_aps`, `_full_config`, `_diagnose_client` |
| Cisco WLC | `wlc_status`, `_ap_summary`, `_client_summary`, `_client_detail`, `_wlan_summary`, `_rogue_aps`, `wlc_diagnose_client` |
| Config & ops | `analyze_config`, `get_triage_status`, `send_cli_command` |
| Provisioning | `generate_fortigate_config`, `generate_switch_config` |
| Observability | `get_top_talkers`, `get_anomalies`, `linux_health` — **disabled by default**, enable them in the MCP Server tab |

Write tools require an *operator* account; use a *viewer* account for read-only
access. The list above is the catalogue — what a given client actually sees is
whatever the MCP Server tab leaves enabled.

The dashboard's **MCP Server** tab (admin) provides setup guidance, a
ready-to-copy JSON snippet, and control over which tools are exposed to clients —
disabled tools disappear from the list and every call to them is rejected.

---

## Credential security

`network_hosts.csv` holds the encrypted credentials of physical devices and is
excluded from Git tracking via `.gitignore`. Before publishing the repository,
verify these files are excluded:

- `network_hosts.csv` — inventory with encrypted credentials
- `backup-config/` — device running-configs
- `detected_versions.json` — triage state cache
- `groups.json` — configured groups and sites
- `secret.key` / `jwt_secret.key` — local cryptographic keys
- `users.json` — local administrator accounts

---

## Contributing

Bug reports and pull requests are welcome. Read
[CONTRIBUTING.md](CONTRIBUTING.md) first: it carries the binding rules
(language convention, the dual exe/Docker artifact, the async-DB rule, the
multi-group scope rule). Security issues go through
[SECURITY.md](SECURITY.md), never a public issue.

Note on branches: `master` is the public branch and carries the product with
the development-only files stripped, so **it ships no test suite**. The tests
live on `Dev`, which is otherwise identical — verify there, then port.

---

## License

Licensed under the [Apache License 2.0](LICENSE). Licenses of bundled
third-party components: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
