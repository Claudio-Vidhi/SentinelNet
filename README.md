# SentinelNet

> Self-hosted network management, observability, backup automation and
> vulnerability intelligence for sysadmins and small IT teams.

**SentinelNet** is a self-hosted platform for centralized management of network
infrastructure. It automates configuration backup, detects the firmware versions
running on active devices and compares them in real time against the European
ENISA EUVD vulnerability database — and it collects passive network telemetry
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
  and checks it against ENISA EUVD, with CVSS severity classification
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
  tables found in backups, rendered with Vis.js.
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

Python **3.14+** (see `pyproject.toml`). Key dependencies: `netmiko` for SSH
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

SentinelNet opens the default browser at **`http://localhost:8765/`**.

On first start a setup wizard asks you to create the local administrator
account. Credentials are stored in `users.json` as bcrypt hashes and are never
transmitted in clear text.

### With Docker

Configurations, credentials and backups are stored in a local `data` directory
for persistence.

```bash
docker compose up -d
```

Or run the pre-built official image without cloning the source:

```bash
docker run -d \
  -p 8765:8765 \
  -v ./data:/app/data \
  -e SENTINELNET_DATA_DIR=/app/data \
  --name sentinelnet \
  claudiovidhi/sentinelnet:latest
```

> [!NOTE]
> `claudiovidhi/sentinelnet` is the author's official public image. If you build
> and publish your own customized image, replace `claudiovidhi` with your Docker
> username.

The application is available at **`http://localhost:8765/`**.

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
| `SENTINELNET_PORT` | Listening port. | `8765` |
| `SENTINELNET_NO_BROWSER` | If `true`, does not open the browser at startup (set automatically when the host is `0.0.0.0`). | `false` |
| `SENTINELNET_CORS_ORIGINS` | Comma-separated list of allowed CORS origins. | `http://localhost:8765,http://127.0.0.1:8765` |
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
        "SENTINELNET_URL": "http://127.0.0.1:8765",
        "SENTINELNET_USERNAME": "admin",
        "SENTINELNET_PASSWORD": "..."
      }
    }
  }
}
```

The central server must be running. Available tools: `list_devices`,
`get_network_map`, `get_port_channels`, `locate_mac`, `search_mac`,
`analyze_config`, `get_triage_status`, `send_cli_command`, `list_sites`,
`generate_switch_config`. Write tools require an *operator* account; use a
*viewer* account for read-only access.

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
