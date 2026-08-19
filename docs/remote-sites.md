# Remote sites and the site agent

SentinelNet manages multiple remote sites (reachable over VPN or the Internet)
from a single central server. Each site has a **connection mode** that
determines how central interacts with that site's devices:

| Mode | How it works | When to use it |
|---|---|---|
| **Central poll** (Mode A) | Central opens SSH connections directly to remote devices through site-to-site VPN routing. No extra process. | Stable site-to-site VPN, remote subnets directly reachable from central. |
| **Site agent** (Mode B) | A lightweight process (`services/site_agent.py`) runs on a server or VM inside the site and connects **outbound** to central over HTTPS. It pushes inventory, MAC tables and status; CLI commands travel through a job queue. | NAT or firewalls that block inbound connections to the site, an unstable VPN, or a requirement to keep credentials inside the site. |
| **Jump site** (Mode C) | Central opens one SSH connection to a bastion host inside the customer's network and tunnels every device SSH session through it (`core/net_ssh.py`, `direct-tcpip` channel). Nothing is installed at the site beyond the bastion's own `sshd`. | Customer refuses any installed agent or software, and grants only SSH access to a single Linux host that can reach the managed devices. |

The default site `central` always exists and cannot be deleted.

---

## 1. Site agent architecture (Mode B)

```
┌─────────────────────────────────────────┐               ┌──────────────────────────────────────────────┐
│         CENTRAL SENTINELNET             │               │            REMOTE SITE (VM / AGENT)          │
│                                         │  HTTPS (443)  │                                              │
│  - Web dashboard & API                  │ ◄───────────  │  - site_agent.py                             │
│  - Site registry & token hash           │  Outbound     │  - Local inventory (network_hosts.csv)       │
│  - Job queue (SQLite)                   │  polling      │  - Credentials stored locally                │
│  - Consolidated inventory & MAC tracker │               │  - Direct local SSH to switches/firewalls    │
└─────────────────────────────────────────┘               └──────────────────────┬───────────────────────┘
                                                                                 │ Local SSH
                                                                                 ▼
                                                                  ┌───────────────────────────────┐
                                                                  │ Local remote switch/firewall  │
                                                                  └───────────────────────────────┘
```

Key principles:

1. **Outbound-only connection.** The agent connects from the site up to central.
   No inbound port is opened at the remote site.
2. **Credential isolation.** SSH and enable passwords for remote devices live
   exclusively in the agent's local data directory (`network_hosts.csv`). Only
   metadata (IP, hostname, vendor, MAC table) is sent to central. This limits
   credential exfiltration from a compromised central server.
3. **CLI command relay.** When an administrator sends a CLI command from the
   dashboard to a device in an agent site, central enqueues a job. The agent
   picks it up during polling, executes it locally over SSH and returns the
   output.
4. **UDP syslog relay.** The agent listens for syslog locally on UDP `5514` (or
   `--syslog-port`), batches messages and transmits them to central over HTTPS
   (`POST /api/agent/syslog`), where they are stored in central observability
   tagged by site and tenant.

> **Known gap:** an authenticated agent currently receives *all* pending jobs
> for its site and executes them against whichever local device record matches
> the requested IP. The agent control plane and the device data plane are not
> yet fully separated. See [roadmap.md](roadmap.md).

---

## 2. Creating a site on central

From the dashboard (**admin** account): **Multi-site** tab → *New site*.

1. **Name** — e.g. `Milan-VM` (the derived alphanumeric id will be `milan-vm`).
2. **Mode** — select `Site agent`.
3. **Subnets** — the site's networks, e.g. `192.168.56.0/24` (for reference and
   documentation).

> **Important:** for **agent** sites, the agent authentication token (e.g.
> `agent_tok_...`) is shown **exactly once**, at creation. Copy it immediately.
> Central stores only the token's SHA-256 hash.

### Creating a site via API

```bash
# 1. Admin authentication to obtain the JWT
TOKEN=$(curl -s -X POST http://<CENTRAL_IP>:8765/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<ADMIN_PASSWORD>"}' | jq -r .access_token)

# 2. Create the agent site
curl -X POST http://<CENTRAL_IP>:8765/api/sites \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Milan-VM", "mode": "agent", "subnets": ["192.168.56.0/24"]}'
```

---

## 3. Deploying the agent

### 3.1 Prepare the remote host

On the VM or server that represents the remote site:

```bash
git clone https://github.com/Claudio-Vidhi/SentinelNet.git && cd SentinelNet
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3.2 Configure the agent

Create `agent.json` in the `SentinelNet` root:

```json
{
  "central_url": "http://<CENTRAL_IP>:8765",
  "site_id": "milan-vm",
  "token": "<TOKEN_SHOWN_AT_CREATION>",
  "interval": 15,
  "verify_tls": false,
  "data_dir": "./agent-data"
}
```

Or pass everything on the command line:

```bash
python3 services/site_agent.py --central-url http://<CENTRAL_IP>:8765 \
                               --site-id milan-vm \
                               --token <TOKEN> \
                               --no-verify-tls \
                               --data-dir ./agent-data
```

A helper script is available if the full repository including `scripts/` is
present:

```bash
python3 scripts/vm_agent_test_helper.py setup \
  --central-url http://<CENTRAL_IP>:8765 \
  --site-id milan-vm \
  --token <TOKEN> \
  --interval 15 \
  --no-verify-tls
```

### 3.3 Create the local device inventory

```bash
mkdir -p agent-data

cat << 'EOF' > agent-data/network_hosts.csv
IP,Vendor,Profile,Username,Password,Enable Secret,Group,Hostname,Site,SSH Port,Transports,SNMP Community,SNMP Disabled
192.0.2.10,cisco,custom,admin,,,Tenant_Milano,switch-01,milan-vm,22,,,
EOF
```

These thirteen columns are the canonical schema — the same ones
`inventory_manager.safe_write_hosts_csv` writes. Unrecognised columns are
dropped the first time the inventory is rewritten.

**`Group` and `Site` are two different things, and conflating them is the
classic multi-site mistake.** `Group` is the **tenant**: the visibility
boundary that RBAC filters on and that every observability row carries.
`Site` is the **physical location**: `central` (the server reaches the device
directly) or an agent site id. One tenant can span several sites; one site can
host devices from several tenants. On import, `group`/`gruppo`/`tenant` all
mean `Group`, and `site`/`sede` mean `Site`.

Only `IP` is required. `Site` defaults to `central`, `SSH Port` to `22`.
`Transports` is a JSON map (`{"ssh": 22}`) — leave it empty for plain SSH.

`Password`, `Enable Secret` and `SNMP Community` must be **Fernet ciphertext
produced by this agent's own key**. A plaintext value is not an error: it is
ignored, and the agent falls back to the default credentials. Set real
credentials through the agent's own inventory, not by pasting them into the
file. The remote editor in the dashboard cannot encrypt them either — central
does not hold the agent's key.

### 3.4 Verify connectivity before starting

```bash
curl -i -X POST http://<CENTRAL_IP>:8765/api/agent/heartbeat \
  -H "X-Site-Id: milan-vm" \
  -H "X-Site-Token: <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

`HTTP/1.1 200 OK` with `{"ok":true,"site_id":"milan-vm",...}` means
authentication is correct.

### 3.5 Start the agent

```bash
python services/site_agent.py --config agent.json
```

Expected output:

```text
[agent] avviato: centrale=http://192.168.1.100:8765 sede=milano-vm intervallo=15s
[heartbeat] sede 'milano-vm' ok, 1 dispositivi locali
```

(Agent log messages are in Italian, per the project's language convention: user-
facing strings are Italian, identifiers are English. See
[CONTRIBUTING.md](../CONTRIBUTING.md) §1.)

### 3.6 Verify on central

1. **Site status** — in the **Multi-site** tab, the `Milan-VM` row shows a live
   **Last contact** timestamp.
2. **Mirrored inventory** — in the **Device inventory** tab, `192.168.56.10`
   appears automatically, tagged with site `milan-vm`.
3. **CLI relay** — select the device and send a CLI command (e.g.
   `show version`). Central enqueues the job, the agent picks it up, runs it
   over local SSH and returns the result within seconds.

---

## 4. Installing the agent as a system service

### Linux (systemd)

`/etc/systemd/system/sentinelnet-agent.service`:

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

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelnet-agent
sudo systemctl status sentinelnet-agent
```

### Windows (NSSM)

```cmd
nssm install SentinelNetAgent C:\SentinelNet\.venv\Scripts\python.exe C:\SentinelNet\services\site_agent.py --config C:\SentinelNet\agent.json
nssm set SentinelNetAgent AppDirectory C:\SentinelNet
nssm start SentinelNetAgent
```

---

## 5. CLI relay and the job queue API

- `POST /api/send-command` (operator/admin) detects automatically whether the
  device belongs to an agent site. It enqueues the job and waits for the agent's
  response for up to ~90 seconds.
- If the agent takes longer, the HTTP response returns:

  ```json
  {"status": "queued", "job_id": "job_1234567890_abc"}
  ```

- The outcome can be retrieved at any time:

  ```bash
  curl -H "Authorization: Bearer $JWT" http://<CENTRAL_IP>:8765/api/command-jobs/job_1234567890_abc
  ```

- Commands on the security blacklist are blocked during relay too.

### 5.1 REST relay (read-only)

Jobs carry a `kind`: `cli` (the default, and what every existing job is) or
`rest`. A `rest` job's `command` column holds `{"path": ..., "params": {...}}`
and the agent executes it against the local device's REST API.

It exists because the questions a client diagnosis needs to ask have no
reliable CLI equivalent — `monitor/firewall/policy-lookup` ("which policy would
match this flow?") has none at all. Without it, branch sites answer
"unavailable" to precisely the questions the feature is for.

The path must match `site_manager.REST_RELAY_ALLOWLIST`: **`monitor/` and
`log/` only**, never `cmdb/` (which writes configuration), never
`config-script/upload`. `rest_path_allowed()` is checked **twice** — by central
when the job is queued, and by the agent before it touches the device. The
second check is deliberate: the point of agent mode is that credentials stay in
the site even if central is compromised, and an agent that runs whatever path
central dictates gives that away. See
[ADR-0008](adr/0008-agent-rest-relay.md).

Unlike the CLI relay, this path does **not** wait: the diagnosis queues the
request, reports it as pending, and picks up the answer on a later run (the
agent polls every `interval` seconds, 60 by default).

Also pushed by the agent, alongside inventory and MAC tables: **ARP tables**
(`POST /api/agent/arp`). Without them a remote client has a switch port but no
IP address — `arp_entries` holds the only MAC↔IP binding, and every view
downstream starts from the IP.

---

## 6. Jump site (bastion SSH, Mode C)

Pick this mode when the customer will not allow any SentinelNet process inside
their network — no agent, nothing installed — and grants only SSH access to a
single Linux host (the **bastion**) that can itself reach the managed devices.
Central tunnels every device SSH session through one connection to that
bastion; the customer never installs anything beyond the bastion's own
`sshd`.

### 6.1 Bastion prerequisites

- The bastion is reachable over SSH from central.
- The bastion account central logs in as is permitted to open TCP forwards
  (`AllowTcpForwarding yes` in `sshd_config` — the OpenSSH default; only an
  explicit `no` blocks it).
- The bastion has IP reachability to the devices central needs to manage.

### 6.2 Create the identity first, then the site

Bastion credentials are not stored on the site. They live as an **identity**
(`security/identity_manager.py`), and the site stores only that identity's id
— `sites.json` never holds the secret itself.

1. **Identities** tab (or `POST /api/identities`) — create an identity with
   the bastion's username and password.
2. **Multi-site** tab → *New site* → **Mode**: `Jump (bastion SSH)`. Three
   fields appear:
   - **Bastion host (IP/hostname)** — the bastion's IP or hostname, e.g. `198.51.100.10`.
   - **Bastion SSH port** — the bastion's SSH port, default `22`.
   - **Bastion identity (credentials)** — the identity created in step 1.

No token is issued for a jump site (there is no agent to configure).

### Creating a jump site via API

```bash
TOKEN=$(curl -s -X POST http://<CENTRAL_IP>:8765/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<ADMIN_PASSWORD>"}' | jq -r .access_token)

# 1. Create the bastion identity
IDENTITY_ID=$(curl -s -X POST http://<CENTRAL_IP>:8765/api/identities \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Bastion","tenant":"Customer_A","username":"svc-jump","password":"<BASTION_PASSWORD>","enable_secret":""}' \
  | jq -r .id)

# 2. Create the jump site, referencing the identity by id
curl -X POST http://<CENTRAL_IP>:8765/api/sites \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"name\": \"Customer A\", \"mode\": \"jump\", \"subnets\": [\"192.0.2.0/24\"], \
       \"jump_host\": \"198.51.100.10\", \"jump_port\": 22, \"jump_identity\": \"$IDENTITY_ID\"}"
```

### 6.3 What is doable, and what is not

The bastion gives us **outbound TCP only, initiated by us**. Everything
SentinelNet does that is not "open a TCP connection from central to a
device" stays broken.

**Works through a jump site:**

| Capability | Why it works |
|---|---|
| CLI collection: inventory, version, config backup (`core/core_engine.py:313,511,555,602`) | netmiko over a `direct-tcpip` channel |
| MAC table and ARP collection (`collectors/mac_collector.py`, `collectors/arp_collector.py`) | same |
| Port actions (`services/port_action.py`) | same |
| Switch and FortiGate day-0 provisioning via CLI | same, but pick the site in **Sede del target / Target site** on the SSH delivery panel: a day-0 device is not in the inventory yet, so the site cannot be derived from its IP |
| WLC CLI (`services/wlc_service.py`) | same |
| Bulk command, CLI modal, config analyzer, netsec audit (they consume CLI output) | same |

**Cannot work over a jump site (only ping and subnet scan are actively
refused — the rest simply have no working code path, and fail with a plain
connection error if you try):**

| Capability | Why |
|---|---|
| ICMP ping monitor (`services/ping_monitor.py:59`, `collectors/network_scanner._ping`) | ICMP is not TCP; an SSH channel cannot carry it |
| Subnet scan and discovery from the central | same, plus it needs broadcast/ARP adjacency |
| Syslog reception, NetFlow/flow ingestion | inbound UDP from devices to us; the bastion never initiates back |
| FortiGate REST, and any other `requests`-based vendor API | needs a listening local port, not a channel — not built |
| SNMP (if ever wired up; `pysnmp` is a dependency but currently unused in code) | UDP |
| Real-time device status in the inventory KPIs | derives from ping |

A jump site shows inventory and configs but never shows online/offline:
triage on a jump site reports reachability as **"not measurable"**, never as
"down". Manual ping (single or bulk) on a jump-site device returns that same
"not measurable" result instead of attempting ICMP; a subnet scan targeting a
jump site's subnet is refused outright with `HTTP 409` rather than answered
with a false "down".

### 6.4 No bastion host-key verification

SentinelNet does **not** verify the bastion's SSH host key. This matches
every other netmiko connection in this codebase, none of which verify host
keys either — but it is a real limitation: a machine-in-the-middle on the
network path to the bastion would not be detected.

### 6.5 Connection lifecycle

One SSH transport is kept per jump site and shared by all of that site's
devices; each device gets its own `direct-tcpip` channel over the shared
transport. A dead transport is rebuilt on the next call. Connecting to the
bastion is bounded by an explicit TCP connect timeout and an SSH banner
timeout, so a black-holed or silent bastion cannot hang a thread for the OS's
TCP retransmit ceiling; a failed connect leaves nothing cached. A channel whose
netmiko session fails to start (bad credentials, for instance) is closed
immediately rather than left on the shared transport, and every cached
transport is closed when the application shuts down.

Because the central has no direct IP route to a jump site's devices, the
direct-socket reachability pre-check that guards the CLI paths (triage and
backup, bulk command, the Linux health poller) is skipped for them: those
paths go straight to the tunnel. It still runs, unchanged, for central and
agent sites.

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| **HTTP 401 (heartbeat failed)** | Wrong token or site id | Check `agent.json`. If the token is lost, use **Regenerate token** in the dashboard and update `agent.json`. |
| **Devices don't appear on central** | `network_hosts.csv` empty or wrong on the remote host | Verify that `data_dir` in `agent.json` points at the folder containing `network_hosts.csv`. |
| **CLI command stuck in `queued`** | Agent not running, or the device IP is missing from the agent's *local* inventory | Confirm `site_agent.py` is running and that the requested IP exists in the agent's local inventory. |
| **TLS certificate error** | Self-signed certificate on central | Set `"verify_tls": false` in `agent.json` (test/lab only), or import the CA into the remote host's trust store. |
