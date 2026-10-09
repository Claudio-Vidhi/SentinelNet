# Probes and the probe agent

> **Upgrading from 0.51 or earlier:** probes used to be called "sites". The
> agent protocol changed (`X-Probe-Id` / `X-Probe-Token`, config key
> `probe_id`, flag `--probe-id`): reinstall every probe agent after upgrading
> central. Data files are renamed automatically on first start. An agent whose
> systemd unit still runs `services/site_agent.py` stops after a self-update
> (`git pull`), because that file is now `services/probe_agent.py`: reinstall it
> (section 4).

SentinelNet manages multiple remote sites (reachable over VPN or the Internet)
from a single central server. Each probe (the record for one remote site) has a
**connection mode** that determines how central interacts with that site's
devices:

| Mode | How it works | When to use it |
|---|---|---|
| **Direct (central server)** (Mode A) | Central opens SSH connections directly to remote devices through site-to-site VPN routing. No extra process. | Stable site-to-site VPN, remote subnets directly reachable from central. |
| **Agent probe** (Mode B) | A lightweight process (`services/probe_agent.py`) runs on a server or VM inside the site and connects **outbound** to central over HTTPS. It pushes inventory, MAC tables and status; CLI commands travel through a job queue. | NAT or firewalls that block inbound connections to the site, an unstable VPN, or a requirement to keep credentials inside the site. |
| **Bastion probe** (Mode C) | Central opens one SSH connection to a bastion host inside the customer's network and tunnels every device SSH session through it (`core/net_ssh.py`, `direct-tcpip` channel). Nothing is installed at the site beyond the bastion's own `sshd`. | Customer refuses any installed agent or software, and grants only SSH access to a single Linux host that can reach the managed devices. |

The default probe `central` always exists and cannot be deleted.

## Supported platforms

**The probe agent runs on Linux only, and a Windows agent is not on the
roadmap.** The agent is not merely "untested" elsewhere: remote management of
it assumes systemd. Reading its log from the dashboard runs `journalctl -u
sentinelnet-agent`, and "Restart agent" exits the process expecting systemd to
bring it back. Neither has an equivalent on a host without systemd, so both
would fail -- the first with an error, the second by leaving the probe with no
agent at all.

**Central is the part that may run on Windows**, as a service or as the exe;
see [hardening.md](hardening.md) section 6 for restarting it from the dashboard
there. Central being on Windows says nothing about the probes: their agents
still need Linux.

A probe whose only available host is Windows is a **bastion probe** (Mode C) or a
Direct (central server) probe (Mode A), not an agent probe.

---

## 1. Probe agent architecture (Mode B)

```
┌─────────────────────────────────────────┐               ┌──────────────────────────────────────────────┐
│         CENTRAL SENTINELNET             │               │            REMOTE SITE (VM / AGENT)          │
│                                         │  HTTPS (443)  │                                              │
│  - Web dashboard & API                  │ ◄───────────  │  - probe_agent.py                            │
│  - Probe registry & token hash          │  Outbound     │  - Local inventory (network_hosts.csv)       │
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
   dashboard to a device in an agent probe, central enqueues a job. The agent
   picks it up during polling, executes it locally over SSH and returns the
   output.
4. **UDP syslog relay.** The agent listens for syslog locally on UDP `5514` (or
   `--syslog-port`), batches messages and transmits them to central over HTTPS
   (`POST /api/agent/syslog`), where they are stored in central observability
   tagged by probe and tenant.
5. **Central never dials the devices.** Principle 1 is only worth anything if
   nothing on central contradicts it, so an agent probe's devices are excluded
   from every direct probe: no ICMP from the ping check or the ping monitor,
   no TCP/22 reachability test, no SSH session for triage or bulk commands.
   Their status is what the agent pushes: ping results every cycle
   (`POST /api/agent/status`), a config snapshot and version report on its own
   `backup_interval` (`POST /api/agent/backup`), and — on demand, rather than
   on a schedule — a `triage` job an operator can enqueue from the dashboard
   the same way as a CLI command. Where nothing has been pushed yet the answer
   is "not measurable" rather than a guessed "offline" — the same tri-state a
   bastion probe uses. The predicates are
   `probe_manager.has_direct_path()` (false for `jump` **and** `agent`) and
   `probe_manager.is_agent_probe()` (the operation belongs to the agent, not
   merely the network path). A probe id central does not know keeps its direct
   path, which is what lets the agent run this same code over its own
   inventory.

6. **Who owns the inventory, per probe.** By default the agent does: it holds
   the device list and the credentials, and the central mirrors what is pushed
   up. Turning on **Inventario dal centrale**
   (`central_manages_devices` on the probe) reverses it — the central owns the
   list for that probe and hands it to the agent on each heartbeat, so a device
   added on the central appears at the site without anyone editing a CSV
   there.

   The flag is off by default, and that is deliberate: switching it on trades
   away principle 2. The credentials stop being probe-only and live on the
   central too, which is the right call when one team runs both ends and the
   wrong one when the customer's passwords must not sit on a shared server.

   Two rules make it safe to run:

   - **Credentials never travel over plain HTTP.** They are resolved to
     cleartext before sending (the agent has a different Fernet key and could
     not decrypt the central's ciphertext), so the push includes them only
     when the request arrived over TLS. Over HTTP the device identity still
     flows and the secrets do not; the response says which, in
     `credentials_included`.
   - **The push adds and updates, never deletes.** A device absent from the
     list means "the central does not know it", not "remove it" — the agent
     may hold devices the central has never seen, and the upward push is how
     it tells the central about them. A push carrying no credentials likewise
     leaves the ones the agent already holds untouched.

7. **MAC/ARP collection has its own cadence.** `l2_interval` (default 300s)
   governs the only phase that opens an SSH session to every device. It is
   deliberately not tied to `interval`: at a 10s poll that meant six sessions
   a minute per switch for tables that do not change that fast. `0` means
   every cycle, which is how it behaved before it had a clock.

> **Known gap:** an authenticated agent currently receives *all* pending jobs
> for its probe and executes them against whichever local device record matches
> the requested IP. The agent control plane and the device data plane are not
> yet fully separated. See [roadmap.md](roadmap.md).

> **Known gap:** two agent probes that use the same RFC 1918 address for
> different devices will overwrite each other's status and hostname on the
> central. Each endpoint refuses an IP that is not tagged to the calling probe,
> so no probe can write another's *record* — but `detected_versions.json` and
> the hostname store are keyed by IP alone across the whole product, so the
> second probe's device resolves to the first one's row. This predates the
> agent relay and applies equally to a Direct (central server) probe; it is an inventory
> keying limitation, not an authentication one.

---

## 2. Creating a probe on central

From the dashboard (**admin** account): **Probes** tab → *New probe*.

1. **Name** — e.g. `Milan-VM` (the derived alphanumeric id will be `milan-vm`).
   *Note: all non-alphanumeric characters including spaces and underscores (`_`)
   are converted to hyphens (`-`). For example, `test_ub_agent` produces id `test-ub-agent`.*
2. **Mode** — select `Agent probe`.
3. **Subnets** — the probe's networks, e.g. `192.168.56.0/24` (for reference and
   documentation).

> **Important:** for **agent** probes, the agent authentication token (e.g.
> `agent_tok_...`) is shown **exactly once**, at creation. Copy it immediately.
> Central stores only the token's SHA-256 hash.

### Creating a probe via API

```bash
# 1. Admin authentication to obtain the JWT
TOKEN=$(curl -s -X POST http://<CENTRAL_IP>:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<ADMIN_PASSWORD>"}' | jq -r .access_token)

# 2. Create the agent probe
curl -X POST http://<CENTRAL_IP>:8000/api/probes \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Milan-VM", "mode": "agent", "subnets": ["192.168.56.0/24"]}'
```

---

## 3. Deploying the agent

### 3.1 Prepare the remote host

On the **Linux** VM or server that represents the remote site (see **Supported
platforms**):

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
  "central_url": "http://<CENTRAL_IP>:8000",
  "probe_id": "milan-vm",
  "token": "<TOKEN_SHOWN_AT_CREATION>",
  "interval": 15,
  "verify_tls": false,
  "data_dir": "./agent-data"
}
```

Or pass everything on the command line:

```bash
python3 services/probe_agent.py --central-url http://<CENTRAL_IP>:8000 \
                               --probe-id milan-vm \
                               --token <TOKEN> \
                               --no-verify-tls \
                               --data-dir ./agent-data
```

A helper script is available if the full repository including `scripts/` is
present:

```bash
python3 scripts/vm_agent_test_helper.py setup \
  --central-url http://<CENTRAL_IP>:8000 \
  --probe-id milan-vm \
  --token <TOKEN> \
  --interval 15 \
  --no-verify-tls
```

### 3.3 Create the local device inventory

```bash
mkdir -p agent-data

cat << 'EOF' > agent-data/network_hosts.csv
IP,Vendor,Profile,Username,Password,Enable Secret,Group,Hostname,Probe,SSH Port,Transports,SNMP Community,SNMP Disabled
192.0.2.10,cisco,custom,admin,,,Tenant_Milano,switch-01,milan-vm,22,,,
EOF
```

These thirteen columns are the canonical schema — the same ones
`inventory_manager.safe_write_hosts_csv` writes. Unrecognised columns are
dropped the first time the inventory is rewritten.

**`Group` and `Probe` are two different things, and conflating them is the
classic multi-site mistake.** `Group` is the **tenant**: the visibility
boundary that RBAC filters on and that every observability row carries.
`Probe` is the **physical location**: `central` (the server reaches the device
directly) or a probe id. One tenant can span several probes; one probe can
host devices from several tenants. On import, `group`/`gruppo`/`tenant` all
mean `Group`, and `probe`/`sonda`/`site` mean `Probe`, so exports from before
the rename still load.

Only `IP` is required. `Probe` defaults to `central`, `SSH Port` to `22`.
`Transports` is a JSON map (`{"ssh": 22}`) — leave it empty for plain SSH.

`Password`, `Enable Secret` and `SNMP Community` must be **Fernet ciphertext
produced by this agent's own key**. A plaintext value is not an error: it is
ignored, and the agent falls back to the default credentials. Set real
credentials through the agent's own inventory, not by pasting them into the
file. The remote editor in the dashboard cannot encrypt them either — central
does not hold the agent's key.

### 3.4 Verify connectivity before starting

```bash
curl -i -X POST http://<CENTRAL_IP>:8000/api/agent/heartbeat \
  -H "X-Probe-Id: milan-vm" \
  -H "X-Probe-Token: <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

`HTTP/1.1 200 OK` with `{"ok":true,"probe_id":"milan-vm",...}` means
authentication is correct.

### 3.5 Start the agent

```bash
python services/probe_agent.py --config agent.json
```

Expected output:

```text
[agent] avviato: centrale=http://192.168.1.100:8000 sonda=milano-vm intervallo=15s
[heartbeat] sonda 'milano-vm' ok, 1 dispositivi locali
```

(Agent log messages are in Italian, per the project's language convention: user-
facing strings are Italian, identifiers are English. See
[CONTRIBUTING.md](../CONTRIBUTING.md) §1.)

### 3.6 Verify on central

1. **Probe status** — in the **Probes** tab, the `Milan-VM` row shows a live
   **Last contact** timestamp.
2. **Mirrored inventory** — in the **Device inventory** tab, `192.168.56.10`
   appears automatically, tagged with probe `milan-vm`.
3. **CLI relay** — select the device and send a CLI command (e.g.
   `show version`). Central enqueues the job, the agent picks it up, runs it
   over local SSH and returns the result within seconds.

---

## 4. Installing the agent as a system service

### Linux (systemd)

`/etc/systemd/system/sentinelnet-agent.service`:

```bash
sudo tee /etc/systemd/system/sentinelnet-agent.service << EOF
[Unit]
Description=SentinelNet Probe Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/SentinelNet
ExecStart=/opt/SentinelNet/.venv/bin/python services/probe_agent.py --config /opt/SentinelNet/agent.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now sentinelnet-agent
sudo systemctl status sentinelnet-agent
```

### Windows

Not supported, and not planned. This section used to carry NSSM instructions;
they are gone because what they produced was an agent the dashboard could
neither read the log of nor restart -- see **Supported platforms** at the top
of this document. Use a Linux host for the agent, or connect the site through a bastion
probe (Mode C, section 6) instead.

---

## 5. CLI relay and the job queue API

- `POST /api/send-command` (operator/admin) detects automatically whether the
  device belongs to an agent probe. It enqueues the job and waits for the agent's
  response for up to ~90 seconds.
- If the agent takes longer, the HTTP response returns:

  ```json
  {"status": "queued", "job_id": "job_1234567890_abc"}
  ```

- The outcome can be retrieved at any time:

  ```bash
  curl -H "Authorization: Bearer $JWT" http://<CENTRAL_IP>:8000/api/command-jobs/job_1234567890_abc
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

The path must match `probe_manager.REST_RELAY_ALLOWLIST`: **`monitor/` and
`log/` only**, never `cmdb/` (which writes configuration), never
`config-script/upload`. `rest_path_allowed()` is checked **twice** — by central
when the job is queued, and by the agent before it touches the device. The
second check is deliberate: the point of agent mode is that credentials stay in
the probe even if central is compromised, and an agent that runs whatever path
central dictates gives that away. See
[ADR-0008](adr/0008-agent-rest-relay.md).

Unlike the CLI relay, this path does **not** wait: the diagnosis queues the
request, reports it as pending, and picks up the answer on a later run (the
agent polls every `interval` seconds, 60 by default).

Also pushed by the agent, alongside inventory and MAC tables: **ARP tables**
(`POST /api/agent/arp`). Without them a remote client has a switch port but no
IP address — `arp_entries` holds the only MAC↔IP binding, and every view
downstream starts from the IP.

Two more pushes complete the protocol: **device status** every cycle
(`POST /api/agent/status`, ping results feeding the tri-state described in
principle 5) and **backup/version reports** (`POST /api/agent/backup`) on the
agent's own `backup_interval` — 3600 seconds by default, `0` disables it —
rather than on any schedule central controls.

---

## 6. Bastion probe (bastion SSH, Mode C)

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

### 6.2 Create the identity first, then the probe

Bastion credentials are not stored on the probe. They live as an **identity**
(`security/identity_manager.py`), and the probe stores only that identity's id
— `probes.json` never holds the secret itself.

1. **Identities** tab (or `POST /api/identities`) — create an identity with
   the bastion's username and password.
2. **Probes** tab → *New probe* → **Mode**: `Bastion probe (SSH)`. Four
   fields appear:
   - **Bastion host (IP/hostname)** — the bastion's IP or hostname, e.g. `198.51.100.10`.
   - **Bastion SSH port** — the bastion's SSH port, default `22`.
   - **Bastion identity (credentials)** — the identity created in step 1.
   - **Default device identity** — optional, and a *different* credential:
     the login used on the devices behind the bastion. See 6.2.1.

No token is issued for a bastion probe (there is no agent to configure).

#### 6.2.1 Two credentials, not one

The bastion login and the device login are separate. A device row picks its
own credential through the `Profile` column (`identity:<id>`, or an inline
username/password); when that column says `default`, the probe's **default
device identity** is used, and only if the probe declares none does the
resolution fall back to the installation-wide `SENTINELNET_ADMIN_USER` /
`SENTINELNET_ADMIN_PASS`. Setting the probe default is what stops a customer's
devices from being dialled with this installation's own admin account.

The field can be changed later from the probe row in the **Probes** tab, or
with `POST /api/probes/update` (`{"id": "...", "device_identity": "<id>"}`);
an empty string clears it.

Because the two hops have their own credential, a refused login is reported
per hop: the bastion refusing us raises `BastionAuthError`
(`core/net_ssh.py`), whose message says the device was never contacted. The
**Test bastion** button on the probe row (`POST /api/probes/test-bastion`) dials
the bastion with the identity as currently configured — bypassing the cached
transport on purpose — and answers `success`, `auth_failed` or `unreachable`.

**Host-key pinning:** On first connection to a bastion, its SSH host key is
pinned to `ssh_known_hosts` inside the data directory. On subsequent
connections, the key must match exactly; if it differs, a `BastionHostKeyError`
is raised and the connection refused. This protects against path interception.
If the bastion is rebuilt and the key changes, the stale entry must be manually
removed from `ssh_known_hosts` before reconnecting.

**Editing the bastion identity:** The bastion identity (username, password, or
enable secret) can be changed in the **Probes** tab or via `POST
/api/probes/update`. When the identity changes, the cached transport is
automatically invalidated by `invalidate_probe()` (`core/net_ssh.py`), so the
next connection uses the updated credentials. This allows credential rotation
without restarting the application.

### Creating a bastion probe via API

```bash
TOKEN=$(curl -s -X POST http://<CENTRAL_IP>:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<ADMIN_PASSWORD>"}' | jq -r .access_token)

# 1. Create the bastion identity
IDENTITY_ID=$(curl -s -X POST http://<CENTRAL_IP>:8000/api/identities \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Bastion","tenant":"Customer_A","username":"svc-jump","password":"<BASTION_PASSWORD>","enable_secret":""}' \
  | jq -r .id)

# 2. Create the bastion probe, referencing the identity by id
curl -X POST http://<CENTRAL_IP>:8000/api/probes \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"name\": \"Customer A\", \"mode\": \"jump\", \"subnets\": [\"192.0.2.0/24\"], \
       \"jump_host\": \"198.51.100.10\", \"jump_port\": 22, \"jump_identity\": \"$IDENTITY_ID\", \
       \"device_identity\": \"$DEVICE_IDENTITY_ID\"}"
```

### 6.3 What is doable, and what is not

The bastion gives us **outbound TCP only, initiated by us**. Everything
SentinelNet does that is not "open a TCP connection from central to a
device" stays broken.

**Works through a bastion probe:**

| Capability | Why it works |
|---|---|
| CLI collection: inventory, version, config backup (`core/core_engine.py`) | netmiko over a `direct-tcpip` channel |
| MAC table and ARP collection (`collectors/mac_collector.py`, `collectors/arp_collector.py`) | same |
| Port actions (`services/port_action.py`) | same |
| Switch day-0 provisioning via CLI | same, but pick the probe in the **Target probe** selector on the SSH delivery panel: a day-0 device is not in the inventory yet, so the probe cannot be derived from its IP. A FortiGate day-0 config is not pushed by SentinelNet at all, so nothing crosses the bastion |
| WLC CLI (`services/wlc_service.py`) | same |
| Bulk command, CLI modal, config analyzer, netsec audit (they consume CLI output) | same |

**Cannot work over a bastion probe (only ping and subnet scan are actively
refused — the rest simply have no working code path, and fail with a plain
connection error if you try):**

| Capability | Why |
|---|---|
| ICMP ping monitor (`services/ping_monitor.py`, `collectors/network_scanner._ping`) | ICMP is not TCP; an SSH channel cannot carry it |
| Subnet scan and discovery from the central | same, plus it needs broadcast/ARP adjacency |
| Syslog reception, NetFlow/flow ingestion | inbound UDP from devices to us; the bastion never initiates back |
| FortiGate REST, and any other `requests`-based vendor API | needs a listening local port, not a channel — not built |
| SNMP (if ever wired up; `pysnmp` is a dependency but currently unused in code) | UDP |
| Real-time device status in the inventory KPIs | derives from ping |

A bastion probe shows inventory and configs but never shows online/offline:
triage on a bastion probe reports reachability as **"not measurable"**, never as
"down". Manual ping (single or bulk) on a bastion-probe device returns that same
"not measurable" result instead of attempting ICMP; a subnet scan targeting a
bastion probe's subnet is refused outright with `HTTP 409` rather than answered
with a false "down".

### 6.4 No bastion host-key verification

SentinelNet does **not** verify the bastion's SSH host key. This matches
every other netmiko connection in this codebase, none of which verify host
keys either — but it is a real limitation: a machine-in-the-middle on the
network path to the bastion would not be detected.

### 6.5 Connection lifecycle

One SSH transport is kept per bastion probe and shared by all of that probe's
devices; each device gets its own `direct-tcpip` channel over the shared
transport. A dead transport is rebuilt on the next call. Connecting to the
bastion is bounded by an explicit TCP connect timeout and an SSH banner
timeout, so a black-holed or silent bastion cannot hang a thread for the OS's
TCP retransmit ceiling; a failed connect leaves nothing cached. A channel whose
netmiko session fails to start (bad credentials, for instance) is closed
immediately rather than left on the shared transport, and every cached
transport is closed when the application shuts down.

Because the central has no direct IP route to a bastion probe's devices, the
direct-socket reachability pre-check that guards the CLI paths (triage and
backup, bulk command, the Linux health poller) is skipped for them: those
paths go straight to the tunnel. It still runs, unchanged, for central and
agent probes.

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| **HTTP 401 (heartbeat failed)** | Wrong token or probe id | Check `agent.json`. If the token is lost, use **Regenerate token** in the dashboard and update `agent.json`. |
| **Devices don't appear on central** | `network_hosts.csv` empty or wrong on the remote host | Verify that `data_dir` in `agent.json` points at the folder containing `network_hosts.csv`. |
| **CLI command stuck in `queued`** | Agent not running, or the device IP is missing from the agent's *local* inventory | Confirm `probe_agent.py` is running and that the requested IP exists in the agent's local inventory. |
| **TLS certificate error** | Self-signed certificate on central | Set `"verify_tls": false` in `agent.json` (test/lab only), or import the CA into the remote host's trust store. |
