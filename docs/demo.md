# Demo mode

Demo mode runs SentinelNet on a separate, synthetic workspace so every feature
can be tried without real devices and without touching real data. All seeded
values are synthetic: RFC 5737 documentation subnets (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`), private ranges, generic hostnames
(`core-sw-01`, `fw-edge-01`, `plc-01`), `aa:bb:cc:…` MACs and CVE ids
(`CVE-2024-6xxxx`) that do not exist.

## How it works

- **Marker + restart.** Starting the demo writes `demo-mode` in the real data
  directory and restarts the app. At import `core/data_config.py` sees the
  marker and runs the whole process on `<real data dir>/demo`. Real data is
  never read or written while in demo; exiting removes the marker and restarts
  back on it.
- **First boot seeds.** If `<real data dir>/demo` is not yet seeded, the app
  seeds it at startup (`services/demo_seed.py`, idempotent: a
  `.demo-seeded` marker records that it ran). Delete the `demo` folder to
  start over.
- **Credentials.** A random password for the demo super-admin `admin` is
  generated once and stored in `<real data dir>/demo/DEMO-CREDENTIALS.txt`.
  The start request returns it, the UI shows it before the restart and
  prefills the login form when the app is back.
- **Nothing leaves the machine** (`core/demo_guard.py`). Background pollers,
  syslog listeners, the ping monitor, scheduled triage and the notification
  loop do not start. Outbound sockets and DNS lookups are refused except
  loopback; ICMP (`ping`/`traceroute`) and SNMP are refused; operations that
  start a device job (subnet scan, scan-verify, triage, backup now, bulk and
  single commands, provisioning push, probe enrollment, live diagnosis, feed
  syncs) answer `409 Demo mode`.

## Starting and exiting

| Where | Who | How |
|---|---|---|
| Settings → **Demo mode** | super_admin | **Start demo mode**, confirm in the dialog |
| First-run screen | anyone, only while the user store is empty | **Try with demo data** |
| Banner at the top (in demo) | super_admin | **Exit demo** |

The restart needs a supervisor (systemd or the Windows service). Without one
the request answers 409; from a source checkout use the dev launcher instead:

```sh
uv run python scripts/dev/run_demo.py            # seed if needed, start on :8931
uv run python scripts/dev/run_demo.py --reset    # wipe the demo workspace first
uv run python scripts/dev/run_demo.py --seed-only
uv run python scripts/dev/run_demo.py --port 8932 --no-browser
```

The launcher uses `data/demo-sandbox` (gitignored with the rest of `data/`)
as its "real" directory, so the demo workspace is
`data/demo-sandbox/demo` and the actual `./data` is never opened. It prints
the login.

## What is seeded

**`acme-hq`** — IT corporate, locations *HQ Campus* (`10.100.0.0/16`) and
*Branch Office* (`10.110.0.0/16`):

- Cisco IOS `core-sw-01` (L3 core, SVIs, ACLs `SERVERS-IN`/`GUEST-IN`, CDP
  neighbours), `access-sw-01`, `access-sw-02`; FortiGate `fw-edge-01`
  (WAN `203.0.113.100`, DMZ VIP, PBR for the guest VLAN) and `fw-branch-01`;
  Aruba `branch-sw-01`; Linux `srv-linux-01` (inventory only).
- Two config versions on `core-sw-01` (guest SSH opened to the servers),
  `access-sw-02` (HTTP, telnet, SNMP `public` added) and `fw-edge-01`
  (a `Temp-Any-Any` rule added); a tenant drift baseline for IOS.
- Interface states, ARP from the core and MAC sightings on the access ports,
  three segments (Users, Servers, DMZ), policy hit counters over 35 days
  (a dead and a nearly unused rule), CVE snapshots (one KEV), saved NetSec
  audits.

**`plant-demo`** — compliant multi-vendor OT cell:

- Jump-host bastion probe `ot-bastion`; Purdue-tagged `plc-01`, `switch-01`
  (SCALANCE), `hmi-01`, `fw-dmz-01` (FortiGate), `sw-core-01` (IOS),
  `fw-edge-pa` (PAN-OS), `fw-branch-srx` (Junos), `sw-dc-nxos` (NX-OS),
  `plc-cell-02` behind an IPS sensor.
- Process criticality and maintenance windows, OT vault artifacts with
  SHA-256, segments with Purdue levels, Modbus/HTTPS flows, a dual-homed host
  and a multi-MAC access port, the path-trace scenario (IT engineer → VIP →
  core ACL → PLC), compensating-control CVEs.

**`plant-legacy`** — OT site with findings: `switch-legacy-01` (telnet, HTTP,
SNMPv2c `public`, unused port up), `plc-legacy-01` (unsegregated S7comm, no
vault artifact, no gateway control). The tenant is in OT Safe Mode.

## Screens to check

| Area | Where | What to look at |
|---|---|---|
| Inventory | Devices | 18 devices across three organizations; use the tenant selector top left |
| Config diff / drift | Config Drift | two versions on `core-sw-01`, `access-sw-02`, `fw-edge-01`, `fw-dmz-01`; baseline deviations on `access-sw-02` |
| Map / topology | Map | `core-sw-01` linked to both access switches from CDP; segments as zones |
| Client map | Endpoints | ARP bindings of `acme-hq` and their access ports |
| Interfaces | Interfaces | down port on `access-sw-01`, admin-down on `access-sw-02`, legacy `Fa0/4` |
| CVE triage | Security | KEV on `access-sw-02` and `hmi-01`, high on `fw-edge-01` |
| Path trace | Routes → path trace | from `10.100.30.50` to the internet (PBR); from `10.20.0.5` to `192.0.2.10:502` (VIP + ACL) |
| Policy test | Routes → policy test | `fw-edge-01`, `core-sw-01`, `fw-dmz-01` against their ACLs/policies |
| NetSec audit | NetSec Audit | saved runs in the history; run CIS on `access-sw-02` v2 |
| Firewall hygiene | Traffic → Hygiene & Delta | dead `Legacy-Vendor-Access` and `Unused-Legacy-Vendor`, barely used `Temp-Any-Any` |
| What-if | Routes → policy test → What-if | remove or add a rule on `fw-edge-01` and see which flows change |
| Status report | NetSec Audit → network status report (pick one tenant top left) | `acme-hq` vs `plant-legacy`: hardening, drift, CVE, segmentation |
| OT: Blueprint / Purdue | Network Blueprint | `plant-demo` Purdue layers, zone/conduit checks |
| OT: compensating controls | Security | `plc-01` behind the core ACL, `plc-cell-02` behind the IPS, `plc-legacy-01` with none |
| OT vault | Devices → OT vault on `plc-01` | verify, download, upload artifacts |
| OT Safe Mode | Settings → tenant telemetry | `plant-legacy` passive-only; a scan of `198.51.100.0/24` is refused |

Active buttons (scan, backup now, push, terminal) answer with the demo-mode
message: that is the guard working, not a bug.
