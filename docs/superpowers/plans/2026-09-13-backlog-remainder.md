# Plan — what is left of the backlog (2026-09-13)

Follows [2026-09-12-deferred-backlog.md](2026-09-12-deferred-backlog.md), whose
phases 0-4 are closed. Every item below was **checked against the tree at
`114deee`** before being written: the previous triage carried entries that
were already done, including one (V4, scheduled ARP/MAC) that had shipped
months earlier.

**Ordering criterion**, the roadmap's own: how much new data or new decision an
item needs. Verifying what already shipped comes first, because an unverified
feature is a liability that looks like an asset.

Gates after every phase (`docs/development.md` §6): pyrefly 0, `pytest -n 4`
green, `check_frontend` if `static/js` or `templates/` changed,
`check_no_private_data`, `graphify update .`. A new guard only counts once it
has been **seen failing** with the fix removed — one test this week passed with
and without its fix.

---

## Verified state

| Item | State | Evidence |
|---|---|---|
| Roadmap §1 items 1-5 (flapping, suppression, confirmation, unreachable, ack) | done | `IFACE_FLAPPING_001`, `suppression.py`, `min_observations`, `DEVICE_UNREACHABLE_001`, schema v11 |
| Roadmap §3 item 2, MAC → server correlation | **done, roadmap not updated** | `mac_history.device_positions()` (`397be2a`) |
| Roadmap §3 item 5, server CVEs via NVD | **Linux done, Windows missing** | `drivers/registry.py` `CPE_PRODUCTS` has `linux`, no `windows` |
| Roadmap §3 item 9, SNMP against servers | **CPU only** | `snmp_poller.py:95` polls `hrProcessorLoad`; the memory OIDs at `:104-105` are CISCO-MEMORY-POOL, so a server reports no RAM; no `hrStorage`, no `sysContact` |
| Live CPU/RAM/disk for Windows hosts | **missing** | `linux_poller._linux_devices()` keeps only `vendor == linux`; Windows has the triage snapshot only, so `DEVICE_LOAD_001` never fires for it |
| Roadmap §3 item 3, syslog from Linux/Windows | not done | the receiver parses RFC 3164/5424 already (`ingesters/syslog.py`); nothing tells an operator how to point rsyslog or NXLog at it |
| Roadmap §3 item 4, service health checks | not done | no TCP port check outside `collectors/network_scanner.scan_subnet` |
| Roadmap §3 item 8, AD/LDAP login | not done | `ldap` appears only as a port name in `services/policy_test` |
| Roadmap §1 item 6, notification engine | undecided | `services/mailer.py` exists, used only by password recovery and invites |
| P5, agent/device plane separation | **deferred to its trigger** (user, 2026-09-13) | roadmap §2 names the trigger; it has not occurred |
| P2, FortiGate HA member parsing | unverifiable | no cluster available |

Out of scope, as before: the Go port (`../sentinelnet-go`) keeps its own plan.

---

## Phase A — Verify what shipped this week (no new code expected)

Nothing here is a feature. It is the difference between "implemented" and
"works", and every item needs the user's hands or hardware.

### A1 — Windows SSH transport, on the user's VM

The twenty PowerShell commands already ran on a real Windows 11. What remains
unproven is netmiko `generic` against the cmd.exe prompt over SSH.

```sh
uv run python scripts/dev/windows_probe.py --ip <vm> --user <account> --save data/probe.txt
```

Done when the probe reports `detect_config_type: windows`, fifteen populated
sections with an administrator account, and a hostname — then one full triage
from the UI against the same VM.

If it fails, the likely point is `find_prompt()` on cmd.exe. The fix belongs in
`drivers/windows.py` (a prompt normaliser, as `drivers/linux.py` has
`sanitize_session`), not in the probe. Record the outcome in
`docs/windows-collection.md` §6 either way.

### A2 — Visual review (the old Phase 5)

Needs the app running and the user's login, which a session cannot do: the
cookie is HttpOnly. **The Chrome DevTools MCP server failed to connect on
2026-09-13** — reconnect it (`/mcp`) before starting.

What to look at is in the review mockup
(<https://claude.ai/code/artifact/cfbfab8c-2e55-4db3-9d46-d2d511f4da69>): the
11px clickable-KPI arrow (U1), the `nowrap` hostname column (U2), and the three
panels nobody has opened — site edit, agent enrollment, the position line under
an inventory IP. Add the HA tab with a tenant that owns no group: that is the
bug fixed in `55dd811`, verified so far only by the node harness.

### A3 — Sync the roadmap

`docs/roadmap.md` §3 still lists item 2 (MAC → server) as open. Mark it done,
and mark item 5 "Linux done, Windows: see B1". Docs only.

### A4 — Release 0.37.0 (the user's call)

`CHANGELOG.md` `[Unreleased]` is complete. MINOR, not PATCH: schema v11, three
new rules, a new platform. `release.py` never pushes; publishing and attaching
the installer stay the user's decision.

---

## Phase B — Close the two gaps the Windows work opened

Small, on data already collected, and they make a just-shipped platform whole.

### B1 — CVE correlation for Windows hosts

A Windows host in inventory gets no CVE correlation: `CPE_PRODUCTS` has no entry
for the driver added this week.

It is not the one-line entry it looks like. NVD names Windows by **edition and
release** (`windows_server_2022`, `windows_10_22h2`, `windows_11_23h2`), so a
single product string would match either nothing or every Windows ever shipped.
It needs a caption → product mapper, the same shape as `CISCO_OS_PRODUCTS` /
`cisco_os()` already in `drivers/registry.py`, fed by the `OS INFO` caption and
build the triage already stores.

- `drivers/registry.py`: a `windows_product(caption, build)` and a `windows`
  entry that uses it.
- An unrecognised edition returns `None`, so the CVE view says "not evaluated"
  instead of guessing — `cve_intel.not_evaluated_for` already has that state.
- **Check every product string against NVD before writing it**; the existing
  entries carry their NVD hit counts in comments for that reason.

Test: Server 2019/2022/2025 and Windows 10/11 captions map to their products;
an unrecognised caption maps to `None`; a Windows device reaches
`cve_intel.query_for` with confidence `exact` when the build is known.

### B2 — Live load for Windows hosts

`DEVICE_LOAD_001` never fires for Windows: the health poller only takes Linux,
and the SNMP poller reads memory from a Cisco-only MIB.

Take the SSH path, not SNMP. The SNMP service on Windows is a deprecated
optional feature, while the OpenSSH server is already a prerequisite of the
platform.

- A Windows branch next to `observability/ingesters/linux_poller.py` — a sibling
  `windows_poller.py` with the same loop if the branch grows past a handful of
  lines — running **one** PowerShell command that prints
  `cpu_pct|memory_pct|disk_pct` from `Win32_Processor`, `Win32_OperatingSystem`
  and `Win32_LogicalDisk` for the system drive. Same pipe-delimited rule as the
  driver, for the same reason: the output is localised.
- The snapshot lands in `api_observations` with a `metrics` branch, which is all
  `DEVICE_LOAD_001` reads. No rule change.
- Off by default, like `linux_poll_s`: it opens SSH sessions with device
  credentials.

Test: parsing of a line captured on a real host (run the command locally, as was
done for the triage commands), a missing field reported as absent and not as
zero, `DEVICE_LOAD_001` firing on a Windows snapshot over threshold.

---

## Phase C — Medium features on existing machinery

### C1 — Syslog from Linux and Windows servers (roadmap §3 item 3)

The receiver already parses RFC 3164 and 5424 and attributes by source IP
against inventory, so this is mostly **documentation**, plus one proof:

- `docs/collectors.md` §5: an rsyslog forwarding stanza, with the UDP/TCP choice
  explained, and for Windows the NXLog option with the honest trade-off —
  Windows does not speak syslog natively.
- One test feeding a verbatim rsyslog RFC 5424 line and an NXLog-formatted line
  through `ingesters/syslog.parse`, attributed to an inventory host.

Done when an operator can follow the doc without reading the code.

### C2 — Service health checks (roadmap §3 item 4)

TCP port checks against registered services (SSH 22, RDP 3389, HTTPS 443, a
database port), as a fact the engine can reason about. Three questions to
settle in a short spec **before** code:

1. **Where the expected ports are declared.** A per-device list in inventory is
   explicit but a new CSV column; deriving it from the triage's `LISTENING
   PORTS` section needs no operator input but checks yesterday's reality, not
   intent.
2. **What a failed check becomes.** A `service.down` event and a rule that uses
   `min_observations` — the confirmation machinery shipped this week exists for
   exactly this.
3. **Reachability vs service.** A host that stopped answering is already
   `DEVICE_UNREACHABLE_001`; a closed port on a reachable host is the new fact.
   The rule must not produce both for the same outage.

Reuse `collectors/network_scanner` for the TCP connect. Off by default.

### C3 — SNMP against appliances (roadmap §3 item 9, remainder)

Only after B2, which covers the Windows case more cheaply. What is left is
appliances reachable neither by SSH nor by a vendor API: `hrStorage` (RAM and
disk percentages) and `sysContact`. Check first whether any device in the
user's estate needs it; if none does, park it with that finding written down.

---

## Phase D — Needs a decision before any code

### D1 — Notification engine and escalation (roadmap §1 item 6)

**This is now unblocked, and that is worth saying plainly.** The roadmap held
confirmation-before-concluding, `device.unreachable` and full acknowledgement
back as debts that explode the day notifications exist. All three shipped this
week. What stays open is product, not plumbing:

- channels: email through the existing `services/mailer.py`, a webhook, or both;
- who is notified: per tenant, per severity, per rule;
- what silences it: `ack`, a suppression window, `resolved` — all already on the
  incident, which is why the engine can stay small;
- rate limiting and a digest, so one flapping link is not forty emails.

Next step: a spec with the user, not an implementation.

### D2 — AD/LDAP login (roadmap §3 item 8)

Security-sensitive, a new dependency (`ldap3`), and it touches the one thing the
whole product trusts. It needs an ADR covering the bind strategy (service
account or user bind), group → role mapping, what happens when the directory is
unreachable — never a silent fallback to local accounts for a directory user —
and how a locally created admin keeps working during a directory outage.

### D3 — Unified remote agent (roadmap §3 item 7)

The site agent also collecting local server data. The largest item left; only
after C2, whose checks would be its first consumer.

---

## Parked, with the trigger that reopens each

| Item | Reopen when |
|---|---|
| **P5** agent/device plane separation | the relay allowlist grows to cover writes, or a second consumer of the relay appears (roadmap §2) |
| **P2** FortiGate HA member parsing | a FortiGate cluster is reachable |
| Windows password policy, missing updates | a customer needs them; `net accounts` is localised and "missing updates" needs the Windows Update API (`docs/windows-collection.md` §5) |
| CIS audit rules for Windows | a CIS Windows benchmark is available to distil, under the existing copyright constraint |

---

## Suggested order

A1 and A2 together, in one session with the app running and the VM up: they
need the same thing from the user. Then A3 and A4. Then B1 and B2, small and
they complete this week's platform. C1 fits one session. C2 and everything in D
start with a short spec, not with code.
