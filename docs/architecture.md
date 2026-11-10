# Architecture

What the system does, in what order, and why in that order. The principles this
architecture answers to live in
[principles.md](principles.md); this
document covers how they were implemented.

---

## 1. What it is, in one line

SentinelNet collects passive observations from the network (syslog, REST
snapshots, SNMP) and normalizes them into **a single event model** that the
views read: port state and flapping (Interfaces), interface errors, client
diagnosis, SIEM notifications, and the syslog search of the Traffic tab.

The value isn't in the collecting: it's in not stopping at raw data. A tab
showing a list of link transitions is not the product; "this port has flapped
six times today and nobody declared it in maintenance" is.

Until 0.65.0 a correlation engine turned those events into evidence and
incidents (rules, retraction, an Incidents tab). It was removed as misleading;
[ADR-0003](adr/0003-evidence-and-derived-incident.md) and
[ADR-0006](adr/0006-deterministic-correlation.md) record what it was.

Alongside this, the platform also does classic device-fleet management: config
backup, firmware triage against NIST NVD, topology map, SSH terminal, day-0
provisioning, multi-site. Those are independent of the observability pipeline
and share inventory, RBAC and audit with it.

---

## 2. The pipeline

```
        SOURCES                           (collectors.md)
  syslog 514 (Windows) / 5514 (Linux)                    ← UDP, passive
  FortiGate REST (api_poller)  ·  SNMP v2c (snmp_poller) ← active polling
  probe agents (outbound HTTPS)
                    │
                    ▼
        RAW TABLES                        observability/storage/schema.sql
  syslog_events · api_observations · quarantined_exporters
                    │
                    │  normalize.py — one adapter per source
                    ▼
        ┌───────────────────────┐
        │  events               │   ← UNIFIED MODEL. One vocabulary.
        └───────────────────────┘      log.security, log.event, device.state,
                    │                  interface.state, interface.change,
                    │                  platform.exporter_unknown, …
                    ▼
        READERS
  Interfaces (+ suppression.py) · interface errors · client diagnosis
  SIEM notifications · /api/observability/events
  flowpath.py (which way it went) · endpoints.py (what an IP is)
  routers/*.py → static/js/*.js
```

The direction is one-way. No stage writes backwards, and the readers **do not
know** what a syslog line or an SNMP snapshot is — they read `events`. That's
why a new source costs one adapter in
[normalize.py](../observability/normalize.py) and nothing downstream.

### 2.1 Why an event layer

Without it, every reader would have to know every source format, and every new
source would touch every reader. With it, the vocabulary is declared once and
every reader sees a single shape.

The case that makes the model clear: a syslog sender that isn't in inventory
produces `platform.exporter_unknown` — an event like any other, on the reserved
`__platform__` tenant. Platform diagnostics get no parallel path. See
[ADR-0002](adr/0002-unified-event-model.md).

The projection runs every 5 minutes (`normalize.normalize_loop`, started with
the other background tasks).

### 2.2 Suppressions

*Was the operator expecting this?* One question, two forms that most tools treat
as separate features: "this port is down by design" (no expiry) and "this device
is under maintenance tonight" (`from_ts`/`to_ts` window). Same model,
[suppression.py](../observability/suppression.py).

Suppression **does not hide the fact**: the event stays in `events` and in the
feed; only the Interfaces tab's reading of the port changes (`maint` /
`by_design` instead of `outage` / `flapping`). Operator knowledge enters at
interpretation time, not at observation time — so when the suppression expires,
history is still complete. Declared from the Interfaces tab
(`POST /api/observability/interfaces/expected`).

---

## 3. The rules (removed)

The correlation rules, the evidence and incident tables, retraction and the
Incidents tab were removed in 0.65.0. New databases do not create `evidence`,
`incidents` or `incident_conclusions`; an older database keeps them, unread,
and retention empties them. Saved `correlation_rules` thresholds are ignored.

---

## 4. Baseline (removed)

The traffic baseline (`observability/baseline.py`, "is this volume normal?")
read only flow records and was removed with the flow collectors in 0.65.0.

---

## 5. Enrichment

Two modules that decide nothing and exist to make already-made decisions
readable:

| Module | Question | Note |
|---|---|---|
| [endpoints.py](../observability/endpoints.py) | *what IS this address?* | multicast, CGNAT, locally-administered MAC… **Derived, never copied**: computed at read time, so the day the table learns a new role, history improves too. IPv4 only, because upstream extraction only recognizes IPv4. |
| [flowpath.py](../observability/flowpath.py) | *which way did it go?* | The **logical** path (host → access port → gateway), not packet-by-packet. An unknown hop is marked `known: False`, never silently skipped. |

### 5.1 Client diagnosis

[services/client_diagnosis.py](../services/client_diagnosis.py) is the one place
where the L2 and L3 halves meet. It **collects nothing new** — it composes
`client_map()` (switch, port, VLAN, ARP gateway), `flowpath.build()` (logical
path), the stored `interface.state` events (link and error-counter delta), the
backup config via `config_analyzer._parse_interface` (is the client VLAN on the
trunks?), `fortigate_service.diagnose_client()` (policy, sessions, logs) and a
`syslog_events` count grouped by `policyid`.

Same contract as `flowpath`: every section carries `known` or `error`, the
report carries `complete`. A section that cannot answer says why instead of
being omitted — the reader is about to go and touch the network.

The VLAN deserves a note: it arrives from **two sources with different ages** —
the MAC table (a manual scan) and SNMP (an automatic poll, §6 of
[collectors.md](collectors.md)). When they disagree, the port was moved to
another VLAN after the last scan: the client is still in the same hole but no
longer on the same network. The report says so, and uses the **live** VLAN for
the trunk check — testing the stale one would answer yesterday's question.

Two things it resolves that nothing else did:

- **Which FortiGate is on this client's path.** The ARP responder in
  `client_map` *is* the VLAN's gateway. Failing that, a single configured
  FortiGate is used; with several and no match it reports that it cannot tell,
  rather than guessing and sending someone to read the wrong policy table.
- **Which probe an arbitrary address belongs to** (`resolve_endpoint`): first
  observed ARP, then the `subnets` declared on the probe — a field that existed
  since the beginning and was read by nobody. The declared answer is marked
  `derived: "declared-subnet"`. This does not contradict
  [ADR-0005](adr/0005-strict-tenant-attribution.md): that forbids *guessing a
  tenant at ingest*, this is a read-time lookup of an operator-declared fact,
  labelled as derived — the same contract as `vlan_real: false`.

Across sites the report adds a section of its own: the far end's policy (a flow
between two sites crosses **two** firewalls and either can deny it), live IPsec
tunnel state, and a longest-prefix route lookup — because a permitted policy
and a missing route produce the same symptom and need different fixes. At
agent-mode probes the firewall half goes through the REST relay
([ADR-0008](adr/0008-agent-rest-relay.md)), which is asynchronous: the report
queues the request and says so, and the next run collects the answer.

Exposed as `POST /api/diagnose/client`, the MCP tool `diagnose_client`, and a
per-row button in the Client Map pane of the Endpoint tab.

One principle recurs: **what isn't known is stated**. An unknown hop in a
flow path is marked `known: False`; an incomplete path says which hop is
missing. Never an invented value passed off as
a measured one.

---

## 6. Persistence

One SQLite file in WAL mode, `observability.db`, with **a single writer**: a
dedicated thread owning its own connection, draining a bounded queue and
committing in batches. Reads from async endpoints go through `await db.read()`
(`asyncio.to_thread`, a read-only connection per call).

Loss is stated, not silent: a queue-full drop increments a counter **and**
logs at most once a minute; when the writer's restart budget is exhausted the
writer is marked dead (`db_health` in the health endpoint, `degraded` flag),
and the app keeps serving reads. The pipeline applies to itself the same
principle it applies to the network: absence of data is a fact.

The rule is binding for all async code — see
[CONTRIBUTING.md](../CONTRIBUTING.md) §3 and
[ADR-0004](adr/0004-single-process-sqlite-writer.md). Direct consequence:
**never `--workers > 1`** with observability enabled.

Forward-only, idempotent migrations in
[schema.sql](../observability/storage/schema.sql), with a downgrade guard: if
the database declares a schema version newer than the code, startup fails rather
than writing to a schema it doesn't understand.

Outside the observability database, state lives in files resolved by
[core/data_config.py](../core/data_config.py): the inventory CSV with encrypted
credentials, `groups.json`, `users.json`, keys, `backup-config/`. See
[operations.md](operations.md) §1.

---

## 7. Multi-tenancy

A user can belong to **multiple** groups. `user_group_scope()` returns the set,
or `None` for users with no restriction. Every query filters with
`WHERE tenant IN (…placeholders…)` and bound parameters; never a scalar group,
never string interpolation. For devices: `assert_group_allowed` /
`assert_device_allowed`.

Tenant attribution happens **at ingestion**, by resolving the datagram's source
IP against the inventory. Unknown exporter → records dropped and quarantined.
*No record is ever written with a fallback tenant*: data without a trustworthy
site poisons scoping for everyone else. See
[ADR-0005](adr/0005-strict-tenant-attribution.md).

---

## 8. What the AI does

The AI **does not decide**. Every verdict is computed by code; the contextual
assists and the MCP server read what the platform already concluded.

Context sent to the provider is assembled **server-side** (the browser sends
only identifying tuples, never volumes), is always aggregated or top-N, and
passes through a single redaction choke-point in
[security/redaction.py](../security/redaction.py) on the way out.

When the model proposes a configuration it emits a fenced `sentinelnet-config`
block: it **proposes, it does not execute**. Applying it goes through
`/api/bulk-command` after explicit user confirmation, with CLI blacklist, RBAC
and audit log unchanged.

---

## 9. Module map

| Folder | Contents |
|---|---|
| [core/](../core/) | `db.py` (SQLite writer), `data_config.py` (paths and config), `app_settings.py`, `core_engine.py` (backup, triage, map), `net_ssh.py` (bastion-aware netmiko entry point), `ssh_pool.py` (dedicated executor for device SSH) |
| [observability/](../observability/) | The whole §2 pipeline, plus `ingesters/` |
| [collectors/](../collectors/) | ARP, MAC tables, MAC history, subnet scanner, `l2_scheduler.py` (scheduled L2 discovery, opt-in) |
| [routers/](../routers/) | ~31 FastAPI routers, one per area |
| [services/](../services/) | FortiGate, WLC, inventory, provisioners, probes, probe agent, Visio export, `netsec_audit/` (compliance engine & `netsec_audit_runs` history), `config_drift/` (§10: per-tenant history & baseline), `notifications.py` (email engine: preferences, admin rules, outbox, digest), `triage_scheduler.py` (scheduled triage), `tenant_telemetry.py` (per-tenant on/off for ping, SNMP, REST, triage) |
| [security/](../security/) | JWT/RBAC/audit, credential encryption, keystore, identities, redaction, `command_policy.py` (the one dangerous-command policy) |
| [ai/](../ai/) | Multi-provider assistant, config analyzer, MCP server and client |
| [drivers/](../drivers/) | One driver per vendor, `BaseDriver` as the contract, `registry.py` (vendor → driver → netmiko mapping) |
| [fw_analyzers/](../fw_analyzers/) | Firewall config analysis (FortiOS, PAN-OS) |
| [redundancy/](../redundancy/) | HA group detection and state |
| [static/js/](../static/js/) | One JS file per tab. Rendering, formatting and presentation helpers live here; decisions (verdicts, scoping, policy) stay server-side — the dashboard is a lens, never the logic |
| [templates/](../templates/) | `dashboard.html`, single page |

[app_server.py](../app_server.py) is deliberately thin: `lifespan`, the FastAPI
instance, `include_router` calls, middleware (security headers, cache control,
per-IP rate limit on the expensive endpoints), static files, `main()`. Logic
lives in routers and services.

`lifespan` does, in order: start the DB writer (with migration), start listeners
and periodic tasks per config, seed the audit template, start the ping monitor;
on the way out, stop the ping monitor, close bastion transports, stop listeners
and drain the write queue.

Periodic tasks: retention (1h), event normalization (5 min), REST poller, SNMP poller
and Linux health poller (configurable interval), scheduled L2 discovery
(opt-in, `l2_poll_s`). The notification loop and the triage scheduler tick
every 60 seconds. The pollers start on the first activation of the master switch
and stay up — they're no-ops when there's nothing to do.

### Where vendor knowledge lives

Deliberate placement, not drift: the **device-facing** vendor knowledge —
backup/version commands, the vendor → driver → netmiko mapping, the ARP CLI
table — lives in `drivers/` (`registry.py`). The **adapter-layer** vendor
knowledge — FortiGate/PAN-OS syslog field parsing, Cisco private MIB OIDs,
per-vendor config parsers — stays where the sources are normalized
(`observability/` ingesters, `ai/config_analyzer.py`, `fw_analyzers/`),
because that is the layer principle §15 assigns new sources to: one adapter
per source, nothing downstream. Moving it into `drivers/` would couple the
device contract to telemetry formats; the split is the contract.

---

## 10. Config drift

[services/config_drift/](../services/config_drift/) answers two different
questions per tenant, deliberately kept apart:

- **History** — did this device change since we last saw it, and what changed?
- **Baseline** — does this device match the standard this tenant expects?

A baseline is stored per tenant **and per configuration profile** — the
grammar a device's config is written in (`ios`, `wlc-aireos`, `fortios`,
`panos`, `linux`, `windows`), resolved by the same vendor mapping the Config
Analyzer parses with (`baseline.profile_for`). One tenant-wide rule list turned
every WLC and firewall into a wall of false deviations, because a switch rule
like `aaa new-model` can never appear in an AireOS or FortiOS config. Stores
written before profiles existed held one string per tenant; they are read as
the `ios` profile, which is what every one of them was typed against.

Both read from the archive `history.py` builds; neither scores anything — the
existing NetSec Audit engine (§9, `services/netsec_audit/`) owns compliance
scoring, benchmarks and export. The baseline answers one question per rule,
present or missing, nothing else.

**The archive is additive.** `backup-config/<tenant>/<vendor>/<name>-<ip>.txt`
is read directly by the policy test loader, the NetSec Audit, the config
analyzer and `download_backup` — that path is a contract the drift feature
does not get to move. Every changed version instead lands in a `.history`
folder beside it, keyed by IP, and nothing is ever pruned: disk only grows
when a config actually changes, which is why per-vendor normalisation
(`normalize.py`, stripping counters/timestamps that change on their own) has
to be right — a normaliser that misses one volatile line turns every
collection run into a fake new version.

`run_backup_and_triage` calls `history.record_version` as an observer after
the existing `save_backup` call, wrapped in try/except at the call site so a
history-recording failure can never fail a backup. `remove_stale_backups`
(`core/core_engine.py`), which used to delete every file for an IP anywhere in
the tree, now moves the current file and its `.history` together when a
device changes tenant — a re-assignment is a normal operational event, not a
data-loss event.

An optional git mirror (`mirror.py`) commits each new archived version to a
git repository rooted at the `.history` folder. It exists purely as a second
copy for disaster recovery: the drift engine never reads from it, and turning
it on fails loudly, not silently, when git is not on the host — a redundancy
feature that quietly isn't running is worse than one that's off.

Seven tenant-scoped routes in `routers/config_drift.py`, all going through
`user_group_scope` (list routes) or `assert_device_allowed` (device routes) —
the same isolation rule as every other device route. The tab
`#tab-config-drift` (`static/js/config-drift.js`) is master-detail: the
tenant's device list stays visible, and the detail pane shows either one
device (deviations, version history) or the tenant's baseline for one profile
with a per-rule coverage table that marks the devices failing each rule. The Situation page's drift verdict names any tenant
that has no baseline yet.

---

## 11. What this architecture does not do

Stated, not forgotten:

- **It blocks nothing.** Passive observability. When the UI shows a DENY, the
  device did the blocking.
- **It does not scale horizontally** on observability: single-process writer.
- **It does not reconstruct the packet-by-packet path**: the flow path is
  logical (§5).
- **It does not correlate.** There is no incident engine since 0.65.0: a
  device going down is an email (ping monitor, `device.down`), a port going
  down is a row in Interfaces, and nothing groups them into one story.
- **It does not escalate.** Email notifications (`services/notifications.py`)
  send once per event to whoever subscribed, with a 30-minute flood window;
  there is no on-call rotation, acknowledgement by reply, or re-notification
  of an event nobody handled ([roadmap.md](roadmap.md) §1).
