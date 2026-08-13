# Architecture

What the system does, in what order, and why in that order. The principles this
architecture answers to live in
[principles.md](principles.md); this
document covers how they were implemented.

---

## 1. What it is, in one line

SentinelNet collects passive observations from the network (flows, syslog, REST
snapshots, SNMP), normalizes them into **a single event model**, applies
**deterministic rules** that produce **evidence with a causal role**, and
derives **explainable incidents** from that evidence.

The value isn't in the collecting: it's in not stopping at raw data. A tab
showing "core utilization 96%" is not the product. The product is "the core is
at 96% because Backup01 started transferring 2.4 Gbps to NAS01 at 09:31; the
traffic is entirely east-west and never crosses the firewall".

Alongside this, the platform also does classic device-fleet management: config
backup, firmware triage against ENISA EUVD, topology map, SSH terminal, day-0
provisioning, multi-site. Those are independent of the observability pipeline
and share inventory, RBAC and audit with it.

---

## 2. The pipeline

```
        SOURCES                           (collectors.md)
  IPFIX 4739 / NetFlow 2055 / sFlow 6343 / syslog 5514   ← UDP, passive
  FortiGate REST (api_poller)  ·  SNMP v2c (snmp_poller) ← active polling
  site agents (outbound HTTPS)
                    │
                    ▼
        RAW TABLES                        observability/storage/schema.sql
  flow_aggregates · syslog_events · api_observations · quarantined_exporters
                    │
                    │  normalize.py — one adapter per source
                    ▼
        ┌───────────────────────┐
        │  events               │   ← UNIFIED MODEL. One vocabulary.
        └───────────────────────┘      flow.aggregate, log.security, device.state,
                    │                  interface.state, interface.change,
                    │                  platform.exporter_unknown, flow.baseline, …
                    │
   baseline.py ─────┤  measures deviation from habit and writes the result
                    │  BACK AS AN EVENT (flow.baseline / flow.emergence /
                    │  flow.top_talker): it doesn't conclude, it supplies facts
                    │
                    │  correlator.py + rules.py   (+ suppression.py)
                    ▼
        ┌───────────────────────┐
        │  evidence             │   ← every row: causal ROLE + PROVENANCE
        └───────────────────────┘      (rule_id, rule_version, thresholds used)
                    │
                    │  incidents.py — groups by entity and time proximity
                    ▼
        ┌───────────────────────┐
        │  incidents            │   ← DERIVED VIEW: cause, confidence,
        └───────────────────────┘      reasoning path
                    │
                    ▼
        PRESENTATION
  timeline.py (sequence) · flowpath.py (which way it went) · endpoints.py (what an IP is)
  routers/*.py → static/js/*.js
```

The direction is one-way. No stage writes backwards, and each stage reads only
the one immediately before it: the correlator **no longer knows** what a syslog
line or a flow record is — it reads `events` and nothing else. That's why a new
source costs one adapter in
[normalize.py](../observability/normalize.py) and nothing downstream.

### 2.1 Why an event layer

Without it, every rule would have to know every source format, and every new
source would touch every rule. With it, the vocabulary is declared once and
rules, baseline, timeline and knowledge base all read a single shape.

The case that makes the model clear: a UDP exporter that isn't in inventory
produces `platform.exporter_unknown` — an event like any other, on the reserved
`__platform__` tenant. Platform diagnostics get no parallel path; they inherit
rules, evidence, incidents and timeline from the normal one. See
[ADR-0002](adr/0002-unified-event-model.md).

### 2.2 Why evidence instead of incidents directly

A rule doesn't conclude "there is an incident": it produces evidence and
**declares its role** — `trigger`, `supporting`, `symptom`, `consequence`. The
incident is what you get by grouping evidence about the same entity close in
time: the cause is the rule behind the `trigger` evidence, and every distinct
form of corroboration raises confidence by one step, recorded in
`reasoning_json.sources_used`.

This is what makes a conclusion explainable rather than asserted. See
[ADR-0003](adr/0003-evidence-and-derived-incident.md).

### 2.3 Retraction

A new fact can invalidate an earlier conclusion: the interface came back up, the
deviation returned to normal. Retraction is **produced by a rule**, never by an
adapter, and the fact that justifies it (the `witness`) is recorded as evidence
in its own right — so `retracted_by_evidence_id` points at something readable,
and the retraction is itself retractable.

Known and accepted limit: retraction happens **after** concluding. That's fine
while only the UI reads conclusions; it would not be with a notification engine
(see [roadmap.md](roadmap.md) §3).

### 2.4 Suppressions

*Was the operator expecting this?* One question, two forms that most tools treat
as separate features: "this port is down by design" (no expiry) and "this device
is under maintenance tonight" (`from_ts`/`to_ts` window). Same model,
[suppression.py](../observability/suppression.py).

Suppression **does not hide the fact**: the event stays in `events` and in the
feed; only whether it becomes evidence changes. Operator knowledge enters at
interpretation time, not at observation time — so when the suppression expires,
history is still complete. Applied in exactly one place (the correlator), not
rule by rule.

---

## 3. The rules

They are **Python callables in a table**, not a DSL. You put a breakpoint inside
one and see why it fired. See [ADR-0001](adr/0001-python-rules-not-yaml.md).

What's configurable at runtime is the **thresholds**, not the logic: each rule
declares its parameters with a default, an admin adjusts them from
`app_settings` (`correlation_rules` section), and the values **actually used**
end up in `evidence.params_json` next to `rule_version`. Without that, two
different outcomes would carry the same provenance.

Current catalog ([rules.py](../observability/rules.py)):

| Rule | What it concludes |
|---|---|
| `TRAFFIC_SPIKE_001` | Anomalous volume on a conversation |
| `BASELINE_SPIKE_001` | Deviation from habit, as measured by the baseline |
| `BASELINE_NORMAL_RETRACT_001` | Deviation is back to normal → retracts the previous one |
| `NEW_TALKER_001` | Host never seen before in that window |
| `TOP_TALKER_001` | Who dominates the traffic, and by how much |
| `BLOCKED_TRAFFIC_001` | The device blocked traffic |
| `HIGH_SEVERITY_LOG_001` | Syslog severity ≤ 3 |
| `IFACE_DOWN_001` / `IFACE_RECOVERED_001` | Interface down / back up (the latter retracts the former) |
| `IFACE_FLAPPING_001` | The port is oscillating: one fact, not N alarms |
| `DEVICE_LOAD_001` | Device CPU/memory load |
| `CFG_CHANGE_001` | Configuration changed between two snapshots |
| `FLOW_EXPORTER_UNKNOWN_001` | Exporter outside inventory: data loss made visible |

New logic is an entry in `RULES`. A new source is an adapter in `normalize.py`.
There is no third extension mechanism, deliberately: it would give three places
to look.

---

## 4. Baseline

[baseline.py](../observability/baseline.py) answers *"is this normal?"* and does
so by **writing a fact**, not an alarm. Three distinct shapes, not three shades
of one:

- `flow.baseline` — how far the present deviates from habit;
- `flow.emergence` — something that wasn't there before (it has no habit);
- `flow.top_talker` — who composed the traffic, and for what share.

The last one answers *"why is the link saturated?"*: a host can dominate traffic
while staying perfectly within its own habit — no deviation, no emergence, and
yet it is the answer.

Never "versus yesterday" alone: first same weekday and same hour, up to 4 weeks
back (Monday doesn't resemble Sunday); then fall back to the same hour on
previous days; then **emit nothing**. A baseline built on two points is worse
than no baseline. A historical hour counts as a sample only if the collector was
actually collecting during it — otherwise an ingestion outage would read as
"zero traffic" and inflate every later deviation.

---

## 5. Enrichment

Three modules that decide nothing and exist to make already-made decisions
readable:

| Module | Question | Note |
|---|---|---|
| [endpoints.py](../observability/endpoints.py) | *what IS this address?* | multicast, CGNAT, locally-administered MAC… **Derived, never copied**: computed at read time, so the day the table learns a new role, history improves too. IPv4 only, because upstream extraction only recognizes IPv4. |
| [flowpath.py](../observability/flowpath.py) | *which way did it go?* | The **logical** path (host → access port → gateway), not packet-by-packet. An unknown hop is marked `known: False`, never silently skipped. |
| [timeline.py](../observability/timeline.py) | *in what order did it happen?* | Merges evidence, raw syslog, per-minute volumes, REST snapshots and physical location. Careful: `observability.db` uses unix integers, `mac_history.db` uses ISO-8601 text — conversion happens there, at the boundary. |

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
- **Which site an arbitrary address belongs to** (`resolve_endpoint`): first
  observed ARP, then the `subnets` declared on the site — a field that existed
  since the beginning and was read by nobody. The declared answer is marked
  `derived: "declared-subnet"`. This does not contradict
  [ADR-0005](adr/0005-strict-tenant-attribution.md): that forbids *guessing a
  tenant at ingest*, this is a read-time lookup of an operator-declared fact,
  labelled as derived — the same contract as `vlan_real: false`.

Across sites the report adds a section of its own: the far end's policy (a flow
between two sites crosses **two** firewalls and either can deny it), live IPsec
tunnel state, and a longest-prefix route lookup — because a permitted policy
and a missing route produce the same symptom and need different fixes. At
agent-mode sites the firewall half goes through the REST relay
([ADR-0008](adr/0008-agent-rest-relay.md)), which is asynchronous: the report
queues the request and says so, and the next run collects the answer.

Exposed as `POST /api/diagnose/client`, the MCP tool `diagnose_client`, and a
per-row button in the Client Map pane of the Endpoint tab.

One principle recurs: **what isn't known is stated**. A synthetic VLAN in the
flow graph is marked `vlan_real: false` and the UI shows an asterisk; an
incomplete path says which hop is missing. Never an invented value passed off as
a measured one.

---

## 6. Persistence

One SQLite file in WAL mode, `observability.db`, with **a single writer**: a
dedicated thread owning its own connection, draining a bounded queue and
committing in batches. Reads from async endpoints go through `await db.read()`
(`asyncio.to_thread`, a read-only connection per call).

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

The AI **does not decide**. Correlation is deterministic; the assistant and the
MCP server read what the engine already concluded and narrate it. See
[ADR-0006](adr/0006-deterministic-correlation.md).

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
| [core/](../core/) | `db.py` (SQLite writer), `data_config.py` (paths and config), `app_settings.py`, `core_engine.py` (SSH, backup, triage, map) |
| [observability/](../observability/) | The whole §2 pipeline, plus `ingesters/` |
| [collectors/](../collectors/) | ARP, MAC tables, MAC history, subnet scanner |
| [routers/](../routers/) | ~24 FastAPI routers, one per area |
| [services/](../services/) | FortiGate, WLC, inventory, provisioners, sites, agent, Visio export, `netsec_audit/` |
| [security/](../security/) | JWT/RBAC/audit, credential encryption, keystore, identities, redaction |
| [ai/](../ai/) | Multi-provider assistant, config analyzer, MCP server and client |
| [drivers/](../drivers/) | One driver per vendor, `BaseDriver` as the contract |
| [fw_analyzers/](../fw_analyzers/) | Firewall config analysis (FortiOS, PAN-OS) |
| [redundancy/](../redundancy/) | HA group detection and state |
| [static/js/](../static/js/) | One JS file per tab; no business logic |
| [templates/](../templates/) | `dashboard.html`, single page |

[app_server.py](../app_server.py) is deliberately thin: `lifespan`, the FastAPI
instance, `include_router` calls, static files, `main()`. Logic lives in routers
and services.

`lifespan` does, in order: start the DB writer (with migration), start listeners
and periodic tasks per config, seed the audit template; on the way out, stop
listeners and drain the write queue.

Periodic tasks: retention (1h), correlation (5 min), REST poller and SNMP poller
(configurable interval). They start on the first activation of the master switch
and stay up — they're no-ops when there's nothing to do.

---

## 10. What this architecture does not do

Stated, not forgotten:

- **It blocks nothing.** Passive observability. When the UI shows a DENY, the
  device did the blocking.
- **It does not scale horizontally** on observability: single-process writer.
- **It does not reconstruct the packet-by-packet path**: the flow path is
  logical (§5).
- **It does not conclude without corroborating flow**, except for high
  severities: a precision-over-recall policy, worth knowing when investigating
  "why didn't this show up". See
  [live-flows-and-siem.md](live-flows-and-siem.md) §4.5.
- **It does not confirm before concluding**: there's no per-rule "how many
  observations are required". That's the debt that becomes serious once
  notifications exist ([roadmap.md](roadmap.md) §3).
