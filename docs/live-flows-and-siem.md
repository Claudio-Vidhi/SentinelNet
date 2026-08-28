# Live Flows and Flow SIEM

A code-oriented reference for anyone working on the two flow tabs. Covers the
ingest pipeline, the data schema, the endpoints, the frontend, the decisions
behind them, and the known limits.

Cross-references: [architecture.md](architecture.md) (full pipeline),
[collectors.md](collectors.md) (sources), [CONTRIBUTING.md](../CONTRIBUTING.md)
§3 (async-DB rule) and §4 (multi-tenant scope rule).

---

## 1. In one line

| | Live Flows | Flow SIEM |
|---|---|---|
| Tab | `tab-flows` | `tab-flow-siem` |
| Question it answers | *how much traffic, between whom, over which protocol* | *was that traffic allowed or blocked, and why* |
| Source table | `flow_aggregates` (+ `syslog_events`, `correlated_events`) | `syslog_events` (+ `siem_suppressions`) |
| Router | [routers/observability.py](../routers/observability.py) | [routers/flow_siem.py](../routers/flow_siem.py) |
| JS | [static/js/observability.js](../static/js/observability.js) | [static/js/flow-analytics.js](../static/js/flow-analytics.js) |
| Visibility | Always present | Behind an admin preview flag |

The split is not cosmetic: `flow_aggregates` **has no notion of ALLOW/DENY**
(they are NetFlow/IPFIX/sFlow counters), while `syslog_events` is the only table
holding real device verdicts. See §7.1 for what happened when that distinction
was ignored.

---

## 2. Ingest pipeline (common to both)

```
network devices
   │ UDP (IPFIX 4739 / NetFlow 2055 / sFlow 6343 / syslog 5514)
   ▼
_IngestProtocol.datagram_received   ← observability/ingesters/udp_server.py
   │ put_nowait on an asyncio.Queue (maxsize 20_000)
   ▼
_consumer (1 task per listener)
   │ parser(data, src_ip)           ← ipfix.py / sflow.py / syslog.py
   │ _resolve_tenant(exporter_ip)   ← inventory_manager.get_device_by_ip
   ▼
db.enqueue_flow() / db.enqueue_write()   ← bounded queue, 10_000
   ▼
"obs-db-writer" thread (single write connection, batch commit of 500)
   ▼
observability.db  (SQLite WAL)
```

### 2.1 Structural decisions in the ingest path

**Separate ingest loop.** The UDP listeners do not run on FastAPI's main event
loop but on a dedicated asyncio loop in its own thread (`_get_ingest_loop()`,
[udp_server.py:141](../observability/ingesters/udp_server.py#L141)). A burst of
tens of thousands of datagrams must not make the WebSocket terminal and the API
unresponsive. This corrects "defect #1" of the original implementation guide,
where parsing happened inline on the main loop.

**`datagram_received` does nothing but enqueue.** No task per packet, no
parsing, no database access in the handler. Queue full → drop plus a
`dropped_queue_full` metric. Losing packets in a measured way is preferable to
blocking the loop.

**GIL switch interval lowered to 1 ms**
([udp_server.py:152](../observability/ingesters/udp_server.py#L152)). The
parsing thread is CPU-bound in bursts; at the 5 ms default the main loop was
waiting tens of milliseconds under load.

**Periodic yield in the consumer** (`await asyncio.sleep(0)` every 20 records).
With a full queue `queue.get()` returns without suspending; without the yield
the consumer would starve its own ingest loop.

**Strict tenant attribution.** The datagram's source IP is resolved to an
inventory device. Unknown exporter (or a collision between two devices with the
same IP) → **records dropped**, upsert into `quarantined_exporters`, one audit
entry rate-limited to 1/hour per exporter, `dropped_unknown_exporter` metric.
*No record is ever written with a `default` tenant*: data without a trustworthy
site is worse than no data, because it poisons multi-tenant scoping. See
[ADR-0005](adr/0005-strict-tenant-attribution.md).

### 2.2 Database layer ([core/db.py](../core/db.py))

Non-negotiable rules:

- **A single write connection**, owned by the writer thread.
- Writes are enqueued with `enqueue_write()` — bounded queue, never blocking.
- Reads from async endpoints go through `await db.read()`, which uses
  `asyncio.to_thread` with a read-only connection per call (WAL allows
  concurrent readers).
- `get_observability_connection()` is **only** for migrations and tests, and is
  forbidden on async paths (grep gate in review). One deliberate exception:
  `set_incident_status()` (`routers/incidents.py`) uses it inside
  `asyncio.to_thread` because it needs an atomic read-then-write transaction.

See [ADR-0004](adr/0004-single-process-sqlite-writer.md).

**Writer resilience.** Batch commits, up to 500 payloads. If one payload in a
batch fails → rollback and re-run item by item, dropping only the faulty
payloads (`writes_dropped_error`). If the writer crashes → restart with
exponential backoff, max 5 attempts; beyond that, writes are dropped but **the
application stays alive**.

**Clock skew.** `flow_window_start()` uses the exporter's timestamp only if it
is within ±300 s of reception; otherwise it falls back to reception time and
increments `clock_skew_fallback`. A device with a wrong clock must not be able
to write buckets into the future or the distant past.

### 2.3 Flow aggregation

`FLOW_UPSERT_SQL` upserts on
`UNIQUE(window_start, tenant, src_ip, dst_ip, protocol, dst_port)` with
`window_start` truncated to the minute. So `flow_aggregates` **is not a flow
log**: it is a per-minute rollup, and `flow_count` counts how many flow records
landed in the bucket.

---

## 3. Data schema ([observability/storage/schema.sql](../observability/storage/schema.sql))

Forward-only, idempotent migrations (`IF NOT EXISTS` everywhere).
`SCHEMA_VERSION = 4`. **Downgrade guard**: if the database declares a version
newer than the code, `migrate()` raises `SchemaTooNewError` and observability
refuses to start.

| Table | Written by | Read by | Notes |
|---|---|---|---|
| `flow_aggregates` | Flow ingester (per-minute upsert) | `/top`, `/flowgraph`, `/protocol-distribution`, correlator, `summary.py` | `source` column added in v3 via idempotent ALTER; NULL means legacy rows |
| `syslog_events` | Syslog ingester | `/syslog`, **all of Flow SIEM**, correlator | `action` is the device's real verdict |
| `correlated_events` | Correlator | `/anomalies`, "spikes" KPI | `dedup_key UNIQUE` + `INSERT OR IGNORE` |
| `siem_suppressions` | `POST /alerts/suppress` | Exclusion in `/events` and `/facets` | PK is `syslog_events.id` |
| `quarantined_exporters` | Ingest | `normalize._from_quarantine` → `platform.exporter_unknown` → `FLOW_EXPORTER_UNKNOWN_001` | Exporters outside inventory; data loss becomes evidence on the reserved `__platform__` tenant instead of staying diagnostic-only |
| `api_observations` | REST/SNMP pollers | `/api-context` | Device snapshots, not flows |

### 3.1 Retention ([observability/rollup.py](../observability/rollup.py))

Hourly job, a technical GDPR measure. DELETEs batched at 5000 rows per
transaction via `rowid`, to avoid holding long locks. **Unresolved** correlated
events (`new`/`ack`) are never deleted automatically — only `resolved` ones.

> Note: `siem_suppressions` is not in the retention table. Suppressions outlive
> the syslog event they point at (harmless orphan rows, but worth knowing).

---

## 4. Live Flows (`tab-flows`)

### 4.1 Endpoints

All in [routers/observability.py](../routers/observability.py), all scoped by
`_tenant_filter()`.

| Endpoint | Auth | What it does |
|---|---|---|
| `GET /api/observability/top` | user | Aggregated top talkers; `window`, `metric` (bytes\|packets), `source`, `limit≤500` |
| `GET /api/observability/flowgraph` | user | Top-50 nodes/edges, KPIs, tenant summary, protocol breakdown |
| `GET /api/observability/protocol-distribution` | user | Totals, time trend and drill-down breakdown |
| `GET /api/observability/syslog` | user | Latest normalized syslog events |
| `GET /api/observability/anomalies` | user | Correlated events, paginated, filtered by status |
| `POST /api/observability/anomalies/{id}/status` | operator | **Deprecated** alias of `POST /api/incidents/{id}/status`, which it delegates to |
| `GET/POST /api/observability/config` | **admin** | Listener config, applied hot |
| `GET /api/observability/health` | **admin** | Active listeners, metrics, DB size |
| `POST /api/observability/api-poll` | operator | One-shot REST poll |

### 4.2 Scope rule (CONTRIBUTING.md §4)

```python
def _tenant_filter(current_user):
    scope = user_group_scope(current_user)
    if scope is None:
        return "", ()                      # admin, or user with no restriction
    groups = sorted(scope)
    placeholders = ",".join("?" * len(groups))
    return f" AND tenant IN ({placeholders})", tuple(groups)
```

Always `WHERE tenant IN (…placeholders…)` with bound parameters. **Never** string
interpolation, **never** a scalar group — a user can belong to multiple sites.
`user_group_scope` returns `None` for admins and for users with no groups
assigned.

### 4.3 Window validation

`_parse_window()` accepts `^(\d{1,4})([mhd])$` with a 7-day ceiling
(`MAX_WINDOW_S`). Malformed or out of range → 400. It is the single entry point
for the window across every endpoint in the router.

### 4.4 `/flowgraph` — the interesting decisions

**Node bytes = src + dst.**

```python
node_bytes[src] = node_bytes.get(src, 0) + nbytes
node_bytes[dst] = node_bytes.get(dst, 0) + nbytes
```

A destination-only host (an internal server never seen as a source) would
otherwise sit at 0 and be unfairly dropped by the top-50 cap.

**Cap at 50 nodes, then filter edges against surviving nodes, then top-50
edges.** The order matters: filtering edges before nodes would produce dangling
edges.

**VLAN: real when known, synthetic when not, and the difference is declared.**
If an ARP binding exists for the IP (the `arp_entries` table behind Client Map,
populated from L3 gateways), the real 802.1Q VLAN is used. Otherwise it falls
back to `_synthetic_vlan(tenant)` and **the node/edge is marked
`vlan_real: false`**. The frontend raises the `vlan_disclosure` flag and shows an
asterisk with a tooltip
([observability.js:872](../static/js/observability.js#L872)). Principle: never
pass an invented value off as a real tag.

`_synthetic_vlan()` uses a **truncated sha1**, not `hash()`: the builtin is
salted per process (`PYTHONHASHSEED` is random), so the same site would have had
different VLANs across restarts and across workers.

**The force-directed graph no longer exists.** The canvas was removed; what
remains are the KPIs, the tenant summary and the two tables. `_fgVisibleEdges()`
returns the whole window precisely because there is no longer a graph to
click-to-filter on.

### 4.5 Correlator ([observability/correlator.py](../observability/correlator.py))

Periodic task every 300 s, 900 s lookback, max 500 events per cycle.

**Precision-over-recall policy:** start from syslog events whose `action` is in
`_SECURITY_ACTIONS`, extract src/dst/port from the message, and **require
corroborating flow evidence** — a bucket in `flow_aggregates` with the same
tenant, the same endpoints, within ±120 s. No flow, no evidence.

One exception: severity ≤ 3 (emerg…error) is emitted as a standalone event
regardless, even without a flow and without extractable endpoints. A `critical`
must not vanish because the NetFlow record didn't arrive.

Dedup: `sha256(tenant|kind|syslog_id|src|dst|flow_tuple)` on a `UNIQUE` column
with `INSERT OR IGNORE`. Re-runs do not duplicate.

Switch/port enrichment is best-effort via `mac_history.client_map` (uplinks
already excluded), same tenant. Absent → `switch_port` is NULL, not a
placeholder.

Never cross-tenant: every query filters by tenant.

### 4.6 Frontend ([static/js/observability.js](../static/js/observability.js))

- **Auto-refresh every 30 s**, paused when the tab is inactive or the page is
  hidden; immediate refresh on return (`visibilitychange`).
- **Overlap prevention**: `flowsFetchInFlight` and `_fgFetchInFlight` prevent
  concurrent fetches.
- **Selection by tuple, not by row index.** `flowKey(f)` is
  `tenant|src|dst|proto|port|source`. The selection survives the tenant filter
  and the periodic refresh; with an index it would have moved under the user's
  fingers.
- **Source chips** (`all`/`netflow`/`ipfix`/`sflow`/`syslog`). In `syslog` mode
  the column layout differs: a dedicated table, not an adaptation of the flow
  table. In `all` mode syslog appears in a separate section below.
- **Hideable columns** persisted in `localStorage`
  (`sentinelnet_flows_hidden_cols`).
- **Status banner**: if `/health` reports observability off or no active
  listener, it says so. Previously the absence of data was silent and
  indistinguishable from "quiet network". `/health` is admin-only: a 403 hides
  the banner rather than raising an error.
- **Flow detail panel** (slide-in): reuses `/api/arp/client-map` for the source's
  MAC/switch/port — no new endpoint.
- **Bridge to topology**: `highlightInTopology(ip)` switches tab and calls
  `networkInstance.focus(ip)` with a retry (20 attempts × 250 ms), because the
  Vis.js graph may not be loaded yet.
- **Bridge to anomalies**: `jumpToAnomaliesForFlow()` applies a client-side
  filter on src/dst and scrolls to an explicit anchor (`#anomSectionTitle`) — the
  old `#tab-flows h4` selector broke on every hierarchy change.

### 4.7 Anomaly status transitions

`_ALLOWED_TRANSITIONS = {(new,ack), (new,resolved), (ack,resolved)}`.

Optimistic concurrency: the client sends `from_status` and the UPDATE carries
`AND status = ?`; `rowcount == 0` → **409** with a "reload the list" message. An
out-of-scope or non-existent event returns an **identical 404**, so as not to
confirm the existence of other sites' events.

### 4.8 AI integration

Two paths, both with **server-side** context assembly:

- no rows selected → `attach_top_flows: true` → top-N summary;
- rows selected → `attach_flow_keys: [{src_ip, dst_ip, protocol, dst_port}]`,
  max 20.

The browser sends **identifying tuples only**: never bytes or packets. Totals are
re-derived from the database in `top_flows_context()`
([observability/summary.py](../observability/summary.py)), and tenant scope stays
applied in `AND` — client-supplied keys cannot extract other tenants' rows. The
context still passes through the redaction choke-point in `ai_assistant.chat()`.
The UI explicitly states what is about to be sent and to which provider. See
[ADR-0006](adr/0006-deterministic-correlation.md).

### 4.9 MCP exposure

`get_top_talkers` and `get_anomalies` are defined in
[ai/mcp_server.py:414](../ai/mcp_server.py#L414) but sit in
`_MCP_DEFAULT_DISABLED` ([routers/mcp.py:15](../routers/mcp.py#L15)): they must
be enabled explicitly.

---

## 5. Flow SIEM (`tab-flow-siem`)

### 5.1 Gating

None. The tab is always present as a sub-tab of **Traffic**, alongside
`tab-flows`. It previously sat behind an admin preview flag
(`/api/settings/flow-siem-preview`, persisted as `flow_siem_preview_enabled`);
that flag and its endpoints were removed, and any leftover key in
`app_settings.json` is ignored. Access is governed only by the per-endpoint
scope checks in §5.2.

### 5.2 Endpoints

Prefix `/api/flow-siem`, all scoped.

| Endpoint | What it does |
|---|---|
| `GET /events` | Event log; `q`, `window`, `action`, `limit≤500`, `offset` |
| `GET /histogram` | Counts and denies per time bucket (10–100 buckets) |
| `GET /facets` | Top source/destination IPs, threat flags, actions |
| `POST /alerts/suppress` | Persisted suppression |

### 5.3 From a syslog row to a SIEM event

`_to_event()` ([flow_siem.py:129](../routers/flow_siem.py#L129)):

| Field | Origin |
|---|---|
| `id` | `syslog_events.id` — **primary key, stable** |
| `src_ip`/`dst_ip` | FortiGate kv `srcip`/`dstip`, falling back to the first two IPs in the message |
| `src_port`/`dst_port` | kv `srcport`/`dstport` |
| `proto` | kv `proto`\|`service`, numeric values mapped (6→TCP, 17→UDP, 1→ICMP) |
| `bytes` | `sentbyte + rcvdbyte`, `None` if absent |
| `action` | The `action` column, or kv `action`, or kv `utmaction` |
| `policy_id` | kv `policyid` — **which rule produced the verdict** |
| `subtype` | kv `subtype`\|`eventtype` — tells a web-filter block from a policy deny |
| `is_deny` | `action` ∈ `SECURITY_ACTIONS` ([fieldmap.py](../observability/fieldmap.py)) |
| `threat_flag` | Derived: see below |

Two notes on that table, both learned the hard way:

**`utmaction` is listed separately from `action` on purpose.** `_KV_RE` starts
with `\b`, and there is no word boundary between the `m` and the `a` of
`utmaction=` — so the `action` alternative does *not* match it. Before the key
was added explicitly, `fieldmap` returned `action=None` for a web-filter log
while the syslog ingester read it fine, and the module whose docstring calls
itself the single source of truth disagreed with the ingester.

**`SECURITY_ACTIONS` covers the UTM verbs, not just the policy ones.** IPS
writes `dropped` / `reset` / `clear_session` and the DNS filter writes
`redirect`; none of them is `drop`. While they were missing, an IPS drop
normalized to `log.event` rather than `log.security`, never reached
`BLOCKED_TRAFFIC_001`, and never raised an incident — and an IPS drop is one of
the commonest reasons a page loads half way. Deliberately **excluded**:
`passthrough` and `bypass` (SSL, traffic *allowed* without inspection),
`detected` (IPS in monitor mode) and `pass`. Those are consent verbs; counting
them as blocks would invent incidents on permitted traffic.

Because extraction happens **at read time** from the stored raw message, adding
a key to that regex improves history retroactively — no re-ingest, no migration.

`_threat_flag()` derives **only from real data**, in priority order:
`BLOCKED_TRAFFIC` (deny) → `HIGH_SEVERITY` (sev ≤ 3) → `HIGH_VOLUME_TRANSFER`
(> 1 MB) → `EXTERNAL_DNS` (dst 8.8.8.8 / 1.1.1.1) → `NORMAL`.

**Whatever the message does not contain stays `None`** and the UI shows a dash.
No field is synthesized.

### 5.4 Batched deep scan

`src_ip`, `dst_ip`, `proto` and `threat_flag` are not columns: they come from
`_to_event()` applied to the message body. The filter **is not expressible in
SQL** and stays in Python. So `/events` reads in batches until it has enough
matches:

```python
wanted = offset + limit
batch  = min(max(limit * 4, 500), MAX_LIMIT * 4)
while len(events) < wanted and scanned < MAX_SCAN:   # MAX_SCAN = 20_000
    ...
```

With a single block of recent rows, a rare IP present in the facets (which scan
2000 rows) never appeared in the table. The 20,000-raw-row ceiling per request
bounds the cost.

**Known cost:** a non-selective filter over a wide window means up to 20,000 rows
read and parsed in Python per request, with streaming repeating the query every
5 s. This is the accepted trade-off for not adding derived columns to the schema.

### 5.5 `field:value` syntax

`_FILTER_FIELDS = (src_ip, dst_ip, action, threat_flag, proto, device_ip, tenant)`.

Free-text search looks at **every** field: clicking an IP among the sources also
returned rows where that IP is the destination, and since those are more
numerous the intended rows fell off the first page. Hence exact per-field
filtering.

An unrecognized prefix is **not** interpreted as a field: it stays free-text
search, so `8.8.8.8:53` keeps working.

`_field_value()` normalizes `action`: the facets label every blocking verdict as
`DENY` (a device may write `blocked`, `drop`, …); without the normalization,
clicking the `DENY` facet would not have found those rows.

### 5.6 Suppression

`POST /alerts/suppress` verifies the event is **within the user's scope**
(otherwise one could suppress another site's alert → 404), then enqueues an
`INSERT OR REPLACE` into `siem_suppressions` with `reason` and `suppressed_by`.

Both `/events` and `/facets` apply
`AND NOT EXISTS (SELECT 1 FROM siem_suppressions x WHERE x.event_id = s.id)`:
without the exclusion in `/facets` too, a facet counted events the table no
longer showed.

### 5.7 Frontend ([static/js/flow-analytics.js](../static/js/flow-analytics.js))

- **Live tail** every 5 s, pausable. Does not run when the tab is inactive.
- **Freeze while a detail is open**: if `_selectedEventId` is set, streaming does
  not refresh the table — a rebuild would move the row the user is reading.
- **Dedup by id**: polling always requests the last 20 events; without dedup the
  same events were re-appended every 5 s (duplicate rows, and a selected id
  opening multiple identical details). Client buffer capped at 150.
- **Scroll preserved**: the table is rebuilt entirely, so the container's
  `scrollTop` is saved and restored.
- **2D canvas histogram**, red bars where `deny_count > 0`. No data → it says so
  (see §7.2).
- **Clickable facets**, each on its own field, writing `field:value` into the
  search box — the same syntax that can be typed by hand, so the filter stays
  visible and editable.
- **Escaping**: project convention is `escapeHtml(...)` for content and
  `jsStr(...)` inside inline handlers.
- **DENY note in the detail drawer**: when the action is a block, the drawer
  clarifies that SentinelNet is a **passive** observability platform — the device
  did the blocking, not SentinelNet.

---

## 6. Configuration and lifecycle

### 6.1 Safe defaults ([core/data_config.py:65](../core/data_config.py#L65))

Everything off, bind on `127.0.0.1`, high unprivileged ports (IPFIX 4739,
NetFlow 2055, sFlow 6343, syslog **5514** — never 514 in-process; privileged
mapping is done through Docker only). `0.0.0.0` requires explicit opt-in.

Precedence: **environment variables > `app_settings.json` > defaults**.

### 6.2 Hot application ([observability/listener_manager.py](../observability/listener_manager.py))

`apply_obs_config()` is idempotent and is called both from the lifespan and from
`POST /api/observability/config`: **no process restart required**.

It diffs active handles against the desired config, with **stop-before-start**
for the same name — mandatory on Windows, which does not allow double-binding a
port. A failed bind produces a `listener_bind_failed` metric, a recorded state in
`listener_status`, an error log, **a skipped listener and a live application**.

State is module-level rather than on `app.state`, so the endpoint can call
`apply_obs_config` without a reference to the `FastAPI` instance.

Background tasks (retention, correlation, API poller) start on the first
activation of the master switch and stay up (they are no-ops when there is
nothing to do); the API poller is restarted if its interval changes.

### 6.3 Lifespan ([app_server.py:25](../app_server.py#L25))

```
db.start_writer()        → migrate() + writer thread
apply_obs_config(cfg)    → listeners + tasks
   yield
listener_manager.shutdown()
db.stop_writer()         → drains the queue, best-effort 10 s
```

`SchemaTooNewError` at startup is fatal and printed to stderr: better not to
start than to write to a database of a future version.

---

## 7. Historical mistakes, corrected (useful for not reintroducing them)

### 7.1 Flow SIEM built on `flow_aggregates`

The first version of the router read `flow_aggregates` and **synthesized the
missing fields**: action from `idx % 5`, source port from `1024 + idx*37`,
timestamp from `now - idx*45`, VLAN fixed at 10. The id was positional
(`siem-fl-<index>`), derived from the byte ranking: **it identified a position in
a leaderboard, not an event**, so on the next refresh the same id pointed at a
different connection and the open detail changed content under the user.

Fix: source is `syslog_events`, id is the primary key.

### 7.2 Sinusoidal histogram

`/histogram` did not query the database: the values were
`abs(sin(i * 0.4)) * 45`, with denies at 15% of that. The bars drawn were a sine
wave. The client-side fallback drew a fake ramp too (`count: 20+i`) on an empty
database: a database with no data looked like real traffic.

### 7.3 No-op suppression

`POST /alerts/suppress` returned `{"suppressed": true}` without writing
anything. The alert reappeared on the next refresh. Hence the
`siem_suppressions` table.

### 7.4 Flow SIEM without tenant scope

The router did not apply `_tenant_filter` at all: a user restricted to one site
saw every site's events.

### 7.5 `hash()` for the synthetic VLAN

Salted per process: different VLANs across restarts and across workers. Replaced
with a truncated sha1.

---

## 8. Tests

| File | Covers |
|---|---|
| `tests/test_flow_siem.py` | `TestFlowSiem`, `TestFlowSiemDeepScan` |
| `tests/test_observability_api.py` | Observability router endpoints |
| `tests/test_observability_flowgraph.py` | `TestFlowGraph`, `TestFlowGraphRealVlan`, `TestFlowGraphVlanTenantScope` |
| `tests/test_observability_ingest.py` | Parsers and ingest pipeline |
| `tests/test_observability_ui.py` | Tab markup and wiring |

Run from the repository root:
`uv run python -m unittest discover -s tests -v`.

---

## 9. Known limits and gotchas

1. **Deep scan cost** (§5.4): up to 20,000 rows parsed in Python per request,
   repeated every 5 s by the live tail. If it becomes a problem, the path is to
   materialize `src_ip`/`dst_ip`/`action` as columns in `syslog_events` at
   ingestion time — not to optimize the Python loop.
2. **`total` in `/events` is the count of matches found so far**, not the real
   total in the window: the deep scan stops as soon as it has enough results. Do
   not use it for page-count pagination.
3. **RFC 3164 has no year and no timezone**: the current year and the server's
   local timezone are assumed. A limitation of the BSD format, not of the parser.
4. **`siem_suppressions` is outside retention** (§3.1).
5. **Synthetic VLAN** when the ARP binding is missing: always marked, never
   silent — but still a value that isn't real.
6. **Correlator precision-over-recall**: a security event with no corroborating
   NetFlow and severity > 3 produces no anomaly. Intended, but worth knowing when
   investigating "why didn't this show up".

---

## 10. Typical investigation path

1. **Live Flows** → KPIs (throughput, top path %, talkers, spikes) and the top
   talker table. Filters: window, metric, source, tenant.
2. Suspicious row → click opens the **detail panel**: the source's
   MAC/switch/port via client-map, a link to topology, a jump to that flow's
   anomalies.
3. **Correlated anomalies** → transitions `new` → `ack` → `resolved`.
4. **Flow SIEM** → filter `src_ip:<ip>` or `dst_ip:<ip>` for the device's real
   ALLOW/DENY verdict, with facets and histogram.
5. Confirmed false positive → **suppress** (persisted, excluded from events and
   facets).
6. Optional: select rows in Live Flows → **AI analysis** with context assembled
   and redacted server-side.
