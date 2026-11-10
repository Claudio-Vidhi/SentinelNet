# Traffic tab and Flow SIEM

A code-oriented reference for anyone working on the Traffic tab and its syslog
search (Flow SIEM). Covers the ingest pipeline, the data schema, the endpoints,
the frontend, the decisions behind them, and the known limits.

NetFlow, IPFIX and sFlow are no longer collected (removed in 0.65.0): the tab
reads syslog verdicts and firewall policy counters only.

Cross-references: [architecture.md](architecture.md) (full pipeline),
[collectors.md](collectors.md) (sources), [CONTRIBUTING.md](../CONTRIBUTING.md)
§3 (async-DB rule) and §4 (multi-tenant scope rule).

---

## 1. In one line

| | Traffic tab (`tab-flows`) | Flow SIEM (Search view) |
|---|---|---|
| Question it answers | *how many sessions and bytes per firewall policy* | *was that traffic allowed or blocked, and why* |
| Source | FortiGate policy counters (live REST) | `syslog_events` (+ `siem_suppressions`) |
| Router | [routers/observability.py](../routers/observability.py), [routers/firewall_traffic.py](../routers/firewall_traffic.py) | [routers/flow_siem.py](../routers/flow_siem.py) |
| JS | [static/js/observability.js](../static/js/observability.js) | [static/js/flow-analytics.js](../static/js/flow-analytics.js) |

`syslog_events` is the only table holding real device verdicts. See §7.1 for
what happened when flow counters were used in its place.

---

## 2. Ingest pipeline (common to both)

```
network devices
   │ UDP syslog 514 (Windows) / 5514 (Linux, Docker)
   ▼
_IngestProtocol.datagram_received   ← observability/ingesters/udp_server.py
   │ put_nowait on an asyncio.Queue (maxsize 20_000)
   ▼
_consumer (1 task per listener)
   │ parser(data, src_ip)           ← syslog.py
   │ _resolve_tenant(exporter_ip)   ← inventory_manager.get_device_by_ip
   ▼
db.enqueue_write()   ← bounded queue, 10_000
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
- `get_observability_connection()` is **only** for migrations, tests and
  helpers handed to `asyncio.to_thread`, and is forbidden in the body of an
  `async def` (`tests/test_no_sync_db_on_event_loop.py`).

See [ADR-0004](adr/0004-single-process-sqlite-writer.md).

**Writer resilience.** Batch commits, up to 500 payloads. If one payload in a
batch fails → rollback and re-run item by item, dropping only the faulty
payloads (`writes_dropped_error`). If the writer crashes → restart with
exponential backoff, max 5 attempts; beyond that, writes are dropped but **the
application stays alive**.

---

## 3. Data schema ([observability/storage/schema.sql](../observability/storage/schema.sql))

Forward-only, idempotent migrations (`IF NOT EXISTS` everywhere).
`SCHEMA_VERSION = 4`. **Downgrade guard**: if the database declares a version
newer than the code, `migrate()` raises `SchemaTooNewError` and observability
refuses to start.

| Table | Written by | Read by | Notes |
|---|---|---|---|
| `flow_aggregates` | nothing since 0.65.0 | nothing | Legacy: kept in databases created before, not created in new ones |
| `syslog_events` | Syslog ingester | `/syslog`, **all of Flow SIEM**, normalizer | `action` is the device's real verdict |
| `siem_suppressions` | `POST /alerts/suppress` | Exclusion in `/events` and `/facets` | PK is `syslog_events.id` |
| `quarantined_exporters` | Ingest | `normalize._from_quarantine` → `platform.exporter_unknown` | Exporters outside inventory; data loss becomes an event on the reserved `__platform__` tenant instead of staying diagnostic-only |
| `api_observations` | REST/SNMP pollers | `/api-context` | Device snapshots, not flows |

### 3.1 Retention ([observability/rollup.py](../observability/rollup.py))

Hourly job, a technical GDPR measure. DELETEs batched at 5000 rows per
transaction via `rowid`, to avoid holding long locks. The legacy incident
tables of an older database age out on their last activity (see
[operations.md](operations.md) §Retention).

> Note: `siem_suppressions` is not in the retention table. Suppressions outlive
> the syslog event they point at (harmless orphan rows, but worth knowing).

---

## 4. Traffic tab (`tab-flows`)

### 4.1 Endpoints

All in [routers/observability.py](../routers/observability.py), all scoped by
`_tenant_filter()`.

| Endpoint | Auth | What it does |
|---|---|---|
| `GET /api/observability/syslog` | user | Latest normalized syslog events |
| `GET /api/observability/interfaces` | `tab-interfaces` | Latest state per port, link transitions over 24h, declared expectations |
| `POST /api/observability/interfaces/expected` | operator + `tab-interfaces` | Declare a port or a whole device expected down / in maintenance |
| `GET/POST /api/observability/config` | **admin** | Listener config, applied hot |
| `GET /api/observability/health` | **admin** | Active listeners, metrics, DB size |
| `POST /api/observability/api-poll` | operator | One-shot REST poll |

`/flowgraph`, `/protocol-distribution`, `/hosts`, `/host-series` and `/top`
were removed in 0.65.0 with the flow views they fed (§4.4). `/anomalies` and
its `/status` alias went with the incidents engine in the same release; the
two interface routes moved here from `/api/incidents/interfaces*`.

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

### 4.4 Removed: the flow views

The tab used to open on an **Overview** (KPI strip, top talkers, protocols and
ports) and had **Per IP** and **Flussi** (top-talker table) views. All of them
read only `flow_aggregates`. 0.65.0 removed them with the flow collectors,
`/top` and the MCP tool `get_top_talkers`. The tab now has **Ricerca** (syslog,
§5) and **Per policy**.

### 4.5 Frontend ([static/js/observability.js](../static/js/observability.js))

- **Auto-refresh every 30 s**, paused when the tab is inactive or the page is
  hidden; immediate refresh on return (`visibilitychange`).
- **Status banner** (above the panes, visible in every view): if `/health` reports observability off or no active
  listener, it says so. Previously the absence of data was silent and
  indistinguishable from "quiet network". `/health` is admin-only: a 403 hides
  the banner rather than raising an error.

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
normalized to `log.event` rather than `log.security` and never counted as a
block — and an IPS drop is one of the commonest reasons a page loads half way. Deliberately **excluded**:
`passthrough` and `bypass` (SSL, traffic *allowed* without inspection),
`detected` (IPS in monitor mode) and `pass`. Those are consent verbs; counting
them as blocks would invent alerts on permitted traffic.

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

Everything off, bind on `127.0.0.1`, syslog on **514** on Windows (matches the
installer's firewall rule) and on the unprivileged **5514** on Linux/Docker,
where the standard port is mapped from compose (`"514:5514/udp"`). `0.0.0.0`
requires explicit opt-in.

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

Background tasks (retention, normalization, API poller) start on the first
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
| `tests/test_traffico_tab.py` | Pills, panes and routes of the tab; `FlowOnlyViewsStayGone` keeps the removed views out |
| `tests/test_observability_ingest.py` | Syslog parser and ingest pipeline |
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
5. **Synthetic VLAN**: gone with `/flowgraph` in 0.65.0 (§4.4, §7.5).

---

## 10. Typical investigation path

1. **Traffic → Ricerca** → filter `src_ip:<ip>` or `dst_ip:<ip>` for the
   device's real ALLOW/DENY verdict, with facets and histogram.
2. **Traffic → Per policy** → which firewall rule carries the sessions.
3. Confirmed false positive → **suppress** (persisted, excluded from events and
   facets).
