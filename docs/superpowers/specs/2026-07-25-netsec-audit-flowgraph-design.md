# NetSec Audit real check engine + Flussi Live graph formatting and drill-down

Date: 2026-07-25
Branch: `feature/pyrefly-quality`

Two independent pieces of work, sharing only a release. Part A replaces the
NetSec Audit substring heuristics with real parsed-config evaluations. Part B
fixes the Flussi Live flow graph rendering and makes the "Dettagli" button show
the data actually drawn on screen.

---

## Part A — NetSec Audit

### Current state

`services/netsec_audit.py` defines 13 rules across three benchmarks and
evaluates each with substring matching against the whole lowercased config
text.

The **benchmark citations are accurate**. NIST SP 800-53 Rev.5 SC-7 (Boundary
Protection), AC-17 (Remote Access), SC-13 (Cryptographic Protection) and
AU-2 / AU-12 (Audit Events, Audit Record Generation) are real controls,
correctly mapped. PCI-DSS v4.0 requirements 1.2, 1.3, 2.2 and 10.2 are real and
correctly mapped. CIS publishes a real *CIS Fortinet FortiGate Benchmark*.

The **evaluations are not**. Representative failures:

- `services/netsec_audit.py:218` — `"22" in cfg` matches `10.0.22.5`, port
  `2200`, or a VLAN id.
- `services/netsec_audit.py:194` — `"public" in cfg` matches the word in any
  comment or object name.
- `services/netsec_audit.py:170` — the any-to-any test is
  `("pass" or "accept" or "allow") and ("any" or "0.0.0.0")`, true for
  essentially every non-trivial FortiGate config.
- `services/netsec_audit.py:162` — `"http " in cfg` matches URLs.

Secondary gaps:

- A missing config block yields `PASS`, silently inflating the score.
- No evidence: a FAIL names no line, interface, policy id, or admin account.
- `static/js/netsec-audit.js:6-12` seeds six hardcoded demo rules that are not
  engine output and persist until a scan replaces them.
- `static/js/netsec-audit.js:194` — `exportAuditReport()` is an `alert()` stub.
- The device dropdown is read by the frontend but `device_ip` never reaches a
  useful path, so stored backups are unreachable from the UI.
- `Math_round` at `services/netsec_audit.py:259` wraps `round()` for no reason.
- The module docstring says "CIS Benchmark v4.0". CIS versions benchmarks
  per product; there is no global v4.0.

### Parsing

`fw_analyzers/fortios.py` already parses the FortiOS `config` / `edit` / `set` /
`next` / `end` block structure via `_forti_tree`, and tokenizes quoted strings
via `_forti_tokens`. `config_analyzer` reimports both, so their shape must not
change.

Add a new function in `services/netsec_audit.py`:

```python
def _parse_with_lines(text: str) -> list[ConfigRecord]
```

A single pass over the lines maintaining a block-path stack, importing
`_forti_tokens` from `fw_analyzers.fortios`. Each `set` directive produces one
record:

| field        | example |
|--------------|---------|
| `path`       | `("system interface", "port1")` |
| `key`        | `"allowaccess"` |
| `values`     | `["ping", "https", "telnet"]` |
| `line`       | `412` |
| `raw`        | `"    set allowaccess ping https telnet"` |

A flat record list gives structural context through `path` and evidence through
`line`, and every rule below is expressible over it. No tree is needed and no
shared code changes.

Parsing is tolerant in the same spirit as `_forti_tree`: unclosed blocks,
anomalous nesting and malformed lines are skipped rather than raised.

Helper accessors over the record list, used by the rules:

- `blocks(records, "system interface")` — records grouped by the `edit` key
  under a named section.
- `setting(records, "system global", "admintimeout")` — a single record from a
  non-`edit` section, or `None`.

### Status model

A fourth status, `UNKNOWN`, is introduced alongside `PASS` / `FAIL` / `WARN`.

A rule returns `UNKNOWN` when the config does not contain the block it needs to
evaluate — an uploaded partial config, or a backup whose section was trimmed.
This replaces the current behaviour where absence produces `PASS`.

**Absence is `UNKNOWN` except where absence is itself the finding.** For most
rules a missing block means "not assessable". For two rules it means
"not configured", which is the violation:

- `AUD-NIST-04` / `AUD-PCI-04` — no `log syslogd setting` block means no remote
  logging exists, which is the control failure. FAIL, not UNKNOWN.
- `AUD-NIST-02` — an admin account with no `trusthost*` key is unrestricted by
  FortiOS default. FAIL, not UNKNOWN. (A missing `system admin` block
  altogether is still UNKNOWN.)

Each rule declares which of the two behaviours it uses, so the distinction is
data on the rule rather than scattered through the evaluation code.

Scoring changes accordingly:

```
score = passed / (passed + failed + warned) * 100     # UNKNOWN excluded
```

If every rule is `UNKNOWN` the score is reported as not determinable rather than
`0` or `100`. The summary object gains an `unknown` count, and the UI shows it
as a fourth stat tile so an incomplete config is visible rather than silently
depressing or inflating the grade.

This will lower scores on partial configs relative to today. That is the
intended correction.

### Rules

Every rule inspects parsed structures and, on a non-PASS verdict, attaches
evidence.

**CIS (Fortinet FortiGate Benchmark)**

| id | check | evaluation |
|---|---|---|
| `AUD-CIS-01` | Insecure management protocols | `system interface` → per-`edit`, `allowaccess` values intersect `{telnet, http}` → FAIL, evidence per interface |
| `AUD-CIS-02` | Any-to-any policy | `firewall policy` → per-`edit`, `action == accept` and `srcaddr` contains `all` and `dstaddr` contains `all` and `service` contains `ALL` → FAIL, evidence per policy id |
| `AUD-CIS-03` | Legacy TLS | `system global` → `ssl-min-proto-version` or `admin-https-ssl-versions` intersects `{sslv3, tlsv1-0, tlsv1-1}` → FAIL; key absent → WARN (platform default varies by FortiOS version) |
| `AUD-CIS-04` | Admin idle timeout | `system global` → `admintimeout` is `0` or `> 30` → FAIL; absent → WARN |
| `AUD-CIS-05` | SNMP default communities | `system snmp community` → per-`edit`, `name` in `{public, private}` → FAIL, evidence per community; section absent → UNKNOWN |
| `AUD-CIS-06` | Strong crypto | `system global` → `strong-crypto` not `enable` → WARN |

**NIST SP 800-53**

| id | check | evaluation |
|---|---|---|
| `AUD-NIST-01` | Boundary protection (SC-7) | `firewall policy` → policies whose `srcintf` names a WAN-role interface, with `dstaddr all` and `action accept` → FAIL, evidence per policy. WAN-role interfaces resolved from `system interface` → `role wan`, falling back to name match on `wan*` / `port1` when `role` is absent |
| `AUD-NIST-02` | Remote admin restriction (AC-17) | `system admin` → per-`edit`, no `trusthost*` key present, or a `trusthost*` of `0.0.0.0 0.0.0.0` → FAIL, evidence per admin account |
| `AUD-NIST-03` | Crypto in transit (SC-13) | shares the `AUD-CIS-03` evaluation, reported under the SC-13 citation |
| `AUD-NIST-04` | Audit logging (AU-2 / AU-12) | `log syslogd setting` → `status` not `enable`, or no `server` value → FAIL; section absent → FAIL (no remote logging configured at all) |

**PCI-DSS v4.0**

| id | check | evaluation |
|---|---|---|
| `AUD-PCI-01` | Req 1.2 — inbound admin ports | WAN-facing `firewall policy` entries with `srcaddr all` whose `service` resolves to TCP 22 or 3389 → FAIL. Service names resolved through `firewall service custom` (`tcp-portrange`), with the FortiOS built-in names `SSH` and `RDP` recognised directly |
| `AUD-PCI-02` | Req 1.3 — internet to CDE | shares the `AUD-CIS-02` evaluation, reported under the 1.3 citation |
| `AUD-PCI-03` | Req 2.2 — vendor defaults | `system admin` contains an account named `admin`, **or** `system password-policy` → `status` not `enable` → FAIL, evidence per finding |
| `AUD-PCI-04` | Req 10.2 — audit trails | shares the `AUD-NIST-04` evaluation, reported under the 10.2 citation |

Rules that share an evaluation share one implementation function; only the
citation, title and remediation text differ per benchmark.

### Evidence

Each evaluated rule gains:

```json
"evidence": [
  {"line": 412,
   "text": "set allowaccess ping https telnet",
   "context": "system interface / port1"}
]
```

`PASS` and `UNKNOWN` carry an empty list. The rules table renders an
expandable evidence row per finding showing line number, the offending
directive, and its block path.

### API

`POST /api/netsec-audit/scan` keeps its request shape
(`config_text`, `device_ip`, `device_name`, `benchmark`). The response gains
`evidence` per rule and `unknown` in the summary. No live device fetch is added;
config comes from the uploaded file or from the freshest stored backup via the
existing `_load_backup_text`.

The frontend gains a device dropdown populated from inventory so `device_ip`
reaches the route, which already handles it.

### Frontend

- Delete the six hardcoded `_auditRules` seeds. The table starts empty with a
  "run a scan" prompt, so nothing on screen is ever non-engine output.
- Render `UNKNOWN` as a fourth status badge and a fourth stat tile.
- Render per-rule evidence in an expandable row.
- Replace `exportAuditReport()`'s `alert()` with a real download: a generated
  HTML report containing the benchmark, score, per-rule verdicts and evidence.
- Keep the existing `escapeHtml(jsStr(x))` escaping convention.

### Cleanups

- Remove `Math_round`, call `round()` directly.
- Correct the module docstring's benchmark naming.

### Tests

`tests/` currently has no coverage of this engine. Add:

- A fixture FortiGate config with known violations (telnet on an interface,
  an any-any policy, `tlsv1-0`, `admintimeout 0`, an SNMP `public` community,
  an admin with no trusthost, no syslogd block).
- A clean fixture that passes every rule.
- A partial fixture exercising `UNKNOWN`.
- Per-rule assertions on status **and** on the evidence line numbers, so a
  regression in the parser is caught rather than masked by a status that
  happens to stay the same.
- A scoring test asserting `UNKNOWN` is excluded from the denominator.

---

## Part B — Flussi Live flow graph

> **SUPERSEDED 2026-07-25.** The owner elected to delete the flow graph rather
> than repair it, after a further bug appeared: selecting Sankey / Trend Rate /
> Matrice leaves the topology graph on screen, because the force-directed
> animation loop keeps running and overdraws whatever the other renderers paint.
>
> The replacement work is: remove the `Grafo dei flussi` panel and all four
> renderers, and use the freed space for an always-visible flow telemetry detail
> panel carrying the content previously reachable only through the "Dettagli"
> modal. The separate `Ripartizione Protocolli Ingest` card and its modal remain.
>
> The diagnosis below is retained because it documents why each view was
> broken, and because the `ctx.font` finding applies to any future canvas work
> in this codebase. Nothing in this section is being implemented.

### Current state

`static/js/observability.js` renders four views onto one canvas:
`topology` (force-directed, `fgStartSimulation`), `sankey`
(`renderFlowSankey`), `trend` (`renderFlowTrendRate`) and `matrix`
(`renderFlowMatrix`), switched by `setFlowGraphView`.

**Root cause of the bad formatting across every view:**

```js
ctx.font = '11px var(--font-code, monospace)';
```

The Canvas 2D API does not resolve CSS custom properties. The font string is
invalid, so the assignment is ignored and the browser retains whatever font was
previously set. This appears at `observability.js:1761`, `1840`, `1846`, `1874`,
`1912`, `1946`, `1955`, `1973`.

Further defects:

- No `devicePixelRatio` scaling — the canvas backing store matches CSS pixels,
  so everything renders soft on HiDPI displays.
- No resize handling — `renderFlowGraphView` reads `clientWidth` only when
  called, so the graph does not reflow.
- Sankey (`observability.js:1775`): each node height is
  `Math.max(24, share * availH)` computed independently, so with a skewed rate
  distribution the heights sum past the available height and nodes run off the
  bottom of the canvas.
- Sankey (`observability.js:1841`): labels cut at a fixed 15 characters
  regardless of the rendered width.
- Sankey: `colW = 135` is fixed while `xProto` and `xDst` derive from `width`,
  so narrow viewports overlap the columns.
- Matrix (`observability.js:1949`): column headers drawn at a fixed `x - 25`
  offset, so labels collide with each other; long IPs are not truncated and
  row labels can overflow the 110px left margin.
- Trend (`observability.js:1900`): the series shape is fabricated —
  `Math.sin(i * 0.4 + idx) * 0.2 + Math.cos(i * 0.8) * 0.1` applied to a single
  scalar rate. The chart presents invented variation as measured history.
- Trend (`observability.js:1908`): legend entries at `padding.left + idx * 150`
  run off the canvas at five series on narrow widths.
- Only the topology view binds canvas interaction (`fgBindCanvasEvents`); the
  other three have no hover or click.
- "Dettagli" (`observability.js:1470`) shows a generic protocol telemetry
  breakdown plus `_fgData.edges.slice(0, 15)` — not the aggregates the current
  chart is drawing.

### Shared canvas layer

One small set of helpers used by all four renderers:

- `fgFonts()` — resolve `--font-code` and the text colours once per render via
  `getComputedStyle`, returning concrete strings. All `ctx.font` assignments use
  template literals over those values. This alone fixes the typography in every
  view.
- `fgSetupCanvas(canvas, cssHeight)` — set the backing store to
  `clientWidth * devicePixelRatio` and scale the context, returning logical
  width and height so renderer maths stays in CSS pixels.
- `fgTruncate(ctx, text, maxWidth)` — ellipsis truncation by
  `ctx.measureText`, replacing every fixed character-count cut.
- A debounced `ResizeObserver` on the canvas container calling
  `renderFlowGraphView`.

### Sankey

- Node heights: compute proportional heights, then apply the minimum and
  redistribute the resulting shortfall proportionally across the nodes that are
  above the minimum, so the column always fits the available height.
- Column geometry derived from the rendered width rather than a fixed `colW`:
  `colW = clamp(90, width * 0.15, 160)` with the three columns spaced evenly
  across the remaining width. Below 420 logical pixels the three-column layout
  cannot fit legible labels, so the view renders a "widen the panel" message
  instead of overlapping columns.
- Labels truncated by measured width.

### Matrix

- Row labels right-aligned against the grid with measured truncation.
- Column headers centred on their column by measured width; rotated 45° when
  the natural width would collide with the neighbouring header.
- Cell values hidden rather than overflowing when the cell is too narrow.

### Trend

New endpoint:

```
GET /api/observability/flowseries?window=<15m|1h|24h>
```

`flow_aggregates.window_start` is truncated to 60s, so real per-bucket history
is directly queryable. The endpoint selects the top 5 `src_ip`/`dst_ip`/
`protocol`/`dst_port` pairs by total bytes over the window — matching the five
series the renderer draws — then groups those by `window_start`. It applies the
same `_tenant_filter` scoping as `obs_flowgraph`, and returns:

```json
{"window": "15m",
 "bucket_seconds": 60,
 "buckets": [1753440000, 1753440060, ...],
 "series": [{"src": "...", "dst": "...", "proto": "tcp", "port": 443,
             "rates_bps": [...]}]}
```

Buckets with no rows are zero-filled so the X axis is continuous rather than
compressing gaps.

The renderer plots those arrays directly. `Math.sin` and the surrounding
fabrication are deleted. The X axis carries real bucket timestamps instead of
the current `-15m` / `Ora` placeholder labels. The legend wraps onto multiple
rows within the canvas width instead of advancing by a fixed 150px.

### Drill-down

`openObsInspectModal` gains a per-view section reflecting exactly what is drawn,
placed above the existing telemetry breakdown, which is retained:

- **Sankey** — the src, protocol and dst nodes actually rendered, each with
  aggregated rate and share of total, plus the ribbons between them. These are
  the same aggregates the renderer computes, so the table and the picture cannot
  disagree.
- **Matrix** — the rendered cells as a sortable src × dst table with rate and
  packet count, zero cells excluded.
- **Trend** — per-series bucket data with min, average and peak over the window.
- **Topology** — nodes with degree, VLAN carrying the existing `vlan_real`
  disclosure marker, and adjacent edges.

To guarantee agreement, each renderer stores its computed aggregates on a
module-level `_fgViewAggregates` as it draws, and the modal reads that rather
than recomputing from `_fgData`.

The arbitrary `slice(0, 15)` cap is replaced by a scrollable full list.

The existing `vlan_real` disclosure convention is preserved wherever VLAN is
shown.

### Tests

The flow graph is canvas-rendered and not unit-testable end to end, so tests
target the data layer:

- `flowseries` endpoint: bucket continuity including zero-fill, tenant scoping,
  window parsing, and behaviour on an empty window.
- Aggregation helpers extracted from the renderers (Sankey node totals, matrix
  cell totals, trend series min/avg/peak) tested as pure functions, which is
  also what makes the modal-renderer agreement checkable.

---

## Out of scope

- Live device config fetch at scan time (`show full-configuration`).
- Multi-vendor audit rules. `drivers/` covers eight vendors; this work is
  FortiOS only. The record-based rule structure leaves room for vendor variants
  later without restructuring.
- Any change to `_forti_tree` or `_forti_tokens`, which `config_analyzer`
  depends on.
- Scheduled or recurring audits.

## Verification

Per `CLAUDE.md`, before each commit on this branch: `pyrefly check`, the full
`unittest` suite, and `graphify update .` before merging to preview.
