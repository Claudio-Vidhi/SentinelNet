# Traffico Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse `#tab-flows` + `#tab-flow-siem` into one Traffico tab with four views (Panoramica / Flussi / Ricerca / Anomalie), driven by a single tenant + window header. Remove the three competing time windows, the two tenant filters, the three protocol breakdowns and the hardcoded `window=7d` on anomalies.

**Architecture:** Pure front-end. `#tab-flows` keeps its id and becomes the container; `#tab-flow-siem` is deleted. The pill/pane mechanism is the one already shipped in the FortiGate tab (`ca-pill` + `fgt-pane`, `fgtSwitchView`/`fgtPickView`) — copied, not reinvented. One module-level state object holds tenant + window + toggles; every loader reads from it instead of from its own `<select>`. No route is added, removed or changed.

**Tech Stack:** Jinja template (`templates/dashboard.html`), vanilla JS (`static/js/observability.js`, `static/js/flow-analytics.js`), `static/js/i18n.js`, `unittest` + `fastapi.testclient.TestClient`, plain `node` for the JS assertions.

**Spec:** `docs/superpowers/specs/2026-08-11-traffico-redesign-design.md`

## Global Constraints

- Code comments in English (`CLAUDE.md` §Coding Style). Docs and user-facing strings follow the file they live in (Italian prose in `docs/`, IT+EN pairs in `static/js/i18n.js`).
- Never write real device models, versions, hostnames, serials or management IPs into tracked files. Examples use RFC 5737 (`192.0.2.x`, `198.51.100.x`), `switch-01` (`CLAUDE.md` §Protect real data).
- Before **each** commit, run and read the output of:
  - `uv run pyrefly check` — must be 0 errors
  - `uv run python -m unittest discover -s tests` — all green
  - `graphify update .` — after code changes
- Single test file run form: `uv run python tests/test_traffico_tab.py`
- Single test run form: `uv run python tests/test_traffico_tab.py TestClassName.test_method_name -v`
- JS assertions run with plain node, no framework: `node tests/js/test_traffico_window.mjs`
- No feature flags, no backwards-compat shims: the old markup is deleted, not hidden (`CLAUDE.md` §Coding Style).
- All values interpolated into HTML from JS use `escapeHtml(jsStr(x))`.
- **No route may change.** `tests/test_router_parity.py` must stay green without being edited — that is the proof.

## Decisions this plan locks in

The spec left three items open. Resolved here so tasks are unambiguous:

- **Default window: `1h`.** Today `#flowsWindow` opens on `15m` while the two others open on `24h`. `1h` is the compromise and the single initial value of `trafState.window`.
- **Anomalie does not get its own range.** It follows the header like everything else. The old `7d` was never a decision, it was a hardcoded string.
- **State lives in one object**, `trafState = { tenant, window, metric, autoRefresh, hideTelemetry }`, defined in `static/js/observability.js` and read by both JS modules. No second source of truth.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `templates/dashboard.html` | `#tab-flows` markup: header, pill bar, 4 panes; `#tab-flow-siem` deleted | Modify |
| `static/js/observability.js` | `trafState`, view switching, Panoramica / Flussi / Anomalie loaders | Modify |
| `static/js/flow-analytics.js` | Ricerca view: reads `trafState` instead of its own selects | Modify |
| `static/js/i18n.js` | IT/EN strings for pills and header | Modify |
| `tests/test_traffico_tab.py` | Structure + route-existence guard for the merged tab | Create |
| `tests/js/test_traffico_window.mjs` | One window drives every view; no hardcoded `7d` | Create |
| `docs/netsec_troubleshooting_qa_v3.md` | §4 element ids | Modify (Task 6) |
| `docs/ui_tab_overlap_analysis.md` | §A3 marked done | Modify (Task 6) |

---

### Task 1: Header, pill bar and four empty panes

`#tab-flow-siem` stays alive and untouched in this task. No panel moves yet — this only proves the shell holds.

> **Deviation taken during implementation.** The legacy controls (`#flowsWindow`, `#flowsMetric`,
> `#flowsTenant*`, `#flowsAutoRefresh`, `#flowsHideTelemetry`, `#flowsLastUpdate`, `#obsChartWindow`)
> are deleted **here**, not in Task 2, and the loaders are repointed at `trafState` in the same
> commit. Leaving two live window selectors in the tab for the length of a commit would ship exactly
> the bug this plan exists to remove. Task 2 keeps only the panel moves.
>
> **Finding for Tasks 2-3.** The two tenant filters are not the same mechanism:
> `/api/observability/top` has **no** tenant parameter (Flussi filters client-side over the rows it
> already fetched, from `rebuildFlowsTenantList()`), while `/api/flow-siem/*` takes a single
> server-side `tenant`. The header keeps the multi-checkbox; when the Ricerca view lands it sends
> `&tenant=X` only if exactly one tenant is selected, and must say on screen when it is showing more
> than the selection — facets and histogram are aggregated server-side and cannot be filtered
> client-side after the fact.

**Files:**
- Modify: `templates/dashboard.html:1484-1490` (the `#tab-flows` opening + its `.subtab-bar`)
- Modify: `static/js/observability.js` (new `trafState` + `trafSwitchView`, near `flowsTabShown()` at `:292`)
- Modify: `static/js/i18n.js` (4 pill labels + header labels, IT and EN)
- Create: `tests/test_traffico_tab.py`

**Interfaces:**
- Produces: `trafState` object; `trafSwitchView(view: 'overview'|'flows'|'search'|'anomalies') -> void`, exported on `window`
- Produces markup: pills `#trafPill-overview|flows|search|anomalies`, panes `#trafPane-overview|flows|search|anomalies`, header controls `#trafTenantBtn` (+ `#trafTenantDropdown`, `#trafTenantAll`, `#trafTenantList`), `#trafWindow`, `#trafMetric`, `#trafAutoRefresh`, `#trafHideTelemetry`, `#trafLastUpdate`
- Consumes: the existing `.ca-pill` / `.fgt-pane` CSS classes — do not add new CSS

- [x] **Step 1: Write the failing test**

Create `tests/test_traffico_tab.py`, modelled on `tests/test_wlc_tab.py` (same `_registered_api_paths()` helper, copy it). Two classes:

```python
class TestTrafficoStructure(unittest.TestCase):
    """Il tab Traffico e' una pill bar su quattro pane, non due tab gemelli.
    Un id che sparisce senza che sparisca il suo pannello lascia un pulsante
    morto: la struttura va asserita, non guardata a occhio."""

    REQUIRED = ["trafPill-overview", "trafPill-flows", "trafPill-search",
                "trafPill-anomalies", "trafPane-overview", "trafPane-flows",
                "trafPane-search", "trafPane-anomalies", "trafWindow",
                "trafTenantBtn", "trafMetric", "trafAutoRefresh",
                "trafHideTelemetry"]

    def test_pills_and_panes_exist(self): ...
```

The second class (`TestTrafficoCallsRealRoutes`) asserts every `apiFetch` path in `observability.js` and `flow-analytics.js` resolves to a registered route — same body as `TestWlcTabCallsRealRoutes.test_every_apifetch_path_exists`, two source files instead of one. It passes today and must keep passing after every later task; it is the parity net for the whole plan.

- [x] **Step 2: Add the header + pill bar markup**

In `#tab-flows`, replace the `.subtab-bar` (the two buttons pointing at `tab-flows` / `tab-flow-siem`) with the header row and the pill bar. The four panes go immediately after, empty, `#trafPane-overview` visible and the other three `style="display:none;"`. Everything currently inside `#tab-flows` stays where it is, below the panes, until Task 2 moves it.

- [x] **Step 3: `trafState` + `trafSwitchView`**

```js
// Single source of truth for the tab: every view reads the same window and
// tenant. Three independent <select> elements is how the old tab ended up
// showing a 15m top-talker next to a 24h chart.
const trafState = { tenant: 'all', window: '1h', metric: 'bytes',
                    autoRefresh: true, hideTelemetry: false };
```

`trafSwitchView(view)` toggles pill `active` and pane visibility, records the current view, and calls the loader for that view **only** — this is the fix for `flowsTabShown()` loading everything at once. Loaders are wired in the tasks that move their content; in this task the map is empty and switching just shows empty panes.

- [x] **Step 4: Verify**
  - `uv run python -m unittest tests.test_traffico_tab` — green (the direct `python tests/...` form cannot import `app_server`; same limitation as `tests/test_wlc_tab.py`)
  - `uv run python -m unittest discover -s tests` — green
  - Browser: the four pills switch four empty panes; the old content is still visible below; Flow SIEM still reachable.
  - Commit: `feat(traffico): header unico e quattro viste, ancora vuote`

---

### Task 2 + Task 3 (done together): every panel moves into its pane

> **Deviation.** Tasks 2 and 3 shipped in one commit. Task 1 deleted the subtab bar,
> which was the *only* entry point to `#tab-flow-siem` — the twin tab was left
> unreachable. Restoring a temporary link would have been a shim; moving the Ricerca
> view in, as Task 3 always intended, was the real fix, so it could not wait.
> Anomalie's markup moved here too; its behaviour fixes (window, incident link)
> remain Task 4.
>
> ECC `code-reviewer` ran over the diff: APPROVE, 0 critical/high/medium.

### Task 2: Panoramica and Flussi move into their panes

**Files:**
- Modify: `templates/dashboard.html` (`#tab-flows` body: KPI strip, `#flowDetailInline`, `#obsProtocolCard`, tenant/proto hero, top talker panel, filter panel + flows table + syslog section)
- Modify: `static/js/observability.js:165` (`setFlowsHideTelemetry`), `:292` (`flowsTabShown`), `:357` (`loadTopTalkers`), `:557` (`renderFlowsTable`), `:1029` (`loadObsProtocolDist`)
- Modify: `tests/test_traffico_tab.py` (extend `REQUIRED`, add the deleted-id assertions)

**Interfaces:**
- Panoramica pane receives: `#flowsObsBanner`, `#fgKpiStrip` (+ its 4 KPI spans), `#fgTalkersTableBody`, `#fgTenantSummary`, `#obsProtocolCard` with `#obsProtocolCanvas`, `#btnChartTypeDonut|Bar|Trend`, `#obsProtocolStats`, and `#fgProtoTableBody` **as the detail table inside that same card**
- Flussi pane receives: `#flowsSourceChips`, `#flowsColsBtn`/`#flowsColsDropdown`, `#flowsTableHead`/`#flowsTableBody`, `#flowsSyslogAllSection` (+ head/body/count), and the `#flowDetailPanel` drawer stays a page-level sibling
- Deleted: `#flowDetailInline` and its wrapper panel, `#obsChartWindow`, `#flowsWindow`, `#flowsMetric`, `#flowsTenantBtn`/`#flowsTenantDropdown`/`#flowsTenantAll`/`#flowsTenantList`, `#flowsAutoRefresh`, `#flowsHideTelemetry`, `#flowsLastUpdate` (all replaced by the `#traf*` header equivalents)

- [x] **Step 1: Extend the test first**

Add to `tests/test_traffico_tab.py`:

```python
GONE = ["flowDetailInline", "obsChartWindow", "flowsWindow", "flowsMetric",
        "flowsTenantBtn", "flowsAutoRefresh", "flowsHideTelemetry"]

def test_replaced_controls_are_gone(self):
    """Un controllo sostituito ma non cancellato resta cliccabile e muove una
    finestra che nessuno legge piu'."""
```

- [x] **Step 2: Move the markup**

Panoramica pane, in order: banner, KPI strip, top talker table, protocol card (chart + `#fgProtoTableBody` inside it), tenant summary. Flussi pane: chips + columns dropdown + flows table + syslog section. Delete the `#flowDetailInline` panel and the two-column hero wrapper.

- [x] **Step 3: Repoint the loaders at `trafState`**

`loadTopTalkers()`, `loadObsProtocolDist()` and `renderFlowsTable()` stop reading `document.getElementById('flowsWindow'|'obsChartWindow'|'flowsMetric')` and read `trafState`. `telemetryParam()` reads `trafState.hideTelemetry`. `setObsChartType()` keeps working on the chart type only — the chart type is a per-card display option, not tab state, so it stays local.

`flowsTabShown()` becomes: ensure the tenant list is populated, then `trafSwitchView(currentView || 'overview')`.

- [x] **Step 4: Verify**
  - Both test files green; `test_router_parity.py` green untouched.
  - Browser: changing the header window updates KPI, top talkers, protocol chart and the flows table together. The protocol card no longer has its own window.
  - Commit: `feat(traffico): Panoramica e Flussi nelle loro viste, una sola finestra`

---

### Task 3: Ricerca moves in, `#tab-flow-siem` is deleted

**Files:**
- Modify: `templates/dashboard.html:3089-3160` (delete `#tab-flow-siem`, its content moves to `#trafPane-search`)
- Modify: `static/js/flow-analytics.js:13` (`populateSiemTenantFilter`), `:25` (`loadFlowSiemTab`), `:60` (`startSiemStreamTimer`)
- Modify: `static/js/observability.js` (register the `search` loader in `trafSwitchView`)
- Modify: `tests/test_traffico_tab.py`

**Interfaces:**
- Ricerca pane receives: `#flowSiemStreamBadge`, `#btnFlowSiemStream`, `#flowSiemHistCanvas`, `#flowSiemQueryInput`, `#flowSiemFacets`, `#flowSiemTableBody`
- Deleted: `#tab-flow-siem`, both `.subtab-bar` copies, `#flowSiemTenant`, `#flowSiemWindow`
- `loadFlowSiemTab()` keeps its name and its four fetches; it takes window/tenant from `trafState`

- [x] **Step 1: Test** — assert `id="tab-flow-siem"` is absent from `dashboard.html`, and that `flowSiemTenant`/`flowSiemWindow` are gone while the six ids above survive.

- [x] **Step 2: Move the markup** into `#trafPane-search`. Drop the hero card: its title text is now the tab's, its stream controls go on one row above the histogram. Revisit the `240px 1fr` grid and the `min-height:450px` on the log — inside a pane with a pill bar the old value overflows (spec §Punti aperti).

- [x] **Step 3: Repoint** `populateSiemTenantFilter()` — it no longer fills a `<select>`, the header owns the tenant list; the function is deleted if nothing else calls it. `loadFlowSiemTab()` reads `trafState`. The live-tail timer must pause when the Ricerca pane is not the visible one, not just when the tab is hidden.

- [x] **Step 4: Verify**
  - Tests green. Browser: live tail runs only while Ricerca is open; switching tenant in the header refilters events, facets and histogram.
  - Commit: `feat(traffico): la Ricerca SIEM diventa una vista, il tab gemello sparisce`

---

### Task 4: Anomalie moves in, window fixed, incident link added

**Files:**
- Modify: `templates/dashboard.html` (anomalies panel → `#trafPane-anomalies`)
- Modify: `static/js/observability.js:806` (`loadAnomalies`)
- Modify: `tests/test_traffico_tab.py`; Create: `tests/js/test_traffico_window.mjs`

**Interfaces:**
- Anomalie pane receives: `#anomSectionTitle`, `#anomStatus`, `#anomIpFilterChip`, `#anomTableBody`
- `loadAnomalies()` sends `window=${trafState.window}` — the literal `window=7d` at `:806` is removed
- Each row links to its incident: the `id` field of `/api/observability/anomalies` **is the incident id** (`routers/observability.py:340` selects `i.id FROM incidents i`). The link calls `switchTab('tab-incidents')` and opens that incident. No API change.

- [x] **Step 1: Write the failing JS test**

`tests/js/test_traffico_window.mjs`, in the style of `tests/js/test_wlc_quality.mjs` (read the source, eval the slice, assert):

```js
// La finestra del tab deve arrivare a tutte le viste. La chiamata anomalie
// nasceva con window=7d cablato: il pannello mostrava una settimana mentre il
// resto del tab mostrava un quarto d'ora, e nessun controllo lo diceva.
assert.ok(!/window=7d/.test(src), 'finestra anomalie ancora cablata');
```

- [x] **Step 2: Move the panel**, wire `#anomStatus` to reload within the header window, keep `clearAnomIpFilter()` and the chip working.

- [x] **Step 3: Add the incident link** on each row (icon or the id itself), guarded: render it only when `id` is present.

- [x] **Step 4: Verify**
  - `node tests/js/test_traffico_window.mjs` green; python tests green.
  - Browser: the anomaly count changes when the header window changes; clicking through lands on the right incident detail.
  - Commit: `fix(traffico): le anomalie seguono la finestra del tab e portano all'incidente`

---

### Task 5: Home stops keeping its own anomaly list

> **Note.** Home also feeds `renderEventStrip()` from the same response, so the fetch stays
> (one call, `status=all&limit=100`): the strip takes the five most recent rows, the summary
> counts the ones still in `new`. The four column-header i18n keys died with the table.

**Files:**
- Modify: `templates/dashboard.html` (`#homeAnomBody` block)
- Modify: the Home renderer that fills it (find with `grep -n homeAnomBody static/js/*.js`)

**Interfaces:**
- `#homeAnomBody` is replaced by a summary line + deep link: `switchTab('tab-flows')` then `trafSwitchView('anomalies')`, status filter preset to `new`
- The count still comes from `/api/observability/anomalies?status=new` — one number, not a table

- [x] **Step 1:** Replace the table with the count + link.
- [x] **Step 2:** Verify the link lands on Traffico with the Anomalie pill active and the status filter on `Nuove`.
- [x] Commit: `refactor(home): le anomalie si contano qui, si leggono in Traffico`

---

### Task 6: Docs, graph, browser sign-off

> **Cosa ha trovato la verifica a browser** (tre difetti che ne' i test ne' due
> revisioni statiche avevano visto):
> 1. `Aggiorna` e `Analizza con AI` occupavano tutta la larghezza — `.btn` e'
>    `width:100%` in questo design system se il chiamante non dice altro.
> 2. `#flowSiemScopeNote` compariva vuota con zero tenant selezionati: il ramo
>    "non filtrato" scattava anche a selezione vuota.
> 3. Il titolo diceva ancora "Flussi Live (Top Talker)" su un tab con quattro
>    viste — e il fallback EN nel markup lo avrebbe mostrato al caricamento
>    prima di applyI18n().
>
> Istanza usa e getta su porta 8000 con `SENTINELNET_DATA_DIR` in una cartella
> temporanea: il `data/` reale non e' stato toccato.

The docs name element ids that this plan deletes. They go stale the moment Task 5 lands, so they are part of the work, not follow-up.

- [x] **Step 1:** `docs/netsec_troubleshooting_qa_v3.md` §4 — rewrite the "UI Navigation & Operational Workflow" block for Q4.1 with the new pills/panes and the single header; drop `#flowsWindow`, `#flowSiemWindow`, `#flowsTenantBtn`, `#flowSiemTenant` from the ID lists.
- [x] **Step 2:** `docs/ui_tab_overlap_analysis.md` — mark §A3 done with the commit range; update the target-IA table (28 → 27 surfaces once Traffico merges; the other four merges are still open); drop `#flowsWindow`/`#flowSiemWindow` from the eleven-selector list in §B3, which becomes ten.
- [x] **Step 3:** `graphify update .`
- [x] **Step 4:** Browser verification of all four views at desktop and narrow width, both themes. Record what was actually opened — `docs/superpowers/plans/2026-08-10-subnet-scan-discovery.md` closed with browser checks still pending; do not repeat that.
- [x] **Step 5:** `uv run pyrefly check`, full `unittest discover`, both JS test files.
- [x] Commit: `docs(traffico): allinea le guide alla nuova struttura del tab`

---

## Out of scope

Named here so no task quietly grows into them:

- **Global tenant selector** (`docs/ui_tab_overlap_analysis.md` §B3). Traffico gets a tab-local header; the app-wide selector is a separate decision.
- **Deprecating `POST /api/observability/anomalies/{id}/status`**, the legacy alias of `POST /api/incidents/{id}/status`. Real duplication, separate ticket, needs a consumer check first.
- **Shun IP button, ACL/Flowspec injection, JA3/SNI extraction** — deferred by the user in `docs/Improvements`.
- The other four merges (A1 endpoint group, A4 config+audit, A5 map, B2 categories).
