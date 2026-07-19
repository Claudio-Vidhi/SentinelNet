# Config Analyzer Search + Observability Checkbox Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a client-side search filter to Config Analyzer sub-tabs and fix the observability settings checkboxes that always render unchecked.

**Architecture:** Both changes live in `templates/dashboard.html` (single-file frontend). Search = one input in the CA filterbar + a DOM row filter reapplied after every render. Checkbox fix = read the nested keys the API actually returns.

**Tech Stack:** Vanilla JS in dashboard.html, FastAPI backend (unchanged), unittest-as-scripts test files.

## Global Constraints

- UI strings in both `it` and `en` i18n dicts (Italian default).
- Escaping convention: `escapeHtml()` for HTML interpolation.
- Tests run as scripts: `uv run python test_observability_ui.py`.
- Final step after all code changes: rebuild exe with `uv run pyinstaller SentinelNet.spec` (user rule).
- Never delete .patch files if any are produced.

---

### Task 1: Fix observability checkboxes (nested vs flat keys)

**Files:**
- Modify: `templates/dashboard.html:9284-9300` (renderObsSettings)
- Test: `test_observability_ui.py` (append one test)

**Interfaces:**
- Consumes: GET `/api/observability/config` response shape from `data_config.obs_config()`: `{enabled, bind, api_poll_s, ipfix: {enabled, port}, sflow: {...}, syslog: {...}, netflow: {...}}`.
- Produces: nothing consumed by other tasks.

**Root cause:** `renderObsSettings(d)` reads `d[`${l}_enabled`]` and `d[`${l}_port`]` (flat), but the GET endpoint returns `data_config.obs_config()` which nests per-listener config under `d[l]`. Flat keys are always `undefined` → checkboxes unchecked, port inputs empty. Listeners still run because `data_config.py` defaults each listener flag to `True` when master `enabled` is true. Do NOT change the POST payload (flat keys) — the save endpoint expects flat keys and `data_config` reads flat keys from `app_settings.json`. Only the GET-side rendering is wrong.

- [ ] **Step 1: Write the failing test**

Append to `test_observability_ui.py` (follow the file's existing static-scan test style; adjust class placement to match neighbors):

```python
class TestObsSettingsNestedKeys(unittest.TestCase):
    """renderObsSettings deve leggere le chiavi annidate restituite da
    obs_config() (d[l].enabled / d[l].port), non le chiavi piatte."""

    def test_render_reads_nested_listener_keys(self):
        html = open(os.path.join(os.path.dirname(__file__),
                                 "templates", "dashboard.html"),
                    encoding="utf-8").read()
        block = html[html.index("function renderObsSettings"):
                     html.index("async function saveObsSettings")]
        self.assertNotIn("d[`${l}_enabled`]", block)
        self.assertNotIn("d[`${l}_port`]", block)
        self.assertIn("d[l]", block)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python test_observability_ui.py TestObsSettingsNestedKeys -v`
Expected: FAIL (flat keys still present).

- [ ] **Step 3: Fix renderObsSettings**

In `templates/dashboard.html` (~line 9288), inside the `OBS_LISTENERS.map(l => ...)` template, replace the two reads:

```js
const listenerRows = OBS_LISTENERS.map(l => {
    const lc = d[l] || {};
    return `
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
            <label style="display:flex; align-items:center; gap:8px; min-width:120px; cursor:pointer;">
                <input type="checkbox" id="obs_${l}_enabled" ${lc.enabled ? 'checked' : ''}>
                <span style="font-size:13px; text-transform:uppercase;">${l}</span>
            </label>
            <input id="obs_${l}_port" type="number" min="1" max="65535"
                   value="${lc.port != null ? lc.port : ''}"
                   placeholder="${OBS_DEFAULT_PORTS[l]}"
                   style="width:100px; padding:6px 10px; border-radius:8px; border:1px solid var(--border);
                          background:var(--surface-3); color:var(--text); font-family:var(--font-code); font-size:12px;">
            <span style="font-size:11px; color:var(--text-muted);">UDP · ${L.hintObsDefaultPort || 'porta predefinita'} ${OBS_DEFAULT_PORTS[l]}</span>
        </div>`;
}).join('');
```

Keep everything else in the function unchanged (master `d.enabled`, `d.bind`, `d.api_poll_s` are already top-level and correct).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python test_observability_ui.py TestObsSettingsNestedKeys -v`
Expected: PASS. Also run the whole file: `uv run python test_observability_ui.py` — all pass.

- [ ] **Step 5: Commit**

```bash
git add templates/dashboard.html test_observability_ui.py
git commit -m "fix(observability): settings checkboxes read nested obs_config keys"
```

---

### Task 2: Search input for Config Analyzer sub-tabs

**Files:**
- Modify: `templates/dashboard.html:2088-2095` (filterbar), `templates/dashboard.html:10645-10693` (renderCaResults), i18n dicts (`it` block ~line 3127 area, `en` block ~line 3876 area)
- Test: `test_ui_revamp.py` (append one test)

**Interfaces:**
- Consumes: existing `renderCaResults()` — the single render entry point for every CA view (home, vlan, routing, acl, iface, validation, firewall incl. its sub-tabs, convert). Firewall sub-tab switches also route through it.
- Produces: global `caApplySearch()`; input `#caSearch`.

**Design:** One search box in the CA filterbar filters rendered `<tbody>` rows by substring (case-insensitive, matches any cell text) and hides `<details>` device blocks whose visible row count drops to zero. Purely DOM-side: works identically on every sub-tab with zero per-view code. Reapplied after each render so the filter survives tab/pill switches. Home and Convert views have no data tables — the filter is simply a no-op there; hide the input on those views to avoid confusion.

- [ ] **Step 1: Write the failing test**

Append to `test_ui_revamp.py` (match the file's static-scan style):

```python
class TestCaSearch(unittest.TestCase):
    """Il Config Analyzer deve avere una ricerca client-side (#caSearch)
    riapplicata dopo ogni render (caApplySearch)."""

    def test_search_input_and_filter_present(self):
        html = open(os.path.join(os.path.dirname(__file__),
                                 "templates", "dashboard.html"),
                    encoding="utf-8").read()
        self.assertIn('id="caSearch"', html)
        self.assertIn("function caApplySearch", html)
        # riapplicata a ogni render
        block = html[html.index("function renderCaResults"):]
        self.assertIn("caApplySearch()", block[:200])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python test_ui_revamp.py TestCaSearch -v`
Expected: FAIL (`#caSearch` not found).

- [ ] **Step 3: Add the input to the filterbar**

In `templates/dashboard.html` ~line 2088, inside the right-hand `<div style="display:flex; gap:8px; ...">`, BEFORE the `<select id="configGroupSelect">`:

```html
<input id="caSearch" type="text" oninput="caApplySearch()"
       data-i18n-placeholder="phCaSearch" placeholder="Cerca..."
       style="padding:6px 12px; border-radius:8px; border:1px solid var(--border); background:var(--surface-2); color:var(--text); font-size:13px; outline:none; width:180px;">
```

Note: check how the codebase translates placeholders (grep `data-i18n-placeholder` in dashboard.html). If that attribute convention doesn't exist, set the placeholder in `renderCaResults`/`loadConfigAnalyzer` via `i18n[currentLang].phCaSearch` instead.

Add i18n keys in BOTH language dicts:
- `it` dict: `phCaSearch: "Cerca nelle tabelle...",`
- `en` dict: `phCaSearch: "Search tables...",`

- [ ] **Step 4: Add caApplySearch and wire into renderCaResults**

Add near `renderCaResults` (~line 10645):

```js
function caApplySearch() {
    const inp = document.getElementById('caSearch');
    if (!inp) return;
    // Home e Converti non hanno tabelle dati: input nascosto e filtro no-op.
    const searchable = !['home', 'convert'].includes(caView);
    inp.style.display = searchable ? '' : 'none';
    if (!searchable) return;
    const q = inp.value.trim().toLowerCase();
    document.querySelectorAll('#caResults tbody tr').forEach(tr => {
        tr.style.display = (!q || tr.textContent.toLowerCase().includes(q)) ? '' : 'none';
    });
    document.querySelectorAll('#caResults details.mac-switch').forEach(det => {
        const rows = det.querySelectorAll('tbody tr');
        const anyVisible = !q || !rows.length ||
            Array.from(rows).some(r => r.style.display !== 'none');
        det.style.display = anyVisible ? '' : 'none';
        if (q && anyVisible && rows.length) det.open = true;
    });
}
```

Wire it so it runs after EVERY render path: rename the existing `renderCaResults` to `caRenderResultsInner`, then add:

```js
function renderCaResults() {
    caRenderResultsInner();
    caApplySearch();
}
```

(This covers all early `return` branches — home, convert, firewall, validation — without touching each one. `caSwitchView` and firewall sub-tab switches already call `renderCaResults`, so the filter persists across pills.)

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run python test_ui_revamp.py TestCaSearch -v`
Expected: PASS. Then full file: `uv run python test_ui_revamp.py` — all pass.

- [ ] **Step 6: Manual smoke check**

Run the app, open Config Analyzer → Firewall → Objects (the view in the user's screenshot), type "microsoft" in the search box: only fqdn address rows containing "microsoft" remain; other devices' blocks collapse/hide. Switch to VLAN pill: filter reapplies. Switch to Home: input hidden.

- [ ] **Step 7: Commit**

```bash
git add templates/dashboard.html test_ui_revamp.py
git commit -m "feat(analyzer): client-side search filter across Config Analyzer sub-tabs"
```

---

### Task 3: Rebuild exe

**Files:** none (build artifact only).

- [ ] **Step 1: Rebuild**

Run: `uv run pyinstaller SentinelNet.spec`
Expected: build completes, `dist/SentinelNet/SentinelNet.exe` updated.

- [ ] **Step 2: Commit** — nothing to commit (build output not tracked); skip if `git status` clean.
