# Endpoint Tab Merge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge the four `Localizzazione Endpoint` subtabs into one `#tab-endpoint` with a pill bar, one header, and one tenant selector — moving markup rather than rewriting it.

**Architecture:** Copy the Traffico pattern (`#trafPill-*` / `#trafPane-*` / `trafSwitchView()`, landed in `942632b`..`f1f40ca`). A single `#tab-endpoint` `.tab-content` holds one hero, one `#locTenant` select, a four-button pill bar, and four `.loc-pane` divs receiving today's markup verbatim. The four old `.tab-content` divs disappear. Lazy loading moves from tab-open to first-pill-activation.

**Tech Stack:** Jinja2 template (`templates/dashboard.html`), vanilla JS modules under `static/js/`, `unittest` structure tests reading the template as text, node for DOM-level checks.

**Spec:** `docs/superpowers/specs/2026-08-12-endpoint-tab-merge-design.md`

## Global Constraints

- Example data only: `192.0.2.x` / `198.51.100.x` (RFC 5737), `aa:bb:cc:...` (RFC 7042), `switch-01`. Never a real hostname, model, version or IP — `CLAUDE.md` §"Protect real data".
- Code comments in English (`CLAUDE.md` §Coding Style). User-facing strings go through `static/js/i18n.js` in both `it` and `en`.
- No feature flags, no backwards-compatibility shims — with exactly one declared exception: the `allowed_tabs` read-time alias in Task 4, because that data is owned by the user, not the code.
- `users.json` is never written by this work.
- Before every commit: `uv run pyrefly check` (0 errors), `uv run python -m unittest discover -s tests` (all green), `graphify update .`.
- Escaping: values in HTML text use `escapeHtml(x)`; only values inside an `on*="fn('…')"` JS string use `escapeHtml(jsStr(x))` (see `c7d40a1`).

---

### Task 1: The shell — pill bar, four empty panes, one header

**Files:**
- Modify: `templates/dashboard.html:235` (nav item), and insert the new `#tab-endpoint` block immediately before `templates/dashboard.html:1034`
- Modify: `static/js/client-map.js` (add `locSwitchView`, top of file)
- Test: `tests/test_endpoint_tab.py` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `locSwitchView(view)` where `view` ∈ `'mac' | 'clientmap' | 'diagnosi' | 'inventory'`; DOM ids `#tab-endpoint`, `#locTenant`, `#locPill-<view>`, `#locPane-<view>`; module-level `let _locView = 'mac'`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_endpoint_tab.py`:

```python
# -*- coding: utf-8 -*-
"""The endpoint group is one tab with four pills, not four twin tabs.

Structure is asserted here, not appearance: that the pills and panes exist,
that the replaced controls are really gone (an orphaned control stays
clickable and drives a filter nobody reads any more), and that a saved
tab permission still resolves to the merged tab.
"""

import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR",
                      tempfile.mkdtemp(prefix="sentinelnet_endpoint_"))

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

VIEWS = ("mac", "clientmap", "diagnosi", "inventory")


def _read(*parts):
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class TestEndpointShell(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "client-map.js")

    def test_the_tab_exists(self):
        self.assertIn('<div id="tab-endpoint" class="tab-content">', self.html)

    def test_pills_and_panes_exist(self):
        for v in VIEWS:
            self.assertIn(f'id="locPill-{v}"', self.html)
            self.assertIn(f'id="locPane-{v}"', self.html)

    def test_pills_are_wired_to_the_switcher(self):
        for v in VIEWS:
            self.assertIn(f"locSwitchView('{v}')", self.html)
        self.assertIn("function locSwitchView", self.js)

    def test_one_tenant_select_in_the_header(self):
        self.assertIn('id="locTenant"', self.html)

    def test_the_nav_item_points_at_the_merged_tab(self):
        self.assertIn('data-tabs="tab-endpoint"', self.html)
        self.assertIn("switchTab('tab-endpoint', this)", self.html)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_endpoint_tab -v`
Expected: 5 failures, all `AssertionError` on missing ids.

- [ ] **Step 3: Add the shell markup**

Replace `templates/dashboard.html:235-237` (the nav item) with:

```html
        <button class="nav-item" data-tabs="tab-endpoint" onclick="switchTab('tab-endpoint', this)">
          <span class="nav-left" data-i18n="tabEndpointLoc"><i class="fa-solid fa-map-pin"></i> Localizzazione Endpoint</span>
        </button>
```

Insert immediately before line `1034` (`<div id="tab-mac" class="tab-content">`):

```html
    <div id="tab-endpoint" class="tab-content">
      <div class="hero" style="grid-template-columns:1fr; margin-bottom:18px;">
        <div class="hero-card">
          <h2 id="locTitle" style="margin:0 0 10px; font-family:var(--font-display); font-size:25px; letter-spacing:-.03em;" data-i18n="titleMacTracker">MAC Address Tracker</h2>
          <p id="locDesc" style="margin:0; color:var(--text-muted); font-size:14px; line-height:1.55; max-width:64ch;" data-i18n="descMacTracker"></p>
        </div>
      </div>

      <div class="filterbar" style="align-items:center; gap:10px; margin-bottom:14px;">
        <span style="font-size:12px; color:var(--text-muted);" data-i18n="locTenantLabel">Tenant</span>
        <select id="locTenant" onchange="locTenantChanged()" style="padding:6px 12px; border-radius:0; border:1px solid var(--border); background:var(--surface-2); color:var(--text); font-size:13px; cursor:pointer; outline:none;"></select>
      </div>

      <div id="locPills" style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px;">
        <button type="button" class="ca-pill active" id="locPill-mac" onclick="locSwitchView('mac')" data-i18n="tabMacTracker">Tracker MAC</button>
        <button type="button" class="ca-pill" id="locPill-clientmap" onclick="locSwitchView('clientmap')" data-i18n="tabClientMap">Client Map</button>
        <button type="button" class="ca-pill" id="locPill-diagnosi" onclick="locSwitchView('diagnosi')" data-i18n="tabDiagnosi">Diagnosi Client</button>
        <button type="button" class="ca-pill" id="locPill-inventory" onclick="locSwitchView('inventory')" data-i18n="tabEndpoints">Endpoint Inventory</button>
      </div>

      <div id="locPane-mac" class="loc-pane"></div>
      <div id="locPane-clientmap" class="loc-pane" style="display:none;"></div>
      <div id="locPane-diagnosi" class="loc-pane" style="display:none;"></div>
      <div id="locPane-inventory" class="loc-pane" style="display:none;"></div>
    </div>
```

- [ ] **Step 4: Add the switcher**

At the top of `static/js/client-map.js`, after the existing header comment block:

```js
// The endpoint group is one tab with four panes. Each pane loads on its first
// activation, not when the tab opens: opening Endpoint must not fire three
// collections at once.
let _locView = 'mac';
const _locLoaded = { mac: false, clientmap: false, diagnosi: false, inventory: false };

const LOC_LOADERS = {
    mac: () => loadMacTracker(),
    clientmap: () => loadClientMapTab(),
    diagnosi: () => diagnosiTabShown(),
    inventory: () => loadEndpointsTab(),
};

// Title and description belong to the pane, not to four separate heroes.
const LOC_HEADINGS = {
    mac:        ['titleMacTracker', 'descMacTracker'],
    clientmap:  ['titleClientMap', 'descClientMap'],
    diagnosi:   ['titleDiagnosi', 'descDiagnosi'],
    inventory:  ['titleEndpoints', 'descEndpoints'],
};

function locSwitchView(view) {
    if (!document.getElementById('locPane-' + view)) return;
    _locView = view;
    for (const v of ['mac', 'clientmap', 'diagnosi', 'inventory']) {
        const pane = document.getElementById('locPane-' + v);
        const pill = document.getElementById('locPill-' + v);
        if (pane) pane.style.display = (v === view) ? '' : 'none';
        if (pill) pill.classList.toggle('active', v === view);
    }
    const [titleKey, descKey] = LOC_HEADINGS[view];
    const title = document.getElementById('locTitle');
    const desc = document.getElementById('locDesc');
    const L = i18n[currentLang] || {};
    if (title) { title.setAttribute('data-i18n', titleKey); title.textContent = L[titleKey] || ''; }
    if (desc) { desc.setAttribute('data-i18n', descKey); desc.textContent = L[descKey] || ''; }
    if (!_locLoaded[view]) {
        _locLoaded[view] = true;
        LOC_LOADERS[view]();
    }
}

// Tenant change redraws only the pane on screen; the others redraw when opened.
function locTenantChanged() {
    for (const v of Object.keys(_locLoaded)) _locLoaded[v] = (v === _locView);
    LOC_LOADERS[_locView]();
}
```

- [ ] **Step 5: Add the three missing i18n keys**

`LOC_HEADINGS` names eight keys. Five already exist (`titleMacTracker`,
`descMacTracker`, `titleClientMap`, `descClientMap`, `titleDiagnosi`,
`titleEndpoints`); **`descDiagnosi`, `descEndpoints` and `locTenantLabel` do
not** — the two description-less tabs never had a hero paragraph. Add them to
both language blocks of `static/js/i18n.js`, next to their siblings.

Italian block:

```js
        descDiagnosi: "Referto completo su un client: porta di accesso, VLAN, binding MAC ↔ IP, gateway, percorso e policy attraversate, piu' le azioni sulla porta.",
        descEndpoints: "Elenco persistente dei binding raccolti, con eta' del dato e filtri di staleness: cosa e' stato visto, dove, e quanto tempo fa.",
        locTenantLabel: "Tenant",
```

English block:

```js
        descDiagnosi: "Full report on one client: access port, VLAN, MAC ↔ IP binding, gateway, path and policies crossed, plus the port actions.",
        descEndpoints: "Persistent list of collected bindings, with data age and staleness filters: what was seen, where, and how long ago.",
        locTenantLabel: "Tenant",
```

- [ ] **Step 6: Run test to verify it passes**

Run: `uv run python -m unittest tests.test_endpoint_tab -v`
Expected: 5 passed.

- [ ] **Step 7: Commit**

```bash
git add templates/dashboard.html static/js/client-map.js static/js/i18n.js tests/test_endpoint_tab.py
git commit -m "feat(endpoint): la testata e le quattro pill, ancora senza contenuto"
```

---

### Task 2: Move the four tabs' content into the panes

**Files:**
- Modify: `templates/dashboard.html` — move the bodies of `#tab-mac` (1034), `#tab-clientmap` (1160), `#tab-diagnosi` (1367), `#tab-endpoints` (1426) into the four `#locPane-*` divs, then delete the four old `.tab-content` wrappers
- Test: `tests/test_endpoint_tab.py` (extend)

**Interfaces:**
- Consumes: `#locPane-*` from Task 1.
- Produces: no new symbols. All inner ids (`#macScanGroup`, `#arpTenantMenu`, `#epFilterTenant`, `#diagClientInput`, `#kpiMacSightings`, …) keep their names and now live inside a pane.

**Move rules — apply to each of the four:**
1. Drop the `<div class="subtab-bar">…</div>` block (the four duplicated bars).
2. Drop the `<div class="hero">…</div>` block (the four duplicated heroes) — Task 1 replaced them with one.
3. Everything else moves verbatim into the matching pane.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_endpoint_tab.py`:

```python
class TestPanesHoldTheContent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")

    def test_the_old_tabs_are_gone(self):
        for old in ("tab-mac", "tab-clientmap", "tab-diagnosi", "tab-endpoints"):
            self.assertNotIn(f'<div id="{old}" class="tab-content">', self.html)

    def test_the_subtab_bar_is_not_duplicated_any_more(self):
        # The bar was copy-pasted into all four tabs; one pill bar replaces it.
        # Do NOT count the 'ti-subtab' class globally: Provisioning, Topologia
        # and Threat Intel share it. Assert instead that no button anywhere
        # still switches to one of the four merged tabs.
        for old in ("tab-mac", "tab-clientmap", "tab-diagnosi", "tab-endpoints"):
            self.assertNotIn(f"switchTab('{old}')", self.html)

    def _pane(self, view):
        start = self.html.index(f'id="locPane-{view}"')
        rest = self.html.find('id="locPane-', start + 1)
        return self.html[start:rest if rest != -1 else len(self.html)]

    def test_each_pane_holds_its_own_panels(self):
        self.assertIn('id="macScanGroup"', self._pane("mac"))
        self.assertIn('id="kpiMacSightings"', self._pane("mac"))
        self.assertIn('id="arpTenantMenu"', self._pane("clientmap"))
        self.assertIn('id="kpiArpBindings"', self._pane("clientmap"))
        self.assertIn('id="diagClientInput"', self._pane("diagnosi"))
        self.assertIn('id="epFilterTenant"', self._pane("inventory"))
```

Note: `_pane` relies on the four panes being adjacent siblings in source order
`mac → clientmap → diagnosi → inventory`, which Task 1 guarantees.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_endpoint_tab.TestPanesHoldTheContent -v`
Expected: FAIL — `tab-mac` div still present, subtab bars still counted.

- [ ] **Step 3: Perform the move**

Work one pane at a time, bottom-up so earlier line numbers stay valid:
`#tab-endpoints` → `#locPane-inventory`, then `#tab-diagnosi` → `#locPane-diagnosi`,
then `#tab-clientmap` → `#locPane-clientmap`, then `#tab-mac` → `#locPane-mac`.

For each: cut the content between the opening `.tab-content` div and its closing `</div>`, remove the subtab bar and hero blocks, paste inside the pane div, delete the now-empty wrapper.

- [ ] **Step 4: Run the tests**

Run: `uv run python -m unittest tests.test_endpoint_tab -v`
Expected: all pass.

Run: `uv run python -m unittest discover -s tests 2>&1 | tail -5`
Expected: failures in `tests/test_ui_revamp.py` naming the old ids — those are fixed in Task 6. Write down which ones.

- [ ] **Step 5: Commit**

```bash
git add templates/dashboard.html tests/test_endpoint_tab.py
git commit -m "feat(endpoint): il contenuto entra nei quattro pane, le quattro barre spariscono"
```

---

### Task 3: One tenant selector

**Files:**
- Modify: `templates/dashboard.html` — delete `#macScanGroup`, `#arpScanGroup`, `#arpTenantMenu` (with `#arpTenantSummary`, `#arpTenantList`), `#epFilterTenant`
- Modify: `static/js/client-map.js` (10 readers), `static/js/endpoint-inventory.js` (3 readers)
- Test: `tests/test_endpoint_tab.py` (extend)

**Interfaces:**
- Consumes: `#locTenant`, `locTenantChanged()` from Task 1.
- Produces: `locTenant()` returning the selected tenant string, `'all'` when nothing is chosen.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_endpoint_tab.py`:

```python
class TestOneTenantSelector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.cm = _read("static", "js", "client-map.js")
        cls.ei = _read("static", "js", "endpoint-inventory.js")

    def test_the_four_old_controls_are_gone(self):
        # An orphaned select stays clickable and filters nothing.
        for old in ("macScanGroup", "arpScanGroup", "arpTenantMenu",
                    "arpTenantSummary", "arpTenantList", "epFilterTenant"):
            self.assertNotIn(f'id="{old}"', self.html)

    def test_nothing_reads_them_any_more(self):
        for old in ("macScanGroup", "arpScanGroup", "arpTenantSummary",
                    "arpTenantList", "epFilterTenant"):
            self.assertNotIn(old, self.cm, f"{old} still read in client-map.js")
            self.assertNotIn(old, self.ei, f"{old} still read in endpoint-inventory.js")

    def test_the_accessor_exists(self):
        self.assertIn("function locTenant(", self.cm)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_endpoint_tab.TestOneTenantSelector -v`
Expected: 3 failures.

- [ ] **Step 3: Add the accessor and rewire**

In `static/js/client-map.js`, next to `locSwitchView`:

```js
// One tenant for the whole group. Empty select means "every tenant in scope".
function locTenant() {
    const el = document.getElementById('locTenant');
    return (el && el.value) || 'all';
}
```

Then replace every reader. Find them with:

```bash
grep -rn "macScanGroup\|arpScanGroup\|arpTenantMenu\|arpTenantList\|arpTenantSummary\|epFilterTenant" static/js/
```

Expected 13 hits: 10 in `client-map.js` (including `val('macScanGroup')` at :189, `g('macScanGroup')` at :228, `fillGroupSel('arpScanGroup', …)` at :262, `arpFilteredDevices('arpScanGroup')` at :283) and 3 in `endpoint-inventory.js`. Each becomes a call to `locTenant()`.

`#arpTenantMenu` was a multi-select feeding a list of tenants; it collapses to `[locTenant()]` — the single-tenant array. This is the accepted behaviour loss recorded in the spec.

`#locTenant` is populated where the old selects were filled (`fillGroupSel`): populate it once when the tab first opens.

- [ ] **Step 4: Run the tests**

Run: `uv run python -m unittest tests.test_endpoint_tab -v`
Expected: all pass.
Run: `node --check static/js/client-map.js && node --check static/js/endpoint-inventory.js`
Expected: silent (syntax OK).

- [ ] **Step 5: Commit**

```bash
git add templates/dashboard.html static/js/client-map.js static/js/endpoint-inventory.js tests/test_endpoint_tab.py
git commit -m "feat(endpoint): un solo selettore di tenant per tutto il gruppo"
```

---

### Task 4: Entry points and the saved tab permission

**Files:**
- Modify: `static/js/core.js:731` (tab dispatch), `static/js/core.js:538-544` (`applyRoleUI`)
- Modify: `static/js/diagnosi.js:82`, `static/js/endpoint-inventory.js:212`
- Modify: `static/js/settings.js:181` (`ASSIGNABLE_TABS`)
- Test: `tests/js/test_loc_permission.mjs` (create), `tests/test_endpoint_tab.py` (extend)

**Interfaces:**
- Consumes: `locSwitchView(view)` from Task 1.
- Produces: `normalizeAllowedTabs(tabs)` → `string[]`.

**This is the task that can break something silently.** `allowed_tabs` lives in
`users.json` (`security/user_manager.py:171`) and `applyRoleUI` matches it against
the id inside the nav item's `onclick`. Rename the tab, and every non-admin
holding `tab-mac` loses the whole group with no error.

- [ ] **Step 1: Write the failing test**

Create `tests/js/test_loc_permission.mjs`:

```js
// A saved permission naming the old tab must still reveal the merged tab.
// This is the one silent regression the merge can cause: no error, the nav
// item simply stops rendering for every non-admin who had 'tab-mac'.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../../static/js/core.js', import.meta.url), 'utf8');
const start = src.indexOf('function normalizeAllowedTabs');
assert.ok(start !== -1, 'normalizeAllowedTabs missing from core.js');
const body = src.slice(start, src.indexOf('\n}', start) + 2);
const normalizeAllowedTabs = new Function(body + '; return normalizeAllowedTabs;')();

// Legacy permission -> merged tab.
assert.deepStrictEqual(normalizeAllowedTabs(['tab-mac']), ['tab-endpoint']);
// New permission passes through.
assert.deepStrictEqual(normalizeAllowedTabs(['tab-endpoint']), ['tab-endpoint']);
// Unrelated permissions untouched, and no duplicate appears.
assert.deepStrictEqual(
    normalizeAllowedTabs(['tab-devices', 'tab-mac', 'tab-endpoint']).sort(),
    ['tab-devices', 'tab-endpoint']);
// Empty means "all tabs" and must stay empty.
assert.deepStrictEqual(normalizeAllowedTabs([]), []);

console.log('ok - legacy tab-mac permission still resolves');
```

Append to `tests/test_endpoint_tab.py` (add `import shutil` and `import subprocess` at the top of the file):

```python
class TestEntryPoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = _read("static", "js", "core.js")
        cls.settings = _read("static", "js", "settings.js")

    def test_no_entry_point_names_the_old_tabs(self):
        for src, name in ((_read("static", "js", "diagnosi.js"), "diagnosi.js"),
                          (_read("static", "js", "endpoint-inventory.js"), "endpoint-inventory.js"),
                          (self.core, "core.js")):
            self.assertNotIn("switchTab('tab-diagnosi')", src, name)
            self.assertNotIn("tabId === 'tab-mac'", src, name)

    def test_assignable_tabs_offers_the_merged_tab(self):
        self.assertIn("{ id: 'tab-endpoint', key: 'tabEndpointLoc' }", self.settings)
        self.assertNotIn("{ id: 'tab-mac'", self.settings)

    @unittest.skipUnless(shutil.which("node"), "node non disponibile")
    def test_a_saved_permission_still_resolves(self):
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_loc_permission.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node tests/js/test_loc_permission.mjs`
Expected: FAIL — `normalizeAllowedTabs missing from core.js`.

- [ ] **Step 3: Implement**

In `static/js/core.js`, above `applyRoleUI`:

```js
// Tab permissions are stored per user in users.json and predate the endpoint
// merge, where four tabs became one. A saved 'tab-mac' must keep revealing the
// group, so the old id is aliased on READ. The stored file is never rewritten:
// it is the user's data, not ours.
function normalizeAllowedTabs(tabs) {
    if (!Array.isArray(tabs) || tabs.length === 0) return [];
    const LEGACY = { 'tab-mac': 'tab-endpoint', 'tab-clientmap': 'tab-endpoint',
                     'tab-diagnosi': 'tab-endpoint', 'tab-endpoints': 'tab-endpoint' };
    return [...new Set(tabs.map(t => LEGACY[t] || t))];
}
```

In `applyRoleUI`, replace the guard:

```js
    const allowed = normalizeAllowedTabs(allowedTabs);
    if (allowed.length > 0) {
        document.querySelectorAll('.nav-item').forEach(btn => {
            const m = btn.getAttribute('onclick').match(/switchTab\('([^']+)'/);
            const tabId = m && m[1];
            if (tabId && !allowed.includes(tabId)) btn.style.display = 'none';
        });
    }
```

`static/js/core.js:731` — replace the dispatch line:

```js
    else if (tabId === 'tab-endpoint') locSwitchView(_locView);
```

`static/js/diagnosi.js:82` and `static/js/endpoint-inventory.js:212` — replace
`switchTab('tab-diagnosi');` with:

```js
    switchTab('tab-endpoint');
    locSwitchView('diagnosi');
```

`static/js/settings.js:181` — replace the entry:

```js
        { id: 'tab-endpoint', key: 'tabEndpointLoc' },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node tests/js/test_loc_permission.mjs`
Expected: `ok - legacy tab-mac permission still resolves`
Run: `uv run python -m unittest tests.test_endpoint_tab -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add static/js/core.js static/js/diagnosi.js static/js/endpoint-inventory.js static/js/settings.js tests/js/test_loc_permission.mjs tests/test_endpoint_tab.py
git commit -m "feat(endpoint): i punti d'ingresso, e il permesso salvato che non deve sparire"
```

---

### Task 5: The two counters stop sharing a name

**Files:**
- Modify: `static/js/i18n.js:193` (`macKpiUniqueLabel`, it), `:213` (`arpKpiUniqueLabel`, it), `:1571` (en), `:1591` (en)
- Test: `tests/test_endpoint_tab.py` (extend)

**Interfaces:**
- Consumes: nothing. Produces: nothing. Four string values change.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_endpoint_tab.py`:

```python
class TestTheTwoCountersAreDistinguishable(unittest.TestCase):
    """Both counters were labelled 'MAC Univoci' and both were correct: one
    counts MACs seen in switch MAC tables, the other MACs with a known ARP
    binding. The merge puts them in different panes, which hides the clash
    instead of resolving it."""

    def test_the_labels_differ_in_both_languages(self):
        src = _read("static", "js", "i18n.js")
        for line in src.splitlines():
            if "macKpiUniqueLabel" in line or "arpKpiUniqueLabel" in line:
                self.assertNotIn("MAC Univoci", line)
                self.assertNotIn("Unique MACs", line)
        self.assertIn("MAC visti sugli switch", src)
        self.assertIn("MACs seen on switches", src)
        self.assertIn("MAC con un IP noto", src)
        self.assertIn("MACs with a known IP", src)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_endpoint_tab.TestTheTwoCountersAreDistinguishable -v`
Expected: FAIL — both labels still read `MAC Univoci`.

- [ ] **Step 3: Change the four strings**

`static/js/i18n.js`, Italian block:

```js
        macKpiUniqueLabel: "MAC visti sugli switch",
```
```js
        arpKpiUniqueLabel: "MAC con un IP noto",
```

English block:

```js
        macKpiUniqueLabel: "MACs seen on switches",
```
```js
        arpKpiUniqueLabel: "MACs with a known IP",
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m unittest tests.test_endpoint_tab -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add static/js/i18n.js tests/test_endpoint_tab.py
git commit -m "fix(endpoint): due contatori diversi smettono di chiamarsi allo stesso modo"
```

---

### Task 6: Fix the tests that named the old ids, then verify for real

**Files:**
- Modify: `tests/test_ui_revamp.py` (assertions naming `tab-mac` / `tab-clientmap` / `tab-diagnosi` / `tab-endpoints`)
- Modify: any other test naming the old ids
- Modify: `docs/ui_tab_overlap_analysis.md` §A1, `docs/netsec_troubleshooting_qa_v3.md` §4

- [ ] **Step 1: Find every stale assertion**

```bash
grep -rn "tab-mac\|tab-clientmap\|tab-diagnosi\|tab-endpoints" tests/
```

Update each to the merged id plus pill, matching what Task 4 changed.

- [ ] **Step 2: Run the full suite**

Run: `uv run pyrefly check`
Expected: 0 errors.
Run: `uv run python -m unittest discover -s tests 2>&1 | grep -E "^(OK|FAILED|Ran )"`
Expected: `OK`.

- [ ] **Step 3: Browser check**

Start a throwaway instance — scratch `SENTINELNET_DATA_DIR`, throwaway admin with
a random password, plain HTTP on `127.0.0.1`. Never the real data dir, and never
write to the real `users.json`.

Confirm, on the running page:
1. All four pills open their pane; only one pane is visible at a time.
2. Opening the tab fires **one** collection, not three (watch the network panel).
3. Changing `#locTenant` redraws the open pane.
4. `diagnoseClientInTab('192.0.2.50')` from the Client Map pane lands on the Diagnosi pill with the field filled.
5. Console has no errors beyond the known login-page a11y advisories.

Static assets are cached hard by Chrome — load the page in a fresh isolated
context, or a stale script will make a correct fix look broken.

- [ ] **Step 4: Mark the analysis DONE**

In `docs/ui_tab_overlap_analysis.md`, retitle §A1 the way §A3 was:

```markdown
### A1. Localizzazione Endpoint: 4 subtabs → 1 tab with pills — **DONE** (2026-08-12, `<first>`..`<last>`)
```

Add a line recording what stayed out: the Ricerca/Raccolta re-cut and §A2, each
with the reason from the spec.

In `docs/netsec_troubleshooting_qa_v3.md` §4, replace the four old tab ids with
`#tab-endpoint` and the four pill ids.

- [ ] **Step 5: Update the graph and commit**

```bash
graphify update .
git add tests/ docs/
git commit -m "docs(endpoint): §A1 chiusa, e le guide non nominano piu' i quattro tab"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
| :--- | :--- |
| Struttura target (`#tab-endpoint`, `loc*` prefix) | 1 |
| Chi ridisegna cosa (tenant → open pane; pill → that pane; lazy load) | 1 (`locSwitchView`, `locTenantChanged`), verified in 6 |
| Mappatura elemento per elemento (4 panes, 4 bars, 4 heroes) | 2 |
| Un solo selettore di tenant; `#arpTenantMenu` collassa | 3 |
| Punti d'ingresso (4 call sites) | 4 |
| Il permesso salvato (`allowed_tabs`, `applyRoleUI`, `ASSIGNABLE_TABS`) | 4 |
| Etichette KPI, it + en | 5 |
| Test + verifica a browser + docs | 6 |
| Fuori perimetro (Ricerca, Raccolta, §A2) | none — recorded in Task 6 Step 4 |

No gaps.

**Type consistency:** `locSwitchView(view)`, `locTenant()`, `locTenantChanged()`,
`normalizeAllowedTabs(tabs)`, `_locView`, `_locLoaded`, `LOC_LOADERS`,
`LOC_HEADINGS` are spelled identically in Tasks 1, 3, 4 and 6. Views are
`mac | clientmap | diagnosi | inventory` everywhere — note the pane is
`inventory` while the old tab was `tab-endpoints`, deliberately, so that no new
id reads as an old one.

**Assumptions checked against the tree before this plan was committed:**

- `client-map.js` already reads i18n as `i18n[currentLang]` (`:95`, `:252`,
  `:282`) — Task 1's block matches it and introduces no helper.
- `.ca-pill` exists in `static/css/dashboard.css`; `.ca-pillbar` does **not** —
  Traffico's bar is a plain `<div id="trafPills">` with inline flex, so the
  endpoint bar is `<div id="locPills">` the same way.
- Of the eight `LOC_HEADINGS` keys, `descDiagnosi` and `descEndpoints` did not
  exist, and neither did `locTenantLabel`. Task 1 Step 5 adds all three in both
  languages. Without that step the merged hero would render two blank
  descriptions.
