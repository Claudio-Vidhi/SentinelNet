# Endpoint Location Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the "Localizzazione Endpoint" tab as one search + right-side
endpoint drawer + four underline sub-tabs (Endpoint, Porte, Diagnosi,
Raccolta), with site-grouped multi-select device pickers for collection.

**Architecture:** Frontend-only restructure of `#tab-endpoint` in
`templates/dashboard.html`, driven by the three existing classic-script
modules (`client-map.js` = shell + Raccolta, `endpoint-inventory.js` =
Endpoint + drawer + Porte, `diagnosi.js` = Diagnosi). One backend change: the
endpoint inventory's free-text `q` also matches a full IP through the ARP
table. Existing endpoints, renderers and helpers are reused; the old MAC
search, locate modal, inline detail row, inventory "ports" mode and separate
port-errors pane go away.

**Tech Stack:** FastAPI + SQLite (`collectors/mac_history.py`), classic
browser scripts sharing one global scope (no bundler), `unittest`-style tests
run by pytest, Node `.mjs` harnesses wrapped by Python tests.

**Spec:** `docs/superpowers/specs/2026-10-14-endpoint-location-redesign-design.md`
(read it first). The clickable prototype the user approved is at
https://claude.ai/artifact/XieVwSmpkYeuVNT7NgQJyD — it is the visual target,
not code to copy.

## Global Constraints

- Repo is PUBLIC: example data only — `192.0.2.x` / `198.51.100.x` /
  `203.0.113.x`, `aa:bb:cc:dd:ee:xx`, `switch-01`, `sede-a`. Never a real value.
- New comments in English; leave existing Italian comments alone.
- No inline handlers (`onclick=`), no inline `style=` in new markup; ids +
  delegated listeners.
- Every user-facing string through `tr('key')` / `data-i18n`, key present in
  BOTH `it` and `en` blocks of `static/js/i18n.js`. No `currentLang === 'en' ? … : …`.
- Every new form control has a `<label for>` or `aria-label` +
  `data-i18n-aria-label`.
- Modals only through `openModal(id[, onClose])` / `closeModal(id)`.
- `core.js` globals (`globalDevices`, `globalLocations`, …) are `let`: read them
  bare, never as `window.X`.
- A delegated listener binds to an id that exists in `dashboard.html`.
- Write actions keep their role classes: scans `requires-write`, retention
  `requires-admin`.
- Do not bump the version: `scripts/release.py` does it at release time. Add a
  CHANGELOG entry under `## [Unreleased]` instead.
- Gates before every commit that touches the matching files:
  `uv run pyrefly check` (0 errors), `uv run python scripts/check_frontend.py`,
  `uv run pytest tests -n 4`, `uv run python scripts/check_no_private_data.py`.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Branch: work on `Dev`. Never push.

## Review Focus

1. **Tenant change while the drawer is open** — the drawer belongs to an
   endpoint of the old tenant; it must close on `locTenantChanged()`, not keep
   showing data the new scope may not include. Pinned in Task 4.
2. **Empty device selection** — the old picker sent "no ips" meaning ALL
   devices. The new picker must never turn "nothing ticked" into "scan
   everything"; the run is refused with a message. Pinned in Task 2 + Task 8.
3. **IP search on a reassigned address** — two MACs that held the same IP both
   match; the search must return both (two rows), never pick one silently.
   Pinned in Task 1.
4. **Devices without a site** (`Location` empty) — they must appear in the
   picker under "Senza sede", not vanish. Pinned in Task 2.
5. **Drawer opened at narrow width** — goes through `openModal`, so Esc and the
   backdrop close it and focus returns to the row; at wide width Esc closes it
   too. Pinned in Task 4 (static harness) and the manual check in Task 9.

---

## File map

| File | Responsibility after this plan |
|---|---|
| `collectors/mac_history.py` | `endpoint_inventory()` matches `q` as a full IP via `arp_entries`. |
| `templates/dashboard.html` | New `#tab-endpoint` markup: page-head, search, tablist, panes, drawer host. |
| `static/css/dashboard.css` | One endpoint-location block scoped to `#tab-endpoint`. |
| `static/js/client-map.js` | Shell (`locSwitchView`, tabs, `Raccogli ora`), Raccolta view, device picker. |
| `static/js/endpoint-inventory.js` | Endpoint view, search, drawer, Porte view. |
| `static/js/diagnosi.js` | Unchanged logic; ids kept. |
| `static/js/core.js` | Palette entries open `raccolta`. |
| `static/js/i18n.js` | New keys (both languages). |
| `tests/test_endpoint_inventory.py` | IP search tests; pane-id assertions updated. |
| `tests/test_endpoint_tab.py` | Rewritten structural tests for the new shell. |
| `tests/test_ui_revamp.py` | Old-id lists updated. |
| `tests/js/test_device_picker.mjs` + `tests/test_device_picker.py` | Picker pure logic. |
| `tests/js/test_endpoint_inventory_ui.mjs` | Rewritten for drawer/Porte. |

---

### Task 1: IP search in the endpoint inventory

**Files:**
- Modify: `collectors/mac_history.py` (`endpoint_inventory`, the `if q:` block near line 897)
- Test: `tests/test_endpoint_inventory.py`

**Interfaces:**
- Produces: `GET /api/endpoints/list?q=192.0.2.10` returns the endpoints whose
  MAC ever had that IP in `arp_entries` of the visible tenants. Partial IPs
  keep the old `LIKE` behaviour.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_endpoint_inventory.py`, in the class that holds
`test_ricerca_libera_su_mac_e_vendor` (it inherits `_Base`, whose `_sighting`
and `_arp` helpers insert rows):

```python
    def test_search_by_full_ip_goes_through_arp(self):
        self._sighting(mac=MAC_A)
        self._sighting(mac=MAC_VM, switch_ip="192.0.2.2")
        self._arp(mac=MAC_A, ip="192.0.2.10")

        out = mac_history.endpoint_inventory(q="192.0.2.10")

        self.assertEqual([r["mac"] for r in out["results"]], [MAC_A])

    def test_search_by_unknown_ip_finds_nothing(self):
        self._sighting(mac=MAC_A)
        self._arp(mac=MAC_A, ip="192.0.2.10")

        self.assertEqual(mac_history.endpoint_inventory(q="192.0.2.99")["total"], 0)

    def test_search_by_ip_returns_every_mac_that_held_it(self):
        # An address handed to a new device: both owners are facts, the
        # search must not pick one.
        self._sighting(mac=MAC_A)
        self._sighting(mac=MAC_VM, switch_ip="192.0.2.2")
        self._arp(mac=MAC_A, ip="192.0.2.10", last_days=5)
        self._arp(mac=MAC_VM, ip="192.0.2.10", source_ip="192.0.2.253")

        out = mac_history.endpoint_inventory(q="192.0.2.10")

        self.assertEqual({r["mac"] for r in out["results"]}, {MAC_A, MAC_VM})

    def test_search_by_ip_respects_the_tenant_scope(self):
        self._sighting(mac=MAC_A, tenant="sede-a")
        self._arp(mac=MAC_A, ip="192.0.2.10", tenant="sede-a")

        out = mac_history.endpoint_inventory(tenants=["sede-b"], q="192.0.2.10")

        self.assertEqual(out["total"], 0)

    def test_partial_ip_keeps_the_text_search(self):
        self._sighting(mac=MAC_A)
        self._arp(mac=MAC_A, ip="192.0.2.10")

        # "192.0.2" is not an address: it falls back to the LIKE search,
        # which does not look at IPs.
        self.assertEqual(mac_history.endpoint_inventory(q="192.0.2")["total"], 0)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_endpoint_inventory.py -k "search_by or partial_ip" -v`
Expected: `test_search_by_full_ip_goes_through_arp` and
`test_search_by_ip_returns_every_mac_that_held_it` FAIL (total 0);
the others may pass already.

- [ ] **Step 3: Implement**

In `collectors/mac_history.py`, make sure `import ipaddress` is at the top with
the other imports. Replace the `if q:` block inside `endpoint_inventory` with:

```python
    if q:
        try:
            ipaddress.ip_address(q)
            is_ip = True
        except ValueError:
            is_ip = False
        if is_ip:
            # The IP lives in arp_entries, joined after this query: resolve it
            # to MACs first, in the same tenant scope.
            arp_sql, arp_args = "SELECT DISTINCT mac FROM arp_entries WHERE ip = ?", [q]
            if tenant_list is not None:
                arp_sql += " AND tenant IN (%s)" % ",".join("?" * len(tenant_list))
                arp_args.extend(tenant_list)
            with _connect() as c:
                macs = [r[0] for r in c.execute(arp_sql, arp_args).fetchall()]
            if not macs:
                return copy.deepcopy(empty)
            where.append("mac IN (%s)" % ",".join("?" * len(macs)))
            args.extend(macs)
        else:
            where.append("(mac LIKE ? OR oui_vendor LIKE ? OR switch_name LIKE ? "
                         "OR interface LIKE ?)")
            args.extend(["%" + q + "%"] * 4)
```

(`copy` is already imported: the cache uses `copy.deepcopy`.)

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/test_endpoint_inventory.py -v`
Expected: all PASS.

- [ ] **Step 5: Gates and commit**

```bash
uv run pyrefly check
uv run python scripts/check_no_private_data.py
git add collectors/mac_history.py tests/test_endpoint_inventory.py
git commit -m "feat(endpoints): search the inventory by full IP through ARP

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Device picker logic (pure functions)

**Files:**
- Modify: `static/js/client-map.js` (add two top-level functions after `locTenantChanged`)
- Create: `tests/js/test_device_picker.mjs`, `tests/test_device_picker.py`

**Interfaces:**
- Produces:
  - `pickerGroups(devs, sel, labelOf)` → `Array<{key: string, label: string,
    devices: Array<{ip: string, name: string, checked: boolean}>, n: number,
    total: number}>`. `devs` items have `IP`, `Hostname`, `Location`; `sel` is a
    `Set` of IPs; `labelOf(locationId)` returns the site name (`''` id → the
    caller's "no site" label). Groups sorted by label, the `''` group last.
  - `pickerSummary(groups)` → `{kind: 'none'|'all'|'sites'|'partial', n: number,
    total: number, sites: string[]}` where `sites` are labels of the groups with
    at least one checked device.

- [ ] **Step 1: Write the failing harness**

`tests/js/test_device_picker.mjs`:

```js
// Device picker grouping and summary (client-map.js), extracted and run in isolation.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../../static/js/client-map.js', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const fn = name => {
    const start = src.indexOf(`function ${name}(`);
    assert.ok(start >= 0, `missing ${name}`);
    const end = src.indexOf('\n}\n', start) + 2;
    return (0, eval)(`(${src.slice(start, end)})`);
};
const pickerGroups = fn('pickerGroups');
const pickerSummary = fn('pickerSummary');

const devs = [
    { IP: '192.0.2.11', Hostname: 'switch-01', Location: 'loc-a' },
    { IP: '192.0.2.12', Hostname: 'switch-02', Location: 'loc-a' },
    { IP: '198.51.100.13', Hostname: 'switch-03', Location: 'loc-b' },
    { IP: '203.0.113.16', Hostname: '', Location: '' },
];
const label = id => ({ 'loc-a': 'Sede A', 'loc-b': 'Sede B' })[id] || 'Senza sede';

// Grouping: by site, sorted, devices without a site last and not dropped.
let g = pickerGroups(devs, new Set(devs.map(d => d.IP)), label);
assert.deepEqual(g.map(x => x.label), ['Sede A', 'Sede B', 'Senza sede']);
assert.deepEqual(g.map(x => [x.n, x.total]), [[2, 2], [1, 1], [1, 1]]);
assert.equal(g[2].devices[0].name, '203.0.113.16', 'no hostname: the IP is the name');
assert.deepEqual(pickerSummary(g), { kind: 'all', n: 4, total: 4, sites: ['Sede A', 'Sede B', 'Senza sede'] });

// Nothing ticked is "none", never "all".
g = pickerGroups(devs, new Set(), label);
assert.deepEqual(pickerSummary(g), { kind: 'none', n: 0, total: 4, sites: [] });

// Whole sites only.
g = pickerGroups(devs, new Set(['192.0.2.11', '192.0.2.12']), label);
assert.deepEqual(pickerSummary(g), { kind: 'sites', n: 2, total: 4, sites: ['Sede A'] });

// Part of a site.
g = pickerGroups(devs, new Set(['192.0.2.11', '198.51.100.13']), label);
assert.equal(g[0].n, 1);
assert.deepEqual(pickerSummary(g), { kind: 'partial', n: 2, total: 4, sites: ['Sede A', 'Sede B'] });

console.log('device_picker: ok');
```

`tests/test_device_picker.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Python wrapper for tests/js/test_device_picker.mjs, so the suite runs it."""

import os
import shutil
import subprocess
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestDevicePicker(unittest.TestCase):

    @unittest.skipUnless(shutil.which("node"), "node not available")
    def test_harness(self):
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_device_picker.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_device_picker.py -v`
Expected: FAIL, `missing pickerGroups`.

- [ ] **Step 3: Implement**

In `static/js/client-map.js`, after `function locTenantChanged() { … }`, add
(both functions must start at column 0 and end with `\n}\n`, the harness
slices on that):

```js
// Devices grouped by site (the inventory's Location) for the scan pickers.
// Devices without a site get their own group, last: dropping them would hide
// them from every scan.
function pickerGroups(devs, sel, labelOf) {
    const byKey = new Map();
    for (const d of devs) {
        const key = d.Location || '';
        if (!byKey.has(key)) byKey.set(key, { key, label: labelOf(key), devices: [], n: 0, total: 0 });
        const g = byKey.get(key);
        const checked = sel.has(d.IP);
        g.devices.push({ ip: d.IP, name: d.Hostname || d.IP, checked });
        g.total += 1;
        if (checked) g.n += 1;
    }
    return [...byKey.values()].sort((a, b) =>
        (a.key === '') - (b.key === '') || a.label.localeCompare(b.label));
}

// What the closed picker says. "none" is its own state: the old picker read an
// empty selection as "every device", which is exactly what must not happen.
function pickerSummary(groups) {
    const n = groups.reduce((s, g) => s + g.n, 0);
    const total = groups.reduce((s, g) => s + g.total, 0);
    const touched = groups.filter(g => g.n);
    const sites = touched.map(g => g.label);
    if (!n) return { kind: 'none', n, total, sites };
    if (n === total) return { kind: 'all', n, total, sites };
    if (touched.every(g => g.n === g.total)) return { kind: 'sites', n, total, sites };
    return { kind: 'partial', n, total, sites };
}
```

- [ ] **Step 4: Run the test**

Run: `uv run pytest tests/test_device_picker.py -v`
Expected: PASS.

- [ ] **Step 5: Gates and commit**

```bash
uv run python scripts/check_frontend.py
git add static/js/client-map.js tests/js/test_device_picker.mjs tests/test_device_picker.py
git commit -m "feat(endpoints): site-grouped device picker logic

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Shell — page head, search box, underline tabs, four panes

Replaces the hero and pill bar, renames the panes, drops the old MAC search and
its grouped results (the inventory already lists every endpoint). The inventory
pane keeps its own controls until Tasks 5/6 rework them.

**Files:**
- Modify: `templates/dashboard.html` (`#tab-endpoint`, lines ~1591–1877)
- Modify: `static/js/client-map.js` (view switcher, removals)
- Modify: `static/js/core.js:2588-2589` (palette)
- Modify: `static/css/dashboard.css` (append block)
- Modify: `static/js/i18n.js` (keys)
- Test: `tests/test_endpoint_tab.py`, `tests/test_endpoint_inventory.py:660-677`,
  `tests/test_ui_revamp.py` (lines ~126, ~757-761, ~843-850)

**Interfaces:**
- Produces:
  - Views: `'endpoint' | 'porte' | 'diagnosi' | 'raccolta'`.
  - `locSwitchView(view)` (same name; diagnosi.js and endpoint-inventory.js
    already call `locSwitchView('diagnosi')`).
  - Ids: `#locSearchForm`, `#locSearch` (input), `#locSearchMsg` (status line),
    `#locTabs` (tablist), `#locTab-<view>` (tab buttons), `#locPane-<view>`
    (panels), `#locBody` (grid wrapper), `#locMain` (left column),
    `#locHeadActions` (page-head actions, empty until Task 8).
  - `_locLoaded.endpoint = false` marks the list stale (used by scans).

- [ ] **Step 1: Rewrite the structural tests (failing)**

Replace the body of `tests/test_endpoint_tab.py` from `VIEWS = …` down to the
end of `class TestPanesHoldTheContent` with:

```python
VIEWS = ("endpoint", "porte", "diagnosi", "raccolta")


def _read(*parts):
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class TestEndpointShell(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "client-map.js")

    def test_the_tab_exists(self):
        self.assertRegex(self.html, r'<div id="tab-endpoint" class="tab-content"[^>]*>')

    def test_page_head_and_search(self):
        tab = self.html[self.html.index('id="tab-endpoint"'):self.html.index('id="tab-wlc"')]
        self.assertIn('class="page-head"', tab)
        self.assertIn('id="locSearch"', tab)
        self.assertIn('id="locSearchMsg"', tab)
        self.assertNotIn('class="hero"', tab)
        self.assertNotIn('id="locPills"', tab)

    def test_tabs_and_panes_exist(self):
        self.assertIn('id="locTabs" class="loc-tabs" role="tablist"', self.html)
        for v in VIEWS:
            self.assertIn(f'id="locTab-{v}"', self.html)
            self.assertIn(f'aria-controls="locPane-{v}"', self.html)
            self.assertIn(f'id="locPane-{v}"', self.html)

    def test_tabs_are_wired_to_the_switcher(self):
        for v in VIEWS:
            self.assertIn(f'data-loc-view="{v}"', self.html)
        self.assertIn("function locSwitchView", self.js)
        self.assertIn("getElementById('locTabs')", self.js)

    def test_no_tenant_select_of_its_own(self):
        self.assertNotIn('id="locTenant"', self.html)
        self.assertIn("window.globalSelectedTenant", self.js)

    def test_the_nav_item_points_at_the_merged_tab(self):
        self.assertIn('data-tabs="tab-endpoint"', self.html)
        self.assertIn('data-tab="tab-endpoint"', self.html)


class TestPanesHoldTheContent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "client-map.js")

    def test_the_old_tabs_are_gone(self):
        for old in ("tab-mac", "tab-clientmap", "tab-diagnosi", "tab-endpoints"):
            self.assertNotIn(f'<div id="{old}" class="tab-content">', self.html)
            self.assertNotIn(f"switchTab('{old}')", self.html)

    def test_the_old_mac_search_is_gone(self):
        # The inventory lists every endpoint; a second search over the raw
        # sightings was a second answer to the same question.
        for old in ("macSearchMac", "macSearchVlan", "macSearchIface",
                    "macSearchSwitch", "btnMacSearch", "macResults", "kpiMacUniqueWrap"):
            self.assertNotIn(f'id="{old}"', self.html)
        for fn in ("function macSearch(", "function renderMacResults(", "function focusMacResults("):
            self.assertNotIn(fn, self.js)

    def _pane(self, view):
        start = self.html.index(f'id="locPane-{view}"')
        rest = self.html.find('id="locPane-', start + 1)
        return self.html[start:rest if rest != -1 else len(self.html)]

    def test_each_pane_holds_its_own_panels(self):
        self.assertIn('id="btnMacScan"', self._pane("raccolta"))
        self.assertIn('id="kpiMacSightings"', self._pane("raccolta"))
        self.assertIn('id="btnArpScan"', self._pane("raccolta"))
        self.assertIn('id="diagClientInput"', self._pane("diagnosi"))
        self.assertIn('id="epResults"', self._pane("endpoint"))
```

In `tests/test_endpoint_inventory.py`, replace `test_la_tab_esiste_ed_e_raggiungibile`
and `test_e_la_quarta_sorella_del_gruppo_client` with:

```python
    def test_la_tab_esiste_ed_e_raggiungibile(self):
        # The inventory is the Endpoint view of #tab-endpoint.
        self.assertIn('id="locPane-endpoint"', self.src)
        self.assertIn('data-loc-view="endpoint"', self.src)

    def test_the_endpoint_view_is_a_tab_of_the_group(self):
        self.assertIn('data-tabs="tab-endpoint"', self.src)
        start = self.src.index('id="locTabs"')
        tabs_html = self.src[start:self.src.index('</div>', start)]
        for view in ("endpoint", "porte", "diagnosi", "raccolta"):
            self.assertIn(f'id="locTab-{view}"', tabs_html)
            self.assertIn(f'data-loc-view="{view}"', tabs_html)
```

In `tests/test_ui_revamp.py`:
- `PANE_IDS_IN_DOC_ORDER` becomes
  `["locPane-raccolta", "locPane-diagnosi", "locPane-porte", "locPane-endpoint"]`
  (the panes keep today's document order; only the tab buttons are reordered).
- In `test_preserve_ids_mac`, delete `'macSearchMac', 'macSearchVlan',
  'macSearchIface', 'macSearchSwitch', 'macResults'` from the id tuple and
  `'macSearch', 'macSearchReset'` from the hook tuple.
- In `test_mac_and_clientmap_tabs_use_component_classes`, replace the class
  loop and the `locPane-mac` assertion with:

```python
        for cls in ('class="page-head"', 'class="loc-tabs"', 'class="panel mac-console"'):
            self.assertIn(cls, tab_html)
        self.assertGreaterEqual(tab_html.count('class="oneline-foot"'), 1)
        self.assertIn('<div id="locPane-raccolta"', tab_html)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_endpoint_tab.py tests/test_endpoint_inventory.py tests/test_ui_revamp.py -n 4`
Expected: FAIL on the new ids.

- [ ] **Step 3: Template**

In `templates/dashboard.html` replace from
`<div id="tab-endpoint" class="tab-content" role="tabpanel" tabindex="0">`
through the closing `</div>` of `#locPills` with:

```html
    <div id="tab-endpoint" class="tab-content" role="tabpanel" tabindex="0">
      <div class="page-head">
        <div class="page-head-text">
          <h2 data-i18n="locTitle">Localizzazione endpoint</h2>
          <p data-i18n="locDesc">Dove sono attaccati i dispositivi della rete, ricostruito dalle MAC table degli switch e dall'ARP dei gateway.</p>
        </div>
        <div class="page-head-actions" id="locHeadActions"></div>
      </div>

      <form id="locSearchForm" class="loc-search" role="search">
        <i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
        <input id="locSearch" type="search" autocomplete="off"
               placeholder="Cerca MAC, IP, vendor, switch o porta" data-i18n-placeholder="locSearchPh"
               aria-label="Cerca MAC, IP, vendor, switch o porta" data-i18n-aria-label="locSearchPh">
        <kbd aria-hidden="true">/</kbd>
      </form>
      <div id="locSearchMsg" class="loc-search-msg" role="status"></div>

      <div id="locTabs" class="loc-tabs" role="tablist" aria-label="Viste" data-i18n-aria-label="ariaLocTabs">
        <button type="button" role="tab" id="locTab-endpoint" data-loc-view="endpoint" aria-controls="locPane-endpoint" aria-selected="true" data-i18n="locTabEndpoint">Endpoint</button>
        <button type="button" role="tab" id="locTab-porte" data-loc-view="porte" aria-controls="locPane-porte" aria-selected="false" tabindex="-1" data-i18n="locTabPorte">Porte</button>
        <button type="button" role="tab" id="locTab-diagnosi" data-loc-view="diagnosi" aria-controls="locPane-diagnosi" aria-selected="false" tabindex="-1" data-i18n="locTabDiagnosi">Diagnosi</button>
        <button type="button" role="tab" id="locTab-raccolta" data-loc-view="raccolta" aria-controls="locPane-raccolta" aria-selected="false" tabindex="-1" data-i18n="locTabRaccolta">Raccolta</button>
      </div>

      <div id="locBody" class="loc-body">
      <div id="locMain" class="loc-main">
```

Pane wrappers (keep their content and order; only the opening tags change):
- `<div id="locPane-mac" class="loc-pane">` →
  `<div id="locPane-raccolta" class="loc-pane" role="tabpanel" aria-labelledby="locTab-raccolta" hidden>`
- `<div id="locPane-diagnosi" class="loc-pane" style="display:none;">` →
  `<div id="locPane-diagnosi" class="loc-pane" role="tabpanel" aria-labelledby="locTab-diagnosi" hidden>`
- `<div id="locPane-porterrors" class="loc-pane" style="display:none;">` →
  `<div id="locPane-porte" class="loc-pane" role="tabpanel" aria-labelledby="locTab-porte" hidden>`
- `<div id="locPane-inventory" class="loc-pane" style="display:none;">` →
  `<div id="locPane-endpoint" class="loc-pane" role="tabpanel" aria-labelledby="locTab-endpoint">`

Inside the Raccolta pane:
- In the `oneline-foot` KPI row, replace the clickable unique-MAC span
  (`<span class="kpi-clickable" id="kpiMacUniqueWrap" …>…</span>`) with
  `<span><span data-i18n="macKpiUniqueLabel">MAC Univoci</span> <b id="kpiMacUniqueMacs">&mdash;</b></span>`.
- Delete the whole `<div class="mac-row mac-search">…</div>` row (search
  fields, Cerca, Reset).
- Delete the comment `<!-- Risultati raggruppati per switch … -->` and the
  `<div class="table-wrap"><div id="macResults"></div></div>` under it.

Right after the closing `</div>` of the last pane (`#locPane-endpoint`) and
before the `</div>` that closes `#tab-endpoint`, add:

```html
      </div><!-- /locMain -->
      </div><!-- /locBody -->
```

- [ ] **Step 4: JS — view switcher and removals**

In `static/js/client-map.js` replace the block from `let _locView = 'mac';`
through the end of `function locSwitchView(view) { … }` (this includes
`LOC_LOADERS` and `LOC_HEADINGS`) with:

```js
// The endpoint group is one tab with four views. Each view loads on its first
// activation, not when the tab opens.
let _locView = 'endpoint';
const _locLoaded = { endpoint: false, porte: false, diagnosi: false, raccolta: false };

const LOC_LOADERS = {
    endpoint: () => loadEndpointsTab(),
    porte: () => loadPortErrorsPane(),
    diagnosi: () => diagnosiTabShown(),
    raccolta: () => loadRaccolta(),
};

function locSwitchView(view) {
    if (!document.getElementById('locPane-' + view)) return;
    _locView = view;
    for (const v of Object.keys(LOC_LOADERS)) {
        const pane = document.getElementById('locPane-' + v);
        const tab = document.getElementById('locTab-' + v);
        if (pane) pane.hidden = v !== view;
        if (tab) {
            tab.setAttribute('aria-selected', v === view ? 'true' : 'false');
            tab.tabIndex = v === view ? 0 : -1;
        }
    }
    if (!_locLoaded[view]) {
        _locLoaded[view] = true;
        LOC_LOADERS[view]();
    }
}
```

Rename `function loadMacTracker()` to `function loadRaccolta()` and delete its
`macSearch();` line.

Delete: `function fillMacSwitchFilter`, the `fillMacSwitchFilter();` call in
`populateMacScanDevices`, `function focusMacResults`, `function macSearch`,
`function macSearchReset`, `function renderMacResults`, the
`#macResults` click listener, the `kpiMacWrap` block, and the listeners for
`macSearchSwitch`, `btnMacSearch`, `btnMacSearchReset`.

In `runMacScan`, replace `macSearch();` with
`_locLoaded.endpoint = false;   // the list reloads the next time it is opened`.

Replace the `#locPills` click listener with:

```js
    document.getElementById('locTabs')?.addEventListener('click', (e) => {
        const tab = e.target.closest('[data-loc-view]');
        if (tab) locSwitchView(tab.dataset.locView);
    });
    // Arrow keys move between the tabs, as in every WAI-ARIA tablist.
    document.getElementById('locTabs')?.addEventListener('keydown', (e) => {
        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
        const tabs = [...document.querySelectorAll('#locTabs [role="tab"]')];
        const i = tabs.indexOf(document.activeElement);
        if (i < 0) return;
        const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
        next.focus();
        locSwitchView(next.dataset.locView);
    });
```

In `static/js/core.js` lines 2588-2589, change both `locSwitchView('mac')` to
`locSwitchView('raccolta')`.

- [ ] **Step 5: CSS**

Append to `static/css/dashboard.css`:

```css
/* Endpoint location: search, tabs, view + drawer grid. */
#tab-endpoint .loc-search { position: relative; margin-bottom: 6px; }
#tab-endpoint .loc-search > i { position: absolute; left: 14px; top: 50%; transform: translateY(-50%); color: var(--text-soft); }
#tab-endpoint .loc-search input {
  width: 100%; padding: 12px 44px 12px 40px; font-family: var(--font-data); font-size: 15px;
  background: var(--surface); color: var(--text); border: var(--seam) solid var(--border-strong); border-radius: 0;
}
#tab-endpoint .loc-search input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px color-mix(in srgb, var(--primary) 18%, transparent); }
#tab-endpoint .loc-search kbd { position: absolute; right: 12px; top: 50%; transform: translateY(-50%); font-family: var(--font-data); font-size: 11px; border: 1px solid var(--border); padding: 1px 6px; color: var(--text-soft); }
#tab-endpoint .loc-search-msg { min-height: 1.2em; font-size: 12.5px; color: var(--text-muted); margin-bottom: 8px; }
#tab-endpoint .loc-tabs { display: flex; gap: 2px; border-bottom: 1px solid var(--border); margin-bottom: 14px; overflow-x: auto; }
#tab-endpoint .loc-tabs [role="tab"] {
  padding: 10px 14px; border: 0; border-bottom: 2px solid transparent; background: none; cursor: pointer; white-space: nowrap;
  font-family: var(--font-legend); font-size: 14px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text-muted);
}
#tab-endpoint .loc-tabs [role="tab"]:hover { color: var(--text); }
#tab-endpoint .loc-tabs [aria-selected="true"] { color: var(--text); border-bottom-color: var(--primary); }
#tab-endpoint .loc-body { display: grid; grid-template-columns: minmax(0, 1fr); align-items: start; }
#tab-endpoint .loc-main { min-width: 0; }
```

- [ ] **Step 6: i18n**

In `static/js/i18n.js`, after the `tabEndpointLoc:` line of the `it` block add:

```js
        locTitle: "Localizzazione endpoint",
        locDesc: "Dove sono attaccati i dispositivi della rete, ricostruito dalle MAC table degli switch e dall'ARP dei gateway.",
        locSearchPh: "Cerca MAC, IP, vendor, switch o porta",
        ariaLocTabs: "Viste della localizzazione endpoint",
        locTabEndpoint: "Endpoint",
        locTabPorte: "Porte",
        locTabDiagnosi: "Diagnosi",
        locTabRaccolta: "Raccolta",
```

and after the `tabEndpointLoc:` line of the `en` block:

```js
        locTitle: "Endpoint location",
        locDesc: "Where network devices are plugged in, rebuilt from switch MAC tables and gateway ARP.",
        locSearchPh: "Search MAC, IP, vendor, switch or port",
        ariaLocTabs: "Endpoint location views",
        locTabEndpoint: "Endpoints",
        locTabPorte: "Ports",
        locTabDiagnosi: "Diagnosis",
        locTabRaccolta: "Collection",
```

- [ ] **Step 7: Run the tests**

Run: `uv run pytest tests/test_endpoint_tab.py tests/test_endpoint_inventory.py tests/test_ui_revamp.py tests/test_lazy_tab_scripts.py tests/test_i18n_keys.py tests/test_a11y_dashboard.py -n 4`
Expected: PASS. If a test still names a removed id
(`grep -n "macSearch\|macResults\|locPill\|locPane-mac\|locPane-inventory\|locPane-porterrors" tests/`),
point that assertion at the new id from the Interfaces block above.

- [ ] **Step 8: Gates and commit**

```bash
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
uv run pytest tests -n 4
git add templates/dashboard.html static/js/client-map.js static/js/core.js static/css/dashboard.css static/js/i18n.js tests/test_endpoint_tab.py tests/test_endpoint_inventory.py tests/test_ui_revamp.py
git commit -m "feat(endpoints): one search, underline tabs, four views

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Endpoint drawer

Replaces the locate modal and the inline detail row with one right-side panel.

**Files:**
- Modify: `templates/dashboard.html` (drawer host inside `#locBody`)
- Modify: `static/js/endpoint-inventory.js`
- Modify: `static/js/client-map.js` (delete `macLocate`, `closeMacLocateModal`;
  close the drawer in `locTenantChanged`)
- Modify: `static/css/dashboard.css`, `static/js/i18n.js`
- Test: `tests/js/test_endpoint_inventory_ui.mjs` (rewrite)

**Interfaces:**
- Consumes: `_epRows` (rows of `/api/endpoints/list`: `mac`, `oui_vendor`,
  `tenant`, `probe`, `ips[]`, `switch_ip`, `switch_name`, `interface`, `vlan`,
  `client_type`, `first_seen`, `last_seen`, `seen_count`, `flags[]`),
  `fmtMacTime` (client-map.js), `_epLoadPortErrors`, `_epReadErrors`,
  `_epReadRow`, `ifaceErrorsBadge`, `expandIface`, `showPortConfig`,
  `endpointsDiagnose`, `openModal`, `closeModal`, `isModalOpen`, `showToast`.
  `/api/mac/locate` answers `{status, origin[], transit[], access_count,
  last_seen, results[]}` (sightings carry `switch_name`, `switch_ip`,
  `interface`, `vlan`, `uplink_to`).
- Produces:
  - `openEpDrawer(mac, tenant, opener)` — async; fetches the locate answer,
    renders, shows.
  - `closeEpDrawer()`.
  - `_epDrawer` — `null` or `{mac, tenant, opener}` (read by Task 5).
  - Ids `#epDrawerHost`, `#epDrawer`, `#epDrawerTitle`.
  - Row markup contract: `tr.ep-row[data-action="ep-open"][data-mac][data-tenant]`.

- [ ] **Step 1: Rewrite the harness (failing)**

Replace `tests/js/test_endpoint_inventory_ui.mjs` with:

```js
// Endpoint UI contracts that a DOM-less test can still pin.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const read = p => readFileSync(new URL(p, import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const src = read('../../static/js/endpoint-inventory.js');
const cm = read('../../static/js/client-map.js');
const html = read('../../templates/dashboard.html');

// One detail UI: the drawer. The inline row and the locate modal are gone.
assert.ok(src.includes('async function openEpDrawer('), 'missing openEpDrawer');
assert.ok(src.includes('function closeEpDrawer('), 'missing closeEpDrawer');
for (const gone of ['function _renderEndpointDetailRow', 'function _toggleEndpointDetail', 'ep-row-toggle']) {
    assert.ok(!src.includes(gone), `still present: ${gone}`);
}
assert.ok(!cm.includes('function macLocate('), 'macLocate modal still present');

// Rows open the drawer, and say which endpoint they are.
assert.ok(src.includes('data-action="ep-open"'), 'rows must carry data-action="ep-open"');

// Narrow screens go through the modal manager; the host exists in the template.
assert.ok(src.includes("openModal('epDrawerHost'"), 'narrow path must use openModal');
assert.ok(html.includes('id="epDrawerHost"') && html.includes('id="epDrawer"'), 'drawer host missing in template');

// A tenant change closes the drawer: its endpoint may be out of the new scope.
const tcStart = cm.indexOf('function locTenantChanged(');
const tc = cm.slice(tcStart, cm.indexOf('\n}\n', tcStart));
assert.ok(tc.includes('closeEpDrawer()'), 'locTenantChanged must close the drawer');

// Port config summary keeps working (used by the Porte view).
const fnStart = src.indexOf('function portCfgSummary');
const portCfgSummary = (0, eval)(`(${src.slice(fnStart, src.indexOf('\n}\n', fnStart) + 2)})`);
assert.deepEqual(
    portCfgSummary('interface GigabitEthernet1/0/4\n switchport access vlan 7\n spanning-tree portfast\n shutdown\n!'),
    { text: 'switchport access vlan 7 · spanning-tree portfast', more: 1, count: 3 });

console.log('endpoint_inventory_ui: ok');
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_endpoint_inventory_ui.py -v`
Expected: FAIL, `missing openEpDrawer`.

- [ ] **Step 3: Template**

In `templates/dashboard.html`, replace `      </div><!-- /locMain -->` with:

```html
      </div><!-- /locMain -->
      <div id="epDrawerHost" class="ep-drawer-host" hidden>
        <aside id="epDrawer" class="ep-drawer" aria-labelledby="epDrawerTitle"></aside>
      </div>
```

- [ ] **Step 4: JS — drawer**

In `static/js/endpoint-inventory.js`:

1. Delete `_renderEndpointDetailRow` and `_toggleEndpointDetail`.
2. In `endpointsRender`, the row opening tag becomes (cells unchanged until
   Task 5):

```js
    const body = _epRows.map(r => `<tr class="ep-row" data-action="ep-open" data-mac="${escapeHtml(r.mac)}" data-tenant="${escapeHtml(r.tenant || '')}" tabindex="0">
```

   In the actions cell, delete the `act('fa-magnifying-glass-location', … 'ep-locate' …)`
   entry: the row itself now opens the location.
3. In the `#epResults` click listener, delete the `ep-locate` branch and the
   `ep-err-read` branch (both lived in the old detail row), and replace the
   final `ep-row-toggle` branch with:

```js
    const openRow = e.target.closest('tr[data-action="ep-open"]');
    if (openRow && !e.target.closest('button, a, input, select')) {
        openEpDrawer(openRow.dataset.mac, openRow.dataset.tenant || '', openRow);
    }
```

   In the `#epResults` keydown listener, the selector becomes
   `tr[data-action="ep-open"]` and the call
   `openEpDrawer(row.dataset.mac, row.dataset.tenant || '', row);`.
4. Add at the end of the file:

```js
// ===== Endpoint drawer =====
// Docked beside the list on wide screens, so the next row is one click away;
// a modal sheet on narrow ones, through the modal manager.
const _EP_NARROW = '(max-width: 900px)';
let _epDrawer = null;      // { mac, tenant, opener }

async function openEpDrawer(mac, tenant, opener) {
    const host = document.getElementById('epDrawerHost');
    const box = document.getElementById('epDrawer');
    if (!host || !box) return;
    _epDrawer = { mac, tenant, opener: opener || document.activeElement };
    const row = _epRows.find(r => r.mac === mac && (r.tenant || '') === tenant)
             || _epRows.find(r => r.mac === mac) || { mac, tenant };
    document.querySelectorAll('#epResults tr.ep-row.is-selected').forEach(tr => tr.classList.remove('is-selected'));
    document.querySelector(`#epResults tr.ep-row[data-mac="${CSS.escape(mac)}"]`)?.classList.add('is-selected');
    box.innerHTML = `<div class="drawer-body"><div class="drawer-section">${escapeHtml(tr('epiLoading'))}</div></div>`;
    _epShowDrawer(host);

    let loc = null;
    try {
        const q = '/api/mac/locate?mac=' + encodeURIComponent(mac) + (tenant ? '&tenant=' + encodeURIComponent(tenant) : '');
        const res = await apiFetch(q);
        loc = res && res.ok ? await res.json() : null;
    } catch (_) { loc = null; }
    if (!_epDrawer || _epDrawer.mac !== mac) return;     // closed, or another row opened meanwhile
    box.innerHTML = _epDrawerHtml(row, loc);
    if (row.switch_ip && row.interface) {
        _epLoadPortErrors(box.querySelector('.ep-err-slot'), row.switch_ip, row.interface, row.tenant || '');
    }
    /** @type {HTMLElement|null} */ (box.querySelector('[data-action="ep-drawer-close"]'))?.focus({ preventScroll: true });
}

function _epShowDrawer(host) {
    host.style.display = '';
    host.hidden = false;
    if (window.matchMedia(_EP_NARROW).matches) {
        openModal('epDrawerHost', closeEpDrawer);
    } else {
        document.getElementById('locBody')?.classList.add('has-drawer');
    }
}

function closeEpDrawer() {
    const host = document.getElementById('epDrawerHost');
    if (!host || host.hidden) { _epDrawer = null; return; }
    const opener = _epDrawer && _epDrawer.opener;
    _epDrawer = null;
    if (isModalOpen('epDrawerHost')) closeModal('epDrawerHost');
    host.hidden = true;
    document.getElementById('locBody')?.classList.remove('has-drawer');
    document.querySelectorAll('#epResults tr.ep-row.is-selected').forEach(tr => tr.classList.remove('is-selected'));
    if (opener && document.contains(opener)) opener.focus({ preventScroll: true });
}

const _EP_STATUS_TAG = {
    resolved: ['iferr-ok', 'epDrStatusResolved'],
    ambiguous: ['iferr-warn', 'epDrStatusAmbiguous'],
    transit_only: ['iferr-warn', 'epDrStatusTransit'],
    not_found: ['iferr-warn', 'epDrStatusNotFound'],
};

function _epDrawerHtml(r, loc) {
    const entries = loc ? ((loc.results && loc.results.length) ? loc.results : [loc]) : [];
    const e = entries[0] || {};
    const [cls, key] = _EP_STATUS_TAG[e.status] || _EP_STATUS_TAG.not_found;
    const kv = (k, v) => `<div class="drawer-kpi"><span class="kpi-label">${escapeHtml(k)}</span><strong>${escapeHtml(v || '—')}</strong></div>`;
    const hop = (s, kind) => `<li class="ep-hop is-${kind}">${escapeHtml(s.switch_name || s.switch_ip)} ${escapeHtml(s.interface || '')}${
        s.uplink_to ? ' → ' + escapeHtml(s.uplink_to) : ''} <span>· ${escapeHtml(tr(kind === 'access' ? 'epDrAccess' : 'epDrTransit'))} · VLAN ${escapeHtml(s.vlan || '—')}</span></li>`;
    const origin = entries.flatMap(x => x.origin || []);
    const transit = entries.flatMap(x => x.transit || []);
    const ips = (r.ips || []).length
        ? `<div class="drawer-kpi-grid">${(r.ips || []).map(ip => kv('IP', ip)).join('')}</div>`
        : `<p class="ep-dr-note">${escapeHtml(tr('epDrNoIp'))}</p>`;
    const banner = e.status === 'ambiguous'
        ? `<p class="ep-dr-note is-warn">${escapeHtml(tr('cmapMultiplePossibleAccessPorts', { access_count: e.access_count }))}</p>`
        : e.status === 'not_found'
        ? `<p class="ep-dr-note is-warn">${escapeHtml(tr('cmapNotInLatestScan') + (e.last_seen ? ' ' + tr('cmapLastSeenAt', { when: fmtMacTime(e.last_seen) }) : ''))}</p>`
        : entries.length > 1
        ? `<p class="ep-dr-note">${escapeHtml(tr('cmapThisMacExistsIn', { length: entries.length }))}</p>`
        : '';
    const port = (r.switch_ip && r.interface) ? `
        <section class="drawer-section">
          <h4 class="drawer-section-title">${escapeHtml(tr('epDrPort', { port: r.interface }))}</h4>
          <div class="ep-err-slot">${escapeHtml(tr('epErrLoading'))}</div>
          <div><button type="button" class="btn btn-secondary btn-small requires-write" data-action="ep-err-read"
              data-device="${escapeHtml(r.switch_ip)}" data-port="${escapeHtml(r.interface)}" data-tenant="${escapeHtml(r.tenant || '')}">
              <i class="fa-solid fa-stethoscope"></i> ${escapeHtml(tr('epErrReadNow'))}</button></div>
        </section>` : '';
    return `
      <div class="drawer-header">
        <div class="drawer-title-wrap">
          <span class="drawer-eyebrow">${escapeHtml(r.tenant || '')}${r.probe ? ' · ' + escapeHtml(r.probe) : ''}</span>
          <h3 id="epDrawerTitle" class="drawer-title ep-dr-mac">${escapeHtml(r.mac)}</h3>
          <span class="ep-dr-vendor">${escapeHtml(r.oui_vendor || '')}</span>
        </div>
        <button type="button" class="drawer-close-btn" data-action="ep-drawer-close" aria-label="${escapeHtml(tr('epDrClose'))}"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="drawer-body">
        <div class="ep-dr-actions">
          <span class="iferr ${cls}">${escapeHtml(tr(key))}</span>
          <button type="button" class="btn btn-primary btn-small" data-action="ep-diagnose" data-mac="${escapeHtml(r.mac)}" data-tenant="${escapeHtml(r.tenant || '')}"><i class="fa-solid fa-stethoscope"></i> ${escapeHtml(tr('tabDiagnosi'))}</button>
          ${(r.switch_ip && r.interface) ? `<button type="button" class="btn btn-secondary btn-small" data-action="ep-portcfg" data-switch-ip="${escapeHtml(r.switch_ip)}" data-switch-port="${escapeHtml(r.interface)}" data-switch-name="${escapeHtml(r.switch_name || '')}"><i class="fa-solid fa-file-lines"></i> ${escapeHtml(tr('epThConfig'))}</button>` : ''}
          <button type="button" class="btn btn-secondary btn-small" data-action="ep-copy-mac" data-mac="${escapeHtml(r.mac)}" aria-label="${escapeHtml(tr('epDrCopyMac'))}"><i class="fa-regular fa-copy"></i></button>
        </div>
        ${banner}
        <section class="drawer-section">
          <h4 class="drawer-section-title">${escapeHtml(tr('epDrPosition'))}</h4>
          <div class="drawer-kpi-grid">${kv(tr('epThSwitch'), r.switch_name || r.switch_ip)}${kv(tr('epThPort'), r.interface)}${kv('VLAN', r.vlan)}${kv(tr('epDetailClientType'), r.client_type)}</div>
        </section>
        <section class="drawer-section"><h4 class="drawer-section-title">IP</h4>${ips}</section>
        <section class="drawer-section">
          <h4 class="drawer-section-title">${escapeHtml(tr('epDrPath'))}</h4>
          <ul class="ep-path">${origin.map(s => hop(s, 'access')).join('')}${transit.map(s => hop(s, 'transit')).join('')}</ul>
          ${transit.length ? '' : `<p class="ep-dr-note">${escapeHtml(tr('epDrNoTransit'))}</p>`}
        </section>
        ${port}
        <section class="drawer-section">
          <h4 class="drawer-section-title">${escapeHtml(tr('epDrHistory'))}</h4>
          <div class="drawer-kpi-grid">${kv(tr('epDetailFirstSeen'), _epTime(r.first_seen))}${kv(tr('epDetailLastSeen'), _epTime(r.last_seen))}${kv(tr('epDetailSeenCount'), String(r.seen_count ?? '—'))}</div>
          <div>${(r.flags || []).map(_epFlag).join(' ')}</div>
        </section>
      </div>`;
}

document.getElementById('epDrawer')?.addEventListener('click', (e) => {
    const t = /** @type {HTMLElement} */ (e.target);
    if (t.closest('[data-action="ep-drawer-close"]')) { closeEpDrawer(); return; }
    const diag = /** @type {HTMLElement|null} */ (t.closest('[data-action="ep-diagnose"]'));
    if (diag) { closeEpDrawer(); endpointsDiagnose(diag.dataset.mac, diag.dataset.tenant || ''); return; }
    const cfg = /** @type {HTMLElement|null} */ (t.closest('[data-action="ep-portcfg"]'));
    if (cfg) { showPortConfig(cfg.dataset.switchIp, cfg.dataset.switchPort, cfg.dataset.switchName); return; }
    const copy = /** @type {HTMLElement|null} */ (t.closest('[data-action="ep-copy-mac"]'));
    if (copy) {
        navigator.clipboard?.writeText(copy.dataset.mac || '').then(
            () => showToast(tr('epDrCopied'), 'success'), () => showToast(copy.dataset.mac || '', 'info'));
        return;
    }
    const read = /** @type {HTMLButtonElement|null} */ (t.closest('[data-action="ep-err-read"]'));
    if (read) {
        const slot = document.querySelector('#epDrawer .ep-err-slot');
        if (slot) slot.textContent = tr('epErrLoading');
        _epReadErrors(read).then(res => {
            if (!slot) return;
            const want = expandIface(read.dataset.port).toLowerCase();
            const p = res && (res.ports || []).find(x => expandIface(x.interface).toLowerCase() === want);
            if (p) slot.innerHTML = ifaceErrorsBadge(_epReadRow(p, res));
            else _epLoadPortErrors(slot, read.dataset.device, read.dataset.port, read.dataset.tenant);
        });
    }
});

// Esc closes the docked drawer too; the narrow sheet gets Esc from the modal manager.
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _epDrawer && !isModalOpen('epDrawerHost')) closeEpDrawer();
});
```

5. In `static/js/client-map.js`: delete `closeMacLocateModal` and `macLocate`
   (keep `fmtMacTime`: the drawer uses it). In `locTenantChanged`, add as the
   first line: `    closeEpDrawer();`.

- [ ] **Step 5: CSS**

Append to `static/css/dashboard.css`:

```css
/* Endpoint drawer: docked column on wide screens, right sheet on narrow ones. */
#tab-endpoint .loc-body.has-drawer { grid-template-columns: minmax(0, 1fr) clamp(340px, 30vw, 440px); }
#tab-endpoint .ep-drawer-host[hidden] { display: none; }
#tab-endpoint .ep-drawer {
  position: sticky; top: 12px; max-height: calc(100vh - 24px); overflow: hidden;
  display: flex; flex-direction: column; background: var(--surface-2);
  border: var(--seam) solid var(--border); margin-left: -1px;
}
#tab-endpoint .ep-dr-mac { font-family: var(--font-data); }
#tab-endpoint .ep-dr-vendor { font-size: 12.5px; color: var(--text-muted); }
#tab-endpoint .ep-dr-actions { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
#tab-endpoint .ep-dr-actions .btn { width: auto; margin: 0; }
#tab-endpoint .ep-dr-note { margin: 0; font-size: 12.5px; color: var(--text-muted); }
#tab-endpoint .ep-dr-note.is-warn { color: var(--lamp-warn-ink); }
#tab-endpoint .ep-path { list-style: none; margin: 0; padding: 0; display: grid; gap: 4px; font-family: var(--font-data); font-size: 12px; }
#tab-endpoint .ep-hop { padding-left: 14px; position: relative; }
#tab-endpoint .ep-hop::before { content: ''; position: absolute; left: 0; top: 5px; width: 7px; height: 7px; border: 2px solid var(--border-strong); border-radius: 50%; }
#tab-endpoint .ep-hop.is-access::before { border-color: var(--primary); background: var(--primary); }
#tab-endpoint .ep-hop span { color: var(--text-soft); }
#tab-endpoint tr.ep-row { cursor: pointer; }
#tab-endpoint tr.ep-row:hover td { background: var(--surface-2); }
#tab-endpoint tr.ep-row.is-selected td { background: color-mix(in srgb, var(--primary) 9%, transparent); }
#tab-endpoint tr.ep-row.is-selected td:first-child { box-shadow: inset 3px 0 0 var(--primary); }
@media (max-width: 900px) {
  #tab-endpoint .loc-body.has-drawer { grid-template-columns: minmax(0, 1fr); }
  #tab-endpoint .ep-drawer-host { position: fixed; inset: 0; z-index: 900; justify-content: flex-end; align-items: stretch;
    background: color-mix(in srgb, var(--bg) 82%, transparent); }
  #tab-endpoint .ep-drawer { position: static; width: min(440px, 100vw); max-height: none; height: 100vh; margin: 0; }
}
```

(`.iferr-ok` / `.iferr-warn` already exist in `dashboard.css`, from
`ifaceErrorsBadge`.)

- [ ] **Step 6: i18n**

`it` block (after the Task 3 keys):

```js
        epDrClose: "Chiudi dettaglio",
        epDrCopyMac: "Copia MAC",
        epDrCopied: "MAC copiato",
        epDrPosition: "Posizione",
        epDrPath: "Percorso",
        epDrPort: "Porta {port}",
        epDrHistory: "Storico",
        epDrAccess: "accesso",
        epDrTransit: "transito",
        epDrNoIp: "Nessun binding ARP. Lancia \"Raccogli ARP\" nella vista Raccolta.",
        epDrNoTransit: "Nessun transito nell'ultima scansione.",
        epDrStatusResolved: "porta di accesso",
        epDrStatusAmbiguous: "ambiguo",
        epDrStatusTransit: "solo transito",
        epDrStatusNotFound: "non nell'ultima scansione",
        epThSwitch: "Switch",
        epThPort: "Porta",
```

`en` block:

```js
        epDrClose: "Close details",
        epDrCopyMac: "Copy MAC",
        epDrCopied: "MAC copied",
        epDrPosition: "Location",
        epDrPath: "Path",
        epDrPort: "Port {port}",
        epDrHistory: "History",
        epDrAccess: "access",
        epDrTransit: "transit",
        epDrNoIp: "No ARP binding. Run \"Collect ARP\" in the Collection view.",
        epDrNoTransit: "No transit in the latest scan.",
        epDrStatusResolved: "access port",
        epDrStatusAmbiguous: "ambiguous",
        epDrStatusTransit: "transit only",
        epDrStatusNotFound: "not in the latest scan",
        epThSwitch: "Switch",
        epThPort: "Port",
```

(If `epThSwitch`/`epThPort` already exist — `grep -n "epThSwitch:\|epThPort:" static/js/i18n.js` —
reuse them and skip those two lines.) Delete keys left without readers once
`macLocate` is gone: `cmapMacOrigin`, `cmapMostRecent`, `cmapNoAccessPortFound`,
`cmapAccessLocationOrigin`, `cmapSingleAccessPortResolved`, `cmapClose`,
`cmapLocateFailed` — each only after
`grep -n "'<key>'\|\"<key>\"\|\.<key>\b" static/js/*.js templates/dashboard.html`
shows no remaining reader.

- [ ] **Step 7: Run the tests**

Run: `uv run pytest tests/test_endpoint_inventory_ui.py tests/test_ui_modal.py tests/test_i18n_keys.py tests/test_lazy_tab_scripts.py -v`
Expected: PASS.

- [ ] **Step 8: Gates and commit**

```bash
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run pytest tests -n 4
git add templates/dashboard.html static/js/endpoint-inventory.js static/js/client-map.js static/css/dashboard.css static/js/i18n.js tests/js/test_endpoint_inventory_ui.mjs
git commit -m "feat(endpoints): endpoint drawer replaces locate modal and detail row

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Endpoint view — toolbar, KPI line, table, search

**Files:**
- Modify: `templates/dashboard.html` (`#locPane-endpoint` content)
- Modify: `static/js/endpoint-inventory.js`
- Modify: `static/css/dashboard.css`, `static/js/i18n.js`
- Test: `tests/test_endpoint_tab.py` (add class)

**Interfaces:**
- Consumes: `openEpDrawer`, `_epDrawer` (Task 4), `locSwitchView`,
  `_locLoaded` (Task 3), `locTenant`, `globalDevices`.
- Produces: `endpointsParams(q)` → `URLSearchParams`; `locSearchSubmit()`;
  `_epQuery` (string, current search term); ids `#epFilterSwitch`,
  `#epFilterVlan`, `#epFilterProbe`, `#epFilterStale`, `#epFilterFrom`,
  `#epFilterTo`, `#btnEpReset`, `#epExportMenu`, `#epQueryChip`, `#epKpis`,
  `#epResults`. Removed: `#epFilterQ`, `#btnEpFilter`, `#btnEpResetTime`.
  `#epModeListBtn` / `#epModePortsBtn` / `#epPortsSwitch` stay until Task 6.

- [ ] **Step 1: Failing structural test**

Append to `tests/test_endpoint_tab.py`:

```python
class TestEndpointView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "endpoint-inventory.js")

    def test_toolbar_controls(self):
        for _id in ("epFilterSwitch", "epFilterVlan", "epFilterProbe", "epFilterStale",
                    "epFilterFrom", "epFilterTo", "btnEpReset", "epExportMenu",
                    "btnEpExportCsv", "btnEpExportJson", "epQueryChip"):
            self.assertIn(f'id="{_id}"', self.html)
        for gone in ("epFilterQ", "btnEpFilter", "btnEpResetTime"):
            self.assertNotIn(f'id="{gone}"', self.html)

    def test_the_search_drives_the_list(self):
        self.assertIn("function locSearchSubmit(", self.js)
        self.assertIn("getElementById('locSearchForm')", self.js)
        # One hit opens the drawer straight away.
        body = self.js[self.js.index("function locSearchSubmit("):]
        self.assertIn("openEpDrawer(", body[:body.index("\n}\n")])
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_endpoint_tab.py -v`
Expected: FAIL on `epFilterSwitch`.

- [ ] **Step 3: Template**

Inside `#locPane-endpoint`, replace everything from `<div id="epKpis" …></div>`
through the closing `</div>` of the filter panel (the `<div class="panel">`
that contains `btnEpExportJson`) with:

```html
      <div id="epKpis" class="oneline-foot ep-kpis"></div>
      <div class="ep-toolbar">
        <span id="epQueryChip"></span>
        <label class="ep-field" for="epFilterSwitch"><span data-i18n="epThSwitch">Switch</span>
          <select id="epFilterSwitch"></select></label>
        <label class="ep-field" for="epFilterVlan">VLAN
          <input id="epFilterVlan" type="text" inputmode="numeric" placeholder="10"></label>
        <label class="ep-field" for="epFilterProbe"><span data-i18n="epFilterProbe">Probe</span>
          <select id="epFilterProbe"></select></label>
        <label class="ep-field" for="epFilterStale"><span data-i18n="epFilterStale">Stale dopo (giorni)</span>
          <input id="epFilterStale" type="number" min="1" max="3650" value="7"></label>
        <label class="ep-field" for="epFilterFrom"><span data-i18n="epFilterFrom">Da (data/ora)</span>
          <input id="epFilterFrom" type="datetime-local"></label>
        <label class="ep-field" for="epFilterTo"><span data-i18n="epFilterTo">A (data/ora)</span>
          <input id="epFilterTo" type="datetime-local"></label>
        <span class="ep-spacer"></span>
        <button type="button" class="btn btn-secondary btn-small" id="btnEpReset" data-i18n="epFilterReset">Reset</button>
        <details id="epExportMenu" class="ep-menu">
          <summary class="btn btn-secondary btn-small" data-i18n="epExport">Esporta</summary>
          <div class="ep-menu-list">
            <button type="button" id="btnEpExportCsv" data-i18n="epExportCsv">CSV</button>
            <button type="button" id="btnEpExportJson" data-i18n="epExportJson">JSON</button>
          </div>
        </details>
      </div>
```

(Leave the `epModeListBtn` row above it in place for now; leave `#epResults`
below.)

- [ ] **Step 4: JS**

In `static/js/endpoint-inventory.js`:

1. Add after `let _epTruncated = false;`:

```js
let _epQuery = '';         // term from the tab's search box, '' = none
```

2. Replace `loadEndpointsTab` with:

```js
function loadEndpointsTab() {
    _epFillFilters();
    endpointsApplyFilters();
}

// Switch and Probe options come from the tenant's inventory, not from the
// rows on screen: options built from the results vanish once they filter.
function _epFillFilters() {
    const tenant = locTenant();
    let devs = globalDevices || [];
    if (tenant && tenant !== 'all') devs = devs.filter(d => d.Group === tenant);
    const sw = /** @type {HTMLSelectElement|null} */ (document.getElementById('epFilterSwitch'));
    if (sw) {
        const cur = sw.value;
        const label = d => d.Hostname || d.IP;
        sw.innerHTML = `<option value="">${escapeHtml(tr('epAllSwitches'))}</option>` + devs.slice()
            .sort((a, b) => label(a).localeCompare(label(b)))
            .map(d => `<option value="${escapeHtml(d.IP)}">${escapeHtml(label(d))}</option>`).join('');
        sw.value = devs.some(d => d.IP === cur) ? cur : '';
    }
    const pr = /** @type {HTMLSelectElement|null} */ (document.getElementById('epFilterProbe'));
    if (pr) {
        const cur = pr.value;
        const probes = [...new Set(devs.map(d => d.Probe).filter(Boolean))].sort();
        pr.innerHTML = `<option value="">${escapeHtml(tr('epAllProbes'))}</option>` +
            probes.map(p => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join('');
        pr.value = probes.includes(cur) ? cur : '';
    }
}
```

3. Add above `endpointsSearch`:

```js
function endpointsParams(q) {
    const val = id => ((/** @type {HTMLInputElement|null} */ (document.getElementById(id)) || {}).value || '').trim();
    const params = new URLSearchParams({ stale_days: String(parseInt(val('epFilterStale'), 10) || 7) });
    if (q) params.set('q', q);
    const tenant = locTenant();
    if (tenant && tenant !== 'all') params.set('tenant', tenant);
    if (val('epFilterSwitch')) params.set('switch', val('epFilterSwitch'));
    if (val('epFilterVlan')) params.set('vlan', val('epFilterVlan'));
    if (val('epFilterProbe')) params.set('probe', val('epFilterProbe'));
    for (const [id, key] of [['epFilterFrom', 'frm'], ['epFilterTo', 'to']]) {
        const v = val(id);
        if (!v) continue;
        try { params.set(key, new Date(v).toISOString()); } catch (e) { params.set(key, v); }
    }
    return params;
}
```

   In `endpointsSearch`, delete the locals `L`, `q`, `tenant`, `staleDays`,
   `fromVal`, `toVal` and the `params` building, and fetch with
   `const res = await apiFetch('/api/endpoints/list?' + endpointsParams(_epQuery).toString());`.

4. In `endpointsRender`, replace the KPI block with:

```js
    const kpis = document.getElementById('epKpis');
    if (kpis) {
        const c = d.counts || {};
        const item = (label, value) => `<span>${escapeHtml(label)} <b>${escapeHtml(String(value ?? 0))}</b></span>`;
        kpis.innerHTML = item(L.epKpiEndpoints, c.endpoints) + item(L.epKpiSwitches, c.switches) +
            item(L.epKpiVlans, c.vlans) + item(L.epKpiStale, c.stale) + item(L.epKpiNew, c.new) + item(L.epKpiNoIp, c.no_ip);
    }
    const chip = document.getElementById('epQueryChip');
    if (chip) chip.innerHTML = _epQuery
        ? `<span class="ep-chip">“${escapeHtml(_epQuery)}”<button type="button" data-action="ep-clear-query" aria-label="${escapeHtml(tr('ariaEpQueryClear'))}">×</button></span>`
        : '';
```

   and replace the `act` helper, `body`, and the final `host.innerHTML = …` with:

```js
    const body = _epRows.map(r => `<tr class="ep-row" data-action="ep-open" data-mac="${escapeHtml(r.mac)}" data-tenant="${escapeHtml(r.tenant || '')}" tabindex="0">
        <td class="ep-mono">${escapeHtml(r.mac)}<span class="ep-sub">${escapeHtml(r.oui_vendor || '')}</span></td>
        <td class="ep-mono">${escapeHtml((r.ips || []).join(', ') || '—')}</td>
        <td>${escapeHtml(r.switch_name || r.switch_ip || '—')}<span class="ep-sub ep-mono">${escapeHtml(r.switch_name ? r.switch_ip || '' : '')}</span></td>
        <td class="ep-mono">${escapeHtml(r.interface || '—')}</td>
        <td class="ep-mono">${escapeHtml(r.vlan || '—')}</td>
        <td>${escapeHtml(_epTime(r.last_seen))}</td>
        <td>${(r.flags || []).map(_epFlag).join(' ')}</td>
    </tr>`).join('');

    host.innerHTML = `${banner}
        <div class="table-wrap ep-table"><table>
          <thead><tr>
            <th>${escapeHtml(L.epThMac)}</th><th>IP</th><th>${escapeHtml(tr('epThSwitch'))}</th>
            <th>${escapeHtml(tr('epThPort'))}</th><th>${escapeHtml(L.epThVlan)}</th>
            <th>${escapeHtml(L.epThLast)}</th><th>${escapeHtml(L.epThFlags)}</th>
          </tr></thead>
          <tbody>${body}</tbody>
        </table></div>`;
    if (_epDrawer) document.querySelector(`#epResults tr.ep-row[data-mac="${CSS.escape(_epDrawer.mac)}"]`)?.classList.add('is-selected');
```

   The `#epResults` click listener's `ep-diagnose` and `ep-portcfg` branches
   now have no buttons to serve — delete them (the drawer has those actions).

5. Add the search:

```js
// The tab's search box. One hit opens that endpoint; several fill the list;
// none says so and leaves the view where it was.
async function locSearchSubmit() {
    const input = /** @type {HTMLInputElement|null} */ (document.getElementById('locSearch'));
    const msg = document.getElementById('locSearchMsg');
    if (!input || !msg) return;
    const term = input.value.trim();
    msg.textContent = '';
    if (!term) { _epQuery = ''; _locLoaded.endpoint = true; locSwitchView('endpoint'); endpointsSearch(); return; }
    const res = await apiFetch('/api/endpoints/list?' + endpointsParams(term).toString());
    if (!res || !res.ok) { msg.textContent = tr('epiCouldNotLoadThe'); return; }
    const d = await res.json();
    if (!d.total) { msg.textContent = tr('locSearchNone', { q: term }); return; }
    _epQuery = term;
    const firstTime = !_locLoaded.endpoint;
    _locLoaded.endpoint = true;          // rendered below: no second fetch
    locSwitchView('endpoint');
    if (firstTime) _epFillFilters();
    endpointsRender(d);
    msg.textContent = tr('locSearchFound', { n: String(d.total) });
    if ((d.results || []).length === 1) openEpDrawer(d.results[0].mac, d.results[0].tenant || '', input);
}
```

6. Replace the static listeners from `document.getElementById('epFilterQ')…`
   through the `btnEpExportJson` line with:

```js
document.getElementById('locSearchForm')?.addEventListener('submit', (e) => { e.preventDefault(); locSearchSubmit(); });
// "/" jumps to the search while the tab is open and nothing else has the keyboard.
document.addEventListener('keydown', (e) => {
    const t = /** @type {HTMLElement} */ (e.target);
    if (e.key !== '/' || /INPUT|SELECT|TEXTAREA/.test(t.tagName) || t.isContentEditable) return;
    if (!document.getElementById('tab-endpoint')?.classList.contains('active')) return;
    e.preventDefault();
    document.getElementById('locSearch')?.focus();
});
for (const id of ['epFilterSwitch', 'epFilterVlan', 'epFilterProbe', 'epFilterStale', 'epFilterFrom', 'epFilterTo']) {
    document.getElementById(id)?.addEventListener('change', endpointsApplyFilters);
}
document.getElementById('btnEpReset')?.addEventListener('click', () => {
    for (const id of ['epFilterSwitch', 'epFilterVlan', 'epFilterProbe', 'epFilterFrom', 'epFilterTo']) {
        const el = /** @type {HTMLInputElement|null} */ (document.getElementById(id));
        if (el) el.value = '';
    }
    const stale = /** @type {HTMLInputElement|null} */ (document.getElementById('epFilterStale'));
    if (stale) stale.value = '7';
    _epQuery = '';
    endpointsApplyFilters();
});
document.getElementById('epQueryChip')?.addEventListener('click', (e) => {
    if (!(/** @type {HTMLElement} */ (e.target)).closest('[data-action="ep-clear-query"]')) return;
    _epQuery = '';
    const input = /** @type {HTMLInputElement|null} */ (document.getElementById('locSearch'));
    if (input) input.value = '';
    const msg = document.getElementById('locSearchMsg');
    if (msg) msg.textContent = '';
    endpointsApplyFilters();
});
document.getElementById('btnEpExportCsv')?.addEventListener('click', () => endpointsExport('csv'));
document.getElementById('btnEpExportJson')?.addEventListener('click', () => endpointsExport('json'));
```

   (`switchTab` adds the class `active` to the open `.tab-content`,
   `core.js:1884`.)

- [ ] **Step 5: CSS**

```css
/* Endpoint view */
#tab-endpoint .ep-kpis { margin-bottom: 10px; }
#tab-endpoint .ep-toolbar { display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: center; padding: 8px 10px; margin-bottom: 10px;
  background: var(--surface); border: var(--seam) solid var(--border); }
#tab-endpoint .ep-field { display: flex; align-items: center; gap: 6px; font-family: var(--font-legend); font-size: 11px;
  letter-spacing: 0.12em; text-transform: uppercase; color: var(--text-soft); }
#tab-endpoint .ep-field input, #tab-endpoint .ep-field select { font-family: var(--font-data); font-size: 12.5px; text-transform: none;
  letter-spacing: 0; padding: 5px 8px; width: auto; margin: 0; }
#tab-endpoint .ep-field input[type="text"], #tab-endpoint .ep-field input[type="number"] { width: 72px; }
#tab-endpoint .ep-spacer { flex: 1; }
#tab-endpoint .ep-toolbar .btn { width: auto; margin: 0; }
#tab-endpoint .ep-menu { position: relative; }
#tab-endpoint .ep-menu > summary { list-style: none; }
#tab-endpoint .ep-menu > summary::-webkit-details-marker { display: none; }
#tab-endpoint .ep-menu-list { position: absolute; right: 0; top: calc(100% + 4px); z-index: 20; display: grid; min-width: 120px;
  background: var(--surface); border: var(--seam) solid var(--border-strong); box-shadow: var(--shadow-float); }
#tab-endpoint .ep-menu-list button { text-align: left; padding: 8px 12px; background: none; border: 0; color: var(--text); cursor: pointer; }
#tab-endpoint .ep-menu-list button:hover { background: var(--surface-2); }
#tab-endpoint .ep-chip { display: inline-flex; align-items: center; gap: 4px; padding: 2px 4px 2px 8px; font-family: var(--font-data); font-size: 12px;
  color: var(--primary); border: 1px solid var(--primary); background: color-mix(in srgb, var(--primary) 10%, transparent); }
#tab-endpoint .ep-chip button { background: none; border: 0; color: inherit; cursor: pointer; font-size: 14px; padding: 0 4px; }
#tab-endpoint .ep-table td { vertical-align: top; }
#tab-endpoint .ep-mono { font-family: var(--font-data); font-size: 12.5px; font-variant-numeric: tabular-nums; }
#tab-endpoint .ep-sub { display: block; margin-top: 2px; font-size: 11.5px; color: var(--text-soft); }
```

- [ ] **Step 6: i18n**

`it`:

```js
        locSearchNone: "Nessun endpoint corrisponde a \"{q}\". Per cercare un IP serve un binding ARP: lancia \"Raccogli ARP\".",
        locSearchFound: "{n} endpoint trovati.",
        epFilterProbe: "Probe",
        epAllSwitches: "Tutti",
        epAllProbes: "Tutte",
        epFilterReset: "Reset",
        epExport: "Esporta",
        ariaEpQueryClear: "Rimuovi ricerca",
```

`en`:

```js
        locSearchNone: "No endpoint matches \"{q}\". Searching by IP needs an ARP binding: run \"Collect ARP\".",
        locSearchFound: "{n} endpoints found.",
        epFilterProbe: "Probe",
        epAllSwitches: "All",
        epAllProbes: "All",
        epFilterReset: "Reset",
        epExport: "Export",
        ariaEpQueryClear: "Clear search",
```

Delete the `epFilterQ` key from both blocks (no reader left). Skip any key above
that already exists (`grep -n "epFilterProbe:\|epExport:" static/js/i18n.js`).

- [ ] **Step 7: Run tests, gates, commit**

```bash
uv run pytest tests/test_endpoint_tab.py tests/test_endpoint_inventory_ui.py tests/test_i18n_keys.py tests/test_a11y_dashboard.py -v
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
uv run pytest tests -n 4
git add templates/dashboard.html static/js/endpoint-inventory.js static/css/dashboard.css static/js/i18n.js tests/test_endpoint_tab.py
git commit -m "feat(endpoints): endpoint view toolbar, compact table, tab search

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Porte view (occupancy + errors)

**Files:**
- Modify: `templates/dashboard.html` (`#locPane-porte`; remove the
  `epModeListBtn` row from `#locPane-endpoint`)
- Modify: `static/js/endpoint-inventory.js`, `static/js/client-map.js` (`LOC_LOADERS.porte`)
- Modify: `static/css/dashboard.css`, `static/js/i18n.js`
- Test: `tests/test_endpoint_tab.py` (add class), `tests/js/test_endpoint_inventory_ui.mjs`

**Interfaces:**
- Consumes: `endpointsPorts`, `endpointsPortsRender`, `loadPortErrorsPane`,
  `_epReadErrors`, `_epDeviceOf`, `openEpDrawer`, `macCell`.
- Produces: `loadPortsView()`; ids `#ptSwitch`, `#ptWindow`, `#ptBad`,
  `#ptRefresh`, `#ptRead`, `#ptLegendBtn`, `#ptLegend`, `#ptResults`.
  Removed: `#peDevice`, `#peWindow`, `#peShow`, `#peRefresh`, `#peReadNow`,
  `#peLegend`, `#peResults`, `#epModeListBtn`, `#epModePortsBtn`,
  `#epPortsSwitch`, `endpointsMode`, `_epMode`.

- [ ] **Step 1: Failing tests**

Append to `tests/test_endpoint_tab.py`:

```python
class TestPortsView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "endpoint-inventory.js")

    def test_one_toolbar_one_host(self):
        for _id in ("ptSwitch", "ptWindow", "ptBad", "ptRefresh", "ptRead",
                    "ptLegendBtn", "ptLegend", "ptResults"):
            self.assertIn(f'id="{_id}"', self.html)
        for gone in ("peDevice", "peShow", "peResults", "epModeListBtn", "epPortsSwitch"):
            self.assertNotIn(f'id="{gone}"', self.html)
        self.assertNotIn("function endpointsMode(", self.js)

    def test_read_now_is_a_write_action(self):
        start = self.html.index('id="ptRead"')
        tag = self.html[self.html.rindex("<button", 0, start):self.html.index(">", start)]
        self.assertIn("requires-write", tag)
```

Append to `tests/js/test_endpoint_inventory_ui.mjs`, before the final `console.log`:

```js
// Porte: a single-MAC port opens that endpoint's drawer.
assert.ok(src.includes('function loadPortsView('), 'missing loadPortsView');
assert.ok(src.includes('data-action="ep-open-mac"'), 'single-MAC port cell must open the drawer');
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_endpoint_tab.py tests/test_endpoint_inventory_ui.py -v`
Expected: FAIL on `ptSwitch` / `loadPortsView`.

- [ ] **Step 3: Template**

Delete the row with `epModeListBtn` / `epModePortsBtn` / `epPortsSwitch` from
`#locPane-endpoint`. Replace the whole content of `#locPane-porte` with the
markup below, where the two lines marked `LEGEND` are the `<p data-i18n="peLegendBadge">`
and the `<dl>…</dl>` copied from the old `<details id="peLegend">` with their
inline `style=` attributes removed (the CSS below styles them):

```html
        <div class="ep-toolbar">
          <label class="ep-field" for="ptSwitch"><span data-i18n="peDevice">Apparato</span>
            <select id="ptSwitch"></select></label>
          <label class="ep-field" for="ptWindow"><span data-i18n="ifErrWindow">Finestra errori</span>
            <select id="ptWindow">
              <option value="1h" data-i18n="ifErrWin1h">Ultima ora</option>
              <option value="24h" selected data-i18n="ifErrWin24h">Ultime 24 ore</option>
              <option value="7d" data-i18n="ifErrWin7d">Ultimi 7 giorni</option>
            </select></label>
          <label class="ep-toggle" for="ptBad"><input type="checkbox" id="ptBad"> <span data-i18n="ptOnlyBad">Solo problemi</span></label>
          <span class="ep-spacer"></span>
          <span class="ep-pop">
            <button type="button" class="btn btn-secondary btn-small" id="ptLegendBtn" aria-expanded="false" aria-controls="ptLegend"
                    aria-label="Legenda errori" data-i18n-aria-label="peLegendTitle">?</button>
            <div id="ptLegend" class="ep-pop-body" hidden>
              LEGEND <p data-i18n="peLegendBadge">…</p>
              LEGEND <dl>…</dl>
            </div>
          </span>
          <button type="button" id="ptRefresh" class="btn btn-secondary btn-small"><i class="fa-solid fa-rotate"></i> <span data-i18n="ifBtnRefresh">Aggiorna</span></button>
          <button type="button" id="ptRead" class="btn btn-secondary btn-small requires-write"><i class="fa-solid fa-stethoscope"></i> <span data-i18n="ifBtnReadErrors">Leggi errori ora</span></button>
        </div>
        <div id="ptResults"></div>
```

(The word `LEGEND` and the `…` are placeholders for the copied elements, not
text to keep.)

- [ ] **Step 4: JS**

In `static/js/endpoint-inventory.js`:

1. Delete `let _epMode`, `function endpointsMode`, the `epModeListBtn` /
   `epModePortsBtn` / `epPortsSwitch` listeners, and in
   `endpointsApplyFilters` the `if (_epMode === 'ports') …` line.
2. In `endpointsPorts(lastRead)`:

```js
    const host = document.getElementById('ptResults');
    const picker = /** @type {HTMLSelectElement|null} */ (document.getElementById('ptSwitch'));
```

   replace `window: '24h'` in the interface-errors query with
   `window: /** @type {HTMLSelectElement|null} */ (document.getElementById('ptWindow'))?.value || '24h'`,
   and delete the `if (!sw) { … epPortsPick … }` early return (the dispatcher
   below never calls it without a switch).
3. In `endpointsPortsRender`: `const host = document.getElementById('ptResults');`;
   remove `data-col-default-hidden="1"` from the errors `<th>`; remove the
   `ep-err-read-switch` button from the summary panel (the toolbar's "Leggi
   errori ora" replaces it); right before `_epPortHist = …` add:

```js
    const onlyBad = /** @type {HTMLInputElement|null} */ (document.getElementById('ptBad'))?.checked;
    const errOf = p => portErrors[expandIface(p.interface).toLowerCase()];
    const ports = (d.ports || []).filter(p => !onlyBad || ['erroring', 'discards'].includes((errOf(p) || {}).status));
```

   and use `ports` instead of `(d.ports || [])` for both `_epPortHist` and `rows`.
4. In `macCell(p, idx)`, replace the first `return` line with:

```js
    if (cur.length === 1 && !nGone) return `<button type="button" class="ep-link" data-action="ep-open-mac" data-mac="${escapeHtml(cur[0])}">${escapeHtml(cur[0])}</button>`;
    if (cur.length <= 3 && !nGone) return escapeHtml(cur.join(', ') || (p.uplink_to ? '→ ' + p.uplink_to : '—'));
```

5. In `loadPortErrorsPane`: `const host = document.getElementById('ptResults');`;
   delete the `picker` lookup and its population block; set
   `const device = '';` and `const show = 'bad';` (this is the "all devices"
   path, problems only); read the window from `#ptWindow`.
6. Delete the old `#epResults` branches `ep-err-read-switch`, `ep-copy-cfg`,
   `ep-toggle-cfg`/`ep-toggle-macs` (the occupancy table no longer renders into
   `#epResults`) — keep their bodies, they move into the `#ptResults` listener
   below. Delete the `peDevice`, `peWindow`, `peShow`, `peRefresh`,
   `peResults`, `peReadNow` listeners. Add:

```js
// Porte: a chosen switch shows all its ports (occupancy + errors); "all"
// shows only the erroring ports across the tenant.
function loadPortsView() {
    const picker = /** @type {HTMLSelectElement|null} */ (document.getElementById('ptSwitch'));
    if (picker) {
        const cur = picker.value;
        const tenant = locTenant();
        let devs = globalDevices || [];
        if (tenant && tenant !== 'all') devs = devs.filter(d => d.Group === tenant);
        const label = d => d.Hostname || d.IP;
        picker.innerHTML = `<option value="">${escapeHtml(tr('ptSwitchAll'))}</option>` + devs.slice()
            .sort((a, b) => label(a).localeCompare(label(b)))
            .map(d => `<option value="${escapeHtml(d.IP)}">${escapeHtml(label(d))} — ${escapeHtml(d.IP)}</option>`).join('');
        picker.value = devs.some(d => d.IP === cur) ? cur : '';
    }
    const bad = /** @type {HTMLInputElement|null} */ (document.getElementById('ptBad'));
    if (bad) bad.disabled = !picker?.value;      // "all" is problems-only by definition
    if (picker?.value) endpointsPorts(); else loadPortErrorsPane();
}

for (const id of ['ptSwitch', 'ptWindow', 'ptBad']) document.getElementById(id)?.addEventListener('change', loadPortsView);
document.getElementById('ptRefresh')?.addEventListener('click', loadPortsView);
document.getElementById('ptRead')?.addEventListener('click', async (e) => {
    const btn = /** @type {HTMLButtonElement} */ (e.currentTarget);
    const device = /** @type {HTMLSelectElement|null} */ (document.getElementById('ptSwitch'))?.value || '';
    if (!device) { showToast(tr('ifErrPickDevice'), 'warning'); return; }
    btn.dataset.device = device;
    btn.dataset.tenant = _epDeviceOf(device).Group || '';
    const read = await _epReadErrors(btn);
    if (read) {
        showToast(tr('ifErrReadDone', { device, src: String(read.source || '').toUpperCase(), s: String(read.interval_s) }), 'success');
        endpointsPorts(read);
    }
});
document.getElementById('ptLegendBtn')?.addEventListener('click', (e) => {
    const btn = /** @type {HTMLElement} */ (e.currentTarget);
    const box = document.getElementById('ptLegend');
    if (!box) return;
    box.hidden = !box.hidden;
    btn.setAttribute('aria-expanded', box.hidden ? 'false' : 'true');
});
document.addEventListener('click', (e) => {
    const box = document.getElementById('ptLegend');
    if (box && !box.hidden && !(/** @type {HTMLElement} */ (e.target)).closest('.ep-pop')) {
        box.hidden = true;
        document.getElementById('ptLegendBtn')?.setAttribute('aria-expanded', 'false');
    }
});
document.getElementById('ptResults')?.addEventListener('click', (e) => {
    const t = /** @type {HTMLElement} */ (e.target);
    const open = /** @type {HTMLElement|null} */ (t.closest('[data-action="ep-open-mac"]'));
    if (open) { openEpDrawer(open.dataset.mac || '', locTenant() === 'all' ? '' : locTenant(), open); return; }
    const pc = /** @type {HTMLElement|null} */ (t.closest('[data-action="pe-portcfg"]'));
    if (pc) { showPortConfig(pc.dataset.ip, pc.dataset.port, pc.dataset.name); return; }
    const copyCfgBtn = /** @type {HTMLElement|null} */ (t.closest('[data-action="ep-copy-cfg"]'));
    if (copyCfgBtn) {
        const raw = copyCfgBtn.dataset.raw || '';
        if (navigator.clipboard && raw) {
            navigator.clipboard.writeText(raw).then(() => {
                const orig = copyCfgBtn.innerHTML;
                copyCfgBtn.innerHTML = `<i class="fa-solid fa-check" style="color:var(--success);"></i>`;
                setTimeout(() => { copyCfgBtn.innerHTML = orig; }, 1500);
            });
        }
        return;
    }
    const toggleCfgBtn = /** @type {HTMLElement|null} */ (t.closest('[data-action="ep-toggle-cfg"], [data-action="ep-toggle-macs"]'));
    if (toggleCfgBtn) {
        const row = /** @type {HTMLTableRowElement|null} */ (toggleCfgBtn.closest('tr'));
        const next = row?.nextElementSibling;
        const open = toggleCfgBtn.getAttribute('aria-expanded') === 'true';
        if (next && next.classList.contains('ep-cfg-row')) next.remove();
        row?.querySelectorAll('[data-action="ep-toggle-cfg"], [data-action="ep-toggle-macs"]').forEach(b => b.setAttribute('aria-expanded', 'false'));
        if (row && !open) {
            const cfgRow = document.createElement('tr');
            cfgRow.className = 'ep-cfg-row';
            const body = toggleCfgBtn.dataset.action === 'ep-toggle-macs'
                ? macHistHtml(_epPortHist[Number(toggleCfgBtn.dataset.idx)] || [])
                : `<pre class="ep-cfg-full">${escapeHtml(toggleCfgBtn.dataset.raw || '')}</pre>`;
            cfgRow.innerHTML = `<td colspan="${row.cells.length}">${body}</td>`;
            row.after(cfgRow);
        }
        toggleCfgBtn.setAttribute('aria-expanded', open ? 'false' : 'true');
    }
});
```

   (The `ep-copy-cfg` check icon keeps its existing inline `style` — it is
   moved code, not new markup.)

7. In `static/js/client-map.js`: `porte: () => loadPortsView(),` in `LOC_LOADERS`.

- [ ] **Step 5: CSS**

```css
/* Porte view */
#tab-endpoint .ep-toggle { display: flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--text-muted); }
#tab-endpoint .ep-pop { position: relative; }
#tab-endpoint .ep-pop-body { position: absolute; right: 0; top: calc(100% + 4px); z-index: 20; width: min(380px, 85vw); padding: 10px 12px;
  background: var(--surface); border: var(--seam) solid var(--border-strong); box-shadow: var(--shadow-float); font-size: 12.5px; color: var(--text-muted); }
#tab-endpoint .ep-pop-body p { margin: 0; }
#tab-endpoint .ep-pop-body dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 12px; margin: 8px 0 0; }
#tab-endpoint .ep-pop-body dd { margin: 0; }
#tab-endpoint .ep-link { background: none; border: 0; padding: 0; color: var(--primary); cursor: pointer; font-family: var(--font-data); font-size: 12px; }
#tab-endpoint .ep-link:hover { text-decoration: underline; }
```

- [ ] **Step 6: i18n**

`it`: `ptSwitchAll: "Tutti (solo problemi)",` and `ptOnlyBad: "Solo problemi",`
`en`: `ptSwitchAll: "All (problems only)",` and `ptOnlyBad: "Problems only",`
Delete from both blocks the keys left without readers: `peShow`, `peShowBad`,
`peShowAll`, `peDeviceAll`, `epModeList`, `epModePorts`, `epPortsPick` — each
only after `grep -n "'<key>'\|\"<key>\"\|\.<key>\b" static/js/*.js templates/dashboard.html`
shows no reader.

- [ ] **Step 7: Run tests, gates, commit**

```bash
uv run pytest tests/test_endpoint_tab.py tests/test_endpoint_inventory_ui.py tests/test_interface_errors_api.py -v
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
uv run pytest tests -n 4
git add templates/dashboard.html static/js/endpoint-inventory.js static/js/client-map.js static/css/dashboard.css static/js/i18n.js tests/test_endpoint_tab.py tests/js/test_endpoint_inventory_ui.mjs
git commit -m "feat(endpoints): Porte view merges port occupancy and port errors

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Diagnosi form

Markup only; every id stays.

**Files:**
- Modify: `templates/dashboard.html` (`#locPane-diagnosi`)
- Modify: `static/css/dashboard.css`, `static/js/i18n.js`, maybe `static/js/diagnosi.js`
- Test: `tests/test_endpoint_tab.py`

- [ ] **Step 1: Failing test**

```python
class TestDiagnosiForm(unittest.TestCase):
    def test_ids_kept_inline_styles_gone(self):
        html = _read("templates", "dashboard.html")
        start = html.index('id="locPane-diagnosi"')
        pane = html[start:html.index('id="diagResult"', start)]
        for _id in ("diagClientInput", "diagDestInput", "diagProtoInput", "diagPortInput",
                    "diagGatewaySelect", "diagGatewayInput", "btnDiagTraceroute", "btnRunDiagnosi"):
            self.assertIn(f'id="{_id}"', pane)
        self.assertNotIn("style=", pane)
        self.assertIn('class="diag-adv"', pane)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_endpoint_tab.py::TestDiagnosiForm -v`
Expected: FAIL (`style=` present).

- [ ] **Step 3: Template**

Replace the `<div class="panel" …>` holding the diagnosis form (everything
inside `#locPane-diagnosi` before `<div id="diagResult"></div>`) with the
markup below. Before deleting the old Traceroute button, copy its `title` /
`data-i18n-title` attributes onto the new one.

```html
      <form id="diagForm" class="diag-row">
        <div class="diag-fg diag-grow">
          <label for="diagClientInput" data-i18n="lblDiagClient"></label>
          <input id="diagClientInput" type="text" placeholder="192.0.2.10 / aa:bb:cc:dd:ee:ff">
        </div>
        <div class="diag-fg diag-grow">
          <label for="diagDestInput" data-i18n="lblDiagDest"></label>
          <input id="diagDestInput" type="text">
        </div>
        <div class="diag-fg">
          <label for="diagProtoInput" data-i18n="lblFgtProto"></label>
          <select id="diagProtoInput"><option value="TCP">TCP</option><option value="UDP">UDP</option><option value="ICMP">ICMP</option></select>
        </div>
        <div class="diag-fg">
          <label for="diagPortInput" data-i18n="colFgtSessDport"></label>
          <input id="diagPortInput" class="diag-port" type="number" min="1" max="65535" value="443">
        </div>
        <button class="btn btn-primary" id="btnRunDiagnosi" type="button" data-i18n="btnDiagRun"></button>
        <span class="preview-badge" data-i18n-title="titleDiagPreview" title="Non ancora validato su hardware reale. I risultati possono essere incompleti.">preview</span>
        <details class="diag-adv">
          <summary data-i18n="diagAdvanced">Avanzate: gateway L3</summary>
          <div class="diag-row diag-row-inner">
            <div class="diag-fg">
              <label for="diagGatewaySelect" data-i18n="lblDiagGateway">Gateway L3</label>
              <select id="diagGatewaySelect"><option value="">Auto (ARP / Subnet)</option></select>
            </div>
            <div class="diag-fg">
              <label for="diagGatewayInput" data-i18n="lblDiagGatewayIp">Oppure IP</label>
              <input id="diagGatewayInput" type="text" placeholder="192.0.2.1">
            </div>
            <button class="btn btn-secondary btn-small" id="btnDiagTraceroute" type="button"><i class="fa-solid fa-route"></i> Traceroute</button>
          </div>
        </details>
      </form>
```

`grep -n "btnRunDiagnosi\|diagClientInput.*keydown\|Enter" static/js/diagnosi.js`:
if Enter in the inputs does not already run the diagnosis, add to `diagnosi.js`:

```js
document.getElementById('diagForm')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (/** @type {HTMLElement} */ (e.target)).tagName === 'INPUT') { e.preventDefault(); runDiagnosi(); }
});
```

- [ ] **Step 4: CSS**

```css
/* Diagnosi form */
#tab-endpoint .diag-row { display: flex; flex-wrap: wrap; gap: 10px 12px; align-items: flex-end; padding: 12px; margin-bottom: 14px;
  background: var(--surface); border: var(--seam) solid var(--border); }
#tab-endpoint .diag-row-inner { border: 0; padding: 10px 0 0; margin: 0; }
#tab-endpoint .diag-fg { display: grid; gap: 4px; min-width: 0; }
#tab-endpoint .diag-fg label { font-family: var(--font-legend); font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--text-soft); margin: 0; }
#tab-endpoint .diag-fg input, #tab-endpoint .diag-fg select { font-family: var(--font-data); font-size: 13px; padding: 7px 9px; margin: 0; }
#tab-endpoint .diag-grow { flex: 1 1 200px; }
#tab-endpoint .diag-port { width: 96px; }
#tab-endpoint .diag-row > .btn { width: auto; margin: 0; }
#tab-endpoint .diag-adv { flex-basis: 100%; font-size: 12.5px; }
#tab-endpoint .diag-adv summary { cursor: pointer; color: var(--primary); }
```

- [ ] **Step 5: i18n**

Add only keys that do not exist yet (`grep -n "diagAdvanced:\|lblDiagGateway:\|lblDiagGatewayIp:" static/js/i18n.js`):
`it`: `diagAdvanced: "Avanzate: gateway L3",` `lblDiagGateway: "Gateway L3",` `lblDiagGatewayIp: "Oppure IP",`
`en`: `diagAdvanced: "Advanced: L3 gateway",` `lblDiagGateway: "L3 gateway",` `lblDiagGatewayIp: "Or IP",`

- [ ] **Step 6: Run tests, gates, commit**

```bash
uv run pytest tests/test_endpoint_tab.py tests/test_client_diagnosis.py tests/test_ui_revamp.py -n 4
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
uv run pytest tests -n 4
git add templates/dashboard.html static/css/dashboard.css static/js/i18n.js static/js/diagnosi.js tests/test_endpoint_tab.py
git commit -m "feat(endpoints): compact diagnosis form, gateway under Advanced

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Raccolta — site pickers and "Raccogli ora"

**Files:**
- Modify: `templates/dashboard.html` (`#locPane-raccolta`, `#locHeadActions`)
- Modify: `static/js/client-map.js`
- Modify: `static/css/dashboard.css`, `static/js/i18n.js`
- Test: `tests/test_endpoint_tab.py`, `tests/test_ui_revamp.py` (id list)

**Interfaces:**
- Consumes: `pickerGroups`, `pickerSummary` (Task 2), `macFilteredDevices`,
  `locationLabel`, `closeEpDrawer` (Task 4).
- Produces: `resetDevPickers()`, `renderDevPicker(kind)` (`kind` =
  `'mac'|'arp'`), `pickerSelectedIps(kind)` → `string[]`,
  `runMacScan(ips, btn)`, `runArpScan(ips, btn)`, `renderCollectSites()`,
  `runCollect()`; ids `#macPicker`, `#arpPicker`, `#macScanResult`,
  `#locCollectPop`, `#locCollectSites`, `#locCollectSum`, `#locCollectGo`.
  Removed: `#macDeviceMenu`, `#macDeviceSummary`, `#macDeviceList`,
  `#arpDeviceMenu`, `#arpDeviceSummary`, `#arpDeviceList` and their functions.

- [ ] **Step 1: Failing tests**

Append to `tests/test_endpoint_tab.py`:

```python
class TestCollectionView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "client-map.js")

    def test_site_pickers_replace_the_flat_lists(self):
        for _id in ("macPicker", "arpPicker", "locCollectPop", "locCollectSites", "locCollectGo"):
            self.assertIn(f'id="{_id}"', self.html)
        for gone in ("macDeviceList", "arpDeviceList", "macDeviceMenu", "arpDeviceMenu"):
            self.assertNotIn(f'id="{gone}"', self.html)
            self.assertNotIn(gone, self.js)

    def test_an_empty_selection_never_means_everything(self):
        # The old pickers sent no "ips" when nothing was ticked, and the
        # server read that as "every device of the tenant".
        for fn in ("async function runMacScan(", "async function runArpScan("):
            start = self.js.index(fn)
            body = self.js[start:self.js.index("\n    }\n", start)]
            self.assertIn("if (!ips.length)", body, fn)
            self.assertIn("payload.ips = ips", body, fn)
            self.assertNotIn("if (ips.length) payload.ips", body, fn)

    def test_collect_now_is_a_write_action(self):
        start = self.html.index('id="locCollectPop"')
        tag = self.html[self.html.rindex("<details", 0, start):self.html.index(">", start)]
        self.assertIn("requires-write", tag)
```

In `tests/test_ui_revamp.py::test_preserve_ids_mac`, delete `'macDeviceMenu',
'macDeviceSummary', 'macDeviceList'` from the id tuple and add `'macPicker',
'arpPicker'`.

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_endpoint_tab.py::TestCollectionView -v`
Expected: FAIL.

- [ ] **Step 3: Template**

In `#locHeadActions` (empty since Task 3) put:

```html
          <details id="locCollectPop" class="loc-collect requires-write">
            <summary class="btn btn-primary"><i class="fa-solid fa-rotate"></i> <span data-i18n="locCollectNow">Raccogli ora</span></summary>
            <div class="loc-collect-panel">
              <div class="pk-site-head" data-i18n="locCollectSites">Sedi da raccogliere</div>
              <div id="locCollectSites" class="pk-list"></div>
              <div class="pk-foot"><span id="locCollectSum"></span>
                <button type="button" class="btn btn-primary btn-small" id="locCollectGo" data-i18n="locCollectGo">Avvia MAC + ARP</button></div>
            </div>
          </details>
```

In `#locPane-raccolta`, inside the MAC/ARP collect row:
- `<div class="mac-row mac-collect">` → `<div class="mac-collect">`;
- each `<div class="mac-group">` → `<section class="mac-block">` (closing tag
  `</section>`), and its `<span class="mac-legend" data-i18n="…">…</span>` →
  `<h3 class="mac-block-title" data-i18n="…">…</h3>` (same `data-i18n` key);
- `<details id="macDeviceMenu" class="mac-dev-menu">…</details>` →
  `<div id="macPicker" class="dev-picker" data-picker="mac"></div>`;
- `<details id="arpDeviceMenu" class="mac-dev-menu">…</details>` →
  `<div id="arpPicker" class="dev-picker" data-picker="arp"></div>`;
- right after `#btnMacScan` add
  `<div id="macScanResult" class="mac-result" role="status" hidden></div>`;
- move `#arpScanSummary` inside the ARP `<section>`, after `#btnArpScan`, as
  `<div id="arpScanSummary" class="mac-result" role="status" hidden></div>`
  (no inline style).

- [ ] **Step 4: JS**

In `static/js/client-map.js`:

1. Delete `populateMacScanDevices`, `selectedMacDevices`, `toggleAllMacDevices`,
   `updateMacDeviceSummary`, `arpFilteredDevices`, `populateArpScanDevices`,
   `selectedArpDevices`, `toggleAllArpDevices`, `updateArpDeviceSummary`, and
   the `#macDeviceList` / `#arpDeviceList` change listeners. Keep
   `macFilteredDevices` and `fillMacDeviceSelect`.
2. Add (top level, after `pickerSummary`):

```js
// ===== Site-grouped device pickers (Raccolta) =====
const _pickSel = { mac: new Set(), arp: new Set() };
const _pickFilter = { mac: '', arp: '' };

function _pickSiteLabel(loc) {
    return loc ? locationLabel(loc) : tr('locNoSite');
}

// First load or tenant change: everything selected, the old default.
function resetDevPickers() {
    const ips = macFilteredDevices().map(d => d.IP);
    _pickSel.mac = new Set(ips);
    _pickSel.arp = new Set(ips);
    _collectSites = null;
    renderDevPicker('mac');
    renderDevPicker('arp');
    renderCollectSites();
}

function pickerSelectedIps(kind) {
    return [..._pickSel[kind]];
}

function renderDevPicker(kind) {
    const host = document.getElementById(kind + 'Picker');
    if (!host) return;
    const wasOpen = !!host.querySelector('details')?.open;
    const groups = pickerGroups(macFilteredDevices(), _pickSel[kind], _pickSiteLabel);
    const s = pickerSummary(groups);
    const summary = s.kind === 'none' ? tr('pickSumNone')
        : s.kind === 'all' ? tr('pickSumAll', { n: String(s.n), s: String(groups.length) })
        : s.kind === 'sites' ? tr('pickSumSites', { sites: s.sites.join(', '), n: String(s.n) })
        : tr('pickSumPartial', { n: String(s.n), total: String(s.total), s: String(s.sites.length) });
    const f = _pickFilter[kind].toLowerCase();
    const list = groups.map(g => {
        const shown = g.devices.filter(d => !f || (d.name + ' ' + d.ip + ' ' + g.label).toLowerCase().includes(f));
        if (!shown.length) return '';
        return `<label class="pk-site"><input type="checkbox" data-pick-site="${escapeHtml(g.key)}" ${g.n === g.total ? 'checked' : ''}
                    ${g.n && g.n < g.total ? 'data-mixed="1"' : ''}> ${escapeHtml(g.label)} <small>${g.n}/${g.total}</small></label>` +
            shown.map(d => `<label class="pk-dev"><input type="checkbox" data-pick-ip="${escapeHtml(d.ip)}" ${d.checked ? 'checked' : ''}>
                    ${escapeHtml(d.name)} <span>${escapeHtml(d.ip)}</span></label>`).join('');
    }).join('') || `<div class="pk-empty">${escapeHtml(tr('uiNoDevices'))}</div>`;
    const chips = groups.map(g => `<button type="button" class="pk-chip" data-pick-only="${escapeHtml(g.key)}"
            aria-label="${escapeHtml(tr('pickOnlySite', { site: g.label }))}">${escapeHtml(g.label)}</button>`).join('');
    host.innerHTML = `<details class="pk" ${wasOpen ? 'open' : ''}>
        <summary aria-label="${escapeHtml(tr(kind === 'mac' ? 'ariaMacPicker' : 'ariaArpPicker'))}"><span>${escapeHtml(summary)}</span><i class="fa-solid fa-chevron-down" aria-hidden="true"></i></summary>
        <div class="pk-panel">
          <div class="pk-chips">${chips}</div>
          <div class="pk-search"><input type="search" data-pick-filter="1" value="${escapeHtml(_pickFilter[kind])}"
              placeholder="${escapeHtml(tr('pickFilterPh'))}" aria-label="${escapeHtml(tr('pickFilterPh'))}"></div>
          <div class="pk-list">${list}</div>
          <div class="pk-foot"><span>${escapeHtml(tr('pickSelectedN', { n: String(s.n) }))}</span>
            <span><button type="button" data-pick-all="1">${escapeHtml(tr('pickAll'))}</button>
                  <button type="button" data-pick-none="1">${escapeHtml(tr('pickNone'))}</button></span></div>
        </div></details>`;
    host.querySelectorAll('[data-mixed]').forEach(cb => { /** @type {HTMLInputElement} */ (cb).indeterminate = true; });
}

for (const kind of ['mac', 'arp']) {
    const host = document.getElementById(kind + 'Picker');
    host?.addEventListener('change', (e) => {
        const t = /** @type {HTMLInputElement} */ (e.target);
        const set = _pickSel[kind];
        if (t.dataset.pickIp) { if (t.checked) set.add(t.dataset.pickIp); else set.delete(t.dataset.pickIp); }
        if (t.dataset.pickSite !== undefined) {
            macFilteredDevices().filter(d => (d.Location || '') === t.dataset.pickSite)
                .forEach(d => { if (t.checked) set.add(d.IP); else set.delete(d.IP); });
        }
        if (!t.dataset.pickFilter) renderDevPicker(kind);
    });
    host?.addEventListener('input', (e) => {
        const t = /** @type {HTMLInputElement} */ (e.target);
        if (!t.dataset.pickFilter) return;
        _pickFilter[kind] = t.value;
        const pos = t.selectionStart;
        renderDevPicker(kind);
        const again = /** @type {HTMLInputElement|null} */ (host.querySelector('[data-pick-filter]'));
        again?.focus();
        if (again && pos !== null) again.setSelectionRange(pos, pos);
    });
    host?.addEventListener('click', (e) => {
        const t = /** @type {HTMLElement} */ (e.target);
        const devs = macFilteredDevices();
        if (t.closest('[data-pick-all]')) _pickSel[kind] = new Set(devs.map(d => d.IP));
        else if (t.closest('[data-pick-none]')) _pickSel[kind] = new Set();
        else {
            const only = /** @type {HTMLElement|null} */ (t.closest('[data-pick-only]'));
            if (!only) return;
            _pickSel[kind] = new Set(devs.filter(d => (d.Location || '') === only.dataset.pickOnly).map(d => d.IP));
        }
        renderDevPicker(kind);
    });
}

// An open picker or the collect popover closes on an outside click.
document.addEventListener('click', (e) => {
    const t = /** @type {HTMLElement} */ (e.target);
    document.querySelectorAll('#tab-endpoint details.pk[open], #locCollectPop[open]').forEach(d => {
        if (!d.contains(t)) /** @type {HTMLDetailsElement} */ (d).open = false;
    });
});

// ===== "Raccogli ora": MAC scan then ARP on the chosen sites =====
let _collectSites = null;      // Set of Location ids ('' = no site); null = not built yet (all)

function renderCollectSites() {
    const box = document.getElementById('locCollectSites');
    if (!box) return;
    const devs = macFilteredDevices();
    const groups = pickerGroups(devs, new Set(), _pickSiteLabel);
    if (_collectSites === null) _collectSites = new Set(groups.map(g => g.key));
    const sites = _collectSites;
    box.innerHTML = groups.map(g => `<label class="pk-dev pk-dev-site"><input type="checkbox" data-collect-site="${escapeHtml(g.key)}"
        ${sites.has(g.key) ? 'checked' : ''}> ${escapeHtml(g.label)} <span>${g.total}</span></label>`).join('')
        || `<div class="pk-empty">${escapeHtml(tr('uiNoDevices'))}</div>`;
    const n = devs.filter(d => sites.has(d.Location || '')).length;
    const sum = document.getElementById('locCollectSum');
    if (sum) sum.textContent = tr('locCollectSum', { n: String(n), s: String(sites.size) });
    const go = /** @type {HTMLButtonElement|null} */ (document.getElementById('locCollectGo'));
    if (go) go.disabled = !n;
}

document.getElementById('locCollectSites')?.addEventListener('change', (e) => {
    const t = /** @type {HTMLInputElement} */ (e.target);
    if (t.dataset.collectSite === undefined || !_collectSites) return;
    if (t.checked) _collectSites.add(t.dataset.collectSite); else _collectSites.delete(t.dataset.collectSite);
    renderCollectSites();
});

async function runCollect() {
    const sites = _collectSites || new Set();
    const ips = macFilteredDevices().filter(d => sites.has(d.Location || '')).map(d => d.IP);
    const pop = /** @type {HTMLDetailsElement|null} */ (document.getElementById('locCollectPop'));
    if (pop) pop.open = false;
    const go = /** @type {HTMLButtonElement|null} */ (document.getElementById('locCollectGo'));
    await runMacScan(ips, go);
    await runArpScan(ips, go);
}
document.getElementById('locCollectGo')?.addEventListener('click', runCollect);
```

3. Replace `runMacScan` with:

```js
    async function runMacScan(ips, btn) {
        const result = document.getElementById('macScanResult');
        if (!ips.length) {
            if (result) { result.hidden = false; result.textContent = tr('pickEmptyRun'); }
            return;
        }
        const transport = /** @type {HTMLSelectElement|null} */ (document.getElementById('macScanTransport'))?.value || '';
        const payload = { group: locTenant(), transport };
        payload.ips = ips;
        const orig = btn ? btn.innerHTML : '';
        if (btn) { btn.disabled = true; btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> ${tr('cmapScanning')}`; }
        try {
            const res = await apiFetch('/api/mac/scan', {
                method: 'POST', headers: {'Content-Type':'application/json'},
                body: JSON.stringify(payload)
            });
            if (res && res.ok) {
                const d = await res.json();
                const okc = d.results.filter(r => !r.error).length;
                const errc = d.results.filter(r => r.error).length;
                if (result) {
                    result.hidden = false;
                    result.textContent = tr('cmapMacScanDoneDevices', {scanned: d.scanned, okc: okc, errc: errc, pruned: d.pruned});
                }
                _locLoaded.endpoint = false;   // the list reloads the next time it is opened
                refreshMacStats(false);
            } else if (res) {
                const e = await res.json().catch(() => ({}));
                showToast((tr('uiError')) + (e.detail || ''), 'error');
            }
        } finally {
            if (btn) { btn.disabled = false; btn.innerHTML = orig; }
        }
    }
```

   In `runArpScan`: signature `async function runArpScan(ips, btn)`; replace
   everything before `const res = await apiFetch('/api/arp/scan'` with:

```js
        const box = document.getElementById('arpScanSummary');
        if (!ips.length) {
            if (box) { box.hidden = false; box.textContent = tr('pickEmptyRun'); }
            return;
        }
        const oldHtml = btn ? btn.innerHTML : '';
        if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ...'; }
        try {
            const payload = { group: locTenant() };
            payload.ips = ips;
```

   delete its later `const box = document.getElementById('arpScanSummary');`
   (now declared above), replace every `box.style.display = 'block';` with
   `box.hidden = false;`, the `finally` body with
   `if (btn) { btn.disabled = false; btn.innerHTML = oldHtml; }`, and prefix
   each device row with its site — add before the `rows` mapping:

```js
            const siteOf = ip => _pickSiteLabel((macFilteredDevices().find(d => d.IP === ip) || {}).Location || '');
```

   and in the row template use `<b>${escapeHtml(siteOf(ip))} · ${escapeHtml(ip)}</b>`.

4. Replace the `btnMacScan` / `btnArpScan` listeners with:

```js
    document.getElementById('btnMacScan')?.addEventListener('click', (e) =>
        runMacScan(pickerSelectedIps('mac'), /** @type {HTMLButtonElement} */ (e.currentTarget)));
    document.getElementById('btnArpScan')?.addEventListener('click', (e) =>
        runArpScan(pickerSelectedIps('arp'), /** @type {HTMLButtonElement} */ (e.currentTarget)));
```

5. `loadRaccolta()` becomes:

```js
    function loadRaccolta() {
        fillMacDeviceSelect(document.getElementById('macOvDevice'), false);
        loadMacOverrides();
        refreshMacStats(true);
    }
```

   The pickers and the header popover belong to the whole tab (the popover is
   visible from every view), so they are built when the tab opens and when the
   tenant changes, not by the Raccolta loader:
   - in `locSwitchView`, as the first line after the `getElementById` guard:
     `    if (_collectSites === null) resetDevPickers();`
   - in `locTenantChanged`, after `closeEpDrawer();`: `    resetDevPickers();`

- [ ] **Step 5: CSS**

```css
/* Raccolta: blocks and the site-grouped device picker */
#tab-endpoint .mac-collect { display: grid; gap: 12px; }
#tab-endpoint .mac-block { background: var(--surface); border: var(--seam) solid var(--border); padding: 0 14px 12px; display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; }
#tab-endpoint .mac-block-title { flex-basis: calc(100% + 28px); margin: 0 -14px; padding: 8px 14px; background: var(--surface-2); border-bottom: 1px solid var(--border);
  font-family: var(--font-legend); font-size: 12px; font-weight: 600; letter-spacing: 0.14em; text-transform: uppercase; color: var(--text-muted); }
#tab-endpoint .mac-result { flex-basis: 100%; font-family: var(--font-data); font-size: 12px; padding: 8px 10px; background: var(--surface-2); border: 1px solid var(--border); }
#tab-endpoint .pk { position: relative; }
#tab-endpoint .pk > summary { list-style: none; display: flex; justify-content: space-between; gap: 10px; align-items: center; min-width: 260px; cursor: pointer;
  padding: 7px 9px; font-family: var(--font-data); font-size: 13px; background: var(--surface-2); border: 1px solid var(--border); }
#tab-endpoint .pk > summary::-webkit-details-marker { display: none; }
#tab-endpoint .pk[open] > summary { border-color: var(--primary); }
#tab-endpoint .pk-panel, #tab-endpoint .loc-collect-panel { position: absolute; z-index: 30; top: calc(100% + 4px); left: 0; width: min(360px, calc(100vw - 32px));
  display: grid; background: var(--surface); border: var(--seam) solid var(--border-strong); box-shadow: var(--shadow-float); }
#tab-endpoint .loc-collect { position: relative; }
#tab-endpoint .loc-collect > summary { list-style: none; }
#tab-endpoint .loc-collect > summary::-webkit-details-marker { display: none; }
#tab-endpoint .loc-collect-panel { left: auto; right: 0; }
#tab-endpoint .pk-chips { display: flex; flex-wrap: wrap; gap: 6px; padding: 8px; border-bottom: 1px solid var(--border); }
#tab-endpoint .pk-chip { font-family: var(--font-legend); font-size: 11px; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase;
  padding: 3px 8px; background: var(--surface); color: var(--text-muted); border: 1px solid var(--border); cursor: pointer; }
#tab-endpoint .pk-chip:hover { border-color: var(--primary); color: var(--primary); }
#tab-endpoint .pk-search { padding: 8px; border-bottom: 1px solid var(--border); }
#tab-endpoint .pk-search input { width: 100%; margin: 0; font-family: var(--font-data); font-size: 12.5px; padding: 6px 8px; }
#tab-endpoint .pk-list { max-height: 300px; overflow: auto; padding: 4px 0; }
#tab-endpoint .pk-site, #tab-endpoint .pk-site-head { display: flex; align-items: center; gap: 8px; padding: 8px 12px 4px; font-family: var(--font-legend);
  font-size: 11.5px; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase; color: var(--text-muted); }
#tab-endpoint .pk-site small { margin-left: auto; font-family: var(--font-data); letter-spacing: 0; color: var(--text-soft); }
#tab-endpoint .pk-dev { display: flex; align-items: center; gap: 8px; padding: 4px 12px 4px 32px; font-size: 13px; cursor: pointer; }
#tab-endpoint .pk-dev-site { padding-left: 12px; }
#tab-endpoint .pk-dev:hover { background: var(--surface-2); }
#tab-endpoint .pk-dev span { margin-left: auto; font-family: var(--font-data); font-size: 11.5px; color: var(--text-soft); }
#tab-endpoint .pk input[type="checkbox"], #tab-endpoint .loc-collect input[type="checkbox"] { accent-color: var(--primary); margin: 0; width: auto; }
#tab-endpoint .pk-foot { display: flex; justify-content: space-between; align-items: center; gap: 8px; padding: 8px 12px; border-top: 1px solid var(--border);
  font-size: 12px; color: var(--text-muted); }
#tab-endpoint .pk-foot button:not(.btn) { background: none; border: 0; color: var(--primary); cursor: pointer; font-size: 12px; padding: 0 0 0 10px; }
#tab-endpoint .pk-foot .btn { width: auto; margin: 0; }
#tab-endpoint .pk-empty { padding: 14px; text-align: center; color: var(--text-muted); font-size: 12.5px; }
```

Delete the rules left without users
(`grep -n "mac-dev-menu\|mac-dev-list\|\.mac-search\|\.mac-group\|\.mac-legend" static/css/dashboard.css templates/dashboard.html static/js/*.js`):
remove a CSS rule only when its class no longer appears in the template or JS.

- [ ] **Step 6: i18n**

`it`:

```js
        locCollectNow: "Raccogli ora",
        locCollectSites: "Sedi da raccogliere",
        locCollectGo: "Avvia MAC + ARP",
        locCollectSum: "{n} dispositivi in {s} sedi",
        locNoSite: "Senza sede",
        pickSumAll: "Tutti ({n}) · {s} sedi",
        pickSumNone: "Nessuno selezionato",
        pickSumSites: "{sites} · {n}",
        pickSumPartial: "{n} di {total} · {s} sedi",
        pickSelectedN: "{n} selezionati",
        pickFilterPh: "Filtra per nome, IP o sede",
        pickOnlySite: "Solo {site}",
        pickAll: "Tutti",
        pickNone: "Nessuno",
        pickEmptyRun: "Seleziona almeno un dispositivo.",
        ariaMacPicker: "Dispositivi per la scansione MAC",
        ariaArpPicker: "Dispositivi per la raccolta ARP",
```

`en`:

```js
        locCollectNow: "Collect now",
        locCollectSites: "Sites to collect",
        locCollectGo: "Run MAC + ARP",
        locCollectSum: "{n} devices in {s} sites",
        locNoSite: "No site",
        pickSumAll: "All ({n}) · {s} sites",
        pickSumNone: "None selected",
        pickSumSites: "{sites} · {n}",
        pickSumPartial: "{n} of {total} · {s} sites",
        pickSelectedN: "{n} selected",
        pickFilterPh: "Filter by name, IP or site",
        pickOnlySite: "Only {site}",
        pickAll: "All",
        pickNone: "None",
        pickEmptyRun: "Select at least one device.",
        ariaMacPicker: "Devices for the MAC scan",
        ariaArpPicker: "Devices for the ARP collection",
```

Remove keys left without readers (`cmapAllDevices`, `cmapSelected`,
`optMacAllDevices`) only after grepping each; `lblAiDevSelected` and
`msgAiNoDevices` belong to the AI tab and stay.

- [ ] **Step 7: Run tests, gates, commit**

```bash
uv run pytest tests/test_endpoint_tab.py tests/test_device_picker.py tests/test_ui_revamp.py tests/test_lazy_tab_scripts.py -n 4
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
uv run pytest tests -n 4
git add templates/dashboard.html static/js/client-map.js static/css/dashboard.css static/js/i18n.js tests/test_endpoint_tab.py tests/test_ui_revamp.py
git commit -m "feat(endpoints): site-grouped scan pickers and Collect now by site

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Sweep, changelog, verification

**Files:**
- Modify: `CHANGELOG.md`, `static/js/i18n.js` / `static/css/dashboard.css` (leftovers only)

- [ ] **Step 1: Leftovers**

```bash
grep -n "locPill\|locPane-mac\|locPane-inventory\|locPane-porterrors\|epModeListBtn\|peResults\|macDeviceList\|macLocate\|ep-row-toggle\|LOC_HEADINGS\|_epMode\|loadMacTracker" static/js/*.js templates/dashboard.html tests/*.py tests/js/*.mjs
```

Expected: no output. Point anything left at the id that replaced it.

- [ ] **Step 2: CHANGELOG**

Under `## [Unreleased]` in `CHANGELOG.md`:

```markdown
### Changed

- **Localizzazione endpoint ridisegnata**: una ricerca unica (MAC, IP, vendor,
  switch, porta) in testa al tab, un pannello di dettaglio a destra al posto
  della modale "Localizza" e della riga espansa, e quattro viste: Endpoint,
  Porte (occupazione ed errori insieme), Diagnosi, Raccolta.
- **Scansioni per sede**: i selettori dei dispositivi per MAC scan e ARP sono
  raggruppati per sede, con selezione di una sede intera o di una sola; "Raccogli
  ora" lancia MAC + ARP sulle sedi scelte. Una selezione vuota non vale più come
  "tutti i dispositivi".

### Added

- Ricerca degli endpoint per indirizzo IP completo, attraverso i binding ARP.

### Removed

- La ricerca separata sugli avvistamenti MAC raggruppati per switch: l'elenco
  Endpoint e il pannello di dettaglio (sezione Percorso) coprono la stessa
  domanda.
```

- [ ] **Step 3: Full gates**

```bash
uv run pyrefly check
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
uv run pytest tests -n 4
uv run python scripts/check_no_private_data.py
```

Expected: 0 errors, all green, "Nessun dato privato nell'albero tracciato."
Do not report a gate as passing without its output.

- [ ] **Step 4: Browser check (real app)**

Start the app and, in the Endpoint location tab, walk the spec's "Where every
current control goes" table row by row, then:
- Wide window: open a row → drawer docked, list still clickable; open a second
  row while the first is open; Esc closes; focus returns to the row.
- Window ≤ 900px: drawer as a sheet over a scrim; Esc and a click on the scrim
  close it.
- Change the global tenant with the drawer open → drawer closes, pickers reset.
- Search: an IP with an ARP binding → drawer opens; a vendor word → list; an
  unknown IP → message, view unchanged; clear the chip → full list.
- Raccolta: "only this site" chip → summary shows that site; untick everything
  → the run refuses with the message and no `/api/mac/scan` request appears in
  the network panel. "Raccogli ora" with two sites → MAC then ARP, ARP rows
  prefixed by site.
- Porte: a switch with errors → errors column visible, "Solo problemi" filters;
  "Tutti" → cross-device list; legend popover opens and closes.
- Light and dark theme.
Fix anything broken before continuing, with its own test where one fits.

- [ ] **Step 5: Screenshots and graph**

```bash
uv run python scripts/dev/capture_screenshots.py
git status --porcelain docs/images
graphify update .
```

Commit `docs/images` only if they changed. If `graphify update` refuses with
"fewer nodes", check what shrank — expected deletions: `macSearch`,
`renderMacResults`, `macLocate`, `_toggleEndpointDetail`, `endpointsMode`, the
old picker functions — before passing `--force`.

- [ ] **Step 6: Commit**

```bash
git add CHANGELOG.md
git add -u static/js/i18n.js static/css/dashboard.css docs/images
git commit -m "docs(changelog): endpoint location redesign

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 7: Rebuild the executable**

```bash
uv run pyinstaller SentinelNet.spec
```

Expected: build completes; report the output path.
