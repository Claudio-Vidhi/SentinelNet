# Schema View Readability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Four controls on the map's **Schema** view (Focus on click, port-label mode, wrapped rows, grouped uplinks) so a site with two cores and many dual-homed access switches can be read. The Hierarchy view is not touched.

**Architecture:** Everything lives in `static/js/topology.js` (Schema = `mapViewMode === 'minimal'`) and its toolbar in `templates/dashboard.html`. Each control is driven by one small **pure** helper. The helper is unit-tested with a Node harness (`tests/js/test_schema_readability.mjs`, same `extract(marker)` pattern as `tests/js/test_map_layout.mjs`) and wired into the existing code paths: `drawMinimalOverlay` (cables and labels), `packSchemaRows` (row layout) and the `selectNode`/`deselectNode` handlers. No backend change.

**Tech Stack:** Classic browser scripts with one shared global scope, vis-network 10.1.0 (vendored, supports per-node `opacity`), canvas overlay, Python `unittest` tests that wrap Node `.mjs` harnesses.

**Spec:** this plan plus the approved interactive preview at https://claude.ai/artifact/RMWUogL7mDwErK6vzhSxQJ (the visual target, not code to copy). Decisions that differ from the preview are listed under **Decisions**.

## Decisions (read before Task 3 and Task 4)

- **Focus table = the existing node drawer.** Clicking a node already opens the drawer, and `#drawerNeighborList` already lists neighbour, local and remote ports and the Po. Focus only adds the dimming. No new panel.
- **Wrapped rows = zigzag on two sub-rows, not N per row.** The overlay routes every vertical cable as *down → across → down* (`drawMinimalOverlay` PASSO 2), so a cable to a third sub-row would cross the boxes above it. With two sub-rows, a lower box sits centred in the gap of the upper row and its drop passes through that gap. Two sub-rows halve the width, and more sub-rows would not narrow it further: the drop clearance fixes the step at `maxW/2 + SCHEMA_GAP/2`. The preview's side channel and its "6/8/10 per riga" choice are therefore dropped. Wrapping applies only to a level row with more than `SCHEMA_WRAP_MIN = 8` boxes.
- **Toggling wrap re-runs the tidy** (`packSchemaRows`, the same action as "Riordina mappa"), so manual drags in that site are lost. The tooltip says so.
- **Grouped uplinks are a drawing change only.** No vis node is merged. The two core boxes stay where they are, and the merged cable leaves from the centre of their union box. A pair is grouped only when the two boxes are adjacent on the same row.
- **draw.io export:** grouping follows the screen. Dimming never applies (the existing `!visioConnectorSink` guard already does that for hover), and port labels are always exported (Task 2).

## Global Constraints

- Repo is PUBLIC: test data uses `switch-01`, `core-01`, `access-01`, `Gi1/0/49`, never real hostnames or IPs. Run `uv run python scripts/check_no_private_data.py`.
- New user-facing strings go through `tr('key')`, with the key in **both** languages in `static/js/i18n.js`. No `currentLang ===` ternary.
- No inline handlers in `dashboard.html`: bind by id in `topology.js` (`document.getElementById(id)?.addEventListener` next to `toggleMinimalHover`, around line 5114). Every id bound in JS must exist in the template.
- Every new control has an accessible name: `<label for>` or `aria-label` + `data-i18n-aria-label`.
- Schema-only controls sit in one wrapper, `#schemaReadWrap`, shown and hidden in `updateMapViewButtons()` like `#minimalHoverWrap`.
- Preferences live in `localStorage`, each read and write wrapped in try/catch: `schemaFocus` (`'1'`/`'0'`, default on), `schemaPortLabels` (`'all'|'focus'|'none'`, default `'all'`), `schemaWrap` (`'1'`/`'0'`, default off), `schemaGroupUplinks` (`'1'`/`'0'`, default off). Apart from the Focus dimming (on by default), the defaults leave the Schema view exactly as it is today.
- New comments in English. Leave the surrounding Italian comments alone.
- Gate before every commit: `uv run pyrefly check`, `uv run python scripts/check_frontend.py`, `uv run python scripts/check_i18n_coverage.py --strict`, `uv run python scripts/check_a11y.py --strict`, `uv run pytest tests -n 4`, `uv run python scripts/check_no_private_data.py`, `graphify update .`.
- Version: MINOR bump at release time (new feature), through the user's release script, not in these tasks.

## Review Focus

1. **Focus survives a re-render.** Changing a filter or tenant redraws the map: a stale `schemaFocusId` for a node that is gone must not dim everything. The focus is cleared in the render path (Task 1 test `test_focus_cleared_on_render`).
2. **Focus on a node with no cables.** Everything else dims and the node stays full. No exception (Task 1 harness case "isolated node").
3. **Hover and focus together.** Hover wins while the mouse is on a cable, and focus returns when it leaves (Task 1 harness case "hover beats focus").
4. **Zigzag with uneven widths.** One very wide box must not let a lower drop land inside an upper box (Task 3 harness case "wide box keeps drops in gaps").
5. **A "pair" that is not one.** Two adjacent top-row boxes with no link between them, sharing only one child, or with a box between them must not be grouped (Task 4 harness cases).

## File Structure

- Modify `static/js/topology.js`: five pure helpers (`schemaDimmed`, `schemaNeighbors`, `schemaPortLabelVisible`, `zigzagRow`, `schemaUplinkGroups`), the focus state, and the wiring into `drawMinimalOverlay`, `packSchemaRows`, `updateMapViewButtons` and the event bindings.
- Modify `templates/dashboard.html`: `#schemaReadWrap`, with four controls, after `#schemaTidyBtn` (around line 1085).
- Modify `static/js/i18n.js`: new keys in `it` and `en`.
- Create `tests/js/test_schema_readability.mjs`: Node harness for the helpers.
- Create `tests/test_map_schema_readability.py`: runs the harness (skipped without `node`), plus static template/source checks.
- Modify the changelog file used by commit `359624a2`, plus the `docs/images/` screenshots.

---

### Task 1: Focus on click

**Files:**
- Modify: `static/js/topology.js`: `selectNode`/`deselectNode`/`click` handlers (~1400-1422), the minimal render branch (~1073-1079), PASSO 3 alpha line in `drawMinimalOverlay` (~3510), `updateMapViewButtons` (~1248), bindings (~5114)
- Modify: `templates/dashboard.html` (~1085), `static/js/i18n.js`
- Create: `tests/js/test_schema_readability.mjs`, `tests/test_map_schema_readability.py`

**Interfaces:**
- Produces: `function schemaDimmed(b, key, hoverKey, focusId)` → `boolean`. `b` is a bundle (`from`, `to`, optional `ends: string[]`), `key` is `pillKey(b)`. Rule: if `hoverKey`, dimmed when `key !== hoverKey`; else if `focusId`, dimmed when `!(b.ends || [b.from, b.to]).includes(focusId)`; else `false`.
- Produces: `function schemaNeighbors(bundles, focusId)` → `Set<string>`: the focus plus every id in `b.ends || [b.from, b.to]` of the bundles touching it.
- Produces: `let schemaFocusId = null;` (module state), `function applySchemaFocus(id)`, which sets the state, sets `opacity: 0.35` on the vis nodes outside `schemaNeighbors(minimalOverlayData.bundles, id)` and `1` on the rest with one `ds.update([...])` (all `1` for `null`), and calls `networkInstance.redraw()`.
- Produces: the template wrapper `#schemaReadWrap` and the checkbox `#toggleSchemaFocus`, label key `lblSchemaFocus` ("Focus su clic" / "Focus on click").

- [ ] **Step 1: Write the failing tests.** In `tests/js/test_schema_readability.mjs`, extract `function schemaDimmed(` and `function schemaNeighbors(` with the `extract()` helper copied from `test_map_layout.mjs`, then:

```js
const b = (from, to, extra = {}) => ({ from, to, ...extra });
// no focus, no hover: nothing dims
assert.equal(schemaDimmed(b('core-01','access-01'), 'k1', null, null), false);
// focus dims cables not touching it
assert.equal(schemaDimmed(b('core-01','access-01'), 'k1', null, 'access-02'), true);
assert.equal(schemaDimmed(b('core-01','access-02'), 'k2', null, 'access-02'), false);
// hover beats focus
assert.equal(schemaDimmed(b('core-01','access-02'), 'k2', 'k1', 'access-02'), true);
assert.equal(schemaDimmed(b('core-01','access-01'), 'k1', 'k1', 'access-02'), false);
// grouped bundle: ends decide
assert.equal(schemaDimmed(b('__pair:core-01|core-02','access-01',{ ends:['core-01','core-02','access-01'] }), 'k3', null, 'core-02'), false);
// isolated node
assert.deepEqual([...schemaNeighbors([b('core-01','access-01')], 'switch-09')], ['switch-09']);
assert.deepEqual([...schemaNeighbors([b('core-01','access-01'), b('core-02','access-01')], 'access-01')].sort(),
                 ['access-01','core-01','core-02']);
```

Add `tests/test_map_schema_readability.py` with class `TestSchemaReadability`:
- `test_harness`: runs the `.mjs` (`@unittest.skipUnless(shutil.which("node"))`, same shape as `tests/test_map_layered.py:116-123`).
- `test_focus_control_wired`: `'id="toggleSchemaFocus"'` and `'id="schemaReadWrap"'` in the template; `"getElementById('toggleSchemaFocus')"` and `"getElementById('schemaReadWrap')"` in `topology.js`; no `onclick=` inside `#schemaReadWrap`.
- `test_focus_cleared_on_render`: the minimal render branch of `topology.js` (the block around `minimalOverlayData = { bundles, groupsInfo, nodes }`) contains `schemaFocusId = null`.

- [ ] **Step 2: Run them and check they fail**

Run: `uv run pytest tests/test_map_schema_readability.py -v`
Expected: FAIL (`function schemaDimmed( not found in topology.js`, missing ids).

- [ ] **Step 3: Implement**
  - Add the two helpers near `pillKey` (~3101).
  - In PASSO 3, replace the condition `hoverBundleKey && !visioConnectorSink && pillKey(b) !== hoverBundleKey` with `!visioConnectorSink && schemaDimmed(b, pillKey(b), hoverBundleKey, schemaFocusId)`.
  - In `selectNode`, when `getMapView() === 'minimal'` and `#toggleSchemaFocus` is checked, call `applySchemaFocus(id)` before `openTopologyNodeDrawer`. In `deselectNode` and on a click on empty space, call `applySchemaFocus(null)`.
  - In the render branch, set `schemaFocusId = null` when a new minimal map is built.
  - Template: `#schemaReadWrap` (`display:none`, same inline style as `#minimalHoverWrap`) containing a `<label for="toggleSchemaFocus">` checkbox.
  - In `updateMapViewButtons`, show the wrapper as `inline-flex` only for `'minimal'`, and restore `checked` from `localStorage.schemaFocus` (default on).
  - On `change`: save the value. When it turns off, call `applySchemaFocus(null)`.
  - i18n `lblSchemaFocus` in `it` and `en`.

- [ ] **Step 4: Run the tests and check they pass**

Run: `uv run pytest tests/test_map_schema_readability.py tests/test_i18n_keys.py tests/test_a11y_dashboard.py tests/test_map_layered.py tests/test_lazy_tab_scripts.py -v`
Expected: PASS.

- [ ] **Step 5: Check by hand.** `uv run python app_server.py`, Mappa → Schema, a tenant with several switches. Click a switch: its cables stay coloured, the rest fades, the drawer opens. Click empty space and everything returns. Hover a cable while a focus is set and only that cable stays bright.

- [ ] **Step 6: Commit** (full gate first)

```bash
git add static/js/topology.js templates/dashboard.html static/js/i18n.js tests/js/test_schema_readability.mjs tests/test_map_schema_readability.py
git commit -m "feat(map): Schema focus on click dims unrelated cables"
```

### Task 2: Port-label mode

**Files:**
- Modify: `static/js/topology.js`: `drawPortLabel` inside PASSO 3 (~3527), bindings, `updateMapViewButtons`
- Modify: `templates/dashboard.html` (inside `#schemaReadWrap`), `static/js/i18n.js`
- Test: `tests/js/test_schema_readability.mjs`, `tests/test_map_schema_readability.py`

**Interfaces:**
- Consumes: `schemaFocusId` (Task 1).
- Produces: `function schemaPortLabelVisible(mode, b, focusId)` → `boolean`: `'none'` → false; `'focus'` → `!!focusId && (b.ends || [b.from, b.to]).includes(focusId)`; anything else → true.
- Produces: the select `#schemaPortLabels`, options `all|focus|none`, label key `lblSchemaPortLabels` ("Etichette porta" / "Port labels"), option keys `optSchemaLblAll` ("Tutte"/"All"), `optSchemaLblFocus` ("Solo focus"/"Focus only"), `optSchemaLblNone` ("Nessuna"/"None").

- [ ] **Step 1: Write the failing tests.** In the harness:

```js
const L = b('core-01','access-01');
assert.equal(schemaPortLabelVisible('all', L, null), true);
assert.equal(schemaPortLabelVisible('none', L, 'core-01'), false);
assert.equal(schemaPortLabelVisible('focus', L, null), false);
assert.equal(schemaPortLabelVisible('focus', L, 'access-01'), true);
assert.equal(schemaPortLabelVisible('focus', L, 'access-02'), false);
assert.equal(schemaPortLabelVisible('bogus', L, null), true);   // unknown stored value = today's look
```

In the Python file, `test_label_select_wired`: the id is in the template inside `#schemaReadWrap` and bound in `topology.js`, and `drawPortLabel`'s body calls `schemaPortLabelVisible(`.

- [ ] **Step 2: Run them and check they fail.** `uv run pytest tests/test_map_schema_readability.py -v` → FAIL.

- [ ] **Step 3: Implement.**
  - Add the helper next to `schemaDimmed`.
  - At the top of `drawPortLabel`, return early when `!visioConnectorSink && !schemaPortLabelVisible(schemaPortLabelMode(), b, schemaFocusId)`. `schemaPortLabelMode()` reads `localStorage.schemaPortLabels` in try/catch (default `'all'`).
  - Port-channel names and brackets (`deferredTags`) are not port labels: they stay.
  - The export skips the check through the `visioConnectorSink` guard, so draw.io always gets every port name. Comment that.
  - On select `change`: save, then `networkInstance?.redraw()`. Restore the value in `updateMapViewButtons`. Add the i18n keys.

- [ ] **Step 4: Run the tests and check they pass** (same command as Task 1, Step 4).

- [ ] **Step 5: Check by hand.** With "Solo focus" and no selection there are no port labels. Click a core: only its labels appear. Export draw.io: all labels are present.

- [ ] **Step 6: Commit:** `feat(map): Schema port labels: all, focus only, none`

### Task 3: Wrapped rows (zigzag)

**Files:**
- Modify: `static/js/topology.js`: `packSchemaRows` (~2414-2477), bindings, `updateMapViewButtons`
- Modify: `templates/dashboard.html`, `static/js/i18n.js`
- Test: harness + Python file

**Interfaces:**
- Produces: `const SCHEMA_WRAP_MIN = 8;`
- Produces: `function zigzagRow(widths, gap)` → `Array<{ x: number, sub: 0|1 }>`. `x` is the box centre relative to the row's left edge; `widths` is in row order. Rule: `step = max(widths)/2 + gap/2`; box `i` gets `sub = i % 2` and `x = max(widths)/2 + i * step`.
- Produces: the checkbox `#toggleSchemaWrap`, label key `lblSchemaWrap` ("Righe a capo" / "Wrap rows"), and title key `titleSchemaWrap` ("Riordina la mappa: gli spostamenti manuali di questa sede si perdono" / "Re-tidies the map: manual moves on this site are lost").

- [ ] **Step 1: Write the failing tests:**

```js
const r = zigzagRow([100, 100, 100, 100], 70);
assert.deepEqual(r.map(p => p.sub), [0, 1, 0, 1]);
// same sub-row neighbours never closer than width + gap
assert.ok(r[2].x - r[0].x >= 100 + 70);
// wide box keeps drops in gaps: every lower centre is >= maxW/2 + gap/2 from every upper centre
const w = [80, 260, 80, 80, 80], z = zigzagRow(w, 70);
for (const lo of z.filter(p => p.sub === 1)) for (const up of z.filter(p => p.sub === 0))
    assert.ok(Math.abs(lo.x - up.x) >= 260 / 2 + 70 / 2 - 0.001);
```

In the Python file: `test_wrap_toggle_wired` (id in the template and bound in JS), and `packSchemaRows` calls `zigzagRow(` and references `SCHEMA_WRAP_MIN`.

- [ ] **Step 2: Run them and check they fail.**

- [ ] **Step 3: Implement.** In `packSchemaRows`, after the row is sorted by barycentre, check whether wrapping is on and `row.length > SCHEMA_WRAP_MIN`. If so:
  - Lay out with `zigzagRow(row.map(r => box[r.nd.id].w), SCHEMA_GAP)`. Sub-row 1 goes `maxH + 60` below sub-row 0 (60 leaves room for the fan runs of the drops).
  - Centre the block under the mean barycentre, the same way the existing `shift` code does.
  - Advance `top` by both sub-rows plus the existing inter-row term.
  - Otherwise keep today's code path unchanged.

  The checkbox `change` saves to `localStorage.schemaWrap`, then calls `packSchemaRows()`. `updateMapViewButtons` restores it. Add the i18n keys, and put the title on the label with `data-i18n-title`.

- [ ] **Step 4: Run the tests and check they pass.**

- [ ] **Step 5: Check by hand** on a tenant with more than 8 access switches under two cores:
  - The access row splits in two and the drawing is about half as wide.
  - Cables to the lower sub-row pass between the upper boxes without crossing them.
  - The level below the access switches sits under both sub-rows.
  - Turning the toggle off re-tidies back to one row.

- [ ] **Step 6: Commit:** `feat(map): Schema rows wrap in two staggered lines`

### Task 4: Grouped uplinks

**Files:**
- Modify: `static/js/topology.js`: `drawMinimalOverlay` (the `bbox` helper ~3297, PASSO 1 positions ~3321, `anchorPoint` ~3382, PASSO 3 drawing), bindings, `updateMapViewButtons`
- Modify: `templates/dashboard.html`, `static/js/i18n.js`
- Test: harness + Python file

**Interfaces:**
- Consumes: `schemaDimmed` and `schemaPortLabelVisible` read `b.ends` (Tasks 1 and 2).
- Produces: `function schemaUplinkGroups(bundles, levelOf, boxOf)` → `Array<{ id: string, pair: [string, string], target: string, parts: bundle[] }>`, where:
  - `levelOf(id)` → `number` (the vis node's `schemaLevel`)
  - `boxOf(id)` → `{left, right, top, bottom} | null`
  - `id = '__pair:' + p + '|' + q`, with `p` the left box
  - The order of the result is stable: by `target`, then `id`.

  Rules for a pair:
  - `p` and `q` have the same level.
  - A bundle joins them.
  - Their boxes overlap vertically.
  - No other box of that level lies horizontally between them.
  - At least **2** targets have a bundle to both.

  A target is grouped only when it has a bundle to each of `p` and `q`.

  When the location has two cores chosen in the toolbar's **Core** menu (`rootsOf(group)[zone]`, two ids), that pair is used as-is and the detection is skipped for it. The adjacency and shared-target rules still apply.
- Produces: the checkbox `#toggleSchemaGroupUplinks`, label key `lblSchemaGroupUplinks` ("Raggruppa uplink" / "Group uplinks").

- [ ] **Step 1: Write the failing tests.** Fixture:
  - `core-01` at x 0–180 and `core-02` at x 220–400, both level 0, joined by `b('core-01','core-02',{type:'pc'})`.
  - `access-01..03` at level 1, each with a bundle to both cores.
  - `access-04` with a bundle to `core-01` only.

```js
const g = schemaUplinkGroups(bundles, levelOf, boxOf);
assert.deepEqual(g.map(x => x.target), ['access-01','access-02','access-03']);
assert.deepEqual(g[0].pair, ['core-01','core-02']);
assert.equal(g[0].id, '__pair:core-01|core-02');
assert.equal(g[0].parts.length, 2);
// no link, no pair
assert.deepEqual(schemaUplinkGroups(bundles.filter(x => x.type !== 'pc'), levelOf, boxOf), []);
// one shared child, no pair
assert.deepEqual(schemaUplinkGroups(onlyAccess01Bundles, levelOf, boxOf), []);
// a box between them (switch-09 at level 0, x 190–210 widened to overlap the gap), no pair
assert.deepEqual(schemaUplinkGroups(bundles, levelOf, boxOfWithSwitch09Between), []);
```

  In the Python file: `test_group_toggle_wired`, and `drawMinimalOverlay` calls `schemaUplinkGroups(`.

- [ ] **Step 2: Run them and check they fail.**

- [ ] **Step 3: Implement.** At the start of `drawMinimalOverlay`, after the `bundles` check, when grouping is on (`localStorage.schemaGroupUplinks === '1'`):
  - Compute the groups.
  - Replace the bundles in `parts` with one synthetic bundle per group: `{ from: id, to: target, ends: [...pair, target], members: [{ local: '', remote: '' }], type: parts.some(p => p.type === 'pc' || p.type === 'peer') ? 'pc' : 'link', pcTag: '', label: '', grouped: '×' + parts.length }`.
  - Make the overlay's `bbox(id)` return the union of the two boxes for an id starting `'__pair:'`. Add a local `posOf(id)` (the centre of `bbox`) and use it in place of the two `networkInstance.getPosition` calls in PASSO 1 and `anchorPoint`.
  - In PASSO 3, draw a grouped bundle's `grouped` text in bold 9px, centred 12 px above its target anchor, in the cable colour.
  - The resize logic (`ds.get(id)` → undefined for a virtual id) already skips it: leave it.
  - The checkbox `change` saves the value and redraws.

- [ ] **Step 4: Run the tests and check they pass.**

- [ ] **Step 5: Check by hand.**
  - Two adjacent cores with shared access switches: one cable per access switch leaves from the gap between the cores, with "×2". Single-homed access switches keep their own cable.
  - Click a core: its grouped cables stay lit. The drawer still lists every port.
  - The draw.io export shows the grouped drawing with every port label.

- [ ] **Step 6: Commit:** `feat(map): Schema can group a core pair's uplinks`

### Task 5: Changelog, screenshots, final gate

**Files:**
- Modify: the changelog file used by commit `359624a2` (`git show --stat 359624a2`)
- Modify: `docs/images/*` via `uv run python scripts/dev/capture_screenshots.py`

- [ ] **Step 1:** Add one changelog entry under the unreleased section, in the existing style: Focus, port-label mode, wrapped rows, grouped uplinks (Schema view only).
- [ ] **Step 2:** `uv run python scripts/dev/capture_screenshots.py`, then look at the map screenshot and check that the Schema toolbar shows the new controls.
- [ ] **Step 3:** Run the full gate from **Global Constraints** and read each output: 0 pyrefly errors, frontend clean, i18n and a11y strict at zero, all tests green, no private data.
- [ ] **Step 4:** `uv run pyinstaller SentinelNet.spec --noconfirm` (the user's standing rule: rebuild the exe after changes).
- [ ] **Step 5: Commit:** `docs(changelog): Schema readability controls`. Pushing and the release stay with the user.
