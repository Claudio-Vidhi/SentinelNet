# Onboarding: New-Customer Wizard + First-Run Checklist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Onboard a whole customer — tenant, credentials, site, devices — from a single
guided flow, and tell a first-time user what to do next from the Home tab.

**Architecture:** Both features are **frontend only**. The wizard is a modal that calls
the existing endpoints in order (`POST /api/groups` -> `POST /api/identities` ->
`POST /api/sites` -> `POST /api/add-device` or `POST /api/import-csv`); the checklist
derives its state from the existing `GET` endpoints. No new route, no new persistence,
no server-side transaction: each step already validates, authorizes and audits itself,
and a partial run leaves real objects the user can keep or fix from the normal tabs.

**Tech Stack:** classic scripts in `static/js` (no bundler, one shared global scope),
`static/js/i18n.js` for copy, `types/globals.d.ts` for anything put on `window`,
node-based source assertions under `tests/js/` shelled out from a `unittest` test.

**Spec:** this document. It implements the two choices made on 2026-08-18: guided
"New customer" wizard for provisioning, first-run checklist on Home for the tutorial.

## Global Constraints

- Version bump: MINOR (`core/version.py` + `pyproject.toml` must match).
- New comments in English; leave surrounding Italian comments alone.
- Example data only: `192.0.2.x` / `198.51.100.x`, `switch-01`, `Customer A`.
- No inline `onclick`/`onsubmit` in `templates/dashboard.html`: id or `data-action`
  plus a delegated listener, bound to an id that actually exists in the template.
- Anything cross-module goes on `window` **and** into `types/globals.d.ts`.
  `core.js` globals are `let` — never read them as `window.X`.
- Never write `identities.json`, `users.json` or any credential file from a task; the
  running app writes them.
- Every user-visible string goes through `data-i18n` with a key in both languages.
- Pre-commit gate (`docs/development.md` §6): `uv run pyrefly check`,
  `uv run python scripts/check_frontend.py`, `uv run python -m unittest discover -s tests`,
  `graphify update .`.

---

## Why

Onboarding one customer today crosses five tabs out of twenty-one, in an order nothing
on screen states:

1. `tab-groups` — create the tenant (`POST /api/groups`)
2. `tab-provisioning` — create the identity (`POST /api/identities`, panel at
   `templates/dashboard.html:584`)
3. `tab-sites` — create the site and pick its mode (`POST /api/sites`)
4. `tab-provisioning` again, or `tab-import` — add devices, setting
   `Profile = identity:<id>`, `Group`, `Site` by hand
5. `tab-devices` — run the first triage

Step 4 silently half-works when steps 1-3 were skipped, because `Group`, `Site` and
`Profile` are free-text columns of `hosts.csv`: the row is accepted and the failure
surfaces later, at connection time, far from its cause. The wizard makes the order
explicit and the checklist makes the destination explicit. Neither removes an existing
path: the five tabs keep working exactly as they do now, for editing and for everything
the wizard does not cover.

## File Structure

- `static/js/wizard.js` (new) — the wizard's state machine and its four API calls. One
  responsibility: drive the modal, call existing endpoints, report per-step outcome.
- `templates/dashboard.html` (modify) — the modal markup plus the two entry buttons
  (`tab-home` hero, `tab-sites` header).
- `static/js/home.js` (modify) — the first-run checklist: read four GETs, tick, dismiss.
- `static/js/i18n.js` (modify) — keys for both.
- `types/globals.d.ts` (modify) — declare `window.openNewCustomerWizard`.
- `tests/js/test_wizard.mjs` (new) — source assertions on call order.
- `tests/js/test_home_checklist.mjs` (new) — source assertions on the checklist.
- `tests/test_onboarding.py` (new) — shells out to both `.mjs` files and asserts the
  template carries every id the two modules bind to.
- `docs/operations.md` (modify) — a short "onboard a customer" paragraph.

---

### Task 1: The wizard module and its call order

**Files:**
- Create: `static/js/wizard.js`
- Test: `tests/js/test_wizard.mjs`

**Interfaces:**
- Produces: `window.openNewCustomerWizard()` opens the modal at step 1.
  `runNewCustomer(data, onStep)` performs the four calls in order and returns
  `{created: string[], failedStep: string|null, error: string|null}`.
  `data` is `{tenant: string, identity: {name, username, password, enable}, site:
  {name, mode, subnets, jump_host, jump_port}, devices: [{ip, vendor}], csv: string|null}`.
  `onStep(stepName, status)` is called with status `"running" | "ok" | "failed"`.

- [ ] **Step 1: Write the failing test**

```javascript
// tests/js/test_wizard.mjs
// The wizard must create the objects in dependency order: a device row whose
// Group/Site/Profile point at things that do not exist yet is accepted by
// hosts.csv and then fails at connection time, far from the cause.
//
//   node tests/js/test_wizard.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/wizard.js'), 'utf8');

// 1. All four endpoints are used.
for (const url of ['/api/groups', '/api/identities', '/api/sites', '/api/add-device']) {
    assert.ok(src.includes(url), `wizard.js non chiama ${url}`);
}

// 2. They appear in dependency order inside runNewCustomer().
const start = src.indexOf('async function runNewCustomer(');
assert.ok(start > 0, 'runNewCustomer() non trovata');
const body = src.slice(start, src.indexOf('\n    }', start));
const order = ['/api/groups', '/api/identities', '/api/sites', '/api/add-device']
    .map(u => body.indexOf(u));
assert.ok(order.every(i => i > 0), 'runNewCustomer() non chiama tutti gli endpoint');
assert.deepEqual([...order].sort((a, b) => a - b), order,
    'ordine di creazione errato: tenant -> identity -> site -> device');

// 3. The devices created must reference the identity just created.
assert.match(body, /identity:/,
    'i device creati dal wizard non usano Profile identity:<id>');

// 4. A failed step must stop the run, not push devices into a half-built customer.
assert.match(body, /failedStep/,
    'runNewCustomer() non segnala lo step fallito');

console.log('ok - wizard call order');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/js/test_wizard.mjs`
Expected: FAIL — `ENOENT ... static/js/wizard.js`.

- [ ] **Step 3: Write minimal implementation**

```javascript
// static/js/wizard.js
// Guided onboarding of one customer. Pure orchestration of endpoints that
// already exist: the wizard adds no persistence of its own, so a run that
// stops halfway leaves ordinary objects the user can finish from the tabs.
(function () {
    'use strict';

    const STEPS = ['tenant', 'identity', 'site', 'devices'];

    async function post(url, payload) {
        const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const body = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(body.detail || body.error || r.statusText);
        return body;
    }

    async function runNewCustomer(data, onStep) {
        const created = [];
        let step = 'tenant';
        try {
            onStep(step, 'running');
            await post('/api/groups', { name: data.tenant });
            created.push('tenant');
            onStep(step, 'ok');

            step = 'identity';
            onStep(step, 'running');
            const ident = await post('/api/identities', {
                name: data.identity.name,
                tenant: data.tenant,
                username: data.identity.username,
                password: data.identity.password,
                enable_secret: data.identity.enable || ''
            });
            const identityId = ident.identity ? ident.identity.id : ident.id;
            created.push('identity');
            onStep(step, 'ok');

            step = 'site';
            onStep(step, 'running');
            const site = await post('/api/sites', {
                name: data.site.name,
                mode: data.site.mode,
                subnets: data.site.subnets || [],
                jump_host: data.site.jump_host || undefined,
                jump_port: data.site.jump_port || undefined,
                jump_identity: data.site.mode === 'jump' ? identityId : undefined
            });
            const siteId = (site.site || site).id;
            created.push('site');
            onStep(step, 'ok');

            step = 'devices';
            onStep(step, 'running');
            if (data.csv) {
                await post('/api/import-csv', { csv: data.csv, site: siteId,
                                                group: data.tenant });
            } else {
                for (const d of data.devices || []) {
                    await post('/api/add-device', {
                        ip: d.ip, vendor: d.vendor, group: data.tenant,
                        site: siteId, profile: 'identity:' + identityId
                    });
                }
            }
            created.push('devices');
            onStep(step, 'ok');
            return { created, failedStep: null, error: null };
        } catch (e) {
            onStep(step, 'failed');
            return { created, failedStep: step, error: String(e.message || e) };
        }
    }

    window.openNewCustomerWizard = function () {
        // Step navigation is wired in Task 2.
        document.getElementById('wizardModal').style.display = 'flex';
    };
    window.runNewCustomer = runNewCustomer;
    window.WIZARD_STEPS = STEPS;
})();
```

Before finalizing the payloads, open `routers/catalog.py:77`, `routers/provisioner.py:314`,
`routers/sites.py:55`, `routers/inventory.py:165` and `:214`, and match their request
models exactly — field names, and the shape each one returns the new id in. Adjust the
code above to what those routes actually accept; do not assume. Add
`static/js/wizard.js` to the script tags in `templates/dashboard.html`.

- [ ] **Step 4: Run test to verify it passes**

Run: `node tests/js/test_wizard.mjs`
Expected: `ok - wizard call order`.

- [ ] **Step 5: Commit**

```bash
git add static/js/wizard.js tests/js/test_wizard.mjs templates/dashboard.html
git commit -m "feat(onboarding): add the new-customer wizard orchestration"
```

---

### Task 2: The modal, its entry points and its wiring

**Files:**
- Modify: `templates/dashboard.html` (modal markup, buttons in `tab-home` and
  `tab-sites`), `static/js/wizard.js` (step navigation and submit),
  `static/js/i18n.js`, `types/globals.d.ts`
- Test: `tests/test_onboarding.py` (new)

**Interfaces:**
- Consumes: `runNewCustomer` and `window.openNewCustomerWizard` from Task 1.
- Produces: the ids `wizardModal`, `wizardOpenBtn`, `wizardNextBtn`, `wizardBackBtn`,
  `wizardSubmitBtn`, `wizardStep1`..`wizardStep4`, `wizardSummary`, `wizardJumpFields`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_onboarding.py
"""The wizard and the checklist bind to ids in dashboard.html.

getElementById('missing')?.addEventListener raises nothing: a renamed id leaves
a silently dead button, so the template and the modules are checked together."""
import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class WizardMarkup(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
        self.js = (ROOT / "static/js/wizard.js").read_text(encoding="utf-8")

    def test_every_id_the_wizard_binds_to_exists_in_the_template(self):
        bound = set(re.findall(r"getElementById\(['\"]([A-Za-z0-9_-]+)['\"]\)", self.js))
        missing = sorted(i for i in bound if f'id="{i}"' not in self.html)
        self.assertEqual(missing, [])

    def test_no_inline_handlers_were_added(self):
        self.assertNotIn("onclick=", self.html)
        self.assertNotIn("onsubmit=", self.html)

    def test_js_source_assertions_pass(self):
        r = subprocess.run(["node", str(ROOT / "tests/js/test_wizard.mjs")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
```

Copy the subprocess/node invocation from `tests/test_endpoint_tab.py`, which already
shells out to `tests/js/test_loc_permission.mjs`, so both tests skip identically when
node is missing.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_onboarding -v`
Expected: FAIL — the ids the wizard binds to are absent from the template.

- [ ] **Step 3: Write minimal implementation**

Add the modal to `templates/dashboard.html`, following the markup and class conventions
of an existing modal in the file:

```html
<div class="modal" id="wizardModal" style="display:none;">
  <div class="modal-content" style="max-width:640px;">
    <h3 data-i18n="wizTitle">Nuovo cliente</h3>

    <section id="wizardStep1">
      <label data-i18n="wizTenant">Tenant</label>
      <input id="wizTenantName" placeholder="Customer A">
    </section>

    <section id="wizardStep2" style="display:none;">
      <label data-i18n="wizIdentity">Credenziali</label>
      <input id="wizIdentityName" placeholder="core-admin">
      <input id="wizIdentityUser" placeholder="admin">
      <input id="wizIdentityPass" type="password">
      <input id="wizIdentityEnable" type="password" placeholder="enable">
    </section>

    <section id="wizardStep3" style="display:none;">
      <label data-i18n="wizSite">Sede</label>
      <input id="wizSiteName" placeholder="Customer A - HQ">
      <select id="wizSiteMode">
        <option value="central" data-i18n="wizModeCentral">Central (rete raggiungibile)</option>
        <option value="agent" data-i18n="wizModeAgent">Agent (processo in sede)</option>
        <option value="jump" data-i18n="wizModeJump">Jump (bastion SSH)</option>
      </select>
      <div id="wizardJumpFields" style="display:none;">
        <input id="wizJumpHost" placeholder="198.51.100.10">
        <input id="wizJumpPort" type="number" value="22">
      </div>
    </section>

    <section id="wizardStep4" style="display:none;">
      <label data-i18n="wizDevices">Dispositivi</label>
      <textarea id="wizDevices" placeholder="192.0.2.10,cisco_ios"></textarea>
    </section>

    <div id="wizardSummary" style="display:none;"></div>

    <div class="modal-actions">
      <button class="btn btn-secondary" id="wizardBackBtn" data-i18n="wizBack">Indietro</button>
      <button class="btn btn-primary" id="wizardNextBtn" data-i18n="wizNext">Avanti</button>
      <button class="btn btn-primary" id="wizardSubmitBtn" style="display:none;" data-i18n="wizCreate">Crea</button>
    </div>
  </div>
</div>
```

Entry buttons: `id="wizardOpenBtn"` in the `tab-sites` header and a second one in the
`tab-home` hero with a distinct id; bind both. In `wizard.js`, add the step navigation,
show `#wizardJumpFields` only for mode `jump`, and on submit call `runNewCustomer`,
rendering each `onStep` callback into `#wizardSummary` as running / ok / failed, with
the failure message and the note that the objects already created were kept. The jump
mode's limitation list from the jump-host plan is shown here too when that mode is
selected. Declare `openNewCustomerWizard` and `runNewCustomer` in `types/globals.d.ts`.
Add every `data-i18n` key to both languages in `static/js/i18n.js`.

- [ ] **Step 4: Run the tests and the frontend check**

Run: `uv run python -m unittest tests.test_onboarding -v` — PASS.
Run: `uv run python scripts/check_frontend.py` — 0 errors.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(onboarding): wire the new-customer wizard modal"
```

---

### Task 3: First-run checklist on Home

**Files:**
- Modify: `static/js/home.js`, `templates/dashboard.html` (`tab-home`),
  `static/js/i18n.js`
- Test: `tests/js/test_home_checklist.mjs` (new), `tests/test_onboarding.py` (append)

**Interfaces:**
- Consumes: `GET /api/groups`, `GET /api/identities`, `GET /api/sites`,
  `GET /api/local-devices`.
- Produces: `renderFirstRunChecklist()` in `home.js`; the dismissal flag lives in
  `localStorage` under `sn.checklist.dismissed`.

- [ ] **Step 1: Write the failing test**

```javascript
// tests/js/test_home_checklist.mjs
// The checklist must derive from real state, not from a counter of its own:
// a user who onboarded from the tabs must not be told to start over.
//
//   node tests/js/test_home_checklist.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/home.js'), 'utf8');

const start = src.indexOf('function renderFirstRunChecklist(');
assert.ok(start > 0, 'renderFirstRunChecklist() non trovata');
const body = src.slice(start, src.indexOf('\n    }', start));

for (const url of ['/api/groups', '/api/identities', '/api/sites', '/api/local-devices']) {
    assert.ok(body.includes(url), `la checklist non legge ${url}`);
}
assert.match(body, /localStorage/, 'la checklist non ricorda di essere stata chiusa');

console.log('ok - home checklist');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/js/test_home_checklist.mjs`
Expected: FAIL — `renderFirstRunChecklist() non trovata`.

- [ ] **Step 3: Write minimal implementation**

Markup in `tab-home`, above the existing hero content:

```html
<article class="panel" id="firstRunChecklist" style="display:none;">
  <h3 data-i18n="chkTitle">Primi passi</h3>
  <ul id="firstRunSteps"></ul>
  <button class="btn btn-secondary btn-small" id="firstRunDismiss" data-i18n="chkDismiss">Nascondi</button>
  <button class="btn btn-primary btn-small" id="wizardOpenBtnHome" data-i18n="chkWizard">Nuovo cliente</button>
</article>
```

In `home.js`, `renderFirstRunChecklist()` fetches the four endpoints in parallel, marks
each of the five steps done when its object exists (tenant, identity, site, at least one
device, at least one triage result), renders each step as a label plus a
`data-switch-tab` button to the tab that completes it, and hides the whole panel when
`localStorage.getItem('sn.checklist.dismissed')` is set or all five are done. Call it
from wherever `home.js` already runs its tab-entry rendering. Escape every interpolated
value with the project convention `escapeHtml(jsStr(x))`.

Append to `tests/test_onboarding.py` a case that shells out to
`tests/js/test_home_checklist.mjs`, and extend the id check to cover
`static/js/home.js`.

- [ ] **Step 4: Run the tests and the frontend check**

Run: `uv run python -m unittest discover -s tests` — all green.
Run: `uv run python scripts/check_frontend.py` — 0 errors.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(onboarding): first-run checklist on the home tab"
```

---

### Task 4: Docs, version, graph

**Files:**
- Modify: `docs/operations.md`, `core/version.py`, `pyproject.toml`

- [ ] **Step 1: Write the onboarding paragraph**

In `docs/operations.md`, a short "Onboard a customer" section: the wizard covers the
happy path (tenant, one identity, one site, devices), the five tabs remain the way to
edit anything afterwards, and the checklist on Home tracks the same five steps for
someone who prefers doing it by hand. Use `Customer A` / `192.0.2.10` as examples.

- [ ] **Step 2: Bump the version**

MINOR bump in `core/version.py`, same value in `pyproject.toml`.

- [ ] **Step 3: Run the full gate**

```sh
uv run pyrefly check
uv run python scripts/check_frontend.py
uv run python -m unittest discover -s tests
graphify update .
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs(onboarding): document the wizard and the first-run checklist"
```

---

## Deferred, on purpose

- **Rollback of a half-finished wizard run** — the created objects are valid on their
  own; the summary names the step that failed and the user finishes it in its tab.
  Add rollback only if half-built customers turn out to be a real support cost.
- **Inline "+ New identity" on every select** — a second, larger change to the same
  area; ship the wizard first and see whether it still hurts.
- **Merging the five setup tabs into one** — big frontend diff against tests already
  written for those tabs. Revisit once the wizard has absorbed the common path.
- **CSV auto-creating groups/sites/identities** — the wizard's step 4 already accepts a
  CSV inside a customer that exists; the standalone import stays strict.
- **An interactive product tour** — the checklist is the cheap 80%.
