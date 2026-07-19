# dashboard.html Deconstruction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the 12,678-line / ~793 KB `templates/dashboard.html` into static CSS/JS files plus a lean HTML shell, with zero behavior change.

**Architecture:** Mechanical extraction, not a rewrite. The app serves one `FileResponse` for the dashboard ([app_server.py:180](../../app_server.py#L180)); we add a `/static` mount, then move code out in dependency order: CSS → i18n dicts → shared core JS → per-tab JS modules. All JS stays as classic `<script src>` globals (NOT ES modules) because the HTML uses inline `onclick="..."` handlers everywhere, which need window-scope functions. Load order in the HTML preserves today's top-to-bottom declaration order, so behavior is identical.

**Tech Stack:** FastAPI `StaticFiles`, plain JS/CSS files under `static/`, PyInstaller spec update, existing unittest-as-scripts suite.

## Global Constraints

- Zero behavior change: no renames, no refactors, no dead-code removal during extraction. One concern per commit.
- Classic scripts only — no `type="module"`, no bundler, no npm.
- `get_resource_path()` must resolve `static/` in both dev and frozen (PyInstaller) modes — same mechanism already used for `templates/`.
- Several tests grep `templates/dashboard.html` directly (`test_observability_ui.py:287`, `test_ui_revamp.py` in many places). Each extraction phase MUST update those tests to scan the moved file(s), or introduce the shared helper in Task 1 and migrate greps as code moves.
- After the final task: rebuild exe with `uv run pyinstaller SentinelNet.spec` and verify the frozen app serves `/static/*` (user rule).
- NOTE: a stale worktree `.claude/worktrees/destructure` exists from a prior attempt — inspect/delete it before starting so it doesn't confuse tooling; do not base work on it without reviewing.

## File Structure (end state)

```
templates/dashboard.html      # HTML shell: markup, modals, <link>/<script> tags (~2.9k lines)
static/css/dashboard.css      # all <style> blocks
static/js/i18n.js             # it/en dicts + i18n helpers (~1.2k lines)
static/js/core.js             # apiFetch, escapeHtml, jsStr, showToast, auth/session, tab switching, theming
static/js/devices.js          # inventory/devices/tenants tab
static/js/topology.js         # topology/map tab
static/js/config-analyzer.js  # ca* functions (largest module, ~2.5k lines)
static/js/observability.js    # flows/syslog/anomalies + obs settings
static/js/threat-intel.js     # threat intel + vendor watch + matcher
static/js/client-map.js       # MAC↔IP client map tab
static/js/provisioning.js     # fortigate/switch provisioner + identities
static/js/ai.js               # AI assistant tab
static/js/settings.js         # settings tab (app, users, backup, blacklist)
```

(Module list is indicative: final split = one file per top-level tab, boundaries at the existing `// ===== <section> =====` comment banners in dashboard.html. A function goes with the tab that owns it; genuinely shared helpers go to core.js.)

## Task Order & Dependencies

Task 1 (static infra) → Task 2 (CSS) → Task 3 (i18n) → Task 4 (core.js) → Tasks 5..N (one per tab module, any order after core) → Final (exe rebuild + cleanup).

Every task ends with: full test suite green + manual smoke load of the dashboard + commit. The app must be fully working after EVERY task — this is what makes the plan safe to pause at any point.

---

### Task 1: Serve /static + test helper

**Files:**
- Create: `static/js/.gitkeep`, `static/css/.gitkeep`
- Modify: `app_server.py` (mount), `SentinelNet.spec` (datas)
- Create: `test_helpers_frontend.py` (shared source-scan helper for tests)

**Interfaces:**
- Produces: URL prefix `/static/` → files under `static/`; `frontend_source()` helper returning concatenated dashboard.html + all static/js/css text, for the grep-style tests.

- [ ] **Step 1: Write failing test**

```python
# test_static_mount.py
import unittest
from fastapi.testclient import TestClient
from app_server import app

class TestStaticMount(unittest.TestCase):
    def test_static_served(self):
        client = TestClient(app)
        r = client.get("/static/js/.gitkeep")
        self.assertEqual(r.status_code, 200)

if __name__ == "__main__":
    unittest.main()
```

Run: `uv run python test_static_mount.py` — expected FAIL (404 / mount missing). (If `TestClient` doesn't work in this app's startup model, follow the pattern used by existing router tests instead.)

- [ ] **Step 2: Implement**

`app_server.py` (near the dashboard route):

```python
from fastapi.staticfiles import StaticFiles
app.mount("/static", StaticFiles(directory=get_resource_path("static")), name="static")
```

`SentinelNet.spec`: add `("static", "static")` to `datas` alongside the existing `templates` entry (copy its exact tuple style).

`test_helpers_frontend.py`:

```python
import glob, os

def frontend_source() -> str:
    """Sorgente frontend completo: dashboard.html + tutti i file static/.
    I test 'grep-style' devono usare questo, non il solo dashboard.html."""
    base = os.path.dirname(__file__)
    parts = [open(os.path.join(base, "templates", "dashboard.html"),
                  encoding="utf-8").read()]
    for p in glob.glob(os.path.join(base, "static", "**", "*.*"), recursive=True):
        if p.endswith((".js", ".css")):
            parts.append(open(p, encoding="utf-8").read())
    return "\n".join(parts)
```

- [ ] **Step 3: Test passes, suite green, commit**

`uv run python test_static_mount.py` → PASS. Run full suite. Commit: `feat(frontend): mount /static and add frontend_source test helper`.

---

### Task 2: Extract CSS

**Files:**
- Create: `static/css/dashboard.css`
- Modify: `templates/dashboard.html`

- [ ] **Step 1:** Locate every `<style>...</style>` block in dashboard.html (the main one in `<head>` plus scoped ones like the `#tab-config` block at ~line 2062). Move their CONTENT verbatim, in document order, into `static/css/dashboard.css`, separated by `/* ===== <origin> ===== */` banners.
- [ ] **Step 2:** Replace the head `<style>` with `<link rel="stylesheet" href="/static/css/dashboard.css">`; delete the now-empty inline blocks.
- [ ] **Step 3:** Update any test that greps dashboard.html for CSS selectors to use `frontend_source()`.
- [ ] **Step 4:** Smoke: load app, verify identical styling (spot-check dark theme, Config Analyzer pills, modals). Full suite green.
- [ ] **Step 5:** Commit: `refactor(frontend): extract CSS to static/css/dashboard.css`.

---

### Task 3: Extract i18n

**Files:**
- Create: `static/js/i18n.js`
- Modify: `templates/dashboard.html`

- [ ] **Step 1:** Move the `const i18n = { it: {...}, en: {...} }` declaration (the ~2.4k-line block spanning both dicts, roughly lines 3100–4300) plus `currentLang` and the `data-i18n` apply-function verbatim into `static/js/i18n.js`.
- [ ] **Step 2:** Add `<script src="/static/js/i18n.js"></script>` in the HTML at the exact position the block occupied (before any script that reads `i18n`).
- [ ] **Step 3:** Migrate tests grepping dashboard.html for i18n keys to `frontend_source()`. Suite green; smoke: toggle language IT↔EN in the UI.
- [ ] **Step 4:** Commit: `refactor(frontend): extract i18n to static/js/i18n.js`.

---

### Task 4: Extract core.js

**Files:**
- Create: `static/js/core.js`
- Modify: `templates/dashboard.html`

- [ ] **Step 1:** Identify the shared runtime used by every tab: `apiFetch`, auth/session/token handling, `escapeHtml`, `jsStr`, `showToast`, tab-switching (`switchTab` / the `tabId === 'tab-...'` dispatcher at ~line 6094), theme handling, `globalGroups` and other cross-tab globals. Move them verbatim to `static/js/core.js`, preserving relative order.
- [ ] **Step 2:** `<script src="/static/js/core.js"></script>` immediately after i18n.js. Everything still declaration-order-safe because remaining inline script comes after.
- [ ] **Step 3:** Suite green (migrate greps as needed); smoke: login, switch every tab once, toast appears on an action.
- [ ] **Step 4:** Commit: `refactor(frontend): extract shared core to static/js/core.js`.

---

### Tasks 5..N: One module per tab (repeatable recipe)

Order suggestion (largest win first): config-analyzer, observability, threat-intel, provisioning, devices, topology, client-map, ai, settings. One task per module, each its own commit.

For each module `<name>`:

- [ ] **Step 1:** In dashboard.html find the section banner(s) (`// ===== Config Analyzer =====` etc.) and cut the whole function group verbatim into `static/js/<name>.js`. If a function is used by other tabs too (check with grep before moving), it belongs in core.js instead — move it there in this task and note it in the commit message.
- [ ] **Step 2:** Add `<script src="/static/js/<name>.js"></script>` after core.js (order among tab modules is free — they only call each other via user events, never at parse time; verify with a grep for cross-module top-level calls before assuming).
- [ ] **Step 3:** Migrate affected test greps to `frontend_source()`. Full suite green.
- [ ] **Step 4:** Smoke the tab end-to-end (open it, trigger its main action, open one modal).
- [ ] **Step 5:** Commit: `refactor(frontend): extract <name> tab to static/js/<name>.js`.

Exit criterion for the series: dashboard.html contains NO `<script>` block with function declarations — only markup, `<link>`, `<script src>` tags, and (if unavoidable) a tiny bootstrap call.

---

### Final Task: Frozen build verification

- [ ] **Step 1:** `uv run pyinstaller SentinelNet.spec` — build succeeds.
- [ ] **Step 2:** Launch `dist/SentinelNet/SentinelNet.exe`, log in, verify `/static/css/dashboard.css` and each `/static/js/*.js` load (no 404 in devtools/network), spot-check two tabs.
- [ ] **Step 3:** Remove the stale `.claude/worktrees/destructure` worktree (`git worktree remove --force` after confirming it holds nothing wanted).
- [ ] **Step 4:** Commit any spec/test residue: `chore(build): ship static assets in frozen build`.
