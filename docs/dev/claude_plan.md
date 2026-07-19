# Merge Implementation Plan: `ui-revamp` + `destructure` → `new_dev`

## Executive Summary

These two branches are **highly mergeable with low conflict risk** because they touch nearly disjoint file sets:

- **`destructure`**: Python-only. Splits `app_server.py` into `routers/*.py`, adds `app_settings.py`. Touches `app_server.py`, `routers/`, `test_router_parity.py`, `test_transports.py`, `test_observability_ui.py`, and docs.
- **`ui-revamp`**: Frontend-only. Rewrites `templates/dashboard.html`, adds `test_ui_revamp.py`, and docs.

The **only real overlaps** are:
1. `report.md` — both branches create this file (guaranteed conflict).
2. `test_observability_ui.py` — destructure repoints a patch target; ui-revamp reads `GET /` (potential logical overlap).
3. Startup route wiring / OpenAPI parity — ui-revamp adds `tab-home`, which is pure frontend (served by `GET /`), but the parity snapshot in destructure could interact.

Critically, the destructure branch's own `report.md` documents that **it was committed in a broken state** (missing imports causing runtime `NameError`s). This must be fixed as part of the merge, or `new_dev` will be broken.

---

## Phase 0: Preparation & Safety

```bash
# Ensure clean working state and up-to-date refs
git fetch --all
git checkout master
git pull

# Create the integration branch from master
git checkout -b new_dev master

# Tag current tips for rollback safety
git tag pre-merge-destructure destructure
git tag pre-merge-ui-revamp ui-revamp
```

**Decision: Merge order.** Merge `destructure` **first**, then `ui-revamp`. Rationale:
- `destructure` restructures the backend that serves `GET /`. Getting the backend correct and tested first gives a stable base.
- `ui-revamp` only depends on `GET /` returning `templates/dashboard.html`, which destructure preserves (it keeps `read_index` in `app_server.py`).

---

## Phase 1: Merge `destructure` into `new_dev`

```bash
git checkout new_dev
git merge --no-ff destructure
```

### Expected conflicts

Since `new_dev == master` at this point, **this merge should apply cleanly with zero conflicts** (destructure was branched from master and touches files master hasn't changed since). The `report.md` will be created cleanly.

### Phase 1.1: Fix the broken destructure state (MANDATORY)

The destructure branch's own `report.md` and implementation guide document guaranteed runtime crashes. **Fix these before proceeding** — do not carry a broken backend into `new_dev`.

**Step 1 — Delete scratch artifact:**
```bash
git rm app_server_clean.py 2>/dev/null || true
grep -rn "app_server_clean" . --include=*.py   # must return nothing
```

**Step 2 — Fix missing imports per router.** Apply these edits:

| File | Add imports |
|---|---|
| `routers/analyzer.py` | `status` (already present in diff — verify: `from fastapi import APIRouter, Depends, HTTPException, status`) |
| `routers/arp.py` | `import mac_history` (verify present — diff shows it *is* present) |
| `routers/topology.py` | `import os` |
| `routers/mac.py` | `import os`; `assert_device_allowed` from `routers.deps` |
| `routers/scan.py` | `import time`, `import core_engine`, `import inventory_manager` |
| `routers/catalog.py` | `assert_group_allowed` from `routers.deps` (verify — diff shows it present) |
| `routers/ai.py` | `assert_device_allowed`, `assert_group_allowed` from `routers.deps`; `import config_analyzer`, `import mac_history`, `import site_manager`; ensure `_AI_PROVIDERS` defined (diff shows it *is* defined) |

> **Note:** The truncated diff already shows several of these fixed in the committed files (e.g. `arp.py` imports `mac_history`, `analyzer.py` imports `status`, `catalog.py` imports `assert_group_allowed`, `ai.py` imports everything). **Verify each router by actual import**, not by reading — the review report predates the final commits and may be stale. Run:

```bash
for m in agent ai analyzer arp auth backup catalog commands deps \
         fortigate inventory mac mcp observability provisioner scan \
         settings sites topology triage wlc; do
  uv run python -c "import routers.$m" 2>&1 | grep -q . && echo "FAIL: routers/$m" || echo "ok: routers/$m"
done
```

Fix any module that fails to import.

**Step 3 — Standardize settings imports.** In `routers/ai.py` and `routers/mcp.py`, ensure they import from `app_settings`, not `routers.settings`:
```python
from app_settings import get_app_settings, save_app_settings
```

**Step 4 — Verify `routers/settings.py` has its constants.** Confirm `_APP_ADV_ENV`, `_APP_ADV_INT_KEYS`, `_APP_ADV_DEFAULTS`, and `import data_config` are present (they were in the original monolith, `routers/settings.py` must carry them).

**Step 5 — Add a runtime smoke test** (the OpenAPI parity gate cannot catch handler-body `NameError`s). Create `test_router_smoke.py` per the destructure implementation guide, authenticating first so handlers actually execute past the auth gate.

**Step 6 — Verify backend:**
```bash
uv run python test_router_parity.py -v
uv run python test_router_smoke.py -v
uv run python -m unittest test_rbac_scope test_auth_cookie test_transports \
    test_sites test_remote_site test_observability_ui \
    test_app_server_ai_profiles test_config_analyzer_multivendor \
    test_ssh_port_and_unredacted -v
```

**Step 7 — Commit the fixes:**
```bash
git add -A
git commit -m "fix(destructure): resolve missing router imports, remove scratch file, add smoke test"
```

---

## Phase 2: Merge `ui-revamp` into `new_dev`

```bash
git merge --no-ff ui-revamp
```

### Expected conflicts

**Conflict A — `report.md` (guaranteed).**
Both branches created `report.md`. Resolution:
```bash
# Combine both reports rather than picking one
git checkout --theirs report.md   # ui-revamp version
# Then manually prepend the destructure report, OR:
```
**Recommended:** Merge both into one document with two sections:
```markdown
# new_dev Merge Report

## Part 1: app_server Destructuring
<contents of destructure report.md>

## Part 2: UI Revamp
<contents of ui-revamp report.md>
```
```bash
git add report.md
```

**Conflict B — `test_observability_ui.py` (likely).**
- `destructure` changed the patch target: `app_server._get_active_ai_profile` → `routers.ai._get_active_ai_profile`.
- `ui-revamp` may not have touched this file, or touched it independently.

Resolution: **Keep the destructure change** (the repointed patch target is correct for the new module layout). If ui-revamp added assertions about `GET /` HTML content, keep both:
```bash
git diff test_observability_ui.py   # inspect
# Manually merge: retain routers.ai patch target AND any ui-revamp assertions
git add test_observability_ui.py
```

**Conflict C — `docs/superpowers/plans/` (unlikely).**
Both add plan files with different names (`2026-07-14-ui-revamp.md` vs `2026-07-15-app-server-destructuring.md`). No conflict expected. If Git flags the directory, keep both files.

**No conflict expected on:**
- `templates/dashboard.html` (only ui-revamp touches it)
- `app_server.py` (only destructure touches it — ui-revamp's `read_index` still serves the same template)
- `routers/*.py`, `app_settings.py` (destructure only)
- `test_ui_revamp.py` (ui-revamp only)
- `test_router_parity.py`, `test_transports.py` (destructure only)

### Phase 2.1: Reconcile the OpenAPI parity snapshot

**Critical interaction:** ui-revamp adds a new frontend tab (`tab-home`) but **adds no new backend routes** — it wires to existing endpoints (`/api/local-devices`, `/api/run-triage`, `/api/observability/anomalies`). Therefore:

- `test_router_parity.py`'s `TestFullParity` (from destructure) compares against `tests_data/openapi_pre_destructure.json`. Since ui-revamp adds no routes, **this snapshot remains valid** and parity should still pass.

Verify:
```bash
uv run python test_router_parity.py -v
```
If it fails on a path/route difference, ui-revamp introduced a backend change it shouldn't have — investigate, do **not** regenerate the snapshot to mask it.

---

## Phase 3: Full Integration Verification

**Step 1 — Full Python test suite:**
```bash
uv run python -m unittest discover -s . -p "test_*.py" -v
```
Expected: OK. Pay special attention to:
- `test_ui_revamp.py` — its `TestFullParity`-style HTML nesting checks and `GET /` assertions must pass against the destructured backend.
- `test_router_parity.py` — OpenAPI parity intact.
- `test_router_smoke.py` — every router serves without 500.

**Step 2 — Confirm `GET /` serves the revamped dashboard through the new backend:**
```bash
uv run python -c "
from fastapi.testclient import TestClient
import app_server
html = TestClient(app_server.app).get('/').text
assert 'nav-group' in html, 'sidebar missing'
assert 'tab-home' in html, 'home tab missing'
assert 'function loadHome' in html, 'loadHome missing'
print('OK: revamped dashboard served through destructured backend')
"
```

**Step 3 — Manual click-through (the blind spots).**
Launch and verify the interactions no automated gate covers:
```bash
SENTINELNET_NO_BROWSER=true uv run python app_server.py
```
Then in browser at the printed URL:
- **Home tab** loads by default, KPIs populate from `/api/local-devices` (destructure's `routers/inventory.py`).
- **WebSocket terminal** (`/api/ws-terminal/{ip}`) — destructure's Task 10 blind spot AND ui-revamp's CLI modal. Open the terminal on a device; confirm OTP handshake (`/api/ws-token`) succeeds and shell attaches. This is the single highest-risk cross-branch path (both branches touch its ends).
- **Every nav group** (Operations/Analysis/Provisioning/Administration): click each tab, confirm no 404/500 in server log, each button fires a real `/api/...` call (cross-check `docs/ui-revamp/button-endpoint-map.md`).
- **RBAC**: log in as viewer/operator/admin; confirm `requires-admin`/`requires-write` nav entries hide correctly.

**Step 4 — Commit the merge:**
```bash
git add -A
git commit   # completes the --no-ff merge with resolved conflicts
```

---

## Phase 4: Finalization

**Step 1 — Rebuild the executable** (project rule; run from repo root where `SentinelNet.spec` lives, since it's gitignored):
```bash
uv run pyinstaller SentinelNet.spec
```
If frozen app dies with `ModuleNotFoundError: routers.<name