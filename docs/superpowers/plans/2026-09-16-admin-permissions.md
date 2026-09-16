# Admin Permissions (tabs + tenant scope) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The super_admin decides, per user, which tabs and which tenants they can use, and the server enforces both — including for admins.

**Architecture:** `require_tab(*tabs)` dependency on every tab-owned route plus an explicit BASE/PUBLIC/MACHINE registry, with a completeness test that fails on any unclassified route. `user_group_scope` stops exempting admins; global admin routes additionally require `require_unscoped_admin`. User management gains a perimeter check for scoped admins. Frontend exposes tenant/tab editors on admin rows.

**Tech Stack:** FastAPI, pytest/unittest + TestClient, classic-script JS, node `.mjs` harness.

**Spec:** `docs/superpowers/specs/2026-09-16-admin-permissions-design.md` (route inventory: `docs/superpowers/specs/2026-09-16-admin-permissions-route-map.md`)

## Global Constraints

- Unrestricted: `super_admin` always; any user with empty `allowed_tabs` for tabs; any non-super_admin with empty `groups` for tenants.
- 403 detail for a missing tab: `"Funzionalita' non abilitata per questo utente."`
- 403 detail for a global route reached by a tenant-scoped admin: `"Operazione riservata ad amministratori senza limiti di tenant."`
- Legacy tab aliases: `tab-mac`, `tab-clientmap`, `tab-diagnosi`, `tab-endpoints` → `tab-endpoint`. Sub-tab grants: `tab-map` ⇒ `tab-map-interactive`; `tab-provisioning` ⇒ `tab-provisioner`.
- Route classes are exactly TAB, BASE, PUBLIC, MACHINE; every `/api/*` route (HTTP + WebSocket) in exactly one.
- Route handlers: do not add or change docstrings (they are the OpenAPI descriptions). Adding a dependency is allowed; if an OpenAPI/contract snapshot test changes, the only acceptable diff is the added dependency/security — read it before updating.
- New comments in English; leave Italian comments alone. User strings via `tr()` in it + en. No inline handlers. Tests use private users stores (see `_PrivateUsers` in `tests/test_super_admin_api.py`), example.com / RFC 5737 values only.
- Stage files by name; never `git add -A`. Commit trailer: `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`. No version bump (release script owns it).
- Gate before every commit: `uv run pyrefly check` (0 errors), `uv run pytest tests -n 4` (green), `uv run python scripts/check_no_private_data.py`; plus `scripts/check_frontend.py`, `check_i18n_coverage.py --strict`, `check_a11y.py --strict` when static/js or templates change.

---

## File Structure

| File | Responsibility |
|---|---|
| `security/user_manager.py` | `TAB_ALIASES`, `SUBTAB_GRANTS`, `effective_tabs(username) -> set[str] \| None` |
| `routers/deps.py` | `require_tab`, `require_unscoped_admin`, `user_group_scope` change, perimeter helpers |
| `routers/route_classes.py` (new) | `BASE_ROUTES`, `PUBLIC_ROUTES`, `MACHINE_ROUTES` sets of `(method, path)`; `route_tabs(route)` |
| `routers/*.py` | `require_tab(...)` / `require_unscoped_admin` / scoping on routes |
| `routers/auth.py` | users perimeter (list filter, groups/tabs subset, invite block) |
| `static/js/settings.js`, `i18n.js` | editors on admin rows, hints |
| `tests/test_route_classes.py`, `tests/test_tab_enforcement.py`, `tests/test_admin_tenant_scope.py` (new), `tests/test_super_admin_api.py` | tests |
| `CHANGELOG.md` | entries |

---

### Task 1: Tab primitives and route registry

**Files:** Modify `security/user_manager.py`, `routers/deps.py`. Create `routers/route_classes.py`, `tests/test_tab_enforcement.py` (unit part), a JS parity test (new `.mjs` + Python wrapper following `tests/test_assignable_tabs.py`).

**Interfaces — Produces:**
- `user_manager.TAB_ALIASES: dict[str, str]`, `user_manager.SUBTAB_GRANTS: dict[str, tuple[str, ...]]`
- `user_manager.effective_tabs(username: str) -> set[str] | None` — `None` = unrestricted (super_admin, or empty list); otherwise normalised ids plus sub-tab grants.
- `deps.require_tab(*tab_ids: str)` → FastAPI dependency; attribute `.tabs = frozenset(tab_ids)`; raises 403 with the constraint's detail.
- `route_classes.BASE_ROUTES`, `PUBLIC_ROUTES`, `MACHINE_ROUTES: frozenset[tuple[str, str]]` (method upper-case, path exactly as in `app.routes`, WebSocket method `"WS"`).
- `route_classes.route_tabs(route) -> frozenset[str] | None` — walks the route's dependant tree (including router-level dependencies) for a callable with `.tabs`; union of all found; `None` if none.

- [ ] **Step 1: failing unit tests** in `tests/test_tab_enforcement.py`:

```python
import pytest
from fastapi import HTTPException


@pytest.fixture
def um(tmp_path, monkeypatch):
    from security import user_manager
    monkeypatch.setattr(user_manager, "USERS_JSON", str(tmp_path / "users.json"))
    return user_manager


def test_effective_tabs(um):
    um.create_user("root", "password-1234", role="super_admin")
    um.create_user("free", "password-1234", role="operator")
    um.create_user("lim", "password-1234", role="admin")
    um.set_allowed_tabs("root", ["tab-devices"])
    um.set_allowed_tabs("lim", ["tab-mac", "tab-map", "tab-provisioning"])
    assert um.effective_tabs("root") is None
    assert um.effective_tabs("free") is None
    assert um.effective_tabs("lim") == {
        "tab-endpoint", "tab-map", "tab-map-interactive",
        "tab-provisioning", "tab-provisioner"}


def test_require_tab(um):
    from routers import deps
    um.create_user("lim", "password-1234", role="admin")
    um.set_allowed_tabs("lim", ["tab-devices"])
    dep = deps.require_tab("tab-devices", "tab-import")
    assert dep.tabs == frozenset({"tab-devices", "tab-import"})
    user = {"sub": "lim", "role": "admin"}
    assert dep(current_user=user) is user
    with pytest.raises(HTTPException) as e:
        deps.require_tab("tab-settings")(current_user=user)
    assert e.value.status_code == 403
    assert e.value.detail == "Funzionalita' non abilitata per questo utente."
```

- [ ] **Step 2:** `uv run pytest tests/test_tab_enforcement.py -v` → FAIL (`AttributeError`).
- [ ] **Step 3: implement.** `effective_tabs`: `None` if role is `super_admin` or `allowed_tabs` empty; else map ids through `TAB_ALIASES`, add `SUBTAB_GRANTS` members. `require_tab`:

```python
def require_tab(*tab_ids):
    """Server-side counterpart of the 'visible tabs' setting: a route owned
    by a tab answers only users who hold that tab."""
    wanted = frozenset(tab_ids)

    def _dep(current_user=Depends(get_current_user)):
        tabs = user_manager.effective_tabs(current_user.get("sub"))
        if tabs is not None and not (tabs & wanted):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Funzionalita' non abilitata per questo utente.")
        return current_user
    _dep.tabs = wanted
    return _dep
```

  `route_classes.py`: empty sets for now plus `route_tabs`. (Task 2 fills the sets.)
- [ ] **Step 4: JS parity test:** evaluate `normalizeAllowedTabs` from `static/js/core.js` and compare its alias map with `user_manager.TAB_ALIASES` (the Python wrapper passes the dict as JSON to node).
- [ ] **Step 5:** tests PASS; gate; commit `feat(auth): server-side tab primitives and route registry`.

---

### Task 2: Classify and gate every route

**Files:** Modify every `routers/*.py` with `/api` routes, `routers/route_classes.py`, `app_server.py` if it declares `/api` routes. Create `tests/test_route_classes.py`. Extend `tests/test_tab_enforcement.py`.

**Interfaces — Consumes:** Task 1. **Produces:** every route classified.

Rules (apply in this order, per route):
1. `/api/agent/*` → MACHINE. Unauthenticated by design (register, login, forgot/reset password, invite accept, SSO login/callback, `/api/version` if it has no auth) → PUBLIC. Verify each against its handler's dependencies; a route with no auth that is NOT one of these is a bug — stop and report it (NEEDS_CONTEXT), do not classify it PUBLIC.
2. Spec D2 BASE list, plus routes the route map marks BASE **only if** truly needed by core/boot scripts or ≥3 unrelated tabs. A route map "BASE" caused by a multi-tab script (settings.js, observability.js, ai.js) calling it is NOT base — split by path prefix to its owning tab(s) after checking the JS caller.
3. Otherwise TAB: tabs whose JS calls it (route map "Calling tabs"/"Proposed tab set"); orphan/MCP-only routes take their feature's tab (spec D2). Admin group: `/api/users*` → `tab-users`; group CRUD → `tab-groups`; `/api/sites*`, `/api/command-jobs*` → `tab-sites` (plus any tab reading them if not BASE); `/api/mcp*` → `tab-mcp`; `/api/settings*`, `/api/fleet*`, `/api/ping-monitor*`, `/api/cloud-backup*` → `tab-settings`; `/api/audit-checklist*` → `tab-netsec-audit`.
4. Prefer router-level `APIRouter(dependencies=[Depends(require_tab(...))])` when every route of the router has the same set; otherwise per-route `dependencies=[...]`.

- [ ] **Step 1: failing completeness test** `tests/test_route_classes.py`:

```python
import re
from pathlib import Path

from fastapi.routing import APIRoute, APIWebSocketRoute

import app_server
from routers import route_classes as rc

TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "dashboard.html"


def _api_routes():
    for r in app_server.app.routes:
        if isinstance(r, APIRoute) and r.path.startswith("/api"):
            for m in sorted(r.methods - {"HEAD", "OPTIONS"}):
                yield m, r.path, r
        elif isinstance(r, APIWebSocketRoute) and r.path.startswith("/api"):
            yield "WS", r.path, r


def test_every_route_in_exactly_one_class():
    problems = []
    for method, path, route in _api_routes():
        key = (method, path)
        classes = [name for name, hit in (
            ("TAB", rc.route_tabs(route) is not None),
            ("BASE", key in rc.BASE_ROUTES),
            ("PUBLIC", key in rc.PUBLIC_ROUTES),
            ("MACHINE", key in rc.MACHINE_ROUTES)) if hit]
        if len(classes) != 1:
            problems.append(f"{method} {path}: {classes or 'unclassified'}")
    assert not problems, "\n".join(problems)


def test_registry_has_no_stale_entries():
    live = {(m, p) for m, p, _ in _api_routes()}
    stale = (rc.BASE_ROUTES | rc.PUBLIC_ROUTES | rc.MACHINE_ROUTES) - live
    assert not stale, sorted(stale)


def test_tab_ids_exist_in_dashboard():
    html = TEMPLATE.read_text(encoding="utf-8")
    known = set(re.findall(r'data-tab="([^"]+)"', html))
    for tabs in re.findall(r'data-tabs="([^"]+)"', html):
        known |= set(tabs.split())
    for method, path, route in _api_routes():
        tabs = rc.route_tabs(route)
        if tabs:
            assert tabs <= known, f"{method} {path}: {sorted(tabs - known)}"
```

- [ ] **Step 2:** run → FAIL listing unclassified routes.
- [ ] **Step 3:** classify router by router until green. Keep the full table (method, path, class, tabs, reason when it deviates from the route map) in the report file.
- [ ] **Step 4: enforcement tests** in `tests/test_tab_enforcement.py` (class using the `_PrivateUsers` pattern): for EACH router file with TAB routes, one GET TAB route: a user with `allowed_tabs` excluding its tab → 403 with the detail; same user with the tab → not that 403 (handler may 404/422); empty list → not that 403; super_admin with a restricting list → not that 403. Parametrise over `(path, tab)` pairs.
- [ ] **Step 5:** WebSocket: reuse an existing `websocket_connect` test (grep tests) to confirm `/api/ws-terminal/{ip}` authenticates as before.
- [ ] **Step 6:** full gate; commit `feat(auth): enforce visible tabs on every API route`.

---

### Task 3: Tenant scope for admins and global-route guard

**Files:** Modify `routers/deps.py`, routers holding require_admin routes (route map "Admin class" G/T), `routers/fortigate.py`, `routers/incidents.py`. Create `tests/test_admin_tenant_scope.py`.

**Interfaces — Consumes:** Task 2 classification. **Produces:**
- `deps.user_group_scope(user)` → `None` only for `super_admin`.
- `deps.is_unscoped_admin(user) -> bool`; `deps.require_unscoped_admin` dependency (403 with the constraint detail).

- [ ] **Step 1: failing tests** (`_PrivateUsers` pattern; build two tenants/devices the way existing scope tests do — grep `assert_device_allowed` / `devices_in_scope` in tests for fixtures to reuse):
  - scoped admin (`groups=["tenant-a"]`): a device-scoped route on a tenant-b device → 403; tenant-a device → not 403; one list route → only tenant-a items.
  - every route whose dependant contains `require_unscoped_admin`: scoped admin → 403 with the detail; unscoped admin → not that 403. The test also asserts this explicit list is guarded: `POST /api/settings/sso`, `POST /api/settings/smtp`, base-URL / TLS / update settings writes, group create/delete, sites create/delete, cloud-backup config, MCP config, incident rule parameters.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3: implement:** change `user_group_scope`; add `is_unscoped_admin` (`role == "super_admin"` or (`role == "admin"` and no groups)) and `require_unscoped_admin`; add it to every G route; for T routes lacking scoping add `assert_device_allowed` / `devices_in_scope` / group filter (FortiGate `{ip}` routes → `assert_device_allowed(current_user, ip)`).
- [ ] **Step 4:** review every remaining `is_admin(` in routers: where it means "sees everything", replace with `user_group_scope(user) is None` or `is_unscoped_admin(user)`; list each decision in the report.
- [ ] **Step 5:** full gate (existing scope tests stay green); commit `feat(auth): tenant scope for admins; global settings need an unscoped admin`.

---

### Task 4: User management perimeter for scoped admins

**Files:** Modify `routers/deps.py` (`assert_can_manage`, `assert_can_assign`), `routers/auth.py` (`list_users_ep`, `create_user_ep`, `set_user_groups_ep`, `set_user_tabs_ep`, `invite_user`). Extend `tests/test_super_admin_api.py`.

**Interfaces — Produces:** `deps.user_visible_to(current_user, target_username) -> bool`, `deps.assert_groups_within_scope(current_user, groups: list[str])`, `deps.assert_tabs_within_grant(current_user, tabs: list[str])`.

- [ ] **Step 1: failing tests** (actor `sadm`: admin, groups `["tenant-a"]`; targets `op-a` groups `["tenant-a"]`, `op-b` `["tenant-b"]`, `op-all` `[]`; groups must exist in inventory — reuse the group fixture from Task 3):
  - `GET /api/users` as sadm → usernames == {sadm, op-a}.
  - role / disable / groups / tabs / email / send-reset / approve on `op-b` and `op-all` → 404; on `op-a` → 200.
  - create operator with `groups=[]` → 403; `["tenant-b"]` → 403; `["tenant-a"]` → 200.
  - `/api/users/groups` op-a → `["tenant-a","tenant-b"]` → 403.
  - sadm with `allowed_tabs=["tab-devices","tab-users"]`: `/api/users/tabs` op-a `["tab-settings"]` → 403; `["tab-devices"]` → 200.
  - invite as sadm → 403. Unscoped admin: one regression assert that `GET /api/users` still lists everyone of lower rank.
- [ ] **Step 2:** FAIL. **Step 3:** implement; `assert_can_manage` raises 404 when `not user_visible_to` (don't leak existence). **Step 4:** gate; commit `feat(auth): scoped admins manage only users inside their tenants`.

---

### Task 5: Frontend editors, hints, changelog

**Files:** `static/js/settings.js` (`renderUsersTable`, `assignableTabs`), `static/js/i18n.js`, `routers/auth.py` (`/api/auth/me` fields only if missing), `CHANGELOG.md`, `tests/js/test_assignable_tabs.mjs` (+ wrapper).

- [ ] **Step 1:** failing JS test: `assignableTabs` for an admin-level row includes `tab-users`, `tab-groups`, `tab-sites`, `tab-mcp`, `tab-settings`; for an operator row excludes them; when the current user has a restricted tab list, only those tabs are offered.
- [ ] **Step 2:** implement: `assignableTabs(rowRole)` honours row role and the actor's effective tabs; `/api/auth/me` returns the actor's `allowed_tabs` (exists) and `groups` (add if absent — BASE route, no docstring change); `renderUsersTable` shows Tenant and Tab editors on admin rows the actor can manage; tenant checkboxes limited to the actor's groups when scoped; hint next to admin-group tabs `tr('setTabNeedsUnscopedAdmin')` — it: "Richiede anche un amministratore senza limiti di tenant.", en: "Also requires an administrator with no tenant restriction.".
- [ ] **Step 3:** 403 surfacing: confirm each lazy tab loader shows the error toast on non-OK responses; fix only loaders that swallow it silently, with the existing toast helper.
- [ ] **Step 4:** CHANGELOG `## [Unreleased]` (Italian): Added — permessi per tab applicati dal server e tenant anche per gli admin, decisi dal super_admin; Changed — chi ha "Tab visibili" impostate non raggiunge più le API delle tab nascoste; le impostazioni globali (SMTP, SSO, URL, certificati, aggiornamenti, tenant, sedi, backup cloud, MCP) richiedono un admin senza limiti di tenant.
- [ ] **Step 5:** frontend checks + full gate; `uv run python scripts/dev/capture_screenshots.py` (commit docs/images only if changed); commit `feat(ui): tenant and tab editors for admins`.
