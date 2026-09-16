# super_admin Role Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `super_admin` role above `admin`, so that only a super_admin can create, modify or remove admin-level accounts.

**Architecture:** One rank ladder in `security/user_manager.py` (`ROLE_RANK`, `is_admin`, `can_manage`, `can_assign`), enforced by one FastAPI helper `assert_can_manage` in `routers/deps.py`, called by every `/api/users/*` route. `require_admin` accepts both admin roles, so the 101 existing routes stay untouched. A one-shot lifespan migration promotes existing admins. The frontend gets `isAdminRole()` and hides what the API would refuse.

**Tech Stack:** Python 3 / FastAPI / pytest (+unittest) / classic-script JS, no bundler.

**Spec:** `docs/superpowers/specs/2026-09-16-super-admin-role-design.md`

## Global Constraints

- Roles, highest first: `super_admin`, `admin`, `operator`, `viewer`. The role string is exactly `super_admin` (underscore).
- Rule: an actor may act on a target only if `rank(target) < rank(actor)`, and may assign only `rank(new_role) < rank(actor)`. `super_admin` may act on anyone and assign anything.
- Self-service is unchanged: deleting your own account and editing your own email stay allowed for every role.
- The last **active super_admin** (not disabled, not pending) cannot be demoted, disabled or deleted. Detail message: `"Deve restare almeno un super amministratore attivo."`
- SSO never yields `super_admin`; `sync_roles` never touches an existing `super_admin`; the SSO `default_role` cannot be `super_admin`.
- Legacy accounts without a `role` field are `super_admin`.
- Migration marker: `app_settings.json` key `user_roles_version` = `2`.
- New comments in English; leave surrounding Italian comments alone.
- User-facing strings go through `tr('key')`, in both `it` and `en`. No inline handlers.
- Never touch the real `data/users.json`: tests use a private `USERS_JSON` (monkeypatch or class-level swap).
- Version: MINOR → `0.40.0` in `core/version.py` and `pyproject.toml`.

---

## File Structure

| File | Change |
|---|---|
| `security/user_manager.py` | ladder, helpers, quorum rename, defaults, migration function |
| `routers/deps.py` | `require_admin`, `require_operator`, `require_super_admin`, `assert_can_manage`, `assert_can_assign`, `user_group_scope` |
| `routers/auth.py` | register creates super_admin; guards on every `/api/users/*` route; `is_admin` in `/api/auth/me` and delete; SSO sync helper |
| `routers/commands.py`, `routers/sites.py`, `routers/cloud_backup.py`, `routers/ai.py` | `role == "admin"` → `is_admin(role)` |
| `routers/settings.py`, `security/sso.py` | SSO cannot mint or demote super_admin |
| `app_server.py` | run the migration in the lifespan |
| `static/js/core.js`, `settings.js`, `devices.js`, `home.js`, `observability.js`, `profile.js`, `redundancy.js`, `topology.js` | `isAdminRole`, `canManageRole`, `canAssignRole`, body classes, filtered controls |
| `static/js/i18n.js`, `templates/dashboard.html`, `static/css/dashboard.css` | label, option, pill |
| `tests/test_role_ladder.py` (new) | unit tests for the ladder + migration |
| `tests/test_super_admin_api.py` (new) | API matrix + SSO |
| `tests/test_admin_quorum.py`, `tests/test_user_lifecycle.py`, `tests/test_break_glass.py` | adapt to the renamed quorum |
| `CHANGELOG.md`, `core/version.py`, `pyproject.toml` | release notes + bump |

---

### Task 1: Role ladder in user_manager

**Files:**
- Modify: `security/user_manager.py:28-32` (VALID_ROLES), `:93-99` (get_role), `:170`, `:222` (defaults), `:255-275` (quorum), `:332-337` (first_admin_username), end of file (migration)
- Create: `tests/test_role_ladder.py`
- Modify: `tests/test_admin_quorum.py`, `tests/test_user_lifecycle.py:50-55, 115-119`

**Interfaces:**
- Produces:
  - `VALID_ROLES = ("super_admin", "admin", "operator", "viewer")`
  - `ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2, "super_admin": 3}`
  - `is_admin(role) -> bool`
  - `can_manage(actor_role: str, target_role: str) -> bool`
  - `can_assign(actor_role: str, new_role: str) -> bool`
  - `count_active_super_admins() -> int`
  - `is_last_active_super_admin(username: str) -> bool` (replaces `is_last_active_admin`)
  - `first_admin_username() -> str | None` (prefers super_admin, then admin)
  - `migrate_admins_to_super_admin() -> list[str]` (sorted promoted usernames; idempotent via marker)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_role_ladder.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The role ladder: who may manage whom, the super_admin quorum and the
one-shot promotion of pre-existing admins."""
import json

import pytest


@pytest.fixture
def um(tmp_path, monkeypatch):
    """user_manager bound to a throwaway users.json (never the real one)."""
    from security import user_manager
    monkeypatch.setattr(user_manager, "USERS_JSON", str(tmp_path / "users.json"))
    return user_manager


@pytest.fixture
def settings(monkeypatch):
    """app_settings replaced by an in-memory dict."""
    from core import app_settings
    store = {}
    monkeypatch.setattr(app_settings, "get_app_settings", lambda: dict(store))
    monkeypatch.setattr(app_settings, "save_app_settings", lambda s: store.update(s))
    return store


def test_is_admin(um):
    assert um.is_admin("super_admin") and um.is_admin("admin")
    assert not um.is_admin("operator") and not um.is_admin("viewer")
    assert not um.is_admin(None)


@pytest.mark.parametrize("actor,target,ok", [
    ("super_admin", "super_admin", True),
    ("super_admin", "admin", True),
    ("admin", "super_admin", False),
    ("admin", "admin", False),
    ("admin", "operator", True),
    ("admin", "viewer", True),
    ("operator", "viewer", True),   # rank-wise; routes still require admin first
    ("viewer", "viewer", False),
])
def test_can_manage(um, actor, target, ok):
    assert um.can_manage(actor, target) is ok


@pytest.mark.parametrize("actor,new_role,ok", [
    ("super_admin", "super_admin", True),
    ("super_admin", "admin", True),
    ("admin", "super_admin", False),
    ("admin", "admin", False),
    ("admin", "operator", True),
    ("admin", "viewer", True),
    ("super_admin", "root", False),
])
def test_can_assign(um, actor, new_role, ok):
    assert um.can_assign(actor, new_role) is ok


def test_quorum_counts_active_super_admins_only(um):
    um.create_user("root-a", "password-1234", role="super_admin")
    um.create_user("adm-b", "password-1234", role="admin")
    assert um.count_active_super_admins() == 1
    assert um.is_last_active_super_admin("root-a")
    assert not um.is_last_active_super_admin("adm-b")
    um.create_user("root-c", "password-1234", role="super_admin")
    assert not um.is_last_active_super_admin("root-a")
    um.set_disabled("root-c", True)
    assert um.is_last_active_super_admin("root-a")
    assert not um.is_last_active_super_admin("root-c")


def test_legacy_account_without_role_is_super_admin(um, tmp_path):
    (tmp_path / "users.json").write_text(
        json.dumps({"legacy": {"hashed_password": "$2b$12$notarealhash"}}),
        encoding="utf-8")
    assert um.get_role("legacy") == "super_admin"
    assert um.list_users()[0]["role"] == "super_admin"
    assert um.first_admin_username() == "legacy"


def test_first_admin_prefers_super_admin(um):
    um.create_user("aaa-admin", "password-1234", role="admin")
    assert um.first_admin_username() == "aaa-admin"   # CLI run before migration
    um.create_user("zzz-root", "password-1234", role="super_admin")
    assert um.first_admin_username() == "zzz-root"


def test_migration_promotes_admins_once(um, settings):
    um.create_user("adm-1", "password-1234", role="admin")
    um.create_user("op-1", "password-1234", role="operator")
    assert um.migrate_admins_to_super_admin() == ["adm-1"]
    assert um.get_role("adm-1") == "super_admin"
    assert um.get_role("op-1") == "operator"
    assert settings["user_roles_version"] == 2
    # An admin created after the migration is never promoted.
    um.create_user("adm-2", "password-1234", role="admin")
    assert um.migrate_admins_to_super_admin() == []
    assert um.get_role("adm-2") == "admin"


def test_migration_on_empty_store_sets_marker(um, settings):
    assert um.migrate_admins_to_super_admin() == []
    assert settings["user_roles_version"] == 2
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_role_ladder.py -v`
Expected: FAIL — `AttributeError: module 'security.user_manager' has no attribute 'is_admin'` (and friends).

- [ ] **Step 3: Implement in `security/user_manager.py`**

Replace the roles block at lines 28-32:

```python
# Ruoli supportati, dal più al meno privilegiato:
#   super_admin → everything, including managing other admin-level accounts
#   admin    → controllo totale, incluso la gestione utenti
#   operator → tutte le operazioni di rete (triage, comandi, CRUD apparati) ma non utenti
#   viewer   → sola lettura (inventario, mappe, threat intel)
VALID_ROLES = ("super_admin", "admin", "operator", "viewer")
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2, "super_admin": 3}
ADMIN_ROLES = ("super_admin", "admin")
# Accounts predating roles are single-user installs: their owner.
LEGACY_ROLE = "super_admin"


def is_admin(role) -> bool:
    return role in ADMIN_ROLES


def can_manage(actor_role: str, target_role: str) -> bool:
    """FortiGate model: only a super_admin touches its peers; everyone else
    manages strictly lower ranks."""
    if actor_role == "super_admin":
        return True
    return ROLE_RANK.get(target_role, 0) < ROLE_RANK.get(actor_role, 0)


def can_assign(actor_role: str, new_role: str) -> bool:
    if new_role not in ROLE_RANK:
        return False
    return actor_role == "super_admin" or ROLE_RANK[new_role] < ROLE_RANK.get(actor_role, 0)
```

In `get_role` (line 99), `list_users` (line 170) and `get_profile` (line 222) replace the default `"admin"` with `LEGACY_ROLE`:

```python
    return user.get("role", LEGACY_ROLE)
```
```python
            "role": d.get("role", LEGACY_ROLE),
```
```python
        "role": d.get("role", LEGACY_ROLE),
```
Also update the `get_role` docstring: "...sono trattati come super_admin."

Replace `count_active_admins` and `is_last_active_admin` (lines 255-275) with:

```python
def count_active_super_admins() -> int:
    """Active super administrators (not disabled, not awaiting approval)."""
    return sum(1 for d in get_users().values()
               if d.get("role", LEGACY_ROLE) == "super_admin" and not d.get("disabled", False)
               and not d.get("pending_approval", False))

def is_last_active_super_admin(username: str) -> bool:
    """True if removing this account's role, access or existence would leave
    the install without a USABLE super administrator.

    Only active accounts count: a disabled one cannot pass get_current_user,
    so counting it is the same as having none, and the app reopens only by
    editing users.json by hand. For the same reason an already disabled
    super_admin is never "the last".
    """
    user = get_users().get(username)
    if (not user or user.get("role", LEGACY_ROLE) != "super_admin" or user.get("disabled", False)
            or user.get("pending_approval", False)):
        return False
    return count_active_super_admins() <= 1
```

Replace `first_admin_username` (lines 332-337):

```python
def first_admin_username():
    """Highest-ranked admin account, alphabetical within a rank, or None.
    Used by the break-glass CLI when no username is given. Plain admins are
    the fallback for a CLI run before the role migration ever executed."""
    admins = sorted((-ROLE_RANK[d.get("role", LEGACY_ROLE)], u)
                    for u, d in get_users().items()
                    if is_admin(d.get("role", LEGACY_ROLE)))
    return admins[0][1] if admins else None
```

Append at the end of the file (`_users_lock` is an `RLock`, so the nested `get_users`/`_save_users` are safe):

```python
ROLES_SCHEMA_VERSION = 2

def migrate_admins_to_super_admin() -> list:
    """One-shot upgrade to the super_admin ladder: every existing admin is
    promoted, so nobody loses power on upgrade. The marker in app_settings
    keeps admins created afterwards from ever being promoted."""
    from core import app_settings
    if int(app_settings.get_app_settings().get("user_roles_version", 1)) >= ROLES_SCHEMA_VERSION:
        return []
    promoted = []
    with _users_lock:
        users = get_users()
        for name, d in users.items():
            if d.get("role") == "admin":
                d["role"] = "super_admin"
                promoted.append(name)
        if promoted:
            _save_users(users)
    app_settings.save_app_settings({"user_roles_version": ROLES_SCHEMA_VERSION})
    return sorted(promoted)
```

(`get_users()` returns `{}` when the file does not exist, and raises `UsersStoreError` on a corrupt store — letting that propagate at startup is correct: the app refuses a corrupt store everywhere else too.)

- [ ] **Step 4: Adapt the existing tests to the renamed quorum**

`tests/test_admin_quorum.py` — the whole module tests the quorum, which now belongs to super_admins:
- `setUp`: `user_manager.create_user("alice", "alicepass123", role="admin")` → `role="super_admin"`.
- `_usable_admins`: `u["role"] == "admin"` → `u["role"] == "super_admin"`.
- `_add_admin`: `role="admin"` → `role="super_admin"`.
- `test_the_rule_itself`: every `is_last_active_admin` → `is_last_active_super_admin` (5 calls).
- `self.assertIn("amministratore", ...)` stays valid ("super amministratore" contains it).

`tests/test_user_lifecycle.py`:
- `setUpClass` line 52: `role="admin"` → `role="super_admin"` (inviting a super_admin needs one).
- lines 115-119 become:

```python
    def test_pending_admin_is_not_an_active_admin(self):
        before = user_manager.count_active_super_admins()
        self._accept_invite(role="super_admin")
        self.assertEqual(user_manager.count_active_super_admins(), before)
        self.assertFalse(user_manager.is_last_active_super_admin(INVITED))
```

`tests/test_break_glass.py`: no edit expected (`first_admin_username` still returns `mike-admin`; legacy still resolves). Run it to confirm.

- [ ] **Step 5: Run to verify**

Run: `uv run pytest tests/test_role_ladder.py tests/test_break_glass.py -v`
Expected: all PASS.

Run: `uv run pytest tests/test_admin_quorum.py -v`
Expected: still FAILS until Task 2 — `routers/auth.py` calls the removed `is_last_active_admin`, and `require_admin` rejects `super_admin` logins. Confirm the errors are exactly those two causes, nothing else.

- [ ] **Step 6: Commit**

```bash
git add security/user_manager.py tests/test_role_ladder.py tests/test_admin_quorum.py tests/test_user_lifecycle.py
git commit -m "feat(auth): super_admin role ladder and quorum in user_manager"
```

---

### Task 2: Enforce the ladder on every user route

**Files:**
- Modify: `routers/deps.py:91-101` (+ new helpers after `assert_group_allowed`)
- Modify: `routers/auth.py:22, 92, 317, 326-470, 567-640, 651-670`
- Modify: `routers/commands.py:92, 103, 358`, `routers/sites.py:76`, `routers/cloud_backup.py:119, 153`, `routers/ai.py:555`
- Create: `tests/test_super_admin_api.py`

**Interfaces:**
- Consumes: `user_manager.is_admin`, `can_manage`, `can_assign`, `is_last_active_super_admin` (Task 1)
- Produces:
  - `deps.require_admin` (accepts `super_admin`, `admin`)
  - `deps.require_operator` (accepts `super_admin`, `admin`, `operator`)
  - `deps.require_super_admin`
  - `deps.assert_can_manage(current_user: dict, target_username: str, new_role: str | None = None, allow_self: bool = False) -> None` — 404 if the target is missing, 403 if forbidden
  - `deps.assert_can_assign(current_user: dict, new_role: str) -> None` — 403 if forbidden

- [ ] **Step 1: Write the failing API tests**

Create `tests/test_super_admin_api.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""An admin cannot take over a super_admin, nor mint an admin-level account.

Every /api/users/* route that touches another account goes through
deps.assert_can_manage; the matrix below hits each of them for real, because
OpenAPI introspection never runs a handler body."""
import os
import tempfile
import unittest

from fastapi.testclient import TestClient

import app_server
from routers.deps import CSRF_HEADER
from security import security_manager, user_invite, user_manager
from services import mailer

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"


class _PrivateUsers(unittest.TestCase):
    """Private users store: setUp wipes it, the suite's shared file is never touched."""

    @classmethod
    def setUpClass(cls):
        cls._orig = user_manager.USERS_JSON
        user_manager.USERS_JSON = os.path.join(
            tempfile.mkdtemp(prefix="superadmin_users_"), "users.json")

    @classmethod
    def tearDownClass(cls):
        user_manager.USERS_JSON = cls._orig

    def setUp(self):
        for u in user_manager.list_users():
            user_manager.delete_user(u["username"])
        security_manager._failed_attempts.clear()
        user_invite.clear()
        self._real_send = mailer.send_email
        mailer.send_email = lambda *a, **k: None

    def tearDown(self):
        mailer.send_email = self._real_send

    def _as(self, name):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": name, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        return c


class TestSuperAdminRoutes(_PrivateUsers):
    def setUp(self):
        super().setUp()
        user_manager.create_user("root", PW, role="super_admin", email="root@example.com")
        user_manager.create_user("adm", PW, role="admin", email="adm@example.com")
        user_manager.create_user("op", PW, role="operator", email="op@example.com")

    # --- admin against super_admin: every route refuses ---

    def test_admin_cannot_touch_super_admin_on_any_route(self):
        adm = self._as("adm")
        calls = [
            ("/api/users/role", {"username": "root", "role": "viewer"}),
            ("/api/users/disable", {"username": "root", "disabled": True}),
            ("/api/users/delete", {"username": "root"}),
            ("/api/users/groups", {"username": "root", "groups": []}),
            ("/api/users/tabs", {"username": "root", "allowed_tabs": []}),
            ("/api/users/email", {"username": "root", "email": "x@example.com"}),
            ("/api/users/send-reset", {"username": "root"}),
            ("/api/users/approve", {"username": "root"}),
        ]
        for path, body in calls:
            with self.subTest(path=path):
                r = adm.post(path, json=body, headers=H)
                self.assertEqual(r.status_code, 403, f"{path}: {r.text}")
        self.assertEqual(user_manager.get_role("root"), "super_admin")
        self.assertFalse(user_manager.is_disabled("root"))
        self.assertEqual(user_manager.get_email("root"), "root@example.com")

    def test_admin_cannot_touch_another_admin(self):
        user_manager.create_user("adm2", PW, role="admin")
        r = self._as("adm").post("/api/users/disable", headers=H,
                                 json={"username": "adm2", "disabled": True})
        self.assertEqual(r.status_code, 403, r.text)

    def test_admin_cannot_assign_admin_level_roles(self):
        adm = self._as("adm")
        for role in ("admin", "super_admin"):
            with self.subTest(role=role):
                r = adm.post("/api/users/role", headers=H,
                             json={"username": "op", "role": role})
                self.assertEqual(r.status_code, 403, r.text)
                r = adm.post("/api/users", headers=H, json={
                    "username": f"new-{role}", "password": PW, "role": role})
                self.assertEqual(r.status_code, 403, r.text)
                r = adm.post("/api/users/invite", headers=H,
                             json={"email": f"{role}@example.com", "role": role})
                self.assertEqual(r.status_code, 403, r.text)
        self.assertEqual(user_manager.get_role("op"), "operator")

    def test_admin_cannot_promote_self(self):
        r = self._as("adm").post("/api/users/role", headers=H,
                                 json={"username": "adm", "role": "super_admin"})
        self.assertEqual(r.status_code, 403, r.text)

    def test_unknown_target_is_404(self):
        r = self._as("adm").post("/api/users/disable", headers=H,
                                 json={"username": "nobody", "disabled": True})
        self.assertEqual(r.status_code, 404, r.text)

    # --- what stays allowed ---

    def test_admin_manages_lower_ranks(self):
        adm = self._as("adm")
        r = adm.post("/api/users/role", headers=H, json={"username": "op", "role": "viewer"})
        self.assertEqual(r.status_code, 200, r.text)
        r = adm.post("/api/users", headers=H,
                     json={"username": "new-op", "password": PW, "role": "operator"})
        self.assertEqual(r.status_code, 200, r.text)

    def test_admin_keeps_self_service(self):
        adm = self._as("adm")
        r = adm.post("/api/users/email", headers=H,
                     json={"username": "adm", "email": "me@example.com"})
        self.assertEqual(r.status_code, 200, r.text)
        r = adm.post("/api/users/delete", headers=H, json={"username": "adm"})
        self.assertEqual(r.status_code, 200, r.text)

    def test_super_admin_manages_peers_and_admins(self):
        user_manager.create_user("root2", PW, role="super_admin")
        root = self._as("root")
        r = root.post("/api/users/role", headers=H, json={"username": "root2", "role": "admin"})
        self.assertEqual(r.status_code, 200, r.text)
        r = root.post("/api/users/role", headers=H, json={"username": "adm", "role": "super_admin"})
        self.assertEqual(r.status_code, 200, r.text)

    def test_last_super_admin_cannot_demote_self(self):
        r = self._as("root").post("/api/users/role", headers=H,
                                  json={"username": "root", "role": "admin"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("super amministratore", r.json()["detail"])

    def test_both_admin_roles_open_admin_routes(self):
        self.assertEqual(self._as("adm").get("/api/users").status_code, 200)
        self.assertEqual(self._as("root").get("/api/users").status_code, 200)
        self.assertEqual(self._as("op").get("/api/users").status_code, 403)


class TestRegisterCreatesSuperAdmin(_PrivateUsers):
    def test_register_role_is_super_admin(self):
        r = TestClient(app_server.app).post(
            "/api/auth/register", json={"username": "first", "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(user_manager.get_role("first"), "super_admin")


if __name__ == "__main__":
    unittest.main()
```

If `/api/auth/register` returns 422, read `UserSchema` in `routers/auth.py` and add its required fields to the JSON.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_super_admin_api.py -v`
Expected: FAIL — `root` logins pass but `/api/users` returns 403 for `root` (`require_admin` rejects `super_admin`); admin-vs-root calls return 200 instead of 403; register creates `admin`.

- [ ] **Step 3: Implement `routers/deps.py`**

Replace lines 91-92:

```python
require_super_admin = require_role("super_admin")
require_admin = require_role("super_admin", "admin")              # solo amministratori
require_operator = require_role("super_admin", "admin", "operator")  # scritture/operazioni di rete
```

In `user_group_scope` (line 101):

```python
    if user_manager.is_admin(current_user.get("role")):
        return None
```

Add right after `assert_group_allowed`:

```python
def assert_can_manage(current_user, target_username: str, new_role=None,
                      allow_self: bool = False) -> None:
    """The single gate for acting on another account (FortiGate model: only a
    super_admin touches admin-level accounts). allow_self keeps self-service
    routes (own email, own deletion) open to every role; it never lets anyone
    raise their own role, because new_role is still checked."""
    target_role = user_manager.get_role(target_username)
    if target_role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utente non trovato.")
    actor_role = current_user.get("role")
    is_self = target_username == current_user.get("sub")
    if not (is_self and allow_self) and not user_manager.can_manage(actor_role, target_role):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Insufficient privileges for this operation.")
    if new_role is not None:
        assert_can_assign(current_user, new_role)


def assert_can_assign(current_user, new_role: str) -> None:
    """For routes that create an account or change a role."""
    if not user_manager.can_assign(current_user.get("role"), new_role):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Insufficient privileges for this operation.")
```

Behaviour check against the tests: `adm` on self with `/role` → `can_manage("admin","admin")` False → 403. `root` demoting self → allowed by `can_manage` → reaches the quorum → 400.

- [ ] **Step 4: Implement `routers/auth.py`**

Line 22:
```python
from routers.deps import (SESSION_COOKIE, assert_can_assign, assert_can_manage,
                          get_current_user, require_admin)
```

Line 92 (register):
```python
    success = user_manager.create_user(payload.username, payload.password, role="super_admin")
```

Line 317 (`/api/auth/me`):
```python
    allowed_tabs = [] if user_manager.is_admin(role) else user_manager.get_allowed_tabs(username)
```

`create_user_ep`, right after the `VALID_ROLES` check (after line 329):
```python
    assert_can_assign(current_user, payload.role)
```

`delete_user_ep` (lines 408-414) — replace the role check and the quorum:
```python
    if payload.username != current_user.get("sub") and not user_manager.is_admin(current_user.get("role")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient privileges for this operation."
        )
    assert_can_manage(current_user, payload.username, allow_self=True)
    if user_manager.is_last_active_super_admin(payload.username):
        raise HTTPException(status_code=400, detail="Deve restare almeno un super amministratore attivo.")
```

`set_user_role_ep` (lines 422-425):
```python
    if payload.role not in user_manager.VALID_ROLES:
        raise HTTPException(status_code=400, detail="Ruolo non valido.")
    assert_can_manage(current_user, payload.username, new_role=payload.role)
    if payload.role != "super_admin" and user_manager.is_last_active_super_admin(payload.username):
        raise HTTPException(status_code=400, detail="Deve restare almeno un super amministratore attivo.")
```

`disable_user_ep` — keep the self check, then replace the two `is_last_active_admin` lines with:
```python
    assert_can_manage(current_user, payload.username)
    if payload.disabled and user_manager.is_last_active_super_admin(payload.username):
        raise HTTPException(status_code=400, detail="Deve restare almeno un super amministratore attivo.")
```

First line of the body (after the docstring) of `set_user_groups_ep`, `set_user_tabs_ep`, `admin_send_reset`, `approve_user`:
```python
    assert_can_manage(current_user, payload.username)
```

`set_user_email`, first line after the docstring:
```python
    assert_can_manage(current_user, payload.username, allow_self=True)
```

`invite_user`, after the `VALID_ROLES` check (after line 666):
```python
    assert_can_assign(current_user, payload.role)
```

The handlers' own 404 branches stay (a concurrent delete can still race).

- [ ] **Step 5: Replace the remaining backend `"admin"` comparisons**

`routers/sites.py` and `routers/cloud_backup.py` do not import `user_manager`: add `from security import user_manager` to their import block. `routers/commands.py` already imports it (line 23). Check `routers/ai.py` needs nothing (tuple literal).

- `routers/commands.py:92` → `if user_manager.is_admin(current_user.get("role")):`
- `routers/commands.py:103` → `return ("(blacklist bypassata: admin)" if user_manager.is_admin(current_user.get("role"))`
- `routers/commands.py:358` → `if not user_manager.is_admin(_role):`
- `routers/sites.py:76` → `if not user_manager.is_admin(current_user.get("role")):`
- `routers/cloud_backup.py:119` → `if not user_manager.is_admin(current_user.get("role")) and last_run.get("error"):`
- `routers/cloud_backup.py:153` → `if user_manager.is_admin(current_user.get("role")):`
- `routers/ai.py:555` → `if payload.attach_device_ips and current_user.get("role") in ("super_admin", "admin", "operator"):`

Verify: `grep -rn '== "admin"\|!= "admin"\|in ("admin"' routers security --include=*.py` → only `security/user_manager.py` migration (`d.get("role") == "admin"`).

- [ ] **Step 6: Run the focused tests**

Run: `uv run pytest tests/test_super_admin_api.py tests/test_admin_quorum.py tests/test_user_lifecycle.py tests/test_role_ladder.py tests/test_break_glass.py -v`
Expected: all PASS.

- [ ] **Step 7: Full suite and fallout**

Run: `uv run pytest tests -n 4`
Expected fallout: tests where an `admin` manages another `admin`, or assigns `admin`, now get 403. Fix by making **the acting account** `super_admin` in that test's setup (`role="admin"` → `role="super_admin"`), never by loosening `assert_can_manage`. OpenAPI snapshot tests: the new helpers add no parameters, so the contract must not change — if one fails, read the diff before touching anything.

- [ ] **Step 8: Commit**

```bash
git add routers/deps.py routers/auth.py routers/commands.py routers/sites.py routers/cloud_backup.py routers/ai.py tests/
git commit -m "feat(auth): only super_admin manages admin-level accounts"
```

---

### Task 3: SSO guard and startup migration

**Files:**
- Modify: `security/sso.py:223-238`
- Modify: `routers/auth.py` (SSO callback, ~lines 794-815)
- Modify: `routers/settings.py:388`
- Modify: `app_server.py:54-58` (lifespan)
- Test: `tests/test_super_admin_api.py` (append)

**Interfaces:**
- Consumes: `user_manager.migrate_admins_to_super_admin()` (Task 1), `_PrivateUsers` test base (Task 2)
- Produces: `routers.auth._sso_synced_role(existing_role: str, mapped_role: str, sync: bool) -> str`

- [ ] **Step 1: Append failing tests to `tests/test_super_admin_api.py`**

Before `if __name__ == "__main__":`:

```python
class TestSsoNeverMintsSuperAdmin(_PrivateUsers):
    @staticmethod
    def _cfg(**over):
        cfg = {"admin_group": "net-admins", "operator_group": "net-ops",
               "default_role": "viewer"}
        cfg.update(over)
        return cfg

    def test_admin_group_maps_to_admin(self):
        from security import sso
        self.assertEqual(sso.resolve_role(self._cfg(), {"groups": ["net-admins"]}), "admin")

    def test_default_role_super_admin_is_clamped(self):
        from security import sso
        self.assertEqual(
            sso.resolve_role(self._cfg(default_role="super_admin"), {"groups": []}), "viewer")

    def test_synced_role_keeps_super_admin(self):
        from routers.auth import _sso_synced_role
        self.assertEqual(_sso_synced_role("super_admin", "viewer", sync=True), "super_admin")
        self.assertEqual(_sso_synced_role("admin", "viewer", sync=True), "viewer")
        self.assertEqual(_sso_synced_role("admin", "viewer", sync=False), "admin")

    def test_settings_refuse_super_admin_default_role(self):
        user_manager.create_user("sso-root", PW, role="super_admin")
        c = self._as("sso-root")
        current = c.get("/api/settings/sso")
        self.assertEqual(current.status_code, 200, current.text)
        body = {k: v for k, v in current.json().items() if not k.startswith("has_")}
        body["default_role"] = "super_admin"
        r = c.post("/api/settings/sso", json=body, headers=H)
        self.assertEqual(r.status_code, 400, r.text)
```

If the POST returns 422 instead of 400, the GET shape does not match `SsoSettingsSchema` (`routers/settings.py` ~line 365): build `body` from that schema's fields with dummy values (`"https://idp.example.com"` for URLs) plus `default_role`.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_super_admin_api.py -v -k Sso`
Expected: FAIL — `ImportError: cannot import name '_sso_synced_role'`; clamp test gets `super_admin`; settings POST returns 200.

- [ ] **Step 3: Implement**

`security/sso.py`, replace the last line of `resolve_role` (`return cfg["default_role"]`):
```python
    # An IdP must never mint the top role: a misconfigured default would
    # hand super_admin to every federated login.
    default = cfg["default_role"]
    return "viewer" if default == "super_admin" else default
```

`routers/settings.py:388`:
```python
    if payload.default_role not in user_manager.VALID_ROLES or payload.default_role == "super_admin":
```

`routers/auth.py`, add just above the SSO callback function:
```python
def _sso_synced_role(existing_role: str, mapped_role: str, sync: bool) -> str:
    """Role after an SSO login. A super_admin is managed locally only: the
    IdP can neither grant nor revoke it."""
    if not sync or existing_role == "super_admin":
        return existing_role
    return mapped_role
```
and in the callback's `else:` branch replace:
```python
        role = mapped_role if cfg["sync_roles"] else existing_role
        if cfg["sync_roles"] and mapped_role != existing_role:
            user_manager.set_role(username, mapped_role)
            log_audit(f"Ruolo di '{username}' allineato a '{mapped_role}' dai gruppi dell'IdP.")
```
with:
```python
        role = _sso_synced_role(existing_role, mapped_role, cfg["sync_roles"])
        if role != existing_role:
            user_manager.set_role(username, role)
            log_audit(f"Ruolo di '{username}' allineato a '{role}' dai gruppi dell'IdP.")
```

`app_server.py` lifespan — insert after the `db.start_writer()` try/except, before `from observability import listener_manager`:
```python
    # One-shot role ladder upgrade: pre-existing admins become super_admin.
    from security import user_manager
    from security.security_manager import log_audit
    for promoted in user_manager.migrate_admins_to_super_admin():
        log_audit(f"Ruolo di '{promoted}' promosso a 'super_admin' dalla migrazione dei ruoli.")
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_super_admin_api.py tests/test_role_ladder.py -v`
Then any existing SSO tests: `uv run pytest tests -k sso -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add security/sso.py routers/settings.py routers/auth.py app_server.py tests/test_super_admin_api.py
git commit -m "feat(auth): SSO cannot grant or revoke super_admin; migrate admins on startup"
```

---

### Task 4: Frontend

**Files:**
- Modify: `static/js/core.js:789-794, 808-817`
- Modify: `static/js/settings.js:7, 505, 516-519, 524-527, 551-553, 587-622, 805, 845, 917, 1001, 1240, 1281, 1307`
- Modify: `static/js/devices.js:68`, `home.js:176`, `observability.js:9`, `profile.js:40`, `redundancy.js:101, 233`, `topology.js:2807-2809`
- Modify: `static/js/i18n.js` (it: near `roleAdmin` ~1532 and `coreAdministrator` ~2277; en: ~4583 and ~5326)
- Modify: `templates/dashboard.html:4682-4686, 4708-4712`
- Modify: `static/css/dashboard.css:1229`

**Interfaces:**
- Consumes: API behaviour from Task 2 (403 on forbidden actions).
- Produces (top-level function declarations in `core.js`, shared global scope):
  - `isAdminRole(role) -> boolean`
  - `canManageRole(actorRole, targetRole) -> boolean`
  - `canAssignRole(actorRole, newRole) -> boolean`

- [ ] **Step 1: Helpers and body class in `core.js`**

Check the name is free: `grep -rn "ROLE_RANK" static/js` → no hits (if taken, use `USER_ROLE_RANK`).

Replace the `roleLabel` block (lines 789-794):

```js
// --- RUOLI / PRIVILEGI ---

// Mirrors security/user_manager.py ROLE_RANK. Hiding a control is a
// convenience only: the API enforces the same ladder.
const ROLE_RANK = { viewer: 0, operator: 1, admin: 2, super_admin: 3 };

function isAdminRole(role) {
    return role === 'super_admin' || role === 'admin';
}

function canManageRole(actorRole, targetRole) {
    if (actorRole === 'super_admin') return true;
    return (ROLE_RANK[targetRole] ?? 0) < (ROLE_RANK[actorRole] ?? 0);
}

function canAssignRole(actorRole, newRole) {
    if (!(newRole in ROLE_RANK)) return false;
    return actorRole === 'super_admin' || ROLE_RANK[newRole] < (ROLE_RANK[actorRole] ?? 0);
}

function roleLabel(role) {
    if (role === 'super_admin') return tr('coreSuperAdministrator');
    if (role === 'admin') return tr('coreAdministrator');
    if (role === 'operator') return tr('coreOperator');
    return tr('coreViewer');
}
```

In `applyRoleUI`, replace lines 811-816 (class swap + icon):

```js
    document.body.classList.remove('role-super_admin', 'role-admin', 'role-operator', 'role-viewer');
    document.body.classList.add('role-' + currentRole);
    // requires-admin controls (dashboard.css) stay visible to a super_admin.
    if (currentRole === 'super_admin') document.body.classList.add('role-admin');
    // Role selects offer only what this account may assign.
    document.querySelectorAll('select[data-role-select]').forEach(sel => {
        sel.querySelectorAll('option').forEach(opt => {
            const ok = canAssignRole(currentRole, opt.value);
            opt.hidden = !ok;
            opt.disabled = !ok;
        });
        if (sel.selectedOptions[0]?.disabled) sel.value = 'viewer';
    });
    const badge = document.getElementById('userBadgeLabel');
    if (badge) {
        const icon = isAdminRole(currentRole) ? 'fa-user-shield'
            : currentRole === 'operator' ? 'fa-user-gear' : 'fa-user';
```

- [ ] **Step 2: Template, i18n, CSS**

`templates/dashboard.html` — both `#newUserRole` (line 4682) and `#inviteRole` (line 4708): add `data-role-select` to the `<select>` and a fourth option. `#newUserRole` becomes:

```html
        <label for="newUserRole" data-i18n="lblNewUserRole">Ruolo</label><select id="newUserRole" data-role-select style="padding-left:12px;">
          <option value="viewer" data-i18n="roleViewer">Viewer (sola lettura)</option>
          <option value="operator" data-i18n="roleOperator">Operator (operazioni)</option>
          <option value="admin" data-i18n="roleAdmin">Admin (totale)</option>
          <option value="super_admin" data-i18n="roleSuperAdmin">Super admin (gestisce gli admin)</option>
        </select>
```
`#inviteRole` becomes:
```html
        <label for="inviteRole" data-i18n="lblNewUserRole">Ruolo</label><select id="inviteRole" data-role-select style="padding-left:12px;">
          <option value="viewer" data-i18n="roleViewer">Viewer (sola lettura)</option>
          <option value="operator" data-i18n="roleOperator">Operator (operazioni)</option>
          <option value="admin" data-i18n="roleAdmin">Admin (totale)</option>
          <option value="super_admin" data-i18n="roleSuperAdmin">Super admin (gestisce gli admin)</option>
        </select>
```
Leave `#ssoDefaultRole` untouched.

`static/js/i18n.js` — Italian dictionary, next to `roleAdmin` and `coreAdministrator`:
```js
        roleSuperAdmin: "Super admin (gestisce gli admin)",
```
```js
        coreSuperAdministrator: "Super amministratore",
```
English dictionary, next to `roleAdmin` and `coreAdministrator`:
```js
        roleSuperAdmin: "Super admin (manages admins)",
```
```js
        coreSuperAdministrator: "Super administrator",
```

`static/css/dashboard.css:1229` — replace the `.role-pill-admin` line with:
```css
.role-pill-admin,
.role-pill-super_admin { background: var(--lamp-fault-wash); color: var(--lamp-fault-ink); border-color: var(--lamp-fault); }
.role-pill-super_admin { font-weight: 700; }
```
Line 1831 (`body:not(.role-admin) .requires-admin`) stays: a super_admin carries `role-admin` (Step 1).

- [ ] **Step 3: Replace the admin checks**

- `settings.js:7, 505, 805, 845, 917, 1001, 1240, 1281, 1307`: `if (currentRole !== 'admin') return;` → `if (!isAdminRole(currentRole)) return;`
- `devices.js:68`: `${currentRole === 'admin'` → `${isAdminRole(currentRole)`
- `home.js:176`: `if (currentRole === 'admin') loadHomeAnomalies();` → `if (isAdminRole(currentRole)) loadHomeAnomalies();`
- `observability.js:9`: `if (currentRole !== 'admin') return;` → `if (!isAdminRole(currentRole)) return;`
- `profile.js:40`: `const unrestricted = p.role === 'admin';` → `const unrestricted = isAdminRole(p.role);`
- `redundancy.js:101, 233`: `currentRole === 'admin'` → `isAdminRole(currentRole)`
- `topology.js:2807`: `const canWrite = (isAdminRole(currentRole) || currentRole === 'operator');`
- `topology.js:2809`: `const canAdmin = isAdminRole(currentRole);`

(`settings.js:524, 551` are rewritten in Step 4.)

- [ ] **Step 4: Users table shows only manageable controls (`settings.js` `renderUsersTable`)**

Replace lines 516-519 (start of the `map`, role options, `isSelf`):
```js
        body.innerHTML = users.map(u => {
            const isSelf = u.username === currentUsername;
            const manageable = !isSelf && canManageRole(currentRole, u.role);
            const roleOptions = ['viewer', 'operator', 'admin', 'super_admin']
                .filter(r => r === u.role || canAssignRole(currentRole, r))
                .map(r => `<option value="${r}" ${r === u.role ? 'selected' : ''}>${roleLabel(r)}</option>`).join('');
            const scope = Array.isArray(u.groups) ? u.groups : [];
```

Scope cell — replace the opening `if (u.role === 'admin') { scopeCell = ...; } else {` (lines 524-526) with:
```js
            if (isAdminRole(u.role) || !manageable) {
                scopeCell = isAdminRole(u.role)
                    ? `<span style="color:var(--text-muted); font-size:12px;">${tr('setAllTenantsAdmin')}</span>`
                    : `<span style="color:var(--text-muted); font-size:12px;">${scope.length ? scope.map(escapeHtml).join(', ') : tr('uiAllTenants')}</span>`;
            } else {
```

Tabs cell — replace `if (u.role === 'admin') { tabsCell = ...; } else {` (lines 551-553) with:
```js
            if (isAdminRole(u.role) || !manageable) {
                tabsCell = `<span style="color:var(--text-muted); font-size:12px;">${isAdminRole(u.role) ? tr('setAllTabsAdmin') : tr('setAllTabs')}</span>`;
            } else {
```

Buttons — add `manageable` to each condition:
```js
            const toggleBtn = !manageable ? '' :
```
(was `const toggleBtn = isSelf ? '' :` — `manageable` is already false for self)
```js
            const approveBtn = (pending && manageable)
```
```js
            const resetBtn = (u.email && !pending && !disabled && manageable)
```

Row template — email input gets a disabled attribute when not editable; insert `${(manageable || isSelf) ? '' : 'disabled'}` right after `data-username="${escapeHtml(u.username)}"` inside the `<input ...>`.

Role cell — replace the `<td><select data-action="change-user-role" ...>${roleOptions}</select></td>` block with:
```js
                <td>${manageable
                    ? `<select data-action="change-user-role" data-username="${escapeHtml(u.username)}" aria-label="${tr('lblNewUserRole')}"
                       style="font-size:12px; padding:4px 8px; border-radius:0; border:1px solid var(--border); background:var(--surface-3); color:var(--text); cursor:pointer; outline:none;">
                    ${roleOptions}
                  </select>`
                    : `<span class="role-pill role-pill-${escapeHtml(u.role)}">${roleLabel(u.role)}</span>`}</td>
```

Actions cell — the delete button only when manageable or self:
```js
                <td style="white-space:nowrap;">${approveBtn}${resetBtn}${toggleBtn}${(manageable || isSelf) ? `<button data-action="delete-user" data-username="${escapeHtml(u.username)}" style="color:var(--danger); background:none; border:none; cursor:pointer;"><i class="fa-solid fa-trash-can"></i> ${delText}</button>` : ''}</td>
```

Note: before this change your own row had an editable role select; now it shows a pill. A super_admin who wants to demote self (with another super_admin present) asks the other one — same as FortiGate.

- [ ] **Step 5: Frontend checks**

Run:
```
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
uv run pytest tests/test_i18n_keys.py tests/test_a11y_dashboard.py tests/test_lazy_tab_scripts.py tests/test_ui_modal.py -v
```
Expected: 0 errors, all PASS. Only if `check_frontend.py` reports the three helpers as undeclared, add to `types/globals.d.ts`:
```ts
declare function isAdminRole(role: string | null | undefined): boolean;
declare function canManageRole(actorRole: string, targetRole: string): boolean;
declare function canAssignRole(actorRole: string, newRole: string): boolean;
```

- [ ] **Step 6: Manual check in the running app**

Start the app with a throwaway data dir (`SENTINELNET_DATA_DIR` set to a new temp folder — never `data/`):
1. Setup wizard → the first account shows the "Super amministratore" pill.
2. Create `adm` (admin) and `op` (operator). Log in as `adm`: new-user and invite selects offer only Viewer/Operator; the super_admin row has a pill and no buttons; the `op` row is fully editable; Users/Settings tabs visible.
3. Log in as the super_admin: every row editable, all four roles offered.

- [ ] **Step 7: Commit**

```bash
git add static/js static/css/dashboard.css templates/dashboard.html types/globals.d.ts
git commit -m "feat(ui): super_admin label and role-aware user management controls"
```

---

### Task 5: Release notes, version, full gate

**Files:**
- Modify: `CHANGELOG.md` (`## [Unreleased]`), `core/version.py`, `pyproject.toml`

- [ ] **Step 1: Changelog entry under `## [Unreleased]`**

```markdown
### Added

- **Ruolo super_admin.** Sopra `admin` c'e' ora `super_admin`: solo un
  super_admin crea, modifica, disabilita o elimina account di livello admin.
  Un admin gestisce soltanto operator e viewer e non puo' assegnare ne'
  `admin` ne' `super_admin`. Stesso modello del profilo `super_admin` di
  FortiGate.

### Changed

- **Aggiornamento automatico dei ruoli.** Al primo avvio della nuova versione
  ogni admin esistente diventa `super_admin` (una sola volta, registrato
  nell'audit log): nessuno perde poteri. Riportare ad `admin` chi non deve
  gestire altri amministratori.
- **Quorum.** Deve restare almeno un **super_admin** attivo (prima: un admin).
- **SSO.** I gruppi dell'IdP assegnano al massimo `admin`; `super_admin` si
  assegna solo localmente e la sincronizzazione dei ruoli non lo tocca.
```

- [ ] **Step 2: Version bump**

`core/version.py`: `__version__ = "0.40.0"`. `pyproject.toml`: `version = "0.40.0"`. Then `uv lock` only if `uv.lock` pins the project version (check `git diff` after `uv sync`).

Do NOT move `[Unreleased]` into a dated section — `release.py` does that at release time.

- [ ] **Step 3: Full gate (AGENTS.md "Before each commit")**

Run each and read the output:
```
uv run pyrefly check                              # 0 errors
uv run python scripts/check_frontend.py
uv run pytest tests -n 4                          # all green
uv run python scripts/check_no_private_data.py
graphify update .
```
If `graphify update .` refuses with "fewer nodes", do not pass `--force`: check what shrank first.

- [ ] **Step 4: Screenshots**

The users table changed visibly: `uv run python scripts/dev/capture_screenshots.py`; commit `docs/images/` only if `git status` shows changes there.

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md core/version.py pyproject.toml docs/images
git commit -m "chore(auth): super_admin changelog and 0.40.0 version"
```

Do not push. Publishing (`git push origin Dev:master`) and the exe rebuild are the user's call.

---

## Next plan

Email notifications part 1 (`docs/superpowers/specs/2026-09-16-email-notifications-design.md`) gets its own plan after this one lands, so it builds on `is_admin` / `require_admin` as they exist then.
