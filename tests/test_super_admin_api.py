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
from unittest.mock import patch

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


class TestSsoUpgradeWarning(_PrivateUsers):
    """When the migration promotes accounts while SSO role sync is on, the
    lifespan must log an extra warning: promoted accounts stop following the
    IdP's groups, and nothing else demotes them back."""

    def test_migration_warns_when_sso_syncs_roles(self):
        user_manager.create_user("adm-legacy", PW, role="admin")
        from security import sso
        with patch.object(sso, "get_config",
                          return_value={"enabled": True, "sync_roles": True}), \
             patch("security.security_manager.log_audit") as mock_audit:
            with TestClient(app_server.app):
                pass
        messages = [c.args[0] for c in mock_audit.call_args_list]
        self.assertTrue(
            any("non seguono piu'" in m for m in messages), messages)

    def test_no_warning_when_sso_role_sync_off(self):
        user_manager.create_user("adm-legacy2", PW, role="admin")
        from security import sso
        with patch.object(sso, "get_config",
                          return_value={"enabled": False, "sync_roles": False}), \
             patch("security.security_manager.log_audit") as mock_audit:
            with TestClient(app_server.app):
                pass
        messages = [c.args[0] for c in mock_audit.call_args_list]
        self.assertFalse(any("non seguono piu'" in m for m in messages), messages)


class TestScopedAdminUserPerimeter(_PrivateUsers):
    """A tenant-scoped admin (groups != []) must not see or touch accounts
    outside its own groups, nor grant a group/tab it does not itself hold."""

    def setUp(self):
        super().setUp()
        g = patch("routers.auth.inventory_manager.get_all_groups",
                  return_value={"tenant-a": {}, "tenant-b": {}})
        g.start()
        self.addCleanup(g.stop)
        user_manager.create_user("root", PW, role="super_admin", email="root@example.com")
        user_manager.create_user("adm", PW, role="admin", email="adm@example.com")
        user_manager.create_user("op", PW, role="operator", email="op@example.com")
        user_manager.create_user("sadm", PW, role="admin", groups=["tenant-a"])
        user_manager.create_user("op-a", PW, role="operator", groups=["tenant-a"])
        user_manager.create_user("op-b", PW, role="operator", groups=["tenant-b"])
        user_manager.create_user("op-all", PW, role="operator")

    def test_list_users_only_own_tenant(self):
        r = self._as("sadm").get("/api/users")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual({u["username"] for u in r.json()}, {"sadm", "op-a"})

    def test_out_of_scope_targets_are_404(self):
        sadm = self._as("sadm")
        calls = [
            ("/api/users/role", {"username": "op-b", "role": "viewer"}),
            ("/api/users/disable", {"username": "op-b", "disabled": True}),
            ("/api/users/groups", {"username": "op-b", "groups": ["tenant-b"]}),
            ("/api/users/tabs", {"username": "op-b", "allowed_tabs": []}),
            ("/api/users/email", {"username": "op-b", "email": "x@example.com"}),
            ("/api/users/send-reset", {"username": "op-b"}),
            ("/api/users/approve", {"username": "op-b"}),
        ]
        for path, body in calls:
            with self.subTest(path=path, target="op-b"):
                r = sadm.post(path, json=body, headers=H)
                self.assertEqual(r.status_code, 404, f"{path}: {r.text}")
        for path, body in calls:
            body2 = dict(body, username="op-all")
            with self.subTest(path=path, target="op-all"):
                r = sadm.post(path, json=body2, headers=H)
                self.assertEqual(r.status_code, 404, f"{path}: {r.text}")

    def test_in_scope_target_stays_reachable(self):
        r = self._as("sadm").post("/api/users/disable", headers=H,
                                  json={"username": "op-a", "disabled": True})
        self.assertEqual(r.status_code, 200, r.text)

    def test_create_user_groups_must_stay_in_scope(self):
        sadm = self._as("sadm")
        r = sadm.post("/api/users", headers=H,
                      json={"username": "new-empty", "password": PW, "role": "operator", "groups": []})
        self.assertEqual(r.status_code, 403, r.text)
        r = sadm.post("/api/users", headers=H,
                      json={"username": "new-b", "password": PW, "role": "operator",
                            "groups": ["tenant-b"]})
        self.assertEqual(r.status_code, 403, r.text)
        r = sadm.post("/api/users", headers=H,
                      json={"username": "new-a", "password": PW, "role": "operator",
                            "groups": ["tenant-a"]})
        self.assertEqual(r.status_code, 200, r.text)

    def test_set_groups_must_stay_in_scope(self):
        r = self._as("sadm").post("/api/users/groups", headers=H,
                                  json={"username": "op-a", "groups": ["tenant-a", "tenant-b"]})
        self.assertEqual(r.status_code, 403, r.text)

    def test_set_tabs_must_stay_within_actors_grant(self):
        user_manager.set_allowed_tabs("sadm", ["tab-devices", "tab-users"])
        sadm = self._as("sadm")
        r = sadm.post("/api/users/tabs", headers=H,
                     json={"username": "op-a", "allowed_tabs": ["tab-settings"]})
        self.assertEqual(r.status_code, 403, r.text)
        r = sadm.post("/api/users/tabs", headers=H,
                     json={"username": "op-a", "allowed_tabs": ["tab-devices"]})
        self.assertEqual(r.status_code, 200, r.text)

    def test_invite_forbidden_for_scoped_admin(self):
        r = self._as("sadm").post("/api/users/invite", headers=H,
                                  json={"email": "invitee@example.com", "role": "viewer"})
        self.assertEqual(r.status_code, 403, r.text)

    def test_unscoped_admin_still_lists_everyone(self):
        r = self._as("adm").get("/api/users")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual({u["username"] for u in r.json()},
                         {"root", "adm", "op", "sadm", "op-a", "op-b", "op-all"})


if __name__ == "__main__":
    unittest.main()
