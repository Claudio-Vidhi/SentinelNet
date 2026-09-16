# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant scope applies to admins (admin-permissions Task 3, spec D3).

A tenant-scoped admin sees and acts only on its tenants' devices, and every
global admin route (settings, SSO/SMTP, sites, tenants, MCP, cloud backup,
incident rule parameters) needs an admin with no tenant restriction."""
import os
import re
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from routers import deps
from routers.deps import CSRF_HEADER
from security import security_manager, user_manager

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"
GLOBAL_DENIED = "Operazione riservata ad amministratori senza limiti di tenant."

DEVICES = [
    {"IP": "192.0.2.10", "Hostname": "fw-a", "Vendor": "fortinet", "Group": "tenant-a"},
    {"IP": "198.51.100.10", "Hostname": "fw-b", "Vendor": "fortinet", "Group": "tenant-b"},
]

# Global routes that must stay out of a scoped admin's reach: the SSO and SMTP
# writes are the escalation paths (re-mapping the IdP admin group, redirecting
# password-reset mail).
MUST_BE_GLOBAL = {
    ("POST", "/api/settings/sso"),
    ("POST", "/api/settings/smtp"),
    ("POST", "/api/settings/app"),            # base URL, TLS cert paths
    ("POST", "/api/settings/tls/self-signed"),
    ("POST", "/api/settings/update"),
    ("GET", "/api/settings/update/check"),
    ("POST", "/api/groups/rename"),
    ("POST", "/api/groups/delete"),
    ("POST", "/api/sites"),
    ("POST", "/api/sites/delete"),
    ("POST", "/api/sites/regenerate-token"),
    ("PUT", "/api/cloud-backup/settings"),
    ("POST", "/api/mcp/settings"),
    ("POST", "/api/incidents/rules/{rule_id}/parameters"),
    ("POST", "/api/provisioner/push-ssh"),
    ("POST", "/api/provisioner/push-serial"),
    ("POST", "/api/fortigate/targets/active"),
}
SHARED_DENIED = ("Indirizzo condiviso con un altro tenant: operazione riservata "
                 "ad amministratori senza limiti di tenant.")


def _uses(dependant, fn) -> bool:
    return any(d.call is fn or _uses(d, fn) for d in dependant.dependencies)


def guarded_routes():
    out = set()
    for r in app_server.app.routes:
        dependant = getattr(r, "dependant", None)
        if dependant is not None and _uses(dependant, deps.require_unscoped_admin):
            for m in getattr(r, "methods", None) or ():
                out.add((m, r.path))
    return out


class _PrivateUsers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig = user_manager.USERS_JSON
        user_manager.USERS_JSON = os.path.join(
            tempfile.mkdtemp(prefix="tenantscope_users_"), "users.json")

    @classmethod
    def tearDownClass(cls):
        user_manager.USERS_JSON = cls._orig

    def setUp(self):
        for u in user_manager.list_users():
            user_manager.delete_user(u["username"])
        security_manager._failed_attempts.clear()
        user_manager.create_user("root", PW, role="super_admin", groups=["tenant-a"])
        user_manager.create_user("adm", PW, role="admin")
        user_manager.create_user("sadm", PW, role="admin", groups=["tenant-a"])
        user_manager.create_user("op", PW, role="operator")
        p = patch("routers.deps.inventory_manager.get_all_devices", return_value=DEVICES)
        p.start()
        self.addCleanup(p.stop)

    def _as(self, name):
        c = TestClient(app_server.app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", json={"username": name, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        c.headers.update(H)
        return c


class TestScopeHelpers(_PrivateUsers):
    def test_user_group_scope_none_only_for_super_admin(self):
        self.assertIsNone(deps.user_group_scope({"sub": "root", "role": "super_admin"}))
        self.assertEqual(deps.user_group_scope({"sub": "sadm", "role": "admin"}), {"tenant-a"})
        self.assertIsNone(deps.user_group_scope({"sub": "adm", "role": "admin"}))

    def test_is_unscoped_admin(self):
        self.assertTrue(deps.is_unscoped_admin({"sub": "root", "role": "super_admin"}))
        self.assertTrue(deps.is_unscoped_admin({"sub": "adm", "role": "admin"}))
        self.assertFalse(deps.is_unscoped_admin({"sub": "sadm", "role": "admin"}))
        self.assertFalse(deps.is_unscoped_admin({"sub": "op", "role": "operator"}))

    def test_require_unscoped_admin_dependency(self):
        for name, role in (("root", "super_admin"), ("adm", "admin")):
            user = {"sub": name, "role": role}
            self.assertIs(deps.require_unscoped_admin(current_user=user), user)
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as e:
            deps.require_unscoped_admin(current_user={"sub": "sadm", "role": "admin"})
        self.assertEqual(e.exception.status_code, 403)
        self.assertEqual(e.exception.detail, GLOBAL_DENIED)


class TestScopedAdminOnTenantData(_PrivateUsers):
    def test_device_route_follows_scope(self):
        with patch("routers.fortigate.fortigate_service.get_admins",
                   side_effect=RuntimeError("no-op")):
            sadm = self._as("sadm")
            self.assertEqual(sadm.get("/api/fortigate/198.51.100.10/system/admins").status_code, 403)
            self.assertNotIn(sadm.get("/api/fortigate/192.0.2.10/system/admins").status_code,
                             (401, 403))
            self.assertNotIn(self._as("adm").get(
                "/api/fortigate/198.51.100.10/system/admins").status_code, (401, 403))

    def test_list_routes_filtered(self):
        targets = [{"ip": "192.0.2.10", "name": "a", "port": 443, "verify_tls": False, "active": False},
                   {"ip": "198.51.100.10", "name": "b", "port": 443, "verify_tls": False, "active": False},
                   {"ip": "203.0.113.99", "name": "orphan", "port": 443, "verify_tls": False, "active": False}]
        tokens = {"192.0.2.10": {"port": 443}, "198.51.100.10": {"port": 443}}
        with patch("routers.fortigate.fortigate_service.list_targets",
                   side_effect=lambda: [dict(t) for t in targets]), \
             patch("routers.fortigate.fortigate_service.token_status", return_value=tokens):
            sadm, adm = self._as("sadm"), self._as("adm")
            self.assertEqual([t["ip"] for t in sadm.get("/api/fortigate/targets").json()],
                             ["192.0.2.10"])
            self.assertEqual(list(sadm.get("/api/fortigate/tokens").json()), ["192.0.2.10"])
            self.assertEqual(len(adm.get("/api/fortigate/targets").json()), 3)
            self.assertEqual(len(adm.get("/api/fortigate/tokens").json()), 2)

    def test_drift_baseline_write_follows_scope(self):
        r = self._as("sadm").put("/api/drift/baseline/tenant-b", json={"text": ""})
        self.assertEqual(r.status_code, 403, r.text)

    def test_site_details_only_for_unscoped_admin(self):
        from services import site_manager
        site = site_manager.create_site("scope-site", "central", ["192.0.2.0/24"])[0]
        self.addCleanup(site_manager.delete_site, site["id"])
        for name, full in (("sadm", False), ("adm", True)):
            with self.subTest(user=name):
                sites = self._as(name).get("/api/sites").json()["sites"]
                self.assertTrue(sites)
                self.assertEqual("subnets" in sites[0], full)


class TestGlobalRoutesNeedUnscopedAdmin(_PrivateUsers):
    def test_explicit_global_routes_are_guarded(self):
        missing = MUST_BE_GLOBAL - guarded_routes()
        self.assertFalse(missing, f"global routes without require_unscoped_admin: {sorted(missing)}")

    def test_every_guarded_route_refuses_a_scoped_admin(self):
        # The guard runs before body and path validation, so no body is needed
        # and nothing past it executes. Unscoped admins are not replayed here:
        # restart/update would act for real; the dependency test covers them.
        sadm = self._as("sadm")
        for method, path in sorted(guarded_routes()):
            url = re.sub(r"\{[^}]+\}", "1", path)
            with self.subTest(method=method, path=path):
                r = sadm.request(method, url)
                self.assertEqual(r.status_code, 403, r.text)
                self.assertEqual(r.json().get("detail"), GLOBAL_DENIED)

    def test_unscoped_admin_reaches_a_global_read(self):
        for name in ("adm", "root"):
            with self.subTest(user=name):
                r = self._as(name).get("/api/settings/smtp")
                self.assertEqual(r.status_code, 200, r.text)

    def test_unscoped_admin_passes_every_guarded_get(self):
        # GETs only: nothing they do is destructive. No AI profile, so
        # /api/ai/models answers 400 instead of calling a provider.
        adm = self._as("adm")
        gets = sorted(p for m, p in guarded_routes() if m == "GET")
        self.assertTrue(gets)
        with patch("routers.ai._get_ai_profiles_raw", return_value=([], None)):
            for path in gets:
                with self.subTest(path=path):
                    r = adm.get(re.sub(r"\{[^}]+\}", "1", path))
                    self.assertFalse(r.status_code == 403
                                     and r.json().get("detail") == GLOBAL_DENIED, path)

    def test_scoped_admin_reads_masked_ai_profiles(self):
        with patch("routers.ai._get_ai_profiles_raw", return_value=([], None)):
            self.assertEqual(self._as("sadm").get("/api/ai/profiles").status_code, 200)


class TestSharedFortiGateIp(_PrivateUsers):
    """Tokens are keyed by IP alone: an IP present in two tenants must not let
    a scoped admin read or overwrite the other tenant's token."""

    SHARED = [
        {"IP": "192.0.2.10", "Hostname": "fw-a", "Vendor": "fortinet", "Group": "tenant-a"},
        {"IP": "192.0.2.10", "Hostname": "fw-b", "Vendor": "fortinet", "Group": "tenant-b"},
        {"IP": "192.0.2.20", "Hostname": "fw-a2", "Vendor": "fortinet", "Group": "tenant-a"},
    ]

    def setUp(self):
        super().setUp()
        for target, kw in (("routers.deps.inventory_manager.get_all_devices",
                            {"return_value": self.SHARED}),
                           ("routers.fortigate.fortigate_service.set_api_token", {}),
                           ("routers.fortigate.fortigate_service.test_connection",
                            {"return_value": {"ok": True}}),
                           ("routers.fortigate.fortigate_service.update_target", {}),
                           ("routers.fortigate.fortigate_service.token_status",
                            {"return_value": {"192.0.2.10": {}, "192.0.2.20": {}}}),
                           ("routers.fortigate.fortigate_service.list_targets",
                            {"side_effect": lambda: [{"ip": "192.0.2.10"}, {"ip": "192.0.2.20"}]})):
            p = patch(target, **kw)
            p.start()
            self.addCleanup(p.stop)

    def test_scoped_admin_cannot_touch_shared_ip(self):
        sadm = self._as("sadm")
        calls = [("POST", "/api/fortigate/token", {"ip": "192.0.2.10", "token": ""}),
                 ("POST", "/api/fortigate/targets/192.0.2.10/test", None),
                 ("PUT", "/api/fortigate/targets/192.0.2.10", {"name": "x"})]
        for method, url, body in calls:
            with self.subTest(url=url):
                r = sadm.request(method, url, json=body)
                self.assertEqual(r.status_code, 403, r.text)
                self.assertEqual(r.json().get("detail"), SHARED_DENIED)
        ok = sadm.post("/api/fortigate/targets/192.0.2.20/test")
        self.assertEqual(ok.status_code, 200, ok.text)

    def test_shared_ip_hidden_from_scoped_listings(self):
        sadm = self._as("sadm")
        self.assertEqual(list(sadm.get("/api/fortigate/tokens").json()), ["192.0.2.20"])
        self.assertEqual([t["ip"] for t in sadm.get("/api/fortigate/targets").json()],
                         ["192.0.2.20"])

    def test_unscoped_admin_unaffected(self):
        adm = self._as("adm")
        r = adm.request("PUT", "/api/fortigate/targets/192.0.2.10?tenant=tenant-a", json={"name": "x"})
        self.assertNotEqual(r.json().get("detail"), SHARED_DENIED)
        self.assertEqual(len(adm.get("/api/fortigate/tokens").json()), 2)


if __name__ == "__main__":
    unittest.main()
