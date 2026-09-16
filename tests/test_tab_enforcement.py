# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Server-side tab enforcement: 'visible tabs' is a hint from the client
today, this makes it a gate the server also checks (admin-permissions
Task 1)."""
import json
import os
import shutil
import subprocess
import unittest

import pytest
from fastapi import HTTPException

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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
        "tab-home", "tab-endpoint", "tab-map", "tab-map-interactive",
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


class TestTabAliasParityWithCoreJS(unittest.TestCase):
    """user_manager.TAB_ALIASES and core.js's normalizeAllowedTabs() must
    agree: a legacy tab id saved for a user has to resolve the same way for
    the server gate and for the nav bar. The node harness runs the real JS
    function against the real Python dict."""

    def test_aliases_match(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node non disponibile")
        from security import user_manager
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_tab_alias_parity.mjs")
        proc = subprocess.run(
            [node, harness, json.dumps(user_manager.TAB_ALIASES)],
            capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


class TestHomeTabAlwaysVisible(unittest.TestCase):
    """core.js's applyRoleUI() must never hide tab-home: a restricted
    allowed_tabs list never contains it (mirrors user_manager's
    ALWAYS_GRANTED_TABS), so treating "not in the list" as "hide" hid Home
    for every tab-restricted user once /api/auth/me started returning the
    actor's real list instead of masking admins to unrestricted."""

    def test_home_stays_visible_for_a_restricted_user(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node non disponibile")
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_home_tab_visible.mjs")
        proc = subprocess.run([node, harness], capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


# One GET TAB route per router file, with the tab that owns it. Handlers may
# answer 404/422/400 once past the gate: only the tab 403 matters here.
TAB_GET_ROUTES = [
    ("/api/ai/conversations", "tab-ai"),
    ("/api/netsec-audit/benchmarks", "tab-netsec-audit"),
    ("/api/arp/stats", "tab-endpoint"),
    ("/api/audit-checklist/templates", "tab-netsec-audit"),
    ("/api/users", "tab-users"),
    ("/api/search", "tab-security"),
    ("/api/groups", "tab-groups"),
    ("/api/cloud-backup/status", "tab-settings"),
    ("/api/bulk-command/no-such-job", "tab-devices"),
    ("/api/drift/devices", "tab-config-drift"),
    ("/api/cve/priority", "tab-security"),
    ("/api/diagnose/gateway-candidates", "tab-endpoint"),
    ("/api/endpoints/list", "tab-endpoint"),
    ("/api/firewall-traffic/devices", "tab-flows"),
    ("/api/flow-siem/facets", "tab-flows"),
    ("/api/fortigate/tokens", "tab-fortigate"),
    ("/api/incidents/rules", "tab-incidents"),
    ("/api/export/devices/columns", "tab-devices"),
    ("/api/mac/stats", "tab-endpoint"),
    ("/api/mcp/settings", "tab-mcp"),
    ("/api/observability/config", "tab-settings"),
    ("/api/policy-test/192.0.2.254/findings", "tab-policy-test"),
    ("/api/identities", "tab-sites"),
    ("/api/routes/devices", "tab-routes"),
    ("/api/scan-subnet/no-such-job", "tab-devices"),
    ("/api/settings/app", "tab-settings"),
    ("/api/sites", "tab-sites"),
    ("/api/portchannels", "tab-map"),
    ("/api/ping/not-an-ip", "tab-devices"),
    ("/api/wlc/192.0.2.254/status", "tab-wlc"),
    ("/api/redundancy/groups", "tab-redundancy"),
]

TAB_DENIED = "Funzionalita' non abilitata per questo utente."


class TestTabGateOnRoutes(unittest.TestCase):
    """Private users store, same pattern as tests/test_super_admin_api.py."""

    PW = "PasswordSicura1!"

    @classmethod
    def setUpClass(cls):
        import tempfile
        from security import user_manager
        cls._orig = user_manager.USERS_JSON
        user_manager.USERS_JSON = os.path.join(
            tempfile.mkdtemp(prefix="tabgate_users_"), "users.json")

    @classmethod
    def tearDownClass(cls):
        from security import user_manager
        user_manager.USERS_JSON = cls._orig

    def setUp(self):
        from security import security_manager, user_manager
        for u in user_manager.list_users():
            user_manager.delete_user(u["username"])
        security_manager._failed_attempts.clear()
        user_manager.create_user("lim", self.PW, role="admin")
        user_manager.create_user("free", self.PW, role="admin")
        user_manager.create_user("root", self.PW, role="super_admin")
        user_manager.set_allowed_tabs("lim", ["tab-home"])
        user_manager.set_allowed_tabs("root", ["tab-home"])

    def _as(self, name):
        from fastapi.testclient import TestClient
        import app_server
        # A handler past the gate may fail on the schema-less test DB: a 500
        # still proves the tab dependency let the request through.
        c = TestClient(app_server.app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", json={"username": name, "password": self.PW})
        self.assertEqual(r.status_code, 200, r.text)
        return c

    @staticmethod
    def _tab_denied(resp):
        return resp.status_code == 403 and resp.json().get("detail") == TAB_DENIED

    def test_routes_gated_by_their_tab(self):
        from security import user_manager
        lim, root = self._as("lim"), self._as("root")
        for path, tab in TAB_GET_ROUTES:
            with self.subTest(path=path, tab=tab):
                user_manager.set_allowed_tabs("lim", ["tab-home"])
                self.assertTrue(self._tab_denied(lim.get(path)), path)
                user_manager.set_allowed_tabs("lim", [tab])
                self.assertFalse(self._tab_denied(lim.get(path)), path)
                user_manager.set_allowed_tabs("lim", [])
                self.assertFalse(self._tab_denied(lim.get(path)), path)
                self.assertFalse(self._tab_denied(root.get(path)), path)

    def test_home_tab_always_granted(self):
        # The frontend never offers tab-home as a grant, yet home loads for
        # everyone: a restricted list must not 403 its boot calls.
        from security import user_manager
        lim = self._as("lim")
        user_manager.set_allowed_tabs("lim", ["tab-devices"])
        self.assertFalse(self._tab_denied(lim.get("/api/drift/summary")))

    def test_alias_and_subtab_grants_through_routes(self):
        from security import user_manager
        lim = self._as("lim")
        with self.subTest("legacy alias tab-mac -> tab-endpoint"):
            user_manager.set_allowed_tabs("lim", ["tab-mac"])
            self.assertFalse(self._tab_denied(lim.get("/api/mac/stats")))
        # No route is gated by tab-map-interactive without tab-map (the map
        # routes carry both), so the tab-map sub-grant cannot be observed
        # through a route; tab-provisioning -> tab-provisioner can.
        with self.subTest("sub-tab tab-provisioning -> tab-provisioner"):
            user_manager.set_allowed_tabs("lim", ["tab-home"])
            self.assertTrue(self._tab_denied(lim.get("/api/ai/profiles")))
            user_manager.set_allowed_tabs("lim", ["tab-provisioning"])
            self.assertFalse(self._tab_denied(lim.get("/api/ai/profiles")))

    def test_ws_terminal_still_authenticates_by_otp(self):
        from fastapi.testclient import TestClient
        import app_server
        c = TestClient(app_server.app)
        with c.websocket_connect("/api/ws-terminal/192.0.2.1") as ws:
            ws.send_text("bogus-otp")
            self.assertIn("Token OTP non valido", ws.receive_text())
