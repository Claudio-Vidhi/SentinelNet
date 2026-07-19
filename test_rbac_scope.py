# -*- coding: utf-8 -*-
"""Harness RBAC multi-gruppo (fase 2.5), riusabile per ogni router estratto:
- utente multi-gruppo: accede ai device di TUTTI i suoi gruppi, negato altrove;
- utente singolo gruppo: accede solo al suo;
- admin: nessuna restrizione;
- lista gruppi vuota: per semantica di prodotto = nessuna restrizione
  (l'admin non ha limitato l'utente) — comportamento intenzionale, asserito;
- inoltre: gate permanente contro l'uso di uno scalare ``user.group``.

Aggiungere qui i nuovi router (parametrizzando ROUTES) nelle fasi 4/5/6."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_rbac_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
import user_manager  # noqa: E402

PASS = "PasswordSicura1!"

DEVICES = [
    {"IP": "10.1.0.1", "Hostname": "fgt-a", "Vendor": "fortinet", "Group": "sede-a"},
    {"IP": "10.2.0.1", "Hostname": "fgt-b", "Vendor": "fortinet", "Group": "sede-b"},
    {"IP": "10.3.0.1", "Hostname": "fgt-c", "Vendor": "fortinet", "Group": "sede-c"},
    {"IP": "10.1.0.2", "Hostname": "wlc-a", "Vendor": "cisco_wlc", "Group": "sede-a"},
    {"IP": "10.3.0.2", "Hostname": "wlc-c", "Vendor": "cisco_wlc", "Group": "sede-c"},
]

# (percorso, gruppo del device) — usati per verificare lo scoping.
ROUTES = [
    ("/api/fortigate/10.1.0.1/status", "sede-a"),
    ("/api/fortigate/10.2.0.1/status", "sede-b"),
    ("/api/fortigate/10.3.0.1/status", "sede-c"),
    ("/api/wlc/10.1.0.2/status", "sede-a"),
    ("/api/wlc/10.3.0.2/status", "sede-c"),
]


class TestRbacScope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        user_manager.create_user("adm", PASS, role="admin")
        user_manager.create_user("multi", PASS, role="operator",
                                 groups=["sede-a", "sede-b"])
        user_manager.create_user("single", PASS, role="operator",
                                 groups=["sede-a"])
        user_manager.create_user("nolimit", PASS, role="operator", groups=[])
        cls.patches = [
            patch("routers.deps.inventory_manager.get_all_devices", return_value=DEVICES),
            # Il servizio non deve mai essere raggiunto davvero: 502 fittizio
            # distinto da 403/404 così il test misura solo lo scoping.
            patch("routers.fortigate.fortigate_service.get_system_status",
                  side_effect=RuntimeError("no-op")),
            patch("routers.wlc.wlc_service.query", side_effect=RuntimeError("no-op")),
        ]
        for p in cls.patches:
            p.start()

    @classmethod
    def tearDownClass(cls):
        for p in cls.patches:
            p.stop()
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def _client(self, username):
        client = TestClient(app_server.app, raise_server_exceptions=False)
        r = client.post("/api/auth/login", json={"username": username, "password": PASS})
        assert r.status_code == 200, r.text
        return client

    def _status(self, client, path):
        return client.get(path).status_code

    def test_multi_group_user_scope(self):
        c = self._client("multi")
        for path, group in ROUTES:
            code = self._status(c, path)
            if group in ("sede-a", "sede-b"):
                self.assertNotIn(code, (401, 403), f"{path}: negato ma in scope")
            else:
                self.assertEqual(code, 403, f"{path}: fuori scope ma non negato")

    def test_single_group_user_scope(self):
        c = self._client("single")
        for path, group in ROUTES:
            code = self._status(c, path)
            if group == "sede-a":
                self.assertNotIn(code, (401, 403), f"{path}: negato ma in scope")
            else:
                self.assertEqual(code, 403, f"{path}: fuori scope ma non negato")

    def test_admin_unrestricted(self):
        c = self._client("adm")
        for path, _group in ROUTES:
            self.assertNotIn(self._status(c, path), (401, 403), path)

    def test_empty_groups_means_unrestricted_by_design(self):
        # Semantica di prodotto: lista vuota = l'admin non ha limitato l'utente.
        c = self._client("nolimit")
        for path, _group in ROUTES:
            self.assertNotIn(self._status(c, path), (401, 403), path)

    def test_anonymous_gets_401(self):
        client = TestClient(app_server.app)
        for path, _group in ROUTES:
            self.assertEqual(client.get(path).status_code, 401, path)

    def test_mcp_client_routes_admin_only(self):
        # La tab MCP Client (preview) rispecchia la RBAC admin-only della tab
        # MCP Server: operator negato (403), admin ammesso, anonimo 401.
        op = self._client("single")
        self.assertEqual(op.get("/api/mcp-client/servers").status_code, 403)
        self.assertEqual(op.get("/api/mcp-client/settings").status_code, 403)
        adm = self._client("adm")
        self.assertNotIn(adm.get("/api/mcp-client/servers").status_code, (401, 403))
        self.assertNotIn(adm.get("/api/mcp-client/settings").status_code, (401, 403))
        anon = TestClient(app_server.app)
        self.assertEqual(anon.get("/api/mcp-client/servers").status_code, 401)

    def test_no_scalar_user_group_in_routers(self):
        # Gate permanente (CONTRIBUTING.md §4): mai `user.group`/`.get("group")`
        # scalare nei router.
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "routers")
        offenders = []
        for name in os.listdir(root):
            if not name.endswith(".py"):
                continue
            text = open(os.path.join(root, name), encoding="utf-8").read()
            for pat in ('user.group', 'current_user.get("group")',
                        "current_user.get('group')", 'user["group"]'):
                if pat in text:
                    offenders.append(f"{name}: {pat}")
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
