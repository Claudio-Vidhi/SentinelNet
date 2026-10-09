# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""A tenant's key is its identity; renaming changes only its display name.

The key is stored in at least eight places (hosts.csv, user scopes, identity
profiles, SNMP defaults, telemetry settings, backup folders, SQLite `tenant`
columns, the site agents' own inventories). Renaming used to rewrite only
hosts.csv, so a user scoped to the tenant lost its devices and everything else
was orphaned under the old key. Deleting moved the devices to 'Generale'."""
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from routers import deps
from routers.deps import CSRF_HEADER
from security import security_manager, user_manager
from services import inventory_manager

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"


class _Isolated(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="group_identity_")
        for const, name in (("HOSTS_CSV", "network_hosts.csv"), ("GROUPS_JSON", "groups.json")):
            p = patch.object(inventory_manager, const, os.path.join(tmp, name))
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(user_manager, "USERS_JSON", os.path.join(tmp, "users.json"))
        p.start()
        self.addCleanup(p.stop)
        security_manager._failed_attempts.clear()
        inventory_manager.save_groups({"tenant-a": {"description": ""},
                                       "tenant-b": {"description": ""}})
        inventory_manager.add_or_update_device("192.0.2.10", "cisco", "custom", "u", "p", "",
                                               "tenant-a")
        user_manager.create_user("adm", PW, role="admin")
        user_manager.create_user("op", PW, role="operator", groups=["tenant-a"])

    def _as(self, name):
        c = TestClient(app_server.app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", json={"username": name, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        c.headers.update(H)
        return c


class TestRename(_Isolated):
    def test_rename_keeps_the_key_and_sets_the_name(self):
        r = self._as("adm").post("/api/groups/rename",
                                 json={"old_name": "tenant-a", "new_name": "Acme SpA"})
        self.assertEqual(r.status_code, 200, r.text)
        groups = inventory_manager.get_all_groups()
        self.assertEqual(groups["tenant-a"]["name"], "Acme SpA")
        self.assertNotIn("Acme SpA", groups)
        self.assertEqual(inventory_manager.get_all_devices()[0]["Group"], "tenant-a")

    def test_scoped_user_keeps_its_devices_after_rename(self):
        self._as("adm").post("/api/groups/rename",
                             json={"old_name": "tenant-a", "new_name": "Acme SpA"})
        seen = deps.devices_in_scope({"sub": "op", "role": "operator"})
        self.assertEqual([d["IP"] for d in seen], ["192.0.2.10"])

    def test_rename_to_another_tenants_name_or_key_is_refused(self):
        adm = self._as("adm")
        adm.post("/api/groups/rename", json={"old_name": "tenant-b", "new_name": "Beta"})
        for taken in ("tenant-b", "Beta"):
            with self.subTest(taken=taken):
                r = adm.post("/api/groups/rename",
                             json={"old_name": "tenant-a", "new_name": taken})
                self.assertEqual(r.status_code, 400, r.text)

    def test_csv_import_by_display_name_lands_in_the_renamed_tenant(self):
        adm = self._as("adm")
        adm.post("/api/groups/rename", json={"old_name": "tenant-a", "new_name": "Acme SpA"})
        r = adm.post("/api/import-csv",
                     json={"csv_data": "IP,Group\n192.0.2.20,Acme SpA\n"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["failed"], [])
        self.assertNotIn("Acme SpA", inventory_manager.get_all_groups())
        dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "192.0.2.20")
        self.assertEqual(dev["Group"], "tenant-a")


class TestDelete(_Isolated):
    def test_delete_with_devices_is_refused_and_moves_nothing(self):
        r = self._as("adm").post("/api/groups/delete", json={"name": "tenant-a"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("1", r.json()["detail"])
        self.assertIn("tenant-a", inventory_manager.get_all_groups())
        self.assertEqual(inventory_manager.get_all_devices()[0]["Group"], "tenant-a")

    def test_delete_empty_tenant_succeeds(self):
        r = self._as("adm").post("/api/groups/delete", json={"name": "tenant-b"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertNotIn("tenant-b", inventory_manager.get_all_groups())


if __name__ == "__main__":
    unittest.main()
