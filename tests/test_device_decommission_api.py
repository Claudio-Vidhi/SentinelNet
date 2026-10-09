# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Bulk decommission / reactivate / delete routes: scope and existence are
checked for every pair before anything is written."""
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from routers.deps import CSRF_HEADER
from security import security_manager, user_manager
from services import inventory_manager

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"
A10 = {"ip": "192.0.2.10", "tenant": "tenant-a"}
B20 = {"ip": "192.0.2.20", "tenant": "tenant-b"}


class _Isolated(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="decom_api_")
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
        for ip, tenant in (("192.0.2.10", "tenant-a"), ("192.0.2.20", "tenant-a"),
                           ("192.0.2.20", "tenant-b")):
            inventory_manager.add_or_update_device(ip, "cisco", "custom", "u", "p", "", tenant)
        user_manager.create_user("adm", PW, role="admin")
        user_manager.create_user("op", PW, role="operator", groups=["tenant-a"])
        user_manager.create_user("view", PW, role="viewer")

    def _as(self, name):
        c = TestClient(app_server.app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", json={"username": name, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        c.headers.update(H)
        return c

    def active(self):
        return sorted(inventory_manager.device_pair(d) for d in inventory_manager.get_all_devices())


class TestRoutes(_Isolated):
    def test_round_trip(self):
        adm = self._as("adm")
        r = adm.post("/api/devices/decommission", json={"devices": [A10, B20]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["count"], 2)
        listed = adm.get("/api/devices/decommissioned").json()["devices"]
        self.assertEqual(sorted(d["IP"] for d in listed), ["192.0.2.10", "192.0.2.20"])
        self.assertTrue(all("Password" not in d for d in listed))
        r = adm.post("/api/devices/reactivate", json={"devices": [A10]})
        self.assertEqual(r.status_code, 200, r.text)
        r = adm.post("/api/devices/delete", json={"devices": [A10, B20]})
        self.assertEqual(r.json()["count"], 2)
        self.assertEqual(self.active(), [("tenant-a", "192.0.2.20")])
        self.assertEqual(inventory_manager.get_decommissioned_devices(), [])

    def test_scoped_operator_out_of_scope_pair_changes_nothing(self):
        r = self._as("op").post("/api/devices/decommission", json={"devices": [A10, B20]})
        self.assertEqual(r.status_code, 403, r.text)
        self.assertEqual(len(self.active()), 3)

    def test_scoped_list_hides_other_tenants(self):
        self._as("adm").post("/api/devices/decommission", json={"devices": [A10, B20]})
        listed = self._as("op").get("/api/devices/decommissioned").json()["devices"]
        self.assertEqual([d["Group"] for d in listed], ["tenant-a"])

    def test_viewer_cannot_act(self):
        r = self._as("view").post("/api/devices/delete", json={"devices": [A10]})
        self.assertEqual(r.status_code, 403, r.text)
        self.assertEqual(len(self.active()), 3)

    def test_unknown_pair_is_404_and_changes_nothing(self):
        r = self._as("adm").post("/api/devices/decommission",
                                 json={"devices": [A10, {"ip": "192.0.2.99", "tenant": "tenant-a"}]})
        self.assertEqual(r.status_code, 404, r.text)
        self.assertEqual(len(self.active()), 3)

    def test_reactivate_needs_a_decommissioned_pair(self):
        r = self._as("adm").post("/api/devices/reactivate", json={"devices": [A10]})
        self.assertEqual(r.status_code, 404, r.text)

    def test_limits(self):
        adm = self._as("adm")
        self.assertEqual(adm.post("/api/devices/delete", json={"devices": []}).status_code, 422)
        many = [{"ip": "192.0.2.1", "tenant": "tenant-a"}] * 1001
        self.assertEqual(adm.post("/api/devices/delete", json={"devices": many}).status_code, 422)


class TestGuardOverHttp(_Isolated):
    def test_reassign_onto_a_decommissioned_pair_is_400(self):
        adm = self._as("adm")
        adm.post("/api/devices/decommission", json={"devices": [B20]})
        r = adm.post("/api/reassign-device", json={"ip": "192.0.2.20", "new_group": "tenant-b"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("riattivalo", r.json()["detail"])

    def test_promote_onto_a_decommissioned_pair_is_400(self):
        adm = self._as("adm")
        adm.post("/api/devices/decommission", json={"devices": [A10]})
        r = adm.post("/api/promote-device",
                     json={"node_id": "n1", "ip": "192.0.2.10", "group": "tenant-a"})
        self.assertEqual(r.status_code, 400, r.text)

    def test_csv_import_reports_the_decommissioned_row_and_imports_the_rest(self):
        adm = self._as("adm")
        adm.post("/api/devices/decommission", json={"devices": [A10]})
        csv_data = ("IP,Vendor,Group\n"
                    "192.0.2.10,cisco,tenant-a\n"
                    "192.0.2.30,cisco,tenant-a\n")
        r = adm.post("/api/import-csv", json={"csv_data": csv_data})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["imported"], ["192.0.2.30"])
        self.assertEqual([f["ip"] for f in body["failed"]], ["192.0.2.10"])


if __name__ == "__main__":
    unittest.main()
