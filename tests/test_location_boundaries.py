# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Boundary tests: every device created or moved requires an organization and a location."""
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from routers.deps import CSRF_HEADER
from security import security_manager, user_manager
from services import inventory_manager, location_manager, probe_manager

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"


class _Isolated(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="loc_bound_")
        for const, name in (
            ("HOSTS_CSV", "network_hosts.csv"),
            ("GROUPS_JSON", "groups.json"),
        ):
            p = patch.object(inventory_manager, const, os.path.join(tmp, name))
            p.start()
            self.addCleanup(p.stop)
        for mod, const, name in (
            (location_manager, "LOCATIONS_JSON", "locations.json"),
            (probe_manager, "PROBES_JSON", "probes.json"),
            (user_manager, "USERS_JSON", "users.json"),
        ):
            p = patch.object(mod, const, os.path.join(tmp, name))
            p.start()
            self.addCleanup(p.stop)

        security_manager._failed_attempts.clear()
        inventory_manager.save_groups({"acme": {"description": ""}, "beta": {"description": ""}})
        self.loc_acme = location_manager.create_location("acme", "Milano")
        self.loc_beta = location_manager.create_location("beta", "Roma")
        user_manager.create_user("adm", PW, role="admin")

    def _as(self, name):
        c = TestClient(app_server.app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", json={"username": name, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        c.headers.update(H)
        return c


class TestLocationBoundaries(_Isolated):
    def test_add_device_requires_valid_location(self):
        adm = self._as("adm")
        # Missing location
        r = adm.post("/api/add-device", json={
            "ip": "192.0.2.10", "vendor": "cisco", "profile": "custom",
            "group": "acme", "location": "",
        })
        self.assertEqual(r.status_code, 400, r.text)

        # Foreign location (belongs to beta, group is acme)
        r = adm.post("/api/add-device", json={
            "ip": "192.0.2.10", "vendor": "cisco", "profile": "custom",
            "group": "acme", "location": self.loc_beta["id"],
        })
        self.assertEqual(r.status_code, 400, r.text)

        # Right location
        r = adm.post("/api/add-device", json={
            "ip": "192.0.2.10", "vendor": "cisco", "profile": "custom",
            "group": "acme", "location": self.loc_acme["id"],
        })
        self.assertEqual(r.status_code, 200, r.text)
        dev = inventory_manager.get_all_devices()[0]
        self.assertEqual(dev["Location"], self.loc_acme["id"])

    def test_reassign_device_requires_location_in_target_group(self):
        adm = self._as("adm")
        inventory_manager.add_or_update_device(
            "192.0.2.10", "cisco", "custom", "u", "p", "", "acme", location=self.loc_acme["id"]
        )
        # Reassign to beta without new_location
        r = adm.post("/api/reassign-device", json={
            "ip": "192.0.2.10", "new_group": "beta", "new_location": "",
        })
        self.assertEqual(r.status_code, 400, r.text)

        # Reassign to beta with foreign location (acme's location)
        r = adm.post("/api/reassign-device", json={
            "ip": "192.0.2.10", "new_group": "beta", "new_location": self.loc_acme["id"],
        })
        self.assertEqual(r.status_code, 400, r.text)

        # Reassign with valid target location
        r = adm.post("/api/reassign-device", json={
            "ip": "192.0.2.10", "new_group": "beta", "new_location": self.loc_beta["id"],
        })
        self.assertEqual(r.status_code, 200, r.text)
        dev = inventory_manager.get_all_devices()[0]
        self.assertEqual((dev["Group"], dev["Location"]), ("beta", self.loc_beta["id"]))

    def test_import_csv_validates_location_column(self):
        adm = self._as("adm")
        csv_data = (
            "IP,Vendor,Group,Sede\n"
            f"192.0.2.1,cisco,acme,{self.loc_acme['id']}\n"
            "192.0.2.2,cisco,acme,\n"
            f"192.0.2.3,cisco,acme,{self.loc_beta['id']}\n"
        )
        r = adm.post("/api/import-csv", json={"csv_data": csv_data})
        self.assertEqual(r.status_code, 200, r.text)
        res = r.json()
        self.assertEqual(res["imported"], ["192.0.2.1"])
        self.assertEqual(len(res["failed"]), 2)
        failed_rows = [f["row"] for f in res["failed"]]
        self.assertEqual(failed_rows, [3, 4])

    def test_import_csv_takes_the_location_by_name_and_its_probe(self):
        probe, _ = probe_manager.create_probe("Lab", "agent")
        location_manager.update_location(self.loc_acme["id"], probe=probe["id"])
        adm = self._as("adm")
        r = adm.post("/api/import-csv", json={"csv_data": "IP,Vendor,Group,Sede\n192.0.2.1,cisco,acme,MILANO\n"})
        self.assertEqual(r.json()["imported"], ["192.0.2.1"], r.text)
        dev = inventory_manager.get_all_devices()[0]
        # A new device without a Probe column takes its location's default.
        self.assertEqual((dev["Location"], dev["Probe"]), (self.loc_acme["id"], probe["id"]))

    def test_agent_push_location_resolution(self):
        probe, token = probe_manager.create_probe("Agent-Lab", "agent")
        client = TestClient(app_server.app)
        h = {"X-Probe-Id": probe["id"], "X-Probe-Token": token}

        # Case 1: no candidate locations in acme for this probe
        r = client.post("/api/agent/inventory", headers=h, json={
            "devices": [{"ip": "192.0.2.50", "vendor": "cisco", "group": "acme"}]
        })
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(len(inventory_manager.get_all_devices()), 0)
        self.assertEqual(probe_manager.get_probe(probe["id"])["unlocated_devices"], 1)

        # Case 2: exactly one candidate location in acme
        loc_lab = location_manager.create_location("acme", "Lab-Loc", probe=probe["id"])
        r = client.post("/api/agent/inventory", headers=h, json={
            "devices": [{"ip": "192.0.2.50", "vendor": "cisco", "group": "acme"}]
        })
        self.assertEqual(r.status_code, 200, r.text)
        devs = inventory_manager.get_all_devices()
        self.assertEqual(len(devs), 1)
        self.assertEqual(devs[0]["Location"], loc_lab["id"])

        # Case 3: existing device keeps its location even if another candidate exists
        location_manager.create_location("acme", "Lab-Loc-2", probe=probe["id"])
        r = client.post("/api/agent/inventory", headers=h, json={
            "devices": [{"ip": "192.0.2.50", "vendor": "cisco", "group": "acme", "hostname": "updated"}]
        })
        self.assertEqual(r.status_code, 200, r.text)
        devs = inventory_manager.get_all_devices()
        self.assertEqual(len(devs), 1)
        self.assertEqual(devs[0]["Location"], loc_lab["id"])
        self.assertEqual(devs[0]["Hostname"], "updated")

    def test_delete_group_refused_while_locations_exist(self):
        adm = self._as("adm")
        # acme has location loc_acme
        r = adm.post("/api/groups/delete", json={"name": "acme"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("1", r.text)
        self.assertIn("sedi", r.text.lower())


if __name__ == "__main__":
    unittest.main()
