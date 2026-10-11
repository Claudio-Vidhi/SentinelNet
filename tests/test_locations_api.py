# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Test API /api/locations (spec 2026-10-09 organizations-locations)."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import app_server
from core import app_settings, data_config
from security import security_manager, user_manager
from services import inventory_manager, location_manager, probe_manager


class _IsolatedLocationsApi(unittest.TestCase):
    PW = "PasswordSicura1!"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="loc_api_")
        self._patches = [
            patch.object(data_config, "DATA_DIR", self.tmp),
            patch.object(user_manager, "USERS_JSON", os.path.join(self.tmp, "users.json")),
            patch.object(inventory_manager, "HOSTS_CSV", os.path.join(self.tmp, "network_hosts.csv")),
            patch.object(probe_manager, "PROBES_JSON", os.path.join(self.tmp, "probes.json")),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._stop_patches)

        security_manager._failed_attempts.clear()
        inventory_manager.save_groups({"acme": {"description": "Acme Corp"},
                                       "beta": {"description": "Beta Ltd"}})

        user_manager.create_user("super_adm", self.PW, role="super_admin")
        user_manager.create_user("scoped_adm", self.PW, role="admin", groups=["acme"])
        user_manager.create_user("scoped_op", self.PW, role="operator", groups=["acme"])

        self.client = TestClient(app_server.app, raise_server_exceptions=False)

    def _stop_patches(self):
        for p in reversed(self._patches):
            p.stop()

    def _login(self, username: str) -> dict:
        r = self.client.post("/api/auth/login", json={"username": username, "password": self.PW})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["access_token"]
        return {"Authorization": f"Bearer {token}", "X-Requested-With": "1"}


class TestLocationsApi(_IsolatedLocationsApi):

    def test_list_locations_scope_and_filter(self):
        loc_a = location_manager.create_location("acme", "Milano")
        loc_b = location_manager.create_location("beta", "Roma")
        inventory_manager.add_or_update_device(
            "192.0.2.10", "cisco", "custom", "u", "p", "", "acme", location=loc_a["id"]
        )

        h_super = self._login("super_adm")
        r = self.client.get("/api/locations", headers=h_super)
        self.assertEqual(r.status_code, 200)
        data = r.json()["locations"]
        self.assertEqual(len(data), 2)
        milano = next(l for l in data if l["id"] == loc_a["id"])
        self.assertEqual(milano["devices"], 1)

        # Scoped user only sees their own org's locations
        h_scoped = self._login("scoped_adm")
        r_scoped = self.client.get("/api/locations", headers=h_scoped)
        self.assertEqual(r_scoped.status_code, 200)
        data_scoped = r_scoped.json()["locations"]
        self.assertEqual(len(data_scoped), 1)
        self.assertEqual(data_scoped[0]["org"], "acme")

        # Scoped user querying foreign org gets 403
        r_foreign = self.client.get("/api/locations?org=beta", headers=h_scoped)
        self.assertEqual(r_foreign.status_code, 403)

    def test_create_location_and_permissions(self):
        h_super = self._login("super_adm")
        payload = {"org": "acme", "name": "Torino", "role": "branch",
                   "subnets": ["10.10.0.0/24"], "probe": "central"}
        r = self.client.post("/api/locations", json=payload, headers=h_super)
        self.assertEqual(r.status_code, 200)
        loc = r.json()["location"]
        self.assertEqual(loc["name"], "Torino")
        self.assertEqual(loc["subnets"], ["10.10.0.0/24"])

        # Operator (non-admin) cannot create
        h_op = self._login("scoped_op")
        r_op = self.client.post("/api/locations", json=payload, headers=h_op)
        self.assertEqual(r_op.status_code, 403)

        # Scoped admin cannot create in foreign org
        h_scoped = self._login("scoped_adm")
        bad_payload = {"org": "beta", "name": "Napoli", "role": "branch", "subnets": [], "probe": "central"}
        r_scoped = self.client.post("/api/locations", json=bad_payload, headers=h_scoped)
        self.assertEqual(r_scoped.status_code, 403)

    def test_update_location_and_apply_probe(self):
        probe, _ = probe_manager.create_probe("Agent-Lab", "agent")
        loc = location_manager.create_location("acme", "Bologna", probe="central")
        inventory_manager.add_or_update_device(
            "192.0.2.20", "cisco", "custom", "u", "p", "", "acme", location=loc["id"], probe="central"
        )

        h_super = self._login("super_adm")
        update_payload = {
            "id": loc["id"],
            "name": "Bologna HQ",
            "role": "hq",
            "probe": probe["id"],
            "apply_probe_to_devices": True,
        }
        r = self.client.post("/api/locations/update", json=update_payload, headers=h_super)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["location"]["name"], "Bologna HQ")
        self.assertEqual(r.json()["location"]["role"], "hq")

        dev = inventory_manager.get_all_devices()[0]
        self.assertEqual(dev["Probe"], probe["id"])

    def test_delete_location_refused_when_has_devices(self):
        loc = location_manager.create_location("acme", "Firenze")
        inventory_manager.add_or_update_device(
            "192.0.2.30", "cisco", "custom", "u", "p", "", "acme", location=loc["id"]
        )

        h_super = self._login("super_adm")
        r = self.client.post("/api/locations/delete", json={"id": loc["id"]}, headers=h_super)
        self.assertEqual(r.status_code, 400)
        self.assertIn("1", r.json()["detail"])

        inventory_manager.delete_devices([("acme", "192.0.2.30")])
        r2 = self.client.post("/api/locations/delete", json={"id": loc["id"]}, headers=h_super)
        self.assertEqual(r2.status_code, 200)
        self.assertIsNone(location_manager.get_location(loc["id"]))

    def test_dismiss_review(self):
        app_settings.save_app_settings({"locations_review_pending": True})
        self.assertTrue(app_settings.get_app_settings().get("locations_review_pending"))

        h_super = self._login("super_adm")
        # The home banner reads the flag from the list.
        self.assertTrue(self.client.get("/api/locations", headers=h_super).json()["review_pending"])
        r = self.client.post("/api/locations/dismiss-review", headers=h_super)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(app_settings.get_app_settings().get("locations_review_pending"))
        self.assertFalse(self.client.get("/api/locations", headers=h_super).json()["review_pending"])


if __name__ == "__main__":
    unittest.main()
