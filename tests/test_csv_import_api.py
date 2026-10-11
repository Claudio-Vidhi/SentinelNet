# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""POST /api/import-csv/preview and /api/import-csv on top of services.csv_import."""
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from routers.deps import CSRF_HEADER
from security import security_manager, user_manager
from services import inventory_manager
from tests.conftest import seed_inventory

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"
LOCS = {"roma": {"org": "acme", "name": "Roma", "role": "branch", "subnets": ["10.20.0.0/16"], "probe": "central"}}


class _Isolated(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="csv_import_api_")
        for const, name in (("HOSTS_CSV", "network_hosts.csv"),):
            p = patch.object(inventory_manager, const, os.path.join(tmp, name))
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(user_manager, "USERS_JSON", os.path.join(tmp, "users.json"))
        p.start()
        self.addCleanup(p.stop)
        security_manager._failed_attempts.clear()
        seed_inventory(orgs=["acme", "beta"], locations=LOCS)
        user_manager.create_user("op", PW, role="operator")
        user_manager.create_user("opbeta", PW, role="operator", groups=["beta"])
        user_manager.create_user("view", PW, role="viewer")

    def _as(self, name):
        c = TestClient(app_server.app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", json={"username": name, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        c.headers.update(H)
        return c


class TestImportApi(_Isolated):
    BODY = {"csv_data": "ip,hostname\n10.20.1.1,rm-fw-01\n", "org": "acme", "location": "roma"}

    def test_preview_writes_nothing(self):
        r = self._as("op").post("/api/import-csv/preview", json=self.BODY)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(set(r.json()), {"columns", "rows", "counts"})
        self.assertEqual(inventory_manager.get_all_devices(), [])

    def test_preview_hides_secrets(self):
        r = self._as("op").post("/api/import-csv/preview", json=dict(
            self.BODY, csv_data="ip,password\n10.20.1.1,secret\n"))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertNotIn("secret", r.text)
        self.assertNotIn("_rec", r.text)

    def test_import_writes(self):
        r = self._as("op").post("/api/import-csv", json=self.BODY)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue({"imported", "updated", "skipped", "failed"} <= set(r.json()))
        self.assertIn("10.20.1.1", [d["IP"] for d in inventory_manager.get_all_devices()])

    def test_scoped_operator_foreign_org_rows_error(self):
        r = self._as("opbeta").post("/api/import-csv/preview", json=self.BODY)
        self.assertEqual(r.status_code, 200, r.text)
        rows = r.json()["rows"]
        self.assertTrue(rows and all(x["status"] == "error" for x in rows))

    def test_bad_requests(self):
        op = self._as("op")
        self.assertEqual(op.post("/api/import-csv/preview", json={}).status_code, 422)
        r = op.post("/api/import-csv/preview", json={"csv_data": "hostname\nx\n"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("IP", r.json()["detail"])

    def test_viewer_forbidden(self):
        v = self._as("view")
        self.assertEqual(v.post("/api/import-csv/preview", json=self.BODY).status_code, 403)
        self.assertEqual(v.post("/api/import-csv", json=self.BODY).status_code, 403)


if __name__ == "__main__":
    unittest.main()
