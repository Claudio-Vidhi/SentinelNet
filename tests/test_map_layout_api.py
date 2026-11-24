# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Map layout saved on the server per user: round trip, isolation, boundary checks."""
import os
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app_server
from routers import topology
from routers.deps import get_current_user

HEADERS = {"X-Requested-With": "x"}


class TestMapLayoutApi(unittest.TestCase):
    def setUp(self):
        self.user = "alice"
        app_server.app.dependency_overrides[get_current_user] = \
            lambda: {"sub": self.user, "role": "super_admin"}
        env = mock.patch.dict(os.environ, {"SENTINELNET_DATA_DIR": tempfile.mkdtemp()})
        env.start()
        audit = mock.patch("routers.topology.log_audit")
        audit.start()
        self.addCleanup(env.stop)
        self.addCleanup(audit.stop)
        self.addCleanup(app_server.app.dependency_overrides.pop, get_current_user, None)
        self.client = TestClient(app_server.app)

    def put(self, keys):
        return self.client.put("/api/map/layout", json={"keys": keys}, headers=HEADERS)

    def get(self):
        return self.client.get("/api/map/layout", headers=HEADERS).json()

    def test_round_trip_and_users_isolated(self):
        self.assertEqual(self.get(), {"layout": None, "saved_at": None})
        keys = {"mapViewMode": "purdue", "purduePositions": '{"all": {"switch-01": [1, 2]}}'}
        res = self.put(keys)
        self.assertEqual(res.status_code, 200)
        got = self.get()
        self.assertEqual(got["layout"], keys)
        self.assertEqual(got["saved_at"], res.json()["saved_at"])

        self.user = "bob"
        self.assertEqual(self.get(), {"layout": None, "saved_at": None})
        self.put({"mapViewMode": "minimal"})
        self.user = "alice"
        self.assertEqual(self.get()["layout"], keys)

    def test_unknown_key_refused(self):
        res = self.put({"mapViewMode": "layered", "sentinelnet_theme": "dark"})
        self.assertEqual(res.status_code, 422)
        self.assertEqual(self.get()["layout"], None)

    def test_non_string_value_refused(self):
        res = self.client.put("/api/map/layout", json={"keys": {"mapRenew": ["x"]}}, headers=HEADERS)
        self.assertEqual(res.status_code, 422)

    def test_oversize_refused(self):
        res = self.put({"mapTitleBlock": "x" * (topology.MAP_LAYOUT_MAX_BYTES + 1)})
        self.assertEqual(res.status_code, 413)
        self.assertEqual(self.get()["layout"], None)


if __name__ == "__main__":
    unittest.main()
