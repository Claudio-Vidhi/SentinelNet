# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Sidebar favorites: per user, validated, never another user's row."""

import os
import shutil
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_favorites_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from core import db  # noqa: E402
from routers.deps import CSRF_HEADER  # noqa: E402
from security import security_manager, user_manager  # noqa: E402

PASS = "PasswordSicura1!"
H = {CSRF_HEADER: "1"}


def _login(username):
    client = TestClient(app_server.app)
    r = client.post("/api/auth/login", json={"username": username, "password": PASS})
    assert r.status_code == 200, r.text
    return client


class TestUiFavorites(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.migrate()
        user_manager.create_user("fav-a", PASS, role="viewer")
        user_manager.create_user("fav-b", PASS, role="viewer")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def setUp(self):
        security_manager._failed_attempts.clear()

    def test_empty_by_default_then_saved_in_order(self):
        a = _login("fav-a")
        self.assertEqual(a.get("/api/profile/favorites").json(), {"tabs": []})
        r = a.put("/api/profile/favorites", json={"tabs": ["tab-routes", "tab-endpoint", "tab-routes"]}, headers=H)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["tabs"], ["tab-routes", "tab-endpoint"], "duplicates dropped, order kept")
        self.assertEqual(a.get("/api/profile/favorites").json()["tabs"], ["tab-routes", "tab-endpoint"])

    def test_one_user_never_sees_another(self):
        _login("fav-a").put("/api/profile/favorites", json={"tabs": ["tab-devices"]}, headers=H)
        b = _login("fav-b")
        b.put("/api/profile/favorites", json={"tabs": ["tab-map"]}, headers=H)
        self.assertEqual(b.get("/api/profile/favorites").json()["tabs"], ["tab-map"])
        self.assertEqual(_login("fav-a").get("/api/profile/favorites").json()["tabs"], ["tab-devices"])

    def test_invalid_ids_and_too_many_are_refused(self):
        a = _login("fav-a")
        for bad in (["../etc"], ["<script>"], ["devices"], [f"tab-x{i}" for i in range(21)]):
            r = a.put("/api/profile/favorites", json={"tabs": bad}, headers=H)
            self.assertEqual(r.status_code, 422, bad)

    def test_requires_a_session(self):
        anon = TestClient(app_server.app)
        self.assertEqual(anon.get("/api/profile/favorites").status_code, 401)
        self.assertEqual(anon.put("/api/profile/favorites", json={"tabs": []}, headers=H).status_code, 401)


if __name__ == "__main__":
    unittest.main()
