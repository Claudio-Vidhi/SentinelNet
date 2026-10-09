# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Factory reset (spec 2026-10-09 factory-reset): the request only leaves a
marker; the next start archives the data directory before anything opens a
file in it, because on Windows an open file cannot be moved."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from core import data_config
from routers.deps import CSRF_HEADER
from security import security_manager, user_manager
from services import self_update

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"
MARK = data_config.FACTORY_RESET_MARKER


class TestApplyAtStart(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fr_")
        self.data = os.path.join(self.root, "data")
        os.makedirs(self.data)
        with open(os.path.join(self.data, "users.json"), "w", encoding="utf-8") as f:
            f.write("{}")
        p = patch.dict(os.environ, {"SENTINELNET_DATA_DIR": self.data})
        p.start()
        self.addCleanup(p.stop)

    def _mark(self):
        with open(os.path.join(self.data, MARK), "w", encoding="utf-8") as f:
            f.write("{}")

    def archives(self):
        return [n for n in os.listdir(self.root) if n.startswith("data.wiped-")]

    def test_no_marker_moves_nothing(self):
        self.assertIsNone(data_config._apply_pending_factory_reset())
        self.assertEqual(self.archives(), [])
        self.assertTrue(os.path.exists(os.path.join(self.data, "users.json")))

    def test_marker_archives_and_leaves_an_empty_dir(self):
        self._mark()
        archive = data_config._apply_pending_factory_reset()
        self.assertEqual(self.archives(), [os.path.basename(archive)])
        self.assertEqual(sorted(os.listdir(archive)), sorted([MARK, "users.json"]))
        self.assertEqual(os.listdir(self.data), [])

    def test_failed_move_keeps_data_and_marker(self):
        self._mark()
        with patch.object(data_config.os, "replace", side_effect=PermissionError("locked")):
            self.assertIsNone(data_config._apply_pending_factory_reset())
        self.assertTrue(os.path.exists(os.path.join(self.data, MARK)))
        self.assertTrue(os.path.exists(os.path.join(self.data, "users.json")))
        self.assertEqual(self.archives(), [])


class TestRoutes(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="fr_api_")
        self.marker = os.path.join(tmp, MARK)
        for p in (patch("routers.settings._reset_marker", lambda: self.marker),
                  patch.object(user_manager, "USERS_JSON", os.path.join(tmp, "users.json"))):
            p.start()
            self.addCleanup(p.stop)
        security_manager._failed_attempts.clear()
        user_manager.create_user("root", PW, role="super_admin")
        user_manager.create_user("adm", PW, role="admin")

    def _as(self, name):
        c = TestClient(app_server.app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", json={"username": name, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        c.headers.update(H)
        return c

    def test_admin_is_refused(self):
        r = self._as("adm").post("/api/settings/factory-reset",
                                 json={"password": PW, "confirm": "RESET"})
        self.assertEqual(r.status_code, 403, r.text)
        self.assertFalse(os.path.exists(self.marker))

    def test_wrong_password_or_missing_confirm_writes_nothing(self):
        root = self._as("root")
        r = root.post("/api/settings/factory-reset", json={"password": "nope", "confirm": "RESET"})
        self.assertEqual(r.status_code, 403, r.text)
        r = root.post("/api/settings/factory-reset", json={"password": PW, "confirm": "reset"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertFalse(os.path.exists(self.marker))

    def test_supervised_request_marks_and_restarts(self):
        with patch.object(self_update, "supervisor", return_value="systemd"), \
             patch.object(self_update, "restart", return_value="systemd") as restart:
            r = self._as("root").post("/api/settings/factory-reset",
                                      json={"password": PW, "confirm": "RESET"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["status"], "restarting")
        restart.assert_called_once()
        with open(self.marker, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["requested_by"], "root")

    def test_unsupervised_request_waits_and_can_be_cancelled(self):
        root = self._as("root")
        with patch.object(self_update, "supervisor", return_value=""):
            r = root.post("/api/settings/factory-reset", json={"password": PW, "confirm": "RESET"})
        self.assertEqual(r.json()["status"], "pending-restart")
        self.assertTrue(root.get("/api/settings/factory-reset").json()["pending"])
        self.assertEqual(root.delete("/api/settings/factory-reset").status_code, 200)
        self.assertFalse(os.path.exists(self.marker))
        self.assertFalse(root.get("/api/settings/factory-reset").json()["pending"])


class TestUi(unittest.TestCase):
    def test_controls_exist_and_are_bound(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "templates", "dashboard.html"), encoding="utf-8") as f:
            html = f.read()
        with open(os.path.join(root, "static", "js", "settings.js"), encoding="utf-8") as f:
            js = f.read()
        bound = ("btnFactoryReset", "btnCancelFactoryReset", "btnFrConfirm", "btnFrCancel",
                 "btnCloseFactoryReset")
        for el in bound + ("factoryResetModal", "frPassword", "frConfirm", "factoryResetStatus"):
            with self.subTest(el=el):
                self.assertTrue(f'id="{el}"' in html, el)
        for el in bound:
            with self.subTest(el=el):
                self.assertTrue(f"getElementById('{el}')" in js, el)
        self.assertTrue('class="panel requires-super-admin' in html)


if __name__ == "__main__":
    unittest.main()
