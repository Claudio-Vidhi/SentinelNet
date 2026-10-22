# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""POST /api/verify-device: the provisioning form's "Verify" button. It tries
the login with what the form holds, before anything is saved."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_verifydev_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from core import core_engine  # noqa: E402
from security import crypto_vault, user_manager  # noqa: E402
from services import inventory_manager  # noqa: E402

ADMIN, ADMIN_PASS = "verifyadmin", "PasswordSicura1!"


class TestVerifyDevice(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        user_manager.create_user(ADMIN, ADMIN_PASS, role="admin")
        cls.client = TestClient(app_server.app)
        cls.client.__enter__()
        r = cls.client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        cls.client.headers.update({"Authorization": f"Bearer {r.json()['access_token']}"})

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def _verify(self, probe_result, **body):
        payload = {"ip": "192.0.2.10", "vendor": "cisco", "profile": "custom",
                   "username": "u", "password": "p", "group": "Default"}
        payload.update(body)
        with mock.patch.object(core_engine, "probe_device", return_value=probe_result) as probe:
            r = self.client.post("/api/verify-device", json=payload)
        return r, probe

    def test_success_returns_hostname_and_saves_nothing(self):
        r, probe = self._verify({"status": "success", "hostname": "switch-01"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {"ok": True, "hostname": "switch-01", "error": None})
        target = probe.call_args.args[0]
        self.assertEqual(crypto_vault.decrypt_password(target["Password"]), "p")
        self.assertFalse(any(d["IP"] == "192.0.2.10" for d in inventory_manager.get_all_devices()))

    def test_failure_reports_the_reason(self):
        r, _ = self._verify({"status": "error", "message": "Authentication failed"})
        self.assertEqual(r.json(), {"ok": False, "hostname": None, "error": "Authentication failed"})

    def test_device_behind_a_site_probe_is_refused(self):
        r, probe = self._verify({"status": "success"}, probe="site-01")
        self.assertEqual(r.status_code, 400)
        probe.assert_not_called()

    def test_existing_device_with_empty_password_uses_the_stored_one(self):
        from tests.conftest import make_location
        inventory_manager.add_or_update_device("192.0.2.11", "cisco", "custom", "old", "stored", "", "Default",
                                               location=make_location("Default", "Roma"))
        try:
            r, probe = self._verify({"status": "success", "hostname": "x"},
                                    ip="192.0.2.11", username="", password="")
            self.assertEqual(r.status_code, 200, r.text)
            target = probe.call_args.args[0]
            self.assertEqual(target["Username"], "old")
            self.assertEqual(crypto_vault.decrypt_password(target["Password"]), "stored")
        finally:
            inventory_manager.delete_device("192.0.2.11")


if __name__ == "__main__":
    unittest.main()
