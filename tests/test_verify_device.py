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
        # Compared before/after: other modules in the same worker share the store.
        before = inventory_manager.get_all_devices()
        r, probe = self._verify({"status": "success", "hostname": "switch-01"})
        self.assertEqual(inventory_manager.get_all_devices(), before)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {"ok": True, "hostname": "switch-01", "vendor": "cisco", "error": None})
        target = probe.call_args.args[0]
        self.assertEqual(crypto_vault.decrypt_password(target["Password"]), "p")

    def test_failure_reports_the_reason(self):
        r, _ = self._verify({"status": "error", "message": "Authentication failed"})
        self.assertEqual(r.json(), {"ok": False, "hostname": None, "vendor": "cisco", "error": "Authentication failed"})

    def test_device_behind_a_remote_probe_is_refused(self):
        r, probe = self._verify({"status": "success"}, probe="probe-roma")
        self.assertEqual(r.status_code, 400)
        probe.assert_not_called()

    def test_auto_vendor_returns_the_detected_one(self):
        with mock.patch.object(core_engine, "probe_device_auto",
                               return_value={"status": "success", "hostname": "fw-01", "vendor": "fortinet"}) as auto:
            r = self.client.post("/api/verify-device", json={
                "ip": "192.0.2.12", "vendor": "auto", "profile": "custom",
                "username": "u", "password": "p", "group": "Default"})
        self.assertEqual(r.json(), {"ok": True, "hostname": "fw-01", "vendor": "fortinet", "error": None})
        auto.assert_called_once()

    def test_auto_is_never_saved(self):
        r = self.client.post("/api/add-device", json={
            "ip": "192.0.2.13", "vendor": "auto", "profile": "default", "group": "Default"})
        self.assertEqual(r.status_code, 400)

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

    def test_add_device_saves_the_verified_hostname(self):
        # The wizard sends back the name /api/verify-device read.
        from tests.conftest import make_location
        loc = make_location("Default", "Milano")
        body = {"ip": "192.0.2.14", "vendor": "cisco", "profile": "default", "group": "Default",
                "location": loc, "hostname": "switch-01"}
        try:
            r = self.client.post("/api/add-device", json=body)
            self.assertEqual(r.status_code, 200, r.text)
            dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "192.0.2.14")
            self.assertEqual(dev["Hostname"], "switch-01")
            # Empty on a later save keeps the stored name.
            r = self.client.post("/api/add-device", json={**body, "hostname": ""})
            self.assertEqual(r.status_code, 200, r.text)
            dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "192.0.2.14")
            self.assertEqual(dev["Hostname"], "switch-01")
        finally:
            inventory_manager.delete_device("192.0.2.14")


if __name__ == "__main__":
    unittest.main()
