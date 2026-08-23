# -*- coding: utf-8 -*-
"""The operator decides how much config history to keep.

Default is keep-everything, which is what shipped. A cap prunes the oldest
versions and their files, and never touches the current backup.
"""
import os
import tempfile
import unittest
from unittest import mock

DEVICE = {"IP": "192.0.2.10", "Group": "ACME", "Vendor": "cisco",
          "Hostname": "switch-01"}


class RetentionCap(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch("core.core_engine.BACKUP_FOLDER", self._tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def _record(self, n):
        from services.config_drift import history
        for i in range(n):
            history.record_version(DEVICE, f"hostname switch-01\n! change {i}\n")

    def test_zero_means_keep_everything(self):
        from services.config_drift import history
        with mock.patch("core.app_settings.get_app_settings",
                        return_value={"config_drift_keep_versions": 0}):
            self._record(5)
        self.assertEqual(5, len(history.list_versions(DEVICE)))

    def test_a_cap_keeps_the_newest_and_drops_the_oldest(self):
        from services.config_drift import history
        with mock.patch("core.app_settings.get_app_settings",
                        return_value={"config_drift_keep_versions": 3}):
            self._record(5)
        versions = history.list_versions(DEVICE)
        self.assertEqual(3, len(versions))
        self.assertIn("change 4", history.read_version(DEVICE, versions[0]["seen_at"]))

    def test_pruned_files_are_removed_from_disk(self):
        from services.config_drift import history
        with mock.patch("core.app_settings.get_app_settings",
                        return_value={"config_drift_keep_versions": 2}):
            self._record(4)
        kept = {v["file"] for v in history.list_versions(DEVICE)}
        on_disk = {f for f in os.listdir(history.history_dir(DEVICE))
                   if f.endswith(".txt")}
        self.assertEqual(kept, on_disk)

    def test_lowering_the_cap_prunes_on_the_next_write(self):
        from services.config_drift import history
        with mock.patch("core.app_settings.get_app_settings",
                        return_value={"config_drift_keep_versions": 0}):
            self._record(5)
        with mock.patch("core.app_settings.get_app_settings",
                        return_value={"config_drift_keep_versions": 2}):
            history.record_version(DEVICE, "hostname switch-01\n! newest\n")
        self.assertEqual(2, len(history.list_versions(DEVICE)))


class SettingsApiRoundTrip(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from app_server import app
        from security import user_manager
        self.client = TestClient(app)
        try:
            user_manager.create_user("admin_ret_test", "Pass123!", role="admin")
        except Exception:
            pass
        from security.security_manager import create_access_token
        token = create_access_token({"sub": "admin_ret_test", "role": "admin", "groups": ["*"]})
        self._headers = {"Authorization": f"Bearer {token}", "X-Requested-With": "SentinelNet"}

    def test_setting_round_trips_through_api(self):
        res = self.client.post("/api/settings/app", json={"config_drift_keep_versions": 5}, headers=self._headers)
        self.assertEqual(200, res.status_code)

        get_res = self.client.get("/api/settings/app", headers=self._headers)
        self.assertEqual(200, get_res.status_code)
        data = get_res.json()
        self.assertEqual(5, data["settings"].get("config_drift_keep_versions"))

    def test_negative_or_invalid_value_rejected(self):
        res_neg = self.client.post("/api/settings/app", json={"config_drift_keep_versions": -2}, headers=self._headers)
        self.assertEqual(400, res_neg.status_code)

        res_str = self.client.post("/api/settings/app", json={"config_drift_keep_versions": "not-a-number"}, headers=self._headers)
        self.assertEqual(400, res_str.status_code)


if __name__ == "__main__":
    unittest.main()
