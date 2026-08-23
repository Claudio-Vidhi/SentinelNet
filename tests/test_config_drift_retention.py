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


if __name__ == "__main__":
    unittest.main()
