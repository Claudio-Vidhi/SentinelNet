# -*- coding: utf-8 -*-
"""cloud_backup.state: what this host believes is already offsite."""
import datetime as dt
import os
import tempfile
import unittest
from unittest import mock

from services.cloud_backup import state as cb_state


class TestCloudBackupState(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        patcher = mock.patch("core.data_config.get_path",
                             side_effect=lambda name: os.path.join(self.dir, name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_absent_file_reads_as_empty_not_an_error(self):
        self.assertEqual({}, cb_state.known_hashes())
        self.assertIsNone(cb_state.hours_since_success())

    def test_corrupt_file_reads_as_empty(self):
        with open(os.path.join(self.dir, cb_state.STATE_FILE), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual({}, cb_state.known_hashes())

    def test_a_successful_run_records_its_time_and_hashes(self):
        cb_state.record_run({"ok": True, "uploaded": 2, "skipped": 5, "failed": 0,
                             "verified": 2, "error": None,
                             "files": {"site-a/cisco/switch-01-192.0.2.10.txt": "sha256:1f0a"}})
        self.assertEqual({"site-a/cisco/switch-01-192.0.2.10.txt": "sha256:1f0a"},
                         cb_state.known_hashes())
        self.assertLess(cb_state.hours_since_success(), 1)

    def test_a_failed_run_does_not_refresh_the_success_time(self):
        cb_state.record_run({"ok": True, "uploaded": 1, "skipped": 0, "failed": 0,
                             "verified": 1, "error": None, "files": {}})
        first = cb_state.read()["last_success_at"]
        cb_state.record_run({"ok": False, "uploaded": 0, "skipped": 0, "failed": 1,
                             "verified": 0, "error": "connection refused", "files": {}})
        data = cb_state.read()
        self.assertEqual(first, data["last_success_at"])
        self.assertFalse(data["last_run"]["ok"])
        self.assertEqual("connection refused", data["last_run"]["error"])

    def test_age_is_reported_even_when_the_last_success_is_old(self):
        cb_state.write({"schema": 1, "files": {},
                        "last_run": {"ok": True, "error": None},
                        "last_success_at": "2026-08-20T09:00:00Z"})
        now = dt.datetime(2026, 8, 25, 9, 0, tzinfo=dt.timezone.utc).timestamp()
        self.assertAlmostEqual(120.0, cb_state.hours_since_success(now), places=1)


if __name__ == "__main__":
    unittest.main()
