# -*- coding: utf-8 -*-
"""Config history: a version per real change, and nothing on a no-op run.

RFC 5737 addresses and placeholder hostnames only.
"""
import tempfile
import unittest
from unittest import mock

DEVICE = {"IP": "192.0.2.10", "Group": "ACME", "Vendor": "cisco",
          "Hostname": "switch-01"}


class HistoryRecordsOnlyRealChanges(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch("core.core_engine.BACKUP_FOLDER", self._tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_first_collection_creates_one_version(self):
        from services.config_drift import history
        self.assertTrue(history.record_version(DEVICE, "hostname switch-01\n"))
        self.assertEqual(1, len(history.list_versions(DEVICE)))

    def test_recollecting_the_same_config_creates_no_version(self):
        from services.config_drift import history
        history.record_version(DEVICE, "hostname switch-01\n")
        self.assertFalse(history.record_version(DEVICE, "hostname switch-01\n"))
        self.assertEqual(1, len(history.list_versions(DEVICE)))

    def test_volatile_lines_alone_are_not_a_change(self):
        from services.config_drift import history
        history.record_version(
            DEVICE, "Current configuration : 10 bytes\nhostname switch-01\n")
        self.assertFalse(history.record_version(
            DEVICE, "Current configuration : 99 bytes\nhostname switch-01\n"))

    def test_a_real_change_creates_a_second_version(self):
        from services.config_drift import history
        history.record_version(DEVICE, "hostname switch-01\n")
        self.assertTrue(history.record_version(
            DEVICE, "hostname switch-01\nip http server\n"))
        versions = history.list_versions(DEVICE)
        self.assertEqual(2, len(versions))
        self.assertGreaterEqual(versions[0]["seen_at"], versions[1]["seen_at"])

    def test_the_archived_text_is_raw_not_normalised(self):
        from services.config_drift import history
        raw = "Current configuration : 10 bytes\nhostname switch-01\n"
        history.record_version(DEVICE, raw)
        history.record_version(DEVICE, "hostname switch-02\n")
        first = history.list_versions(DEVICE)[-1]
        self.assertIn("Current configuration",
                      history.read_version(DEVICE, first["seen_at"]))

    def test_last_seen_is_updated_even_with_no_change(self):
        from services.config_drift import history
        history.record_version(DEVICE, "hostname switch-01\n")
        first = history.last_seen_at(DEVICE)
        with mock.patch("services.config_drift.history._now",
                        return_value="20260822T031407Z"):
            history.record_version(DEVICE, "hostname switch-01\n")
        self.assertNotEqual(first, history.last_seen_at(DEVICE))

    def test_an_unknown_device_has_no_versions(self):
        from services.config_drift import history
        self.assertEqual([], history.list_versions(
            {"IP": "192.0.2.99", "Group": "ACME", "Vendor": "cisco"}))


class ChangingTenantKeepsTheHistory(unittest.TestCase):
    """A device moving between tenants is a normal operational event. It used
    to delete the device's config; with history it would delete the archive."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch("core.core_engine.BACKUP_FOLDER", self._tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_history_follows_the_device_to_the_new_tenant(self):
        from core import core_engine
        from services.config_drift import history

        history.record_version(DEVICE, "hostname switch-01\n")
        history.record_version(DEVICE, "hostname switch-01\nip http server\n")
        self.assertEqual(2, len(history.list_versions(DEVICE)))

        moved = dict(DEVICE, Group="BETA")
        core_engine.save_backup(moved, "switch-01", "hostname switch-01\n")

        self.assertEqual(2, len(history.list_versions(moved)))
        self.assertEqual([], history.list_versions(DEVICE))


class HostnameChangeLeavesOneBackup(unittest.TestCase):
    """sys_name is re-read from the live device on every collection, so a
    plain hostname change is a normal, same-tenant event — not a re-parent.
    It must not leave the old file behind: an operator asking for this
    device's backup could otherwise be served the stale one (routers/backup.py
    returns the first filesystem match for an IP)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch("core.core_engine.BACKUP_FOLDER", self._tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_a_renamed_device_leaves_exactly_one_backup_file(self):
        from core import core_engine
        import os

        core_engine.save_backup(DEVICE, "switch-01", "hostname switch-01\n")
        core_engine.save_backup(DEVICE, "switch-01-renamed", "hostname switch-01-renamed\n")

        matches = []
        for root, _dirs, files in os.walk(self._tmp.name):
            matches.extend(f for f in files if f.endswith(f"-{DEVICE['IP']}.txt"))
        self.assertEqual(["switch-01-renamed-192.0.2.10.txt"], matches)


if __name__ == "__main__":
    unittest.main()
