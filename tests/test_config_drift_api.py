# -*- coding: utf-8 -*-
"""Drift API: tenant isolation is enforced, and diffs carry no secrets."""
import unittest

from routers import config_drift


class ADiffNeverLeaksASecret(unittest.TestCase):
    """A config diff is dense with credentials. The operator does not need the
    secret in order to read the change."""

    def test_secrets_are_masked_in_the_unified_diff(self):
        before = "enable secret Sup3r-Enable\nhostname switch-01\n"
        after = "enable secret N3w-Enable\nhostname switch-02\n"
        diff = config_drift._unified("cisco", before, after, "a", "b")
        self.assertNotIn("Sup3r-Enable", diff)
        self.assertNotIn("N3w-Enable", diff)
        self.assertIn("switch-02", diff)

    def test_an_identical_pair_produces_an_empty_diff(self):
        text = "hostname switch-01\n"
        self.assertEqual("", config_drift._unified("cisco", text, text, "a", "b"))


class TheOverviewCountsRealDeviations(unittest.TestCase):
    """The home 'Config drift' card: devices whose latest config breaks their
    tenant baseline, out of the devices that could actually be checked."""

    def setUp(self):
        import os
        import tempfile
        from unittest import mock
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        p = mock.patch("core.backup_store.BACKUP_FOLDER", self._tmp.name)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch("services.config_drift.baseline._store_path",
                       lambda: os.path.join(self._tmp.name, "config_baselines.json"))
        p.start()
        self.addCleanup(p.stop)

    def test_only_checkable_devices_count_and_deviations_are_named(self):
        from services.config_drift import baseline, history
        ok = {"IP": "192.0.2.10", "Group": "ACME", "Vendor": "cisco", "Hostname": "switch-01"}
        bad = {"IP": "192.0.2.11", "Group": "ACME", "Vendor": "cisco", "Hostname": "switch-02"}
        no_rules = {"IP": "192.0.2.12", "Group": "OTHER", "Vendor": "cisco", "Hostname": "switch-03"}
        never_backed_up = {"IP": "192.0.2.13", "Group": "ACME", "Vendor": "cisco", "Hostname": "switch-04"}
        baseline.save("ACME", "+ service password-encryption\n")
        history.record_version(ok, "hostname switch-01\nservice password-encryption\n")
        history.record_version(bad, "hostname switch-02\n")
        history.record_version(no_rules, "hostname switch-03\n")

        s = config_drift.drift_summary_for([ok, bad, no_rules, never_backed_up])

        self.assertEqual(4, s["devices"])
        self.assertEqual(2, s["checked"])
        self.assertEqual(["192.0.2.11"], [d["ip"] for d in s["deviating"]])
        self.assertEqual(1, s["deviating"][0]["deviations"])


if __name__ == "__main__":
    unittest.main()
