# -*- coding: utf-8 -*-
"""AP serials live in a small store, not in an SSH call during an export.

CDP announces an access point but carries no serial. The controller has it,
so the WLC tab writes it down when it visits; the export only ever reads.
"""
import os
import tempfile
import unittest
from unittest import mock


class ApStoreRoundTrip(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        patcher = mock.patch("core.data_config.get_path",
                             side_effect=lambda name: os.path.join(self._tmp.name, name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_recorded_aps_can_be_looked_up(self):
        from services import ap_store
        written = ap_store.record_aps("192.0.2.10", "ACME", [
            {"name": "ap-lobby", "serial": "FCW0000AAAA", "model": "AIR-EXAMPLE"},
            {"name": "ap-floor2", "serial": "FCW0000BBBB", "model": "AIR-EXAMPLE"},
        ])
        self.assertEqual(2, written)
        entry = ap_store.lookup("ap-lobby")
        self.assertEqual("FCW0000AAAA", entry["serial"])
        self.assertEqual("192.0.2.10", entry["wlc_ip"])
        self.assertEqual("ACME", entry["tenant"])
        self.assertTrue(entry["seen_at"])

    def test_an_unknown_ap_is_none_not_an_empty_dict(self):
        from services import ap_store
        self.assertIsNone(ap_store.lookup("ap-nowhere"))

    def test_a_second_visit_replaces_that_controller_s_entries(self):
        from services import ap_store
        ap_store.record_aps("192.0.2.10", "ACME",
                            [{"name": "ap-lobby", "serial": "FCW0000AAAA"}])
        ap_store.record_aps("192.0.2.10", "ACME",
                            [{"name": "ap-lobby", "serial": "FCW0000CCCC"}])
        self.assertEqual("FCW0000CCCC", ap_store.lookup("ap-lobby")["serial"])

    def test_another_controller_s_entries_survive(self):
        from services import ap_store
        ap_store.record_aps("192.0.2.10", "ACME",
                            [{"name": "ap-lobby", "serial": "FCW0000AAAA"}])
        ap_store.record_aps("198.51.100.10", "BETA",
                            [{"name": "ap-remote", "serial": "FCW0000DDDD"}])
        self.assertEqual("FCW0000AAAA", ap_store.lookup("ap-lobby")["serial"])
        self.assertEqual("FCW0000DDDD", ap_store.lookup("ap-remote")["serial"])

    def test_an_ap_with_no_serial_is_not_recorded(self):
        """A summary row with no inventory match must not create an entry that
        claims to know a serial it does not have."""
        from services import ap_store
        ap_store.record_aps("192.0.2.10", "ACME", [{"name": "ap-lobby"}])
        self.assertIsNone(ap_store.lookup("ap-lobby"))


class ApNameMatching(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        patcher = mock.patch("core.data_config.get_path",
                             side_effect=lambda name: os.path.join(self._tmp.name, name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_cdp_announces_an_fqdn_the_controller_names_short(self):
        from services import ap_store
        ap_store.record_aps("192.0.2.10", "ACME",
                            [{"name": "ap-lobby", "serial": "FCW0000AAAA"}])
        self.assertIsNotNone(ap_store.lookup("AP-Lobby.example.local"))

    def test_normalize_is_idempotent(self):
        from services import ap_store
        once = ap_store.normalize_ap_name("AP-Lobby.example.local")
        self.assertEqual(once, ap_store.normalize_ap_name(once))

    def test_lookup_by_ip(self):
        from services import ap_store
        ap_store.record_aps("192.0.2.10", "ACME",
                            [{"name": "ap-lobby", "ip": "192.0.2.55", "serial": "FCW0000AAAA"}])
        entry = ap_store.lookup("ap-unknown-name", ip="192.0.2.55")
        self.assertIsNotNone(entry)
        self.assertEqual("FCW0000AAAA", entry["serial"])

    def test_lookup_with_prefix_variation(self):
        from services import ap_store
        ap_store.record_aps("192.0.2.10", "ACME",
                            [{"name": "ap04-volta", "serial": "FCW0000VOLTA"}])
        # CDP reports GC-AP04-VOLTA
        entry = ap_store.lookup("GC-AP04-VOLTA")
        self.assertIsNotNone(entry)
        self.assertEqual("FCW0000VOLTA", entry["serial"])


if __name__ == "__main__":
    unittest.main()
