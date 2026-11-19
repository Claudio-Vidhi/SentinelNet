# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for industrial OUI lookup database and MAC collector/history integration."""
import os
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_ind_oui_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from collectors import industrial_oui, mac_collector, mac_history  # noqa: E402


class TestIndustrialOuiDatabase(unittest.TestCase):
    def test_all_11_vendors_present(self):
        required = {
            "Siemens",
            "Rockwell/Allen-Bradley",
            "Schneider Electric",  # check-private-data: ok
            "Beckhoff",
            "Omron",
            "Moxa",
            "Hirschmann",
            "Phoenix Contact",
            "Wago",
            "Fanuc",
            "ABB",
        }
        self.assertEqual(set(industrial_oui.INDUSTRIAL_VENDORS), required)

    def test_each_vendor_has_oui_entries(self):
        samples = {
            "00:0e:8c:11:22:33": "Siemens",                 # (check-private-data: ok)
            "00:00:bc:11:22:33": "Rockwell/Allen-Bradley",  # (check-private-data: ok)
            "00:80:f4:11:22:33": "Schneider Electric",      # (check-private-data: ok)
            "00:01:05:11:22:33": "Beckhoff",                # (check-private-data: ok)
            "00:00:0a:11:22:33": "Omron",                   # (check-private-data: ok)
            "00:90:e8:11:22:33": "Moxa",                    # (check-private-data: ok)
            "00:80:63:11:22:33": "Hirschmann",              # (check-private-data: ok)
            "00:a0:45:11:22:33": "Phoenix Contact",         # (check-private-data: ok)
            "00:30:de:11:22:33": "Wago",                    # (check-private-data: ok)
            "00:e0:e4:11:22:33": "Fanuc",                   # (check-private-data: ok)
            "00:21:c1:11:22:33": "ABB",                     # (check-private-data: ok)
        }
        for mac, expected_vendor in samples.items():
            self.assertEqual(industrial_oui.lookup_industrial_oui(mac), expected_vendor)
            self.assertTrue(industrial_oui.is_industrial_oui(mac))

    def test_mac_format_normalization(self):
        # Colon, hyphen, Cisco dotted, and raw hex formats
        for fmt in (
            "00:0E:8C:AA:BB:CC",  # (check-private-data: ok)
            "00-0E-8C-AA-BB-CC",  # (check-private-data: ok)
            "000e.8caa.bbcc",     # (check-private-data: ok)
            "000E8CAABBCC",       # (check-private-data: ok)
        ):
            self.assertEqual(industrial_oui.lookup_industrial_oui(fmt), "Siemens")

    def test_unknown_and_invalid_mac_returns_empty(self):
        self.assertEqual(industrial_oui.lookup_industrial_oui("aa:bb:cc:dd:ee:ff"), "")
        self.assertFalse(industrial_oui.is_industrial_oui("aa:bb:cc:dd:ee:ff"))
        self.assertEqual(industrial_oui.lookup_industrial_oui(""), "")
        self.assertEqual(industrial_oui.lookup_industrial_oui(None), "")
        self.assertEqual(industrial_oui.lookup_industrial_oui("not-a-mac"), "")


class TestMacCollectorAndHistoryIntegration(unittest.TestCase):
    def setUp(self):
        mac_history.init_db()
        with mac_history._connect() as conn:
            conn.execute("DELETE FROM mac_sightings")
            conn.execute("DELETE FROM arp_entries")

    def test_cli_mac_table_populates_industrial_oui(self):
        raw = " 10    000e.8c12.3456    DYNAMIC     Gi1/0/5\n"  # (check-private-data: ok)
        rows = mac_collector.parse_cli_mac_table(raw)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["mac"], "000e.8c12.3456")  # (check-private-data: ok)
        self.assertEqual(rows[0]["oui_vendor"], "Siemens")

    def test_matm_oper_populates_industrial_oui(self):
        payload = {
            "Cisco-IOS-XE-matm-oper:matm-table": [
                {
                    "vlan": 20,
                    "matm-mac-entry": [
                        {
                            "mac-addr": "00:90:e8:aa:bb:01",  # (check-private-data: ok)
                            "interface": "Gi1/0/2",
                            "e-type": "matm-dynamic",
                        }
                    ],
                }
            ]
        }
        rows = mac_collector.parse_matm_oper_json(payload)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["oui_vendor"], "Moxa")

    def test_mac_history_records_and_exposes_industrial_oui(self):
        mac = "00:00:bc:aa:bb:01"  # (check-private-data: ok)
        mac_history.record_sightings(
            [{"mac": mac, "vlan": "10", "interface": "Gi1/0/1"}],
            "192.0.2.10",
            "switch-01",
        )
        locs = mac_history.search(mac=mac)
        self.assertEqual(len(locs), 1)
        self.assertEqual(locs[0]["oui_vendor"], "Rockwell/Allen-Bradley")

        inv = mac_history.endpoint_inventory()
        self.assertEqual(len(inv["results"]), 1)
        self.assertEqual(inv["results"][0]["oui_vendor"], "Rockwell/Allen-Bradley")


if __name__ == "__main__":
    unittest.main()
