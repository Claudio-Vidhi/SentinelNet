# -*- coding: utf-8 -*-
"""Test unitari di wlc_service (AireOS / Catalyst 9800, SSH mockato)."""
import unittest
from unittest import mock

import wlc_service as wlc

AIREOS = {"IP": "192.0.2.10", "Vendor": "cisco_wlc", "Profile": "custom"}
C9800 = {"IP": "192.0.2.11", "Vendor": "cisco_9800", "Profile": "custom"}
CISCO = {"IP": "192.0.2.12", "Vendor": "cisco", "Profile": "custom"}


class PlatformTest(unittest.TestCase):
    def test_platforms(self):
        self.assertEqual(wlc.platform_of(AIREOS), "aireos")
        self.assertEqual(wlc.platform_of(C9800), "iosxe")
        self.assertEqual(wlc.platform_of(CISCO), "iosxe")


class MacTest(unittest.TestCase):
    def test_normalize_formats(self):
        for raw in ("AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff",
                    "aabbccddeeff"):
            self.assertEqual(wlc.normalize_mac(raw, "aireos"),
                             "aa:bb:cc:dd:ee:ff")

    def test_invalid_mac(self):
        with self.assertRaises(wlc.WlcError):
            wlc.normalize_mac("not-a-mac", "aireos")


class QueryTest(unittest.TestCase):
    def test_command_per_platform(self):
        with mock.patch.object(wlc, "ssh_run", return_value="out") as m:
            r = wlc.query(AIREOS, "client_summary")
            self.assertEqual(r["command"], "show client summary")
            self.assertEqual(r["platform"], "aireos")
            r = wlc.query(C9800, "client_summary")
            self.assertEqual(r["command"], "show wireless client summary")
            self.assertEqual(r["platform"], "iosxe")
        self.assertEqual(m.call_count, 2)

    def test_client_detail_substitutes_mac(self):
        with mock.patch.object(wlc, "ssh_run", return_value="out") as m:
            r = wlc.query(C9800, "client_detail", mac="AABB.CCDD.EEFF")
        self.assertEqual(
            r["command"],
            "show wireless client mac-address aa:bb:cc:dd:ee:ff detail")

    def test_client_detail_requires_mac(self):
        with self.assertRaises(wlc.WlcError):
            wlc.query(AIREOS, "client_detail")

    def test_unknown_service(self):
        with self.assertRaises(wlc.WlcError):
            wlc.query(AIREOS, "nope")


class DiagnoseTest(unittest.TestCase):
    def test_best_effort_sections(self):
        def fake_query(device, service, mac=None):
            if service == "rogue_aps":
                raise wlc.WlcError("boom")
            return {"platform": "aireos", "command": service, "data": "ok"}
        with mock.patch.object(wlc, "query", side_effect=fake_query):
            out = wlc.diagnose_wifi_client(AIREOS, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(out["sections"]["client_detail"]["data"], "ok")
        self.assertIn("error", out["sections"]["rogue_aps"])


if __name__ == "__main__":
    unittest.main()
