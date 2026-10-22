# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Vendor "auto": netmiko's SSH autodetect names the vendor before the probe,
and the "Aggiungi apparati" panel routes to flows that really exist."""

import os
import re
import unittest
from unittest import mock

from core import core_engine

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEV = {"IP": "192.0.2.10", "Vendor": "auto", "Profile": "custom", "SSH Port": "22"}


def _detect(guess):
    det = mock.MagicMock()
    det.autodetect.return_value = guess
    return mock.patch.object(core_engine, "_VendorDetect", return_value=det)


class TestProbeDeviceAuto(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(core_engine, "get_device_credentials", return_value=("u", "p", ""))
        p.start()
        self.addCleanup(p.stop)

    def test_known_type_probes_with_the_mapped_vendor(self):
        with _detect("fortinet"), mock.patch.object(
                core_engine, "probe_device", return_value={"status": "success", "hostname": "fw-01"}) as probe:
            res = core_engine.probe_device_auto(dict(DEV))
        self.assertEqual(res, {"status": "success", "hostname": "fw-01", "vendor": "fortinet"})
        self.assertEqual(probe.call_args.args[0]["Vendor"], "fortinet")

    def test_type_without_a_driver_asks_the_user(self):
        with _detect("cisco_nxos"), mock.patch.object(core_engine, "probe_device") as probe:
            res = core_engine.probe_device_auto(dict(DEV))
        self.assertEqual(res["status"], "error")
        self.assertIn("cisco_nxos", res["message"])
        probe.assert_not_called()

    def test_nothing_detected(self):
        with _detect(None):
            self.assertEqual(core_engine.probe_device_auto(dict(DEV))["status"], "error")

    def test_telnet_only_device_is_not_autodetected(self):
        dev = dict(DEV, Transports='{"telnet":23}')
        with _detect("cisco_ios") as det:
            res = core_engine.probe_device_auto(dev)
        self.assertEqual(res["status"], "error")
        det.assert_not_called()

    def test_every_mapped_vendor_has_a_driver(self):
        for vendor in set(core_engine.AUTODETECT_VENDORS.values()):
            core_engine.resolve_driver(vendor)


class TestAddDevicesPanel(unittest.TestCase):
    """Every source card is gated, every in-panel source has its input block,
    and the ids the script binds exist in the template."""

    def setUp(self):
        with open(os.path.join(_REPO_ROOT, "templates", "dashboard.html"), encoding="utf-8") as f:
            self.html = f.read()
        with open(os.path.join(_REPO_ROOT, "static", "js", "add-devices.js"), encoding="utf-8") as f:
            self.js = f.read()

    def test_cards_match_the_gates(self):
        block = self.js[self.js.index("const SOURCE_GATES = {"):self.js.index("};", self.js.index("const SOURCE_GATES = {"))]
        gates = dict(re.findall(r"(\w+): \[([^\]]*)\]", block))
        cards = re.findall(r'data-adw-source="(\w+)"', self.html)
        self.assertEqual(sorted(cards), sorted(gates))
        for src, tabs in gates.items():
            for tab in re.findall(r"'([\w-]+)'", tabs):
                self.assertIn(f'id="{tab}"', self.html, f"{src} gate {tab} missing")

    def test_in_panel_sources_have_an_input_block(self):
        for src in ("addr", "csv", "scan", "nbr"):
            self.assertIn(f'data-adw-for="{src}"', self.html)

    def test_bound_ids_exist(self):
        for el_id in set(re.findall(r"\$\('(\w+)'\)", self.js)):
            self.assertIn(f'id="{el_id}"', self.html, f"#{el_id} missing")
        self.assertIn('<script src="/static/js/add-devices.js"></script>', self.html)
        self.assertIn('data-action="open-add-devices"', self.html)


if __name__ == "__main__":
    unittest.main()
