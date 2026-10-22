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
    def test_every_card_has_a_source_whose_targets_exist(self):
        with open(os.path.join(_REPO_ROOT, "templates", "dashboard.html"), encoding="utf-8") as f:
            html = f.read()
        with open(os.path.join(_REPO_ROOT, "static", "js", "add-devices.js"), encoding="utf-8") as f:
            core = f.read()
        block = core[core.index("const ADD_SOURCES = {"):core.index("};", core.index("const ADD_SOURCES = {"))]
        self.assertIn('data-adw-source="addr"', html)
        self.assertIn('<script src="/static/js/add-devices.js"></script>', html)
        sources = dict(re.findall(r"(\w+):\s*\{([^}]*)\}", block))
        cards = re.findall(r'data-add-source="(\w+)"', html)
        self.assertEqual(sorted(cards), sorted(sources))
        for name, body in sources.items():
            for key, value in re.findall(r"(tab|click|focus|gate): '([\w-]+)'", body):
                self.assertIn(f'id="{value}"', html, f"{name}.{key} -> #{value} missing")
        self.assertIn('data-action="open-add-devices"', html)


if __name__ == "__main__":
    unittest.main()
