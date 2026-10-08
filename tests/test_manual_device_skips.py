# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Loops over the whole inventory never hand a manual device to a probe."""
import os
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_manualskip_"))

MANUAL = {"IP": "192.0.2.50", "Vendor": "linux", "Group": "Generale",
          "Site": "central", "Transports": '{"manual":null}'}
DEVICES = "services.inventory_manager.get_all_devices"
TELEMETRY = "services.tenant_telemetry.is_telemetry_enabled"


class Skips(unittest.TestCase):
    def test_ping_cycle(self):
        from services import ping_monitor
        with mock.patch(DEVICES, return_value=[MANUAL]), \
             mock.patch(TELEMETRY, return_value=True), \
             mock.patch.object(ping_monitor, "_ping_one") as ping:
            ping_monitor._run_cycle()
        ping.assert_not_called()

    def test_snmp_targets(self):
        from observability.ingesters import snmp_poller
        with mock.patch(DEVICES, return_value=[MANUAL]), \
             mock.patch(TELEMETRY, return_value=True), \
             mock.patch("security.snmp_defaults.resolve_snmp_community", return_value="public"):
            self.assertEqual(snmp_poller._snmp_devices(), [])

    def test_linux_targets(self):
        from observability.ingesters import linux_poller
        with mock.patch(DEVICES, return_value=[MANUAL]):
            self.assertEqual(linux_poller._linux_devices(), [])

    def test_mac_collect_all(self):
        from collectors import mac_collector
        with mock.patch.object(mac_collector, "collect_one") as one, \
             mock.patch("collectors.mac_history.prune", return_value=0):
            out = mac_collector.collect_all([MANUAL])
        one.assert_not_called()
        self.assertEqual(out["scanned"], 0)

    def test_arp_collect_all(self):
        from collectors import arp_collector
        with mock.patch.object(arp_collector, "collect_from_device") as one:
            arp_collector.collect_all([MANUAL])
        one.assert_not_called()


class CredentialGuard(unittest.TestCase):
    def test_manual_device_has_no_credentials(self):
        from core.device_credentials import CredentialResolveError, get_device_credentials
        with self.assertRaises(CredentialResolveError):
            get_device_credentials(dict(MANUAL, Profile="default"))


if __name__ == "__main__":
    unittest.main()
