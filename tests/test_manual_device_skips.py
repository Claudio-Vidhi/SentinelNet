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
          "Probe": "central", "Transports": '{"manual":null}'}
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


    def test_api_poller_skips_manual(self):
        from observability.ingesters import api_poller
        with mock.patch(DEVICES, return_value=[MANUAL]), \
             mock.patch(TELEMETRY, return_value=True), \
             mock.patch("services.fortigate_service.token_status",
                        return_value={MANUAL["IP"]: {}}), \
             mock.patch("services.cve_intel.refresh_due"), \
             mock.patch.object(api_poller, "_poll_device") as poll:
            api_poller.poll_once()
        poll.assert_not_called()


class CredentialGuard(unittest.TestCase):
    def test_manual_device_has_no_credentials(self):
        # Profile "custom" with a full login resolves for a normal device, so
        # only the manual guard can make this raise.
        from core.device_credentials import CredentialResolveError, get_device_credentials
        from security.crypto_vault import encrypt_password
        dev = dict(MANUAL, Profile="custom", Username="admin",
                   Password=encrypt_password("pw"))
        self.assertEqual(get_device_credentials(dict(dev, Transports=""))[:2],
                         ("admin", "pw"))
        with self.assertRaises(CredentialResolveError) as ctx:
            get_device_credentials(dev)
        self.assertIn("manuale", str(ctx.exception))


class AgentPaths(unittest.TestCase):
    NORMAL = {"IP": "192.0.2.51", "Vendor": "linux", "Group": "Generale",
              "Probe": "site-a", "Transports": ""}

    def test_agent_inventory_omits_manual(self):
        from routers import agent
        manual = dict(MANUAL, Probe="site-a")
        with mock.patch(DEVICES, return_value=[manual, self.NORMAL]):
            out = agent._devices_for_probe("site-a", with_credentials=False)
        self.assertEqual([d["ip"] for d in out], ["192.0.2.51"])

    def test_agent_inventory_with_credentials_does_not_raise(self):
        from routers import agent
        manual = dict(MANUAL, Probe="site-a")
        with mock.patch(DEVICES, return_value=[manual, self.NORMAL]),              mock.patch("core.device_credentials.get_device_credentials",
                        return_value=("u", "p", "")):
            out = agent._devices_for_probe("site-a", with_credentials=True)
        self.assertEqual([d["ip"] for d in out], ["192.0.2.51"])

    def test_push_mac_skips_manual(self):
        from services import probe_agent
        from collectors import mac_collector
        agent_obj = probe_agent.Agent.__new__(probe_agent.Agent)
        with mock.patch.object(probe_agent.core_engine, "get_device_credentials") as creds,              mock.patch.object(mac_collector, "collect_mac_table") as collect:
            out = agent_obj.push_mac([MANUAL])
        creds.assert_not_called()
        collect.assert_not_called()
        self.assertEqual(out, {"recorded": 0})


class PingRoutes(unittest.TestCase):
    ADMIN = {"sub": "admin", "role": "admin"}

    def _patches(self):
        return (mock.patch(DEVICES, return_value=[MANUAL]),
                mock.patch("collectors.network_scanner._ping", return_value=False),
                mock.patch("services.inventory_manager.get_detected_versions",
                           return_value={MANUAL["IP"]: {"status": "manual"}}),
                mock.patch("services.inventory_manager.update_version_inventory"))

    def test_ping_check_never_pings_a_manual_device(self):
        from routers import triage
        devs, icmp, vers, upd = self._patches()
        with devs, icmp as ping, vers, upd as write, \
             mock.patch.object(triage, "user_group_scope", return_value=None):
            out = triage.ping_check(triage.PingCheckRequest(), current_user=self.ADMIN)
        ping.assert_not_called()
        write.assert_not_called()
        self.assertEqual(out["results"], {})

    def test_ping_single_never_pings_a_manual_device(self):
        from routers import triage
        devs, icmp, vers, upd = self._patches()
        with devs, icmp as ping, vers, upd as write, \
             mock.patch.object(triage, "assert_group_allowed"):
            out = triage.ping_single(MANUAL["IP"], current_user=self.ADMIN)
        ping.assert_not_called()
        write.assert_not_called()
        self.assertIsNone(out["reachable"])


class TriageRun(unittest.TestCase):
    def test_run_triage_does_not_hand_manual_to_background(self):
        from routers import triage
        normal = dict(MANUAL, IP="192.0.2.51", Transports="")
        admin = {"sub": "admin", "role": "admin"}
        with mock.patch(DEVICES, return_value=[MANUAL, normal]),              mock.patch.object(triage, "user_group_scope", return_value=None),              mock.patch.object(triage.threading, "Thread") as thread:
            triage.triage_job["status"] = "idle"
            try:
                triage.run_triage(triage.TriageRunRequest(), current_user=admin)
            finally:
                triage.triage_job["status"] = "idle"
        handed = thread.call_args.kwargs["args"][0]
        self.assertEqual([d["IP"] for d in handed], ["192.0.2.51"])


if __name__ == "__main__":
    unittest.main()
