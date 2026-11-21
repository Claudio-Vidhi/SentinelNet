# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the continuous ping monitor service."""

import unittest
from unittest.mock import patch

from services import ping_monitor


class PingMonitorConfigTest(unittest.TestCase):
    def test_get_config_defaults(self):
        with patch.object(ping_monitor, "get_app_settings", return_value={}):
            cfg = ping_monitor.get_config()
        self.assertEqual(cfg, {"enabled": False, "interval_seconds": 60})

    def test_get_config_clamps_interval(self):
        settings = {"ping_monitor": {"enabled": True, "interval_seconds": 1}}
        with patch.object(ping_monitor, "get_app_settings", return_value=settings):
            cfg = ping_monitor.get_config()
        self.assertTrue(cfg["enabled"])
        self.assertEqual(cfg["interval_seconds"], ping_monitor.MIN_INTERVAL)

    def test_save_config_clamps_and_persists(self):
        saved = {}
        with patch.object(ping_monitor, "save_app_settings",
                          side_effect=lambda d: saved.update(d)), \
             patch.object(ping_monitor, "log_audit"):
            cfg = ping_monitor.save_config(True, 3, "tester")
        self.assertEqual(cfg, {"enabled": True,
                               "interval_seconds": ping_monitor.MIN_INTERVAL})
        self.assertEqual(saved["ping_monitor"]["interval_seconds"],
                         ping_monitor.MIN_INTERVAL)


class PingMonitorCycleTest(unittest.TestCase):
    def setUp(self):
        with ping_monitor._lock:
            ping_monitor._state.clear()
            ping_monitor._last_run = None

    def _run_with(self, devices, ping_results):
        with patch("services.inventory_manager.get_all_devices",
                   return_value=devices), \
             patch("collectors.network_scanner._ping",
                   side_effect=lambda ip: ping_results[ip]):
            ping_monitor._run_cycle()

    def test_cycle_tracks_up_down(self):
        devices = [{"IP": "192.0.2.1"}, {"IP": "192.0.2.2"}, {"IP": " "}]
        self._run_with(devices, {"192.0.2.1": True, "192.0.2.2": False})
        with ping_monitor._lock:
            state = dict(ping_monitor._state)
        self.assertTrue(state["192.0.2.1"]["up"])
        self.assertFalse(state["192.0.2.2"]["up"])
        self.assertEqual(state["192.0.2.2"]["fails"], 1)
        self.assertEqual(len(state), 2)  # blank IP skipped

    def test_cycle_records_transition(self):
        devices = [{"IP": "192.0.2.1"}]
        self._run_with(devices, {"192.0.2.1": True})
        self._run_with(devices, {"192.0.2.1": False})
        with ping_monitor._lock:
            st = ping_monitor._state["192.0.2.1"]
        self.assertFalse(st["up"])
        self.assertEqual(st["checks"], 2)
        self.assertEqual(st["fails"], 1)
        self.assertGreaterEqual(st["last_change"], 0)

    def test_removed_devices_drop_out(self):
        self._run_with([{"IP": "192.0.2.1"}], {"192.0.2.1": True})
        self._run_with([{"IP": "192.0.2.9"}], {"192.0.2.9": True})
        with ping_monitor._lock:
            state = dict(ping_monitor._state)
        self.assertNotIn("192.0.2.1", state)
        self.assertIn("192.0.2.9", state)

    def _run_services(self, icmp, open_ports):
        dev = [{"IP": "192.0.2.5", "Service Ports": "22,3389"}]
        with patch("core.core_engine.is_reachable",
                   side_effect=lambda ip, port, timeout=2: port in open_ports), \
             patch("services.notifications.emit") as emit:
            self._run_with(dev, {"192.0.2.5": icmp})
        return emit

    def test_services_checked_and_confirmed_after_two_cycles(self):
        self._run_services(True, {22, 3389})
        self.assertFalse(self._run_services(True, {22}).called)   # 1st miss: not yet
        emit = self._run_services(True, {22})                       # 2nd miss: confirmed
        emit.assert_called_once()
        self.assertEqual(emit.call_args.kwargs["ctx"]["port"], 3389)
        self.assertEqual(emit.call_args.kwargs["kind"], "device.down")
        with patch.object(ping_monitor, "get_app_settings", return_value={}):
            dev = ping_monitor.get_status()["devices"][0]
        self.assertEqual(dev["services"], [{"port": 22, "up": True}, {"port": 3389, "up": False}])

    def test_open_port_makes_icmp_silent_host_up(self):
        self._run_services(False, {3389})
        with ping_monitor._lock:
            self.assertTrue(ping_monitor._state["192.0.2.5"]["up"])

    def test_host_down_raises_no_per_port_alerts(self):
        self._run_services(True, {22, 3389})
        self._run_services(False, set())
        emit = self._run_services(False, set())
        kinds = [(c.kwargs["ctx"].get("port"), c.kwargs["kind"]) for c in emit.call_args_list]
        self.assertEqual(kinds, [(None, "device.down")])

    def test_port_still_closed_after_host_outage_is_reported(self):
        self._run_services(True, {22, 3389})
        self._run_services(False, set())
        self._run_services(False, set())
        emit = self._run_services(True, {22})     # host back, RDP still dead
        ports = [c.kwargs["ctx"].get("port") for c in emit.call_args_list]
        self.assertIn(3389, ports)

    def test_service_ports_normalized_and_validated(self):
        from services.inventory_manager import normalize_service_ports
        self.assertEqual(normalize_service_ports(" 3389, 22 443;22"), "22,443,3389")
        self.assertEqual(normalize_service_ports(""), "")
        for bad in ("http", "0", "70000", ",".join(str(p) for p in range(1, 18))):
            with self.assertRaises(ValueError):
                normalize_service_ports(bad)

    def test_status_summary(self):
        self._run_with([{"IP": "192.0.2.1"}, {"IP": "192.0.2.2"}],
                       {"192.0.2.1": True, "192.0.2.2": False})
        with patch.object(ping_monitor, "get_app_settings", return_value={}):
            status = ping_monitor.get_status()
        self.assertEqual(status["summary"], {"total": 2, "up": 1, "down": 1, "unknown": 0})
        self.assertIsNotNone(status["last_run"])
        self.assertFalse(status["enabled"])


from tests.test_purdue_model import _PurdueBase  # noqa: E402  (temp data dir + one location)


class ServicePortsRouteTest(_PurdueBase):
    def test_add_device_stores_normalized_ports_and_refuses_bad_ones(self):
        from fastapi.testclient import TestClient
        import app_server
        from security import user_manager
        from services import inventory_manager
        user_manager.create_user("op", self.PW, role="operator", groups=["plant"])
        client = TestClient(app_server.app, raise_server_exceptions=False)
        r = client.post("/api/auth/login", json={"username": "op", "password": self.PW})
        headers = {"Authorization": f"Bearer {r.json()['access_token']}", "X-Requested-With": "1"}
        base = {"ip": "10.10.1.30", "vendor": "linux", "profile": "default",
                "group": "plant", "location": "loc-ot"}
        r = client.post("/api/add-device", headers=headers, json={**base, "service_ports": "3389 22"})
        self.assertEqual(r.status_code, 200, r.text)
        def stored():
            return next(d for d in inventory_manager.get_all_devices()
                        if d["IP"] == "10.10.1.30")["Service Ports"]
        self.assertEqual(stored(), "22,3389")
        # Omitted = keep: an edit that does not send the field must not wipe it.
        client.post("/api/add-device", headers=headers, json=base)
        self.assertEqual(stored(), "22,3389")
        r = client.post("/api/add-device", headers=headers, json={**base, "service_ports": "rdp"})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()