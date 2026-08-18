# -*- coding: utf-8 -*-
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

    def test_status_summary(self):
        self._run_with([{"IP": "192.0.2.1"}, {"IP": "192.0.2.2"}],
                       {"192.0.2.1": True, "192.0.2.2": False})
        with patch.object(ping_monitor, "get_app_settings", return_value={}):
            status = ping_monitor.get_status()
        self.assertEqual(status["summary"], {"total": 2, "up": 1, "down": 1, "unknown": 0})
        self.assertIsNotNone(status["last_run"])
        self.assertFalse(status["enabled"])


if __name__ == "__main__":
    unittest.main()