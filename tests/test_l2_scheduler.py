# -*- coding: utf-8 -*-
"""Scheduler L2: ARP/MAC/prune schedulati, default spento, fasi isolate,
task che segue la config a runtime (WP9, docs/app-review-fix-plan.md)."""

import asyncio
import os
import tempfile
import unittest
from unittest import mock

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_l2sched_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config, db  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from collectors import arp_collector, l2_scheduler, mac_collector, mac_history  # noqa: E402
from observability import listener_manager  # noqa: E402
from services import inventory_manager  # noqa: E402


class TestCollectOnce(unittest.TestCase):

    def test_cycle_runs_all_phases(self):
        devs = [{"IP": "192.0.2.1"}]
        with mock.patch.object(inventory_manager, "get_all_devices", return_value=devs), \
             mock.patch.object(mac_collector, "collect_all",
                               return_value={"ok": 1}) as m_mac, \
             mock.patch.object(arp_collector, "collect_all",
                               return_value={"total_new": 0}) as m_arp, \
             mock.patch.object(mac_history, "prune", return_value=0) as m_prune:
            res = l2_scheduler._collect_once()
        m_mac.assert_called_once_with(devs)
        m_arp.assert_called_once_with(devs)
        m_prune.assert_called_once()
        self.assertTrue(res["pruned"])

    def test_phases_are_isolated(self):
        devs = [{"IP": "192.0.2.1"}]
        with mock.patch.object(inventory_manager, "get_all_devices", return_value=devs), \
             mock.patch.object(mac_collector, "collect_all",
                               side_effect=RuntimeError("boom")), \
             mock.patch.object(arp_collector, "collect_all",
                               return_value={"total_new": 1}) as m_arp, \
             mock.patch.object(mac_history, "prune", return_value=0) as m_prune:
            res = l2_scheduler._collect_once()
        m_arp.assert_called_once()
        m_prune.assert_called_once()
        self.assertIsNone(res["mac"])

    def test_empty_inventory_still_prunes(self):
        with mock.patch.object(inventory_manager, "get_all_devices", return_value=[]), \
             mock.patch.object(mac_collector, "collect_all") as m_mac, \
             mock.patch.object(mac_history, "prune", return_value=0) as m_prune:
            res = l2_scheduler._collect_once()
        m_mac.assert_not_called()
        m_prune.assert_called_once()
        self.assertTrue(res["pruned"])


class TestConfigFlag(unittest.TestCase):

    def test_default_off(self):
        os.environ.pop("SENTINELNET_OBS_L2_POLL_S", None)
        self.assertEqual(data_config.obs_config()["l2_poll_s"], 0)

    def test_env_override(self):
        os.environ["SENTINELNET_OBS_L2_POLL_S"] = "900"
        try:
            self.assertEqual(data_config.obs_config()["l2_poll_s"], 900)
        finally:
            os.environ.pop("SENTINELNET_OBS_L2_POLL_S", None)


class TestListenerManagerWiring(unittest.TestCase):

    def _cfg(self, l2_poll_s):
        off = {"enabled": False, "port": 0}
        return {
            "enabled": True, "bind": "127.0.0.1",
            "ipfix": dict(off), "netflow": dict(off),
            "sflow": dict(off), "syslog": dict(off),
            "api_poll_s": 0, "snmp_poll_s": 0, "linux_poll_s": 0,
            "l2_poll_s": l2_poll_s,
        }

    def test_task_follows_config(self):
        db.stop_writer()
        db.migrate()

        async def scenario():
            await listener_manager.apply_obs_config(self._cfg(60))
            task = listener_manager._l2_poller_task
            assert task is not None and not task.done()

            await listener_manager.apply_obs_config(self._cfg(0))
            assert listener_manager._l2_poller_task is None
            await asyncio.sleep(0.2)
            assert task.cancelled() or task.done()

            await listener_manager.shutdown()

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
