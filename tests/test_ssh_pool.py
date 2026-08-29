# -*- coding: utf-8 -*-
"""Pool SSH dedicato per il lavoro bloccante verso i dispositivi (WP11,
docs/app-review-fix-plan.md): le sessioni lunghe non occupano piu' il
threadpool condiviso delle rotte sync."""

import asyncio
import inspect
import threading
import unittest

from core import ssh_pool


class TestSshPool(unittest.TestCase):

    def test_work_runs_on_the_dedicated_pool(self):
        async def scenario():
            return await ssh_pool.run_ssh(lambda: threading.current_thread().name)
        name = asyncio.run(scenario())
        self.assertTrue(name.startswith("device-ssh"), name)

    def test_args_and_kwargs_are_forwarded(self):
        def add(a, b, extra=0):
            return a + b + extra

        async def scenario():
            return await ssh_pool.run_ssh(add, 2, 3, extra=10)
        self.assertEqual(asyncio.run(scenario()), 15)

    def test_exceptions_propagate(self):
        def boom():
            raise ValueError("esploso")

        async def scenario():
            return await ssh_pool.run_ssh(boom)
        with self.assertRaises(ValueError):
            asyncio.run(scenario())

    def test_pool_is_bounded(self):
        self.assertEqual(ssh_pool.ssh_executor._max_workers,
                         ssh_pool.SSH_EXECUTOR_MAX_WORKERS)


class TestRoutesAreAsync(unittest.TestCase):
    """Le quattro rotte che bloccavano il threadpool condiviso ora sono
    asincrone e delegano il lavoro SSH al pool dedicato."""

    def test_routes_are_coroutines(self):
        from routers.triage import triage_single_device
        from routers.arp import arp_scan
        from routers.mac import mac_scan
        from routers.sites import test_bastion_ep
        for route in (triage_single_device, arp_scan, mac_scan, test_bastion_ep):
            self.assertTrue(inspect.iscoroutinefunction(route), route.__name__)


if __name__ == "__main__":
    unittest.main()
