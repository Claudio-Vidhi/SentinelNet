# -*- coding: utf-8 -*-
"""Triaging many devices at once must not trip authentication throttles.

Field report: past 4-5 devices at once, the rest came back 'auth failed'. The
credentials were right; the AAA server / device login throttles refused the
burst. Logins now queue behind a small number of slots, and an auth failure
from a group run is retried once, alone, after the others finished.
"""
import threading
import time
import unittest
from unittest import mock

from core import core_engine
from routers import triage


class LoginsQueueInsteadOfBursting(unittest.TestCase):
    def test_no_more_than_the_slot_count_run_at_once(self):
        running, peak, lock = 0, 0, threading.Lock()

        def fake_session(device):
            nonlocal running, peak
            with lock:
                running += 1
                peak = max(peak, running)
            time.sleep(0.05)
            with lock:
                running -= 1
            return {"status": "success"}

        with mock.patch.object(core_engine, "_run_backup_and_triage", fake_session):
            threads = [threading.Thread(target=core_engine.run_backup_and_triage,
                                        args=({"IP": f"192.0.2.{i}", "Vendor": "cisco"},))
                       for i in range(1, 11)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertLessEqual(peak, core_engine.TRIAGE_MAX_CONCURRENT)
        self.assertGreaterEqual(peak, 2, "slots must still allow some parallelism")


class AGroupRunRetriesAuthFailuresAlone(unittest.TestCase):
    def test_an_auth_failure_is_retried_once_after_the_batch(self):
        calls = []

        def fake_triage(device):
            calls.append(device["IP"])
            if device["IP"] == "192.0.2.2" and calls.count("192.0.2.2") == 1:
                return {"status": "error", "message": "Authentication failed.",
                        "inventory_status": "auth_failed"}
            return {"status": "success"}

        devices = [{"IP": f"192.0.2.{i}", "Vendor": "cisco"} for i in range(1, 5)]
        with mock.patch.object(core_engine, "run_backup_and_triage", fake_triage), \
             mock.patch.object(triage.time, "sleep"):
            triage.run_triage_background(devices)

        self.assertEqual(2, calls.count("192.0.2.2"))
        results = {r["ip"]: r["result"]["status"] for r in triage.triage_job["results"]}
        self.assertEqual("success", results["192.0.2.2"])
        self.assertEqual(4, len(triage.triage_job["results"]))
        self.assertEqual(4, triage.triage_job["progress"])

    def test_an_offline_device_is_not_retried(self):
        calls = []

        def fake_triage(device):
            calls.append(device["IP"])
            return {"status": "error", "message": "timed out", "inventory_status": "offline"}

        with mock.patch.object(core_engine, "run_backup_and_triage", fake_triage), \
             mock.patch.object(triage.time, "sleep"):
            triage.run_triage_background([{"IP": "192.0.2.9", "Vendor": "cisco"}])
        self.assertEqual(["192.0.2.9"], calls)


if __name__ == "__main__":
    unittest.main()
