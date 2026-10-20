# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""ARP and MAC scans give a refused login one more try at the end of the run:
an AAA server hit by a burst of parallel logins refuses some of them."""
import os
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_retry_"))

A = {"IP": "192.0.2.1", "Vendor": "cisco", "Group": "Generale"}
B = {"IP": "192.0.2.2", "Vendor": "cisco", "Group": "Generale"}
REFUSED = "Authentication to device failed. ... Authentication failed."


class ArpRetry(unittest.TestCase):
    def _run(self, outcomes):
        from collectors import arp_collector
        calls = []

        def collect(d):
            calls.append(d["IP"])
            return outcomes[d["IP"]].pop(0)
        with mock.patch.object(arp_collector, "collect_from_device", collect), \
                mock.patch.object(arp_collector, "RETRY_PAUSE_S", 0), \
                mock.patch("collectors.mac_history.record_arp_entries",
                           return_value={"new": 1, "updated": 0}):
            return arp_collector.collect_all([A, B]), calls

    def test_refused_login_succeeds_on_second_try(self):
        ok = {"status": "success", "source_type": "switch",
              "entries": [{"mac": "aa:bb:cc:dd:ee:01", "ip": "192.0.2.9"}]}
        out, calls = self._run({
            "192.0.2.1": [{"status": "error", "message": REFUSED}, ok],
            "192.0.2.2": [{"status": "error", "message": "timed out"}]})
        self.assertEqual(calls.count("192.0.2.1"), 2)
        self.assertEqual(calls.count("192.0.2.2"), 1)   # not a refusal: no retry
        self.assertEqual(out["devices"]["192.0.2.1"]["status"], "success")
        self.assertTrue(out["devices"]["192.0.2.1"]["retried"])
        self.assertNotIn("retried", out["devices"]["192.0.2.2"])

    def test_second_refusal_is_reported_as_retried(self):
        refused = {"status": "error", "message": REFUSED}
        out, calls = self._run({"192.0.2.1": [refused, refused],
                                "192.0.2.2": [refused, refused]})
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(d["retried"] for d in out["devices"].values()))


class MacRetry(unittest.TestCase):
    def test_refused_login_succeeds_on_second_try(self):
        from collectors import mac_collector, arp_collector
        seq = {"192.0.2.1": [{"error": "MAC-table non ottenibile (CLI): " + REFUSED},
                             {"rows": [], "method": "cli", "error": None}],
               "192.0.2.2": [{"rows": [], "method": "cli", "error": None}]}

        def one(d, transport=None):
            return dict(seq[d["IP"]].pop(0), device=d, if_macs=[])
        with mock.patch.object(mac_collector, "collect_one", one), \
                mock.patch.object(arp_collector, "RETRY_PAUSE_S", 0), \
                mock.patch("collectors.mac_history.record_sightings", return_value={}), \
                mock.patch("collectors.mac_history.prune", return_value=0):
            out = mac_collector.collect_all([A, B])
        by_ip = {r["ip"]: r for r in out["results"]}
        self.assertNotIn("error", by_ip["192.0.2.1"])
        self.assertTrue(by_ip["192.0.2.1"]["retried"])
        self.assertNotIn("retried", by_ip["192.0.2.2"])

    def test_cli_refusal_reaches_the_result(self):
        from collectors import mac_collector
        with mock.patch.object(mac_collector, "collect_via_cli",
                               side_effect=Exception(REFUSED)):
            res = mac_collector.collect_mac_table("192.0.2.1", "u", "p",
                                                  transports={"ssh": 22})
        self.assertIn("Authentication failed", res["error"])



class SequentialLogins(unittest.TestCase):
    def test_setting_drives_both_scans(self):
        from collectors import arp_collector, mac_collector, mac_history
        seen = []

        class Pool:
            def __init__(self, max_workers):
                seen.append(max_workers)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def map(self, fn, items):
                return [fn(i) for i in items]
        err = {"status": "error", "message": "timed out"}
        with mock.patch("concurrent.futures.ThreadPoolExecutor", Pool),                 mock.patch.object(arp_collector, "collect_from_device", return_value=err),                 mock.patch.object(mac_collector, "collect_one",
                                  side_effect=lambda d, transport=None:
                                  {"device": d, "error": "timed out", "if_macs": []}),                 mock.patch("collectors.mac_history.prune", return_value=0):
            for on in (True, False):
                mac_history.set_sequential_logins(on)
                arp_collector.collect_all([A, B])
                mac_collector.collect_all([A, B])
        mac_history.set_sequential_logins(False)
        self.assertEqual(seen, [1, 1, 2, 2])
        self.assertFalse(mac_history.stats()["sequential_logins"])


    def test_route_runs_and_requires_login(self):
        from fastapi.testclient import TestClient
        import app_server
        r = TestClient(app_server.app).post("/api/mac/settings/sequential",
                                            json={"enabled": True})
        self.assertIn(r.status_code, (401, 403))


if __name__ == "__main__":
    unittest.main()
