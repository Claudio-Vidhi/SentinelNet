# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""EPSS lookups are cached for a day and back off after a failure.

On an isolated management LAN every CVE search used to wait out the 3s
timeout of an unreachable api.first.org.
"""
import unittest
from unittest.mock import MagicMock, patch

import requests

from routers import backup


def _ok(data):
    r = MagicMock()
    r.raise_for_status.return_value = None
    r.json.return_value = {"data": data}
    return r


class EpssCache(unittest.TestCase):
    def setUp(self):
        backup._epss_cache.clear()
        backup._epss_down_until = 0.0

    def test_second_lookup_is_served_from_cache(self):
        with patch.object(backup.requests, "get",
                          return_value=_ok([{"cve": "CVE-2024-0001", "epss": "0.5"}])) as get:
            self.assertEqual(backup._epss_scores(["CVE-2024-0001"]), {"CVE-2024-0001": 0.5})
            self.assertEqual(backup._epss_scores(["CVE-2024-0001"]), {"CVE-2024-0001": 0.5})
        self.assertEqual(get.call_count, 1)

    def test_failure_backs_off_instead_of_retrying_every_lookup(self):
        with patch.object(backup.requests, "get",
                          side_effect=requests.ConnectTimeout("offline")) as get:
            self.assertEqual(backup._epss_scores(["CVE-2024-0002"]), {})
            self.assertEqual(backup._epss_scores(["CVE-2024-0002"]), {})
        self.assertEqual(get.call_count, 1)

    def test_only_missing_ids_are_requested(self):
        backup._epss_cache["CVE-2024-0003"] = (0.1, backup.time.time())
        with patch.object(backup.requests, "get",
                          return_value=_ok([{"cve": "CVE-2024-0004", "epss": "0.2"}])) as get:
            out = backup._epss_scores(["CVE-2024-0003", "CVE-2024-0004"])
        self.assertEqual(out, {"CVE-2024-0003": 0.1, "CVE-2024-0004": 0.2})
        self.assertIn("cve=CVE-2024-0004", get.call_args.args[0])
        self.assertNotIn("CVE-2024-0003", get.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
