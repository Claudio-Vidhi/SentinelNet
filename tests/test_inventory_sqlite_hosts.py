# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import os
import tempfile
import unittest
from unittest.mock import patch

from services import inventory_manager as im, location_manager as lm
from tests.conftest import make_location, seed_inventory


class TestHostsOnSqlite(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        p = patch.object(im, "HOSTS_CSV", os.path.join(self.dir, "network_hosts.csv"))
        p.start()
        self.addCleanup(p.stop)
        im.add_group("acme")
        self.loc = make_location("acme", "Roma")

    def _add(self, ip):
        im.add_or_update_device(ip, "cisco", "custom", "u", "p", "", "acme", location=self.loc)

    def test_add_then_read_without_any_csv(self):
        self._add("192.0.2.1")
        self.assertEqual([d["IP"] for d in im.get_all_devices()], ["192.0.2.1"])
        self.assertFalse(os.path.exists(os.path.join(self.dir, "network_hosts.csv")))

    def test_version_bumps_on_write(self):
        v = im.inventory_version()
        self._add("192.0.2.1")
        self.assertGreater(im.inventory_version(), v)

    def test_decommission_round_trip(self):
        self._add("192.0.2.1")
        self.assertEqual(im.decommission([("acme", "192.0.2.1")], "admin"), 1)
        self.assertEqual(im.get_all_devices(), [])
        self.assertEqual(im.get_decommissioned_devices()[0]["Decommissioned By"], "admin")
        self.assertEqual(im.reactivate([("acme", "192.0.2.1")]), 1)
        self.assertEqual(len(im.get_all_devices()), 1)

    def test_returned_rows_are_copies(self):
        self._add("192.0.2.1")
        im.get_all_devices()[0]["Hostname"] = "poisoned"
        self.assertEqual(im.get_all_devices()[0]["Hostname"], "")

    def test_location_referenced_by_decommissioned_device_cannot_go(self):
        seed_inventory(decommissioned=[{"IP": "192.0.2.9", "Group": "acme", "Location": self.loc,
                                        "Decommissioned": "x", "Decommissioned By": "a"}])
        with self.assertRaisesRegex(ValueError, "1 apparati"):
            lm.delete_location(self.loc)


if __name__ == "__main__":
    unittest.main()
