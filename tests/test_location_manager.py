# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Locations: one organization each, subnets owned here, probes derive theirs."""
import os
import tempfile
import unittest
from unittest.mock import patch

from services import inventory_manager, location_manager, probe_manager


class _Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="loc_")
        for p in (
            patch.object(location_manager, "LOCATIONS_JSON", os.path.join(tmp, "locations.json")),
            patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv")),
            patch.object(inventory_manager, "GROUPS_JSON", os.path.join(tmp, "groups.json")),
            patch.object(probe_manager, "PROBES_JSON", os.path.join(tmp, "probes.json")),
        ):
            p.start()
            self.addCleanup(p.stop)
        inventory_manager.save_groups({"acme": {"description": ""}, "beta": {"description": ""}})


class TestRegistry(_Base):
    def test_create_slugs_and_validates(self):
        loc = location_manager.create_location("acme", "Milano", "hq", ["10.10.0.0/16"])
        self.assertEqual(loc["id"], "milano")
        self.assertEqual(loc["org"], "acme")
        self.assertEqual(loc["probe"], "central")
        self.assertEqual(loc["subnets"], ["10.10.0.0/16"])
        again = location_manager.create_location("beta", "Milano")
        self.assertEqual(again["id"], "milano-2")
        for bad in (dict(org="nope", name="X"), dict(org="acme", name=""),
                    dict(org="acme", name="X", role="castle"),
                    dict(org="acme", name="X", subnets=["10.0.0.0/33"]),
                    dict(org="acme", name="X", probe="ghost")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                location_manager.create_location(**bad)

    def test_list_filters_by_org_and_update_keeps_id(self):
        loc = location_manager.create_location("acme", "Milano")
        location_manager.create_location("beta", "Roma")
        self.assertEqual([x["id"] for x in location_manager.list_locations("acme")], ["milano"])
        upd = location_manager.update_location(loc["id"], name="Milano HQ", role="hq",
                                               subnets=["10.10.0.0/16"])
        self.assertEqual((upd["id"], upd["name"], upd["role"]), ("milano", "Milano HQ", "hq"))
        with self.assertRaises(ValueError):
            location_manager.update_location(loc["id"], role="castle")
        with self.assertRaises(ValueError):
            location_manager.update_location("ghost", name="X")

    def test_probe_subnets_are_the_union_of_its_locations(self):
        probe, _ = probe_manager.create_probe("Lab", "agent")
        location_manager.create_location("acme", "A", subnets=["10.1.0.0/16"], probe=probe["id"])
        location_manager.create_location("beta", "B", subnets=["10.2.0.0/16", "10.1.0.0/16"],
                                         probe=probe["id"])
        location_manager.create_location("acme", "C", subnets=["10.3.0.0/16"])
        self.assertEqual(location_manager.probe_subnets(probe["id"]),
                         ["10.1.0.0/16", "10.2.0.0/16"])
        self.assertEqual(probe_manager.get_probe(probe["id"])["subnets"],
                         ["10.1.0.0/16", "10.2.0.0/16"])
        self.assertEqual(probe_manager.get_probe("central")["subnets"], ["10.3.0.0/16"])

    def test_delete_refused_while_devices_reference_it(self):
        loc = location_manager.create_location("acme", "Milano")
        inventory_manager.add_or_update_device("192.0.2.10", "cisco", "custom", "u", "p", "",
                                               "acme", location=loc["id"])
        with self.assertRaisesRegex(ValueError, "1"):
            location_manager.delete_location(loc["id"])
        inventory_manager.delete_devices([("acme", "192.0.2.10")])
        location_manager.delete_location(loc["id"])
        self.assertIsNone(location_manager.get_location(loc["id"]))

    def test_decommissioned_devices_count(self):
        loc = location_manager.create_location("acme", "Milano")
        inventory_manager.add_or_update_device("192.0.2.10", "cisco", "custom", "u", "p", "",
                                               "acme", location=loc["id"])
        inventory_manager.decommission([("acme", "192.0.2.10")], "op")
        self.assertEqual(location_manager.devices_in(loc["id"]), 1)
        with self.assertRaises(ValueError):
            location_manager.delete_location(loc["id"])

    def test_apply_probe_to_devices(self):
        probe, _ = probe_manager.create_probe("Lab", "agent")
        loc = location_manager.create_location("acme", "Milano")
        inventory_manager.add_or_update_device("192.0.2.10", "cisco", "custom", "u", "p", "",
                                               "acme", location=loc["id"])
        location_manager.update_location(loc["id"], probe=probe["id"])
        self.assertEqual(location_manager.apply_probe_to_devices(loc["id"]), 1)
        self.assertEqual(inventory_manager.get_all_devices()[0]["Probe"], probe["id"])


if __name__ == "__main__":
    unittest.main()
