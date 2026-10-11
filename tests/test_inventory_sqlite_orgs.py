# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import os
import tempfile
import unittest
from unittest.mock import patch

from services import inventory_manager as im, location_manager as lm


class TestOrgsLocationsOnSqlite(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        p = patch.object(im, "HOSTS_CSV", os.path.join(self.dir, "network_hosts.csv"))
        p.start()
        self.addCleanup(p.stop)

    def test_db_lives_next_to_the_hosts_path(self):
        self.assertEqual(im.inventory_db_path(), os.path.join(self.dir, "inventory.db"))

    def test_groups_live_in_the_database(self):
        im.add_group("acme")
        self.assertIn("acme", im.get_all_groups())
        self.assertFalse(os.path.exists(os.path.join(self.dir, "groups.json")))

    def test_rename_keeps_key(self):
        im.add_group("acme")
        im.update_group("acme", "Acme S.p.A.")
        self.assertEqual(im.resolve_group("Acme S.p.A."), "acme")

    def test_location_round_trip(self):
        im.add_group("acme")
        loc = lm.create_location("acme", "Roma", subnets=["10.20.0.0/16"])
        self.assertEqual(lm.get_location(loc["id"])["subnets"], ["10.20.0.0/16"])
        self.assertFalse(os.path.exists(os.path.join(self.dir, "locations.json")))

    def test_org_with_locations_is_refused(self):
        im.add_group("acme")
        lm.create_location("acme", "Roma")
        with self.assertRaises(ValueError):
            im.delete_group("acme")
        self.assertIn("acme", im.get_all_groups())
