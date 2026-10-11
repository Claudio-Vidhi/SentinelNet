# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Every write to locations records a revision (spec 2026-10-11 network-blueprint)."""
import os
import tempfile
import unittest
from unittest.mock import patch

from services import blueprint_store, inventory_manager, inventory_store, location_manager, probe_manager


class TestRevisionedWrites(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="loc_rev_")
        for p in (patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv")),
                  patch.object(probe_manager, "PROBES_JSON", os.path.join(tmp, "probes.json"))):
            p.start()
            self.addCleanup(p.stop)
        inventory_manager.save_groups({"acme": {"description": ""}, "beta": {"description": ""}})

    def revs(self, org="acme"):
        with inventory_manager._db() as conn:
            return [(r["rev"], r["by"], r["source"]) for r in blueprint_store.revisions(conn, org)]

    def test_create_update_delete_each_make_one_revision(self):
        location_manager.create_location("acme", "Milano", "hq", by="mario")
        location_manager.create_location("acme", "Roma", by="mario")
        location_manager.update_location("roma", subnets=["10.20.0.0/16"], by="anna")
        location_manager.update_location("roma", subnets=["10.20.0.0/16"], by="anna")   # no change
        location_manager.delete_location("roma", by="anna")
        self.assertEqual(self.revs(), [(4, "anna", "locations"), (3, "anna", "locations"),
                                       (2, "mario", "locations"), (1, "mario", "locations")])

    def test_other_organization_untouched(self):
        location_manager.create_location("acme", "Milano", "hq", by="mario")
        location_manager.create_location("beta", "Zurigo", "hq", by="mario")
        before = self.revs("beta")
        location_manager.update_location("milano", name="Milano HQ", by="mario")
        self.assertEqual(self.revs("beta"), before)

    def test_delete_takes_the_links_and_the_revision_shows_it(self):
        location_manager.create_location("acme", "Milano", "hq")
        location_manager.create_location("acme", "Roma")
        with inventory_manager._db() as conn, conn:
            inventory_store.put_links(conn, {"milano--roma--vpn": {
                "org": "acme", "a": "milano", "b": "roma", "kind": "vpn", "note": ""}})
            blueprint_store.record_revisions(conn, "", "blueprint")
        location_manager.delete_location("roma")
        with inventory_manager._db() as conn:
            snap = blueprint_store.revision(conn, "acme", blueprint_store.latest_rev(conn, "acme"))["snapshot"]
        self.assertEqual((list(snap["locations"]), snap["links"]), (["milano"], {}))

    def test_gateway_survives_an_edit_from_the_organizations_tab(self):
        location_manager.create_location("acme", "Milano", "hq")
        with inventory_manager._db() as conn:
            locs = inventory_store.read_locations(conn)
        locs["milano"]["gateway"] = "10.10.0.1"
        location_manager._save(locs)
        location_manager.update_location("milano", subnets=["10.10.0.0/16"])
        self.assertEqual(location_manager.get_location("milano")["gateway"], "10.10.0.1")
