# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Blueprint storage: revisions per organization, drafts, observations."""
import os
import tempfile
import unittest

from services import blueprint_store, inventory_store

LOC = {"org": "acme", "name": "Milano", "role": "hq", "subnets": ["10.10.0.0/16"], "probe": "central"}


class _Base(unittest.TestCase):
    def setUp(self):
        path = os.path.join(tempfile.mkdtemp(prefix="bp_store_"), "inventory.db")
        self.conn = inventory_store.connect(path)
        self.addCleanup(self.conn.close)
        inventory_store.write_orgs(self.conn, {"acme": {"description": ""}, "beta": {"description": ""}})
        inventory_store.write_locations(self.conn, {
            "milano": dict(LOC), "roma": dict(LOC, name="Roma", role="branch", subnets=["10.20.0.0/16"]),
            "zurigo": dict(LOC, org="beta", name="Zurigo")})

    def record(self, by="mario", source="locations", note=""):
        with self.conn:
            return blueprint_store.record_revisions(self.conn, by, source, note)


class TestRevisions(_Base):
    def test_first_record_then_only_on_change(self):
        self.assertEqual(self.record(), [("acme", 1), ("beta", 1)])
        self.assertEqual(self.record(), [])
        locs = inventory_store.read_locations(self.conn)
        locs["roma"]["subnets"] = ["10.21.0.0/16"]
        inventory_store.write_locations(self.conn, locs)
        self.assertEqual(self.record("anna", "blueprint", "nuova subnet"), [("acme", 2)])
        revs = blueprint_store.revisions(self.conn, "acme")
        self.assertEqual([(r["rev"], r["by"], r["source"], r["note"]) for r in revs],
                         [(2, "anna", "blueprint", "nuova subnet"), (1, "mario", "locations", "")])
        self.assertEqual(blueprint_store.latest_rev(self.conn, "acme"), 2)
        rev2 = blueprint_store.revision(self.conn, "acme", 2)
        self.assertEqual(rev2["snapshot"]["locations"]["roma"]["subnets"], ["10.21.0.0/16"])
        self.assertNotIn("zurigo", rev2["snapshot"]["locations"])
        self.assertIsNone(blueprint_store.revision(self.conn, "acme", 9))
        self.assertEqual(blueprint_store.latest_rev(self.conn, "nobody"), 0)

    def test_snapshot_holds_the_links(self):
        self.record()
        inventory_store.write_links(self.conn, {"milano--roma--vpn": {
            "org": "acme", "a": "milano", "b": "roma", "kind": "vpn", "note": ""}})
        self.assertEqual(self.record(), [("acme", 2)])
        snap = blueprint_store.revision(self.conn, "acme", 2)["snapshot"]
        self.assertEqual(list(snap["links"]), ["milano--roma--vpn"])


class TestDrafts(_Base):
    def test_put_get_delete(self):
        self.assertIsNone(blueprint_store.get_draft(self.conn, "acme"))
        ops = [{"op": "delete_location", "id": "roma", "source": "manual"}]
        with self.conn:
            blueprint_store.put_draft(self.conn, "acme", 3, "manual", ops, "mario")
        d = blueprint_store.get_draft(self.conn, "acme")
        self.assertEqual((d["base_rev"], d["source"], d["ops"], d["updated_by"]), (3, "manual", ops, "mario"))
        with self.conn:
            blueprint_store.put_draft(self.conn, "acme", 4, "manual", [], "anna")
        self.assertEqual(blueprint_store.get_draft(self.conn, "acme")["base_rev"], 4)
        with self.conn:
            blueprint_store.delete_draft(self.conn, "acme")
        self.assertIsNone(blueprint_store.get_draft(self.conn, "acme"))


class TestObservations(_Base):
    def test_replaced_each_time(self):
        self.assertIsNone(blueprint_store.get_observation(self.conn, "acme"))
        with self.conn:
            blueprint_store.put_observation(self.conn, "acme", {"10.10.0.1": {"routes": {"rows": [], "error": "x"}}})
            at = blueprint_store.put_observation(self.conn, "acme", {})
        obs = blueprint_store.get_observation(self.conn, "acme")
        self.assertEqual((obs["at"], obs["data"]), (at, {}))
