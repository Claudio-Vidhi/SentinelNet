# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Blueprint schema: location gateway, links between locations (spec 2026-10-11)."""
import os
import sqlite3
import tempfile
import unittest

from services import inventory_store

LOC = {"org": "acme", "name": "Milano", "role": "hq", "subnets": ["10.10.0.0/16"], "probe": "central"}
LINK = {"org": "acme", "a": "milano", "b": "roma", "kind": "vpn", "note": ""}


class _Base(unittest.TestCase):
    def setUp(self):
        path = os.path.join(tempfile.mkdtemp(prefix="bp_schema_"), "inventory.db")
        self.conn = inventory_store.connect(path)
        self.addCleanup(self.conn.close)
        inventory_store.write_orgs(self.conn, {"acme": {"description": ""}})
        inventory_store.write_locations(self.conn, {
            "milano": dict(LOC),
            "roma": dict(LOC, name="Roma", role="branch", subnets=["10.20.0.0/16"]),
        })


class TestGateway(_Base):
    def test_gateway_defaults_empty_and_round_trips(self):
        locs = inventory_store.read_locations(self.conn)
        self.assertEqual(locs["milano"]["gateway"], "")
        locs["milano"]["gateway"] = "10.10.0.1"
        inventory_store.write_locations(self.conn, locs)
        self.assertEqual(inventory_store.read_locations(self.conn)["milano"]["gateway"], "10.10.0.1")

    def test_database_from_before_gets_the_column(self):
        path = os.path.join(tempfile.mkdtemp(prefix="bp_old_"), "inventory.db")
        raw = sqlite3.connect(path)
        raw.executescript(
            "CREATE TABLE organizations (key TEXT PRIMARY KEY, name TEXT, description TEXT NOT NULL DEFAULT '');"
            "CREATE TABLE locations (id TEXT PRIMARY KEY, org TEXT NOT NULL REFERENCES organizations(key), "
            "name TEXT NOT NULL, role TEXT NOT NULL, subnets TEXT NOT NULL DEFAULT '[]', "
            "probe TEXT NOT NULL DEFAULT 'central');"
            "INSERT INTO organizations VALUES ('acme', NULL, '');"
            "INSERT INTO locations VALUES ('milano', 'acme', 'Milano', 'hq', '[]', 'central');")
        raw.commit()
        raw.close()
        conn = inventory_store.connect(path)
        self.addCleanup(conn.close)
        self.assertEqual(inventory_store.read_locations(conn)["milano"]["gateway"], "")


class TestLinks(_Base):
    def test_round_trip(self):
        inventory_store.write_links(self.conn, {"milano--roma--vpn": dict(LINK)})
        self.assertEqual(inventory_store.read_links(self.conn), {"milano--roma--vpn": LINK})

    def test_unordered_self_unknown_kind_or_location_refused(self):
        for bad in (dict(LINK, a="roma", b="milano"), dict(LINK, b="milano"),
                    dict(LINK, kind="carrier-pigeon"), dict(LINK, b="zara")):
            with self.subTest(bad=bad), self.assertRaises(sqlite3.IntegrityError):
                inventory_store.write_links(self.conn, {"x": bad})
        self.assertEqual(inventory_store.read_links(self.conn), {})

    def test_deleting_a_location_drops_its_links(self):
        inventory_store.write_links(self.conn, {"milano--roma--vpn": dict(LINK)})
        locs = inventory_store.read_locations(self.conn)
        del locs["roma"]
        inventory_store.write_locations(self.conn, locs)
        self.assertEqual(inventory_store.read_links(self.conn), {})

    def test_draft_and_observation_go_with_their_organization(self):
        with self.conn:
            self.conn.execute("INSERT INTO blueprint_drafts (org, base_rev, source, ops, updated_at) "
                              "VALUES ('acme', 0, 'manual', '[]', 'now')")
            self.conn.execute("INSERT INTO blueprint_observations (org, at, data) VALUES ('acme', 'now', '{}')")
            self.conn.execute("INSERT INTO blueprint_revisions (org, rev, at, source, snapshot) "
                              "VALUES ('acme', 1, 'now', 'migration', '{}')")
        inventory_store.write_locations(self.conn, {})
        inventory_store.write_orgs(self.conn, {})
        for table, left in (("blueprint_drafts", 0), ("blueprint_observations", 0),
                            ("blueprint_revisions", 1)):   # history outlives the organization
            with self.subTest(table=table):
                self.assertEqual(self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], left)


class TestAssistantInstructions(_Base):
    def test_round_trip(self):
        self.assertEqual(inventory_store.read_instructions(self.conn, "acme"), "")
        inventory_store.write_instructions(self.conn, "acme", "Sedi: nome della città.")
        self.assertEqual(inventory_store.read_instructions(self.conn, "acme"), "Sedi: nome della città.")
        self.assertEqual(inventory_store.read_instructions(self.conn, "nobody"), "")

    def test_survive_every_org_write(self):
        inventory_store.write_instructions(self.conn, "acme", "Sedi: nome della città.")
        orgs = inventory_store.read_orgs(self.conn)
        orgs["acme"]["name"] = "ACME S.p.A."          # what a rename writes
        orgs["beta"] = {"description": ""}             # what a create writes
        inventory_store.write_orgs(self.conn, orgs)
        self.assertEqual(inventory_store.read_instructions(self.conn, "acme"), "Sedi: nome della città.")
        self.assertNotIn("assistant_instructions", inventory_store.read_orgs(self.conn)["acme"])

    def test_database_from_before_gets_the_column(self):
        path = os.path.join(tempfile.mkdtemp(prefix="bp_old_org_"), "inventory.db")
        raw = sqlite3.connect(path)
        raw.executescript(
            "CREATE TABLE organizations (key TEXT PRIMARY KEY, name TEXT, description TEXT NOT NULL DEFAULT '');"
            "INSERT INTO organizations VALUES ('acme', NULL, '');")
        raw.commit()
        raw.close()
        conn = inventory_store.connect(path)
        self.addCleanup(conn.close)
        self.assertEqual(inventory_store.read_instructions(conn, "acme"), "")
        inventory_store.write_instructions(conn, "acme", "x")
        self.assertEqual(inventory_store.read_instructions(conn, "acme"), "x")


class TestInstructionsThroughTheManager(unittest.TestCase):
    def test_rename_through_update_group_keeps_them(self):
        from unittest.mock import patch
        from services import inventory_manager
        tmp = tempfile.mkdtemp(prefix="bp_instr_mgr_")
        p = patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv"))
        p.start()
        self.addCleanup(p.stop)
        inventory_manager.save_groups({"acme": {"description": ""}})
        with inventory_manager._db() as conn:
            inventory_store.write_instructions(conn, "acme", "Ruoli: hq solo Milano.")
        self.assertTrue(inventory_manager.update_group("acme", "ACME", "cliente"))
        with inventory_manager._db() as conn:
            self.assertEqual(inventory_store.read_instructions(conn, "acme"), "Ruoli: hq solo Milano.")
