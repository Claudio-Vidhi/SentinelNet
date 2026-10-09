# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""(Group, Probe) pairs become locations; subnets move from probes to them."""
import csv
import json
import os
import tempfile
import unittest

from core import location_migration

HDR = "IP,Vendor,Group,Hostname,Probe\n"


class TestLocationMigration(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="locmig_")

    def _w(self, name, obj):
        with open(os.path.join(self.d, name), "w", encoding="utf-8", newline="") as f:
            f.write(obj if isinstance(obj, str) else json.dumps(obj))

    def _r(self, name):
        with open(os.path.join(self.d, name), encoding="utf-8") as f:
            return json.load(f)

    def _rows(self, name="network_hosts.csv"):
        with open(os.path.join(self.d, name), encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def test_pairs_become_locations_and_rows_get_them(self):
        self._w("groups.json", {"acme": {}, "beta": {}})
        self._w("probes.json", {"central": {"id": "central", "name": "Centrale", "mode": "central",
                                            "subnets": []},
                                "lab": {"id": "lab", "name": "Lab", "mode": "agent",
                                        "subnets": ["10.1.0.0/16"]}})
        self._w("network_hosts.csv", HDR + "192.0.2.1,cisco,acme,sw-01,central\n"
                                           "192.0.2.2,cisco,acme,sw-02,lab\n"
                                           "192.0.2.3,cisco,beta,sw-03,lab\n")
        self.assertTrue(location_migration.migrate(self.d))
        locs = self._r("locations.json")
        pairs = sorted((v["org"], v["probe"]) for v in locs.values())
        self.assertEqual(pairs, [("acme", "central"), ("acme", "lab"), ("beta", "lab")])
        self.assertEqual(sorted(locs), ["centrale", "lab", "lab-2"])
        lab = [v for v in locs.values() if v["probe"] == "lab"]
        self.assertTrue(all(v["subnets"] == ["10.1.0.0/16"] for v in lab))
        self.assertTrue(all(v["role"] == "branch" for v in lab))
        self.assertEqual(locs["centrale"]["role"], "hq")
        rows = self._rows()
        self.assertTrue(all(r["Location"] in locs for r in rows))
        self.assertEqual({(r["Group"], locs[r["Location"]]["org"]) for r in rows},
                         {("acme", "acme"), ("beta", "beta")})
        with open(os.path.join(self.d, "network_hosts.csv"), encoding="utf-8") as f:
            self.assertEqual(f.readline().strip(), "IP,Vendor,Group,Hostname,Probe,Location")
        self.assertNotIn("subnets", self._r("probes.json")["lab"])
        self.assertTrue(self._r("app_settings.json")["locations_review_pending"])
        self.assertTrue(os.path.exists(os.path.join(self.d, "network_hosts.csv.pre-locations")))

    def test_second_run_is_a_noop(self):
        self._w("groups.json", {"acme": {}})
        self._w("network_hosts.csv", HDR + "192.0.2.1,cisco,acme,sw-01,central\n")
        self.assertTrue(location_migration.migrate(self.d))
        self.assertEqual(location_migration.migrate(self.d), [])

    def test_fresh_install_writes_an_empty_registry_and_no_banner(self):
        self.assertEqual(location_migration.migrate(self.d), [])
        self.assertEqual(self._r("locations.json"), {})
        self.assertFalse(os.path.exists(os.path.join(self.d, "app_settings.json")))

    def test_empty_group_rows_migrate_with_generale(self):
        # Decision A: «Generale» is migrated like any organization.
        self._w("groups.json", {"Generale": {}})  # check-generale: ok
        self._w("network_hosts.csv", HDR + "192.0.2.1,cisco,,sw-01,central\n")
        location_migration.migrate(self.d)
        (row,) = self._rows()
        self.assertEqual(row["Group"], "Generale")  # check-generale: ok
        self.assertIn(row["Location"], self._r("locations.json"))

    def test_a_group_missing_from_the_registry_is_added(self):
        # A location's organization must exist, or the location is an orphan.
        self._w("groups.json", {})
        self._w("network_hosts.csv", HDR + "192.0.2.1,cisco,acme,sw-01,central\n")
        location_migration.migrate(self.d)
        self.assertIn("acme", self._r("groups.json"))

    def test_decommissioned_rows_get_a_location_too(self):
        self._w("groups.json", {"acme": {}})
        self._w("network_hosts.csv", HDR)
        self._w("decommissioned_hosts.csv",
                "IP,Vendor,Group,Hostname,Probe,Decommissioned,Decommissioned By\n"
                "192.0.2.9,cisco,acme,old,central,2026-10-09T12:00:00Z,op\n")
        location_migration.migrate(self.d)
        (row,) = self._rows("decommissioned_hosts.csv")
        self.assertIn(row["Location"], self._r("locations.json"))
        self.assertEqual(row["Decommissioned By"], "op")

    def test_discovered_node_classification_moves_off_the_fallback_tenant(self):
        import sqlite3
        self._w("groups.json", {"Generale": {}})  # check-generale: ok
        self._w("network_hosts.csv", HDR + "192.0.2.1,cisco,Generale,sw-01,central\n")  # check-generale: ok
        conn = sqlite3.connect(os.path.join(self.d, "device_meta.db"))
        conn.execute("CREATE TABLE assignments (tenant TEXT, node_id TEXT, name TEXT, "
                     "PRIMARY KEY (tenant, node_id))")
        conn.executemany("INSERT INTO assignments VALUES (?, ?, ?)", [
            ("Generale", "192.0.2.1", "managed"),  # check-generale: ok
            ("Generale", "discovered_ap-01", "ap"),  # check-generale: ok
            ("acme", "192.0.2.5", "other"),
        ])
        conn.commit()
        conn.close()
        location_migration.migrate(self.d)
        conn = sqlite3.connect(os.path.join(self.d, "device_meta.db"))
        rows = sorted(conn.execute("SELECT tenant, node_id FROM assignments"))
        conn.close()
        self.assertEqual(rows, [("", "discovered_ap-01"),
                                ("Generale", "192.0.2.1"),  # check-generale: ok
                                ("acme", "192.0.2.5")])

    def test_legacy_rows_without_probe_use_central(self):
        self._w("groups.json", {"acme": {}})
        self._w("network_hosts.csv", "IP,Vendor,Group\n192.0.2.1,cisco,acme\n")
        location_migration.migrate(self.d)
        (row,) = self._rows()
        self.assertEqual(self._r("locations.json")[row["Location"]]["probe"], "central")


class TestWiring(unittest.TestCase):
    def test_lifespan_runs_it_after_the_probe_migration(self):
        import inspect
        import app_server
        src = inspect.getsource(app_server.lifespan)
        self.assertLess(src.index("probe_migration.migrate"),
                        src.index("location_migration.migrate"))
        self.assertLess(src.index("location_migration.migrate"), src.index("db.start_writer"))


if __name__ == "__main__":
    unittest.main()
