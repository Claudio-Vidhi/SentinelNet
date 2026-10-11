# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import csv
import json
import os
import tempfile
import unittest

from core import inventory_migration as mig
from services import inventory_store as st

HDR = st.HOST_FIELDS


def _csv(path, rows, extra=()):
    fields = HDR + list(extra)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({**{h: "" for h in fields}, **r})


def _json(path, value):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(value, f)


class TestInventoryMigration(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        _json(os.path.join(self.d, "groups.json"), {"acme": {"description": "", "name": "Acme"}})
        _json(os.path.join(self.d, "locations.json"),
              {"roma": {"org": "acme", "name": "Roma", "role": "branch",
                        "subnets": ["10.20.0.0/16"], "probe": "central"}})
        _csv(os.path.join(self.d, "network_hosts.csv"),
             [{"IP": "192.0.2.1", "Group": "acme", "Location": "roma", "Vendor": "cisco"},
              {"IP": "192.0.2.2", "Group": "acme", "Location": "roma", "Vendor": "hp"}])
        _csv(os.path.join(self.d, "decommissioned_hosts.csv"),
             [{"IP": "192.0.2.9", "Group": "acme", "Location": "roma",
               "Decommissioned": "2026-10-10T00:00:00Z", "Decommissioned By": "admin"}],
             extra=st.DECOM_FIELDS)

    def _db(self):
        return st.connect(os.path.join(self.d, "inventory.db"))

    def test_migrates_everything_and_renames_sources(self):
        self.assertTrue(mig.migrate(self.d))
        with self._db() as c:
            self.assertEqual(len(st.read_hosts(c, "hosts")), 2)
            self.assertEqual(st.read_hosts(c, "decommissioned_hosts")[0]["Decommissioned By"], "admin")
            self.assertEqual(st.read_orgs(c)["acme"]["name"], "Acme")
            self.assertEqual(st.read_locations(c)["roma"]["subnets"], ["10.20.0.0/16"])
        for n in ("groups.json", "locations.json", "network_hosts.csv", "decommissioned_hosts.csv"):
            self.assertFalse(os.path.exists(os.path.join(self.d, n)), n)
            self.assertTrue(os.path.exists(os.path.join(self.d, n + ".pre-sqlite")), n)

    def test_second_run_is_a_noop(self):
        mig.migrate(self.d)
        self.assertEqual(mig.migrate(self.d), [])

    def test_orphan_location_stops_and_leaves_files(self):
        _csv(os.path.join(self.d, "network_hosts.csv"),
             [{"IP": "192.0.2.1", "Group": "acme", "Location": "nowhere"}])
        with self.assertRaisesRegex(mig.MigrationError, "192.0.2.1"):
            mig.migrate(self.d)
        self.assertFalse(os.path.exists(os.path.join(self.d, "inventory.db")))
        self.assertTrue(os.path.exists(os.path.join(self.d, "network_hosts.csv")))

    def test_duplicate_key_keeps_last_and_reports(self):
        _csv(os.path.join(self.d, "network_hosts.csv"),
             [{"IP": "192.0.2.1", "Group": "acme", "Location": "roma", "Hostname": "a"},
              {"IP": "192.0.2.1", "Group": "acme", "Location": "roma", "Hostname": "b"}])
        steps = mig.migrate(self.d)
        self.assertTrue(any("duplicate" in s for s in steps))
        with self._db() as c:
            self.assertEqual([r["Hostname"] for r in st.read_hosts(c, "hosts")], ["b"])

    def test_crash_after_db_rename_finishes_renames(self):
        mig.migrate(self.d)
        for n in ("network_hosts.csv", "groups.json"):   # as if the renames never ran
            os.replace(os.path.join(self.d, n + ".pre-sqlite"), os.path.join(self.d, n))
        self.assertEqual(mig.migrate(self.d), [])
        self.assertFalse(os.path.exists(os.path.join(self.d, "network_hosts.csv")))
        with self._db() as c:
            self.assertEqual(len(st.read_hosts(c, "hosts")), 2)

    def test_agent_dir_hosts_only(self):
        for n in ("groups.json", "locations.json", "decommissioned_hosts.csv"):
            os.remove(os.path.join(self.d, n))
        _csv(os.path.join(self.d, "network_hosts.csv"), [{"IP": "192.0.2.1", "Group": "acme"}])
        mig.migrate(self.d)
        with self._db() as c:
            self.assertEqual(st.read_hosts(c, "hosts")[0]["Location"], "")

    def test_agent_dir_blanks_unknown_location(self):
        # Controller ruling: an agent has no locations.json, so a Location it
        # carries names nothing here; blank it instead of refusing.
        for n in ("groups.json", "locations.json", "decommissioned_hosts.csv"):
            os.remove(os.path.join(self.d, n))
        _csv(os.path.join(self.d, "network_hosts.csv"),
             [{"IP": "192.0.2.1", "Group": "acme", "Location": "roma"}])
        steps = mig.migrate(self.d)
        self.assertTrue(any("sede sconosciuta" in s for s in steps), steps)
        with self._db() as c:
            self.assertEqual(st.read_hosts(c, "hosts")[0]["Location"], "")

    def test_fresh_install_does_nothing(self):
        d = tempfile.mkdtemp()
        self.assertEqual(mig.migrate(d), [])
        self.assertFalse(os.path.exists(os.path.join(d, "inventory.db")))


if __name__ == "__main__":
    unittest.main()
