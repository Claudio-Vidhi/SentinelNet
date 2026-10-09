# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""One-shot rename of persisted 'site' names to 'probe'."""
import csv
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from core import probe_migration
from security import user_manager

PW = "PasswordSicura1!"
HEADER_OLD = "IP,Vendor,Group,Hostname,Site\n"  # check-site-name: ok


class TestProbeMigration(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="probe_mig_")
        p = patch.object(user_manager, "USERS_JSON", os.path.join(self.d, "users.json"))
        p.start()
        self.addCleanup(p.stop)

    def _write(self, name, text):
        with open(os.path.join(self.d, name), "w", encoding="utf-8", newline="") as f:
            f.write(text)

    def _hosts_header(self):
        with open(os.path.join(self.d, "network_hosts.csv"), encoding="utf-8") as f:
            return next(csv.reader(f))

    def test_registry_file_renamed_and_backed_up(self):
        self._write("sites.json", json.dumps({"central": {"id": "central"}}))  # check-site-name: ok
        self.assertTrue(probe_migration.migrate(self.d))
        self.assertTrue(os.path.exists(os.path.join(self.d, "probes.json")))
        self.assertFalse(os.path.exists(os.path.join(self.d, "sites.json")))  # check-site-name: ok
        self.assertTrue(os.path.exists(os.path.join(self.d, "sites.json.pre-probe")))  # check-site-name: ok

    def test_csv_header_renamed_without_registry_file(self):
        self._write("network_hosts.csv", HEADER_OLD + "192.0.2.1,cisco,acme,sw-01,central\n")
        probe_migration.migrate(self.d)
        self.assertEqual(self._hosts_header()[-1], "Probe")
        with open(os.path.join(self.d, "network_hosts.csv"), encoding="utf-8") as f:
            self.assertEqual(list(csv.DictReader(f))[0]["Probe"], "central")

    def test_mac_history_column_renamed(self):
        db = os.path.join(self.d, "mac_history.db")
        with sqlite3.connect(db) as c:
            c.execute("CREATE TABLE mac_sightings (mac TEXT, site TEXT DEFAULT 'central')")  # check-site-name: ok
            c.execute("INSERT INTO mac_sightings VALUES ('AA:BB:CC:DD:EE:FF', 'central')")
        probe_migration.migrate(self.d)
        with sqlite3.connect(db) as c:
            cols = [r[1] for r in c.execute("PRAGMA table_info(mac_sightings)")]
            self.assertIn("probe", cols)
            self.assertEqual(c.execute("SELECT probe FROM mac_sightings").fetchone()[0], "central")

    def test_jobs_table_dropped(self):
        db = os.path.join(self.d, "agent_jobs.db")
        with sqlite3.connect(db) as c:
            c.execute("CREATE TABLE command_jobs (id TEXT, site_id TEXT)")  # check-site-name: ok
        probe_migration.migrate(self.d)
        with sqlite3.connect(db) as c:
            self.assertIsNone(c.execute(
                "SELECT name FROM sqlite_master WHERE name='command_jobs'").fetchone())

    def test_user_tab_restriction_follows_the_rename(self):
        user_manager.create_user("op", PW, role="operator")
        user_manager.set_allowed_tabs("op", ["tab-devices", "tab-sites"])  # check-site-name: ok
        probe_migration.migrate(self.d)
        self.assertEqual(user_manager.get_allowed_tabs("op"), ["tab-devices", "tab-probes"])

    def test_second_run_is_a_noop(self):
        self._write("sites.json", "{}")  # check-site-name: ok
        self._write("network_hosts.csv", HEADER_OLD)
        probe_migration.migrate(self.d)
        self.assertEqual(probe_migration.migrate(self.d), [])


if __name__ == "__main__":
    unittest.main()
