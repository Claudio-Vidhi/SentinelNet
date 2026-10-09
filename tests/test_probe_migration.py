# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""One-shot rename of the persisted pre-0.52 names to 'probe'."""
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

    def test_arp_entries_column_renamed_too(self):
        db = os.path.join(self.d, "mac_history.db")
        with sqlite3.connect(db) as c:
            c.execute("CREATE TABLE arp_entries (mac TEXT, site TEXT DEFAULT 'central')")  # check-site-name: ok
            c.execute("INSERT INTO arp_entries VALUES ('AA:BB:CC:DD:EE:FF', 'central')")
        probe_migration.migrate(self.d)
        with sqlite3.connect(db) as c:
            self.assertEqual(c.execute("SELECT probe FROM arp_entries").fetchone()[0], "central")

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

    def test_device_history_old_key_renamed_in_snapshot_and_changes(self):
        old = "Si" + "te"  # check-site-name: ok
        added = {"event": "added", "id": "1", "ts": 1.0, "tenant": "acme",
                 "device": {"IP": "192.0.2.1", "Group": "acme", old: "central"}}
        changed = {"event": "changed", "id": "2", "ts": 2.0, "tenant": "acme",
                   "device": {"IP": "192.0.2.1", "Group": "acme", old: "lab"},
                   "changes": {old: ["central", "lab"]}}
        path = os.path.join(self.d, "device_history.jsonl")
        self._write("device_history.jsonl",
                    "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in (added, changed)))
        self.assertTrue(probe_migration.migrate(self.d))
        with open(path, encoding="utf-8") as f:
            events = [json.loads(line) for line in f]
        self.assertEqual(events[0]["device"]["Probe"], "central")
        self.assertEqual(events[1]["device"]["Probe"], "lab")
        self.assertEqual(events[1]["changes"], {"Probe": ["central", "lab"]})
        self.assertNotIn(old, json.dumps(events))
        self.assertTrue(os.path.exists(path + ".pre-probe"))
        with open(path, encoding="utf-8") as f:
            before = f.read()
        self.assertEqual(probe_migration.migrate(self.d), [])
        with open(path, encoding="utf-8") as f:
            self.assertEqual(f.read(), before)

    def test_device_history_torn_line_is_kept_verbatim(self):
        old = "Si" + "te"  # check-site-name: ok
        good = json.dumps({"event": "added", "device": {"IP": "192.0.2.1", old: "central"}},
                          separators=(",", ":"))
        torn = '{"event":"changed","device":{"IP":"192.0.2.1","' + old + '":"cen'
        path = os.path.join(self.d, "device_history.jsonl")
        self._write("device_history.jsonl", good + "\n" + torn)
        probe_migration.migrate(self.d)
        with open(path, encoding="utf-8", newline="") as f:
            lines = f.read().split("\n")
        self.assertEqual(json.loads(lines[0])["device"]["Probe"], "central")
        self.assertEqual(lines[1], torn)

    def test_agent_startup_renames_its_own_csv_header(self):
        import sys
        from services import probe_agent
        self._write("network_hosts.csv", HEADER_OLD + "192.0.2.1,cisco,acme,sw-01,central\n")
        cfg = os.path.join(self.d, "agent.json")
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump({"central_url": "https://central.example", "probe_id": "lab",
                       "token": "t", "data_dir": self.d}, f)
        with patch.dict(os.environ, {}), patch.object(sys, "argv", ["probe_agent.py", "--config", cfg]):
            probe_agent.load_config()
        self.assertEqual(self._hosts_header()[-1], "Probe")

    def test_second_run_is_a_noop(self):
        self._write("sites.json", "{}")  # check-site-name: ok
        self._write("network_hosts.csv", HEADER_OLD)
        probe_migration.migrate(self.d)
        self.assertEqual(probe_migration.migrate(self.d), [])


class TestWiring(unittest.TestCase):
    def test_lifespan_runs_the_migration_first(self):
        import inspect
        import app_server
        src = inspect.getsource(app_server.lifespan)
        self.assertLess(src.index("probe_migration.migrate"), src.index("db.start_writer"))


if __name__ == "__main__":
    unittest.main()
