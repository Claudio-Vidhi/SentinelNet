# -*- coding: utf-8 -*-
"""Test della migrazione v7: ``correlated_events`` → ``evidence``.

La migrazione è distruttiva per struttura (le due tabelle vecchie spariscono)
ma NON per contenuto: ogni riga deve ritrovarsi come evidenza, e ciò che non è
più risolvibile deve restare conservato invece di essere buttato.
"""

import json
import os
import sqlite3
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_mig7_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402

# Struttura pre-v7, riprodotta letteralmente com'era nello schema.
_V6_TABLES = """
CREATE TABLE correlated_events (
    id INTEGER PRIMARY KEY, created_ts INTEGER NOT NULL, tenant TEXT NOT NULL,
    kind TEXT, src_ip TEXT, dst_ip TEXT, switch_port TEXT, severity INTEGER,
    status TEXT DEFAULT 'new', dedup_key TEXT UNIQUE, evidence_json TEXT);
CREATE TABLE incident_events (
    incident_id INTEGER NOT NULL, correlated_event_id INTEGER NOT NULL,
    PRIMARY KEY (incident_id, correlated_event_id));
"""


class TestMigrationV7(unittest.TestCase):

    def setUp(self):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()                       # DB alla versione corrente
        conn = db.get_observability_connection()
        conn.executescript(_V6_TABLES)     # si ricreano le tabelle legacy
        conn.execute("UPDATE schema_version SET version = 6")
        conn.commit()
        conn.close()

    def _seed_legacy(self, with_event=True):
        conn = db.get_observability_connection()
        syslog_id = 4242
        if with_event:
            conn.execute(
                """INSERT INTO events (ts, ingested_ts, tenant, source, source_id,
                        event_type, entity_type, entity_id, dedup_key)
                   VALUES (1000, 1000, 'sede-a', 'syslog', ?, 'log.security',
                           'device', '10.1.0.254', 'syslog:4242')""",
                (syslog_id,))
        conn.execute(
            """INSERT INTO correlated_events
                   (id, created_ts, tenant, kind, src_ip, dst_ip, switch_port,
                    severity, status, dedup_key, evidence_json)
               VALUES (7, 1200, 'sede-a', 'traffico_bloccato_alto', '10.1.0.5',
                       '8.8.8.8', 'SW-A1:Gi1/0/7', 3, 'new', 'legacy-dk', ?)""",
            (json.dumps({"syslog_id": syslog_id, "syslog_ts": 1000,
                         "action": "blocked"}),))
        conn.execute("INSERT INTO incidents (tenant, entity_key, opened_ts, "
                     "last_event_ts, event_count) "
                     "VALUES ('sede-a', 'ip:10.1.0.5', 1000, 1200, 1)")
        conn.execute("INSERT INTO incident_events VALUES (1, 7)")
        conn.commit()
        conn.close()

    def _migrate(self):
        conn = db.get_observability_connection()
        try:
            db._migrate_v7_evidence(conn)
            conn.commit()
        finally:
            conn.close()

    def _evidence(self):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute("SELECT * FROM evidence")]
        finally:
            conn.close()

    def test_legacy_row_becomes_a_trigger_evidence(self):
        self._seed_legacy()
        self._migrate()
        rows = self._evidence()
        self.assertEqual(len(rows), 1)
        ev = rows[0]
        self.assertEqual(ev["role"], "trigger")
        self.assertEqual(ev["rule_id"], "LEGACY_CORRELATOR")
        self.assertEqual(ev["src_ip"], "10.1.0.5")
        self.assertEqual(ev["switch_port"], "SW-A1:Gi1/0/7")
        self.assertEqual(ev["entity_key"], "ip:10.1.0.5")
        self.assertEqual(ev["ts"], 1000)          # dal syslog_ts dell'evidenza
        self.assertEqual(ev["incident_id"], 1)    # appartenenza preservata
        self.assertIsNotNone(ev["event_id"])      # evento normalizzato risolto

    def test_unresolvable_row_is_kept_not_dropped(self):
        # Il syslog d'origine è già stato potato (retention 7g contro 90g):
        # non c'è un evento a cui puntare, ma il contenuto non va perso.
        self._seed_legacy(with_event=False)
        self._migrate()
        rows = self._evidence()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["event_id"])
        self.assertEqual(json.loads(rows[0]["attrs_json"])["action"], "blocked")

    def test_legacy_tables_are_gone_afterwards(self):
        self._seed_legacy()
        self._migrate()
        conn = db.get_observability_connection()
        try:
            names = {r["name"] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            conn.close()
        self.assertNotIn("correlated_events", names)
        self.assertNotIn("incident_events", names)

    def test_migration_is_idempotent(self):
        self._seed_legacy()
        self._migrate()
        self._migrate()                    # niente più da fare, nessun errore
        self.assertEqual(len(self._evidence()), 1)

    def test_full_migrate_runs_the_step_and_lands_on_v7(self):
        self._seed_legacy()
        db.migrate()
        conn = db.get_observability_connection()
        try:
            version = conn.execute(
                "SELECT MAX(version) AS v FROM schema_version").fetchone()["v"]
            names = {r["name"] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            conn.close()
        self.assertEqual(version, db.SCHEMA_VERSION)
        self.assertNotIn("correlated_events", names)
        self.assertEqual(len(self._evidence()), 1)

    def test_downgrade_guard_still_fires(self):
        conn = db.get_observability_connection()
        conn.execute("UPDATE schema_version SET version = ?",
                     (db.SCHEMA_VERSION + 1,))
        conn.commit()
        conn.close()
        with self.assertRaises(db.SchemaTooNewError):
            db.migrate()


if __name__ == "__main__":
    unittest.main()
