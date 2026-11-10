# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Salute della piattaforma: gli exporter fuori inventario diventano un evento.

I record di un exporter non censito vengono scartati di proposito (attribuirli
a una sede sbagliata è peggio che perderli), ma la perdita non deve restare in
una tabella di diagnostica che nessuno guarda. Il fatto passa dal bus eventi
come tutti gli altri.
"""

import json
import os
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_platform_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import normalize  # noqa: E402

NOW = int(time.time())
ROGUE = "192.168.31.224"


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()

    def setUp(self):
        conn = db.get_observability_connection()
        for table in ("events", "normalize_cursors", "quarantined_exporters",
                      "syslog_events", "api_observations"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def _quarantine(self, ip=ROGUE, first_seen=None, last_seen=None, packets=227):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO quarantined_exporters "
            "(exporter_ip, first_seen, last_seen, packet_count) VALUES (?,?,?,?)",
            (ip, first_seen if first_seen is not None else NOW - 7200,
             last_seen if last_seen is not None else NOW - 60, packets))
        conn.commit()
        conn.close()

    def _rows(self, sql, params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params)]
        finally:
            conn.close()

class TestQuarantineAdapter(_Base):

    def test_a_quarantined_exporter_becomes_an_event(self):
        self._quarantine()
        normalize.normalize_once(NOW)
        events = self._rows("SELECT * FROM events "
                            "WHERE event_type = 'platform.exporter_unknown'")
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["entity_type"], "exporter")
        self.assertEqual(ev["entity_id"], ROGUE)
        self.assertEqual(ev["source"], "platform")
        metrics = json.loads(ev["metrics_json"])
        self.assertEqual(metrics["packets"], 227)
        self.assertEqual(metrics["persisted_s"], 7140)

    def test_the_tenant_is_reserved_not_borrowed(self):
        # Un exporter non attribuibile non può prendere in prestito la sede di
        # qualcun altro: è esattamente il motivo per cui viene scartato.
        self._quarantine()
        normalize.normalize_once(NOW)
        self.assertEqual(
            self._rows("SELECT DISTINCT tenant FROM events")[0]["tenant"],
            normalize.PLATFORM_TENANT)

    def test_an_exporter_that_stopped_produces_nothing(self):
        self._quarantine(last_seen=NOW - normalize.LOOKBACK_S - 600)
        normalize.normalize_once(NOW)
        self.assertEqual(
            self._rows("SELECT * FROM events "
                       "WHERE event_type = 'platform.exporter_unknown'"), [])

    def test_reprojection_within_a_bucket_updates_instead_of_duplicating(self):
        self._quarantine(packets=10)
        normalize.normalize_once(NOW)
        conn = db.get_observability_connection()
        conn.execute("UPDATE quarantined_exporters SET packet_count = 99")
        conn.commit()
        conn.close()
        normalize.normalize_once(NOW + 30)

        events = self._rows("SELECT * FROM events "
                            "WHERE event_type = 'platform.exporter_unknown'")
        self.assertEqual(len(events), 1)
        self.assertEqual(json.loads(events[0]["metrics_json"])["packets"], 99)

    def test_a_new_bucket_refreshes_the_knowledge_time(self):
        # A fact emitted once and then only updated in place would age out of
        # every "recent events" window.
        self._quarantine(last_seen=NOW - 900)
        normalize.normalize_once(NOW)
        self._quarantine_touch(NOW - 60)
        normalize.normalize_once(NOW)

        events = self._rows("SELECT ts FROM events "
                            "WHERE event_type = 'platform.exporter_unknown' "
                            "ORDER BY ts")
        self.assertEqual(len(events), 2)
        self.assertNotEqual(events[0]["ts"], events[1]["ts"])

    def _quarantine_touch(self, last_seen):
        conn = db.get_observability_connection()
        conn.execute("UPDATE quarantined_exporters SET last_seen = ?", (last_seen,))
        conn.commit()
        conn.close()


if __name__ == "__main__":
    unittest.main()
