# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Device load measures (cpu_pct, memory_pct, ...) reach ``events.metrics_json``
and never count as a configuration change.
"""

import json
import os
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_load_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import normalize  # noqa: E402

NOW = int(time.time())
DEVICE = "192.168.31.6"


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
        for table in ("events", "normalize_cursors", "api_observations",
                      "syslog_events"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def _snapshot(self, ts, metrics, results=None):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO api_observations (ts, tenant, device_ip, kind, summary_json) "
            "VALUES (?, 'sede-a', ?, 'snmp_system', ?)",
            (ts, DEVICE, json.dumps({"results": results or {"name": "SW1"},
                                     "metrics": metrics})))
        conn.commit()
        conn.close()

    def _rows(self, sql, params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params)]
        finally:
            conn.close()


class TestMeasuresReachTheEvents(_Base):

    def test_declared_metrics_land_in_the_event(self):
        self._snapshot(NOW - 60, {"cpu_pct": 91, "memory_pct": 40.5})
        normalize.normalize_once(NOW)
        ev = self._rows("SELECT * FROM events WHERE event_type = 'device.state'")[0]
        self.assertEqual(json.loads(ev["metrics_json"]),
                         {"cpu_pct": 91, "memory_pct": 40.5})

    def test_a_measure_never_counts_as_a_configuration_change(self):
        # Una misura cambia a ogni lettura: è il suo mestiere. Confrontarla
        # produrrebbe un "cambiamento" a ogni giro di polling su ogni apparato.
        self._snapshot(NOW - 300, {"cpu_pct": 10})
        self._snapshot(NOW - 60, {"cpu_pct": 97})
        normalize.normalize_once(NOW)
        self.assertEqual(
            self._rows("SELECT * FROM events WHERE event_type = 'device.change'"),
            [])

    def test_a_snapshot_without_metrics_is_fine(self):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO api_observations (ts, tenant, device_ip, kind, summary_json) "
            "VALUES (?, 'sede-a', ?, 'system_status', ?)",
            (NOW - 60, DEVICE, json.dumps({"results": {"name": "FGT"}})))
        conn.commit()
        conn.close()
        normalize.normalize_once(NOW)
        ev = self._rows("SELECT * FROM events WHERE event_type = 'device.state'")[0]
        self.assertEqual(json.loads(ev["metrics_json"]), {})



if __name__ == "__main__":
    unittest.main()
