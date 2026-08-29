# -*- coding: utf-8 -*-
"""Metriche di saturazione per normalizzatore e correlatore (WP8,
docs/app-review-fix-plan.md): una sorgente che legge sempre il suo tetto
per ciclo lo dichiara, invece di accumulare ritardo in silenzio."""

import os
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_capm_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import correlator, metrics, normalize  # noqa: E402

NOW = int(time.time())


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
        metrics.reset()
        conn = db.get_observability_connection()
        for table in ("events", "normalize_cursors", "syslog_events",
                      "flow_aggregates", "api_observations"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()


class TestCorrelatorCapMetric(_Base):

    def setUp(self):
        super().setUp()
        self._orig_cap = correlator.MAX_EVENTS_PER_CYCLE
        correlator.MAX_EVENTS_PER_CYCLE = 2

    def tearDown(self):
        correlator.MAX_EVENTS_PER_CYCLE = self._orig_cap

    def _seed_events(self, n):
        conn = db.get_observability_connection()
        for i in range(n):
            conn.execute(
                """INSERT INTO events (ts, ingested_ts, tenant, source, source_id,
                                       event_type, entity_type, entity_id, severity,
                                       dedup_key)
                   VALUES (?, ?, 't1', 'syslog', ?, 'test.synthetic', 'device',
                           '192.0.2.1', 5, ?)""",
                (NOW - 60 + i, NOW, i, f"cap-test:{i}"))
        conn.commit()
        conn.close()

    def test_saturated_window_is_counted(self):
        self._seed_events(4)
        correlator.correlate_once(NOW)
        counters = metrics.snapshot()["counters"]
        self.assertEqual(counters.get("correlation_capped"), 1)

    def test_normal_window_is_not_counted(self):
        self._seed_events(1)
        correlator.correlate_once(NOW)
        counters = metrics.snapshot()["counters"]
        self.assertNotIn("correlation_capped", counters)


class TestNormalizeCapMetric(_Base):

    def setUp(self):
        super().setUp()
        self._orig_cap = normalize.MAX_ROWS_PER_SOURCE
        normalize.MAX_ROWS_PER_SOURCE = 2

    def tearDown(self):
        normalize.MAX_ROWS_PER_SOURCE = self._orig_cap

    def _seed_flows(self, n):
        conn = db.get_observability_connection()
        for i in range(n):
            conn.execute(
                """INSERT INTO flow_aggregates
                       (window_start, tenant, src_ip, dst_ip, protocol, dst_port,
                        total_bytes, total_packets, flow_count, exporter_ip, source)
                   VALUES (?, 't1', '192.0.2.1', '198.51.100.9', 'TCP', 443,
                           1000, 10, 1, '192.0.2.254', 'netflow')""",
                (NOW - 60 - i * 60,))
        conn.commit()
        conn.close()

    def test_source_at_cap_is_counted(self):
        self._seed_flows(5)
        counts = normalize.normalize_once(NOW)
        self.assertEqual(counts["flow"], 2)
        counters = metrics.snapshot()["counters"]
        self.assertEqual(counters.get("normalize_capped{source=flow}"), 1)

    def test_source_below_cap_is_not_counted(self):
        self._seed_flows(1)
        counts = normalize.normalize_once(NOW)
        self.assertEqual(counts["flow"], 1)
        counters = metrics.snapshot()["counters"]
        self.assertNotIn("normalize_capped{source=flow}", counters)


if __name__ == "__main__":
    unittest.main()
