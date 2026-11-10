# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Metriche di saturazione per il normalizzatore (WP8,
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
from observability import metrics, normalize  # noqa: E402

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
                      "api_observations"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()


class TestNormalizeCapMetric(_Base):

    def setUp(self):
        super().setUp()
        self._orig_cap = normalize.MAX_ROWS_PER_SOURCE
        normalize.MAX_ROWS_PER_SOURCE = 2

    def tearDown(self):
        normalize.MAX_ROWS_PER_SOURCE = self._orig_cap

    def _seed_syslog(self, n):
        conn = db.get_observability_connection()
        for i in range(n):
            conn.execute(
                "INSERT INTO syslog_events (ts, tenant, device_ip, severity, "
                "action, message) VALUES (?, 't1', '192.0.2.254', 6, NULL, 'x')",
                (NOW - 60 - i * 60,))
        conn.commit()
        conn.close()

    def test_source_at_cap_is_counted(self):
        self._seed_syslog(5)
        counts = normalize.normalize_once(NOW)
        self.assertEqual(counts["syslog"], 2)
        counters = metrics.snapshot()["counters"]
        self.assertEqual(counters.get("normalize_capped{source=syslog}"), 1)

    def test_source_below_cap_is_not_counted(self):
        self._seed_syslog(1)
        counts = normalize.normalize_once(NOW)
        self.assertEqual(counts["syslog"], 1)
        counters = metrics.snapshot()["counters"]
        self.assertNotIn("normalize_capped{source=syslog}", counters)


if __name__ == "__main__":
    unittest.main()
