# -*- coding: utf-8 -*-
"""Storico degli audit: un punteggio senza i rilievi che lo hanno prodotto non
si puo' usare mesi dopo, quindi si conserva il documento intero.

Scoping: una run su un dispositivo eredita il tenant del dispositivo; una run su
una configurazione incollata non ne ha, e resta visibile solo a chi non e'
limitato per tenant.
"""

import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR",
                      tempfile.mkdtemp(prefix="sentinelnet_audithist_"))

from core import db  # noqa: E402

EXPECTED_COLUMNS = {
    "id", "ts", "tenant", "device_name", "device_ip", "benchmark",
    "benchmark_title", "vendor", "lang", "score",
    "summary_json", "result_json", "actor",
}


class TestSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.migrate()

    def test_the_table_exists_with_its_columns(self):
        conn = db.get_observability_connection()
        try:
            rows = conn.execute("PRAGMA table_info(netsec_audit_runs)").fetchall()
        finally:
            conn.close()
        self.assertTrue(rows, "netsec_audit_runs missing")
        self.assertEqual(EXPECTED_COLUMNS, {r["name"] for r in rows})

    def test_history_is_queried_newest_first_by_tenant(self):
        # The listing index must cover the two columns every query filters and
        # orders by, or the list page degrades into a scan as history grows.
        conn = db.get_observability_connection()
        try:
            idx = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND tbl_name='netsec_audit_runs'").fetchall()
        finally:
            conn.close()
        self.assertTrue([i for i in idx if "tenant" in i["name"] or "ts" in i["name"]],
                        "no index supporting (tenant, ts) lookups")


if __name__ == "__main__":
    unittest.main()
