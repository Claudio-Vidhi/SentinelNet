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


import json
from fastapi.testclient import TestClient
from security import user_manager

PASS = "PasswordSicura1!"
CSRF = {"X-Requested-With": "SentinelNet"}
CONFIG = "hostname switch-01\nno ip http server\n"


class TestSaving(unittest.TestCase):
    """The client asks to keep a run; it never supplies the result."""

    @classmethod
    def setUpClass(cls):
        db.migrate()
        try:
            user_manager.create_user("adm_audit_hist", PASS, role="admin", groups=None)
        except Exception:
            pass
        import app_server
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": "adm_audit_hist", "password": PASS})
        assert r.status_code == 200, r.text
        cls.client = c

    def test_a_scan_without_the_flag_stores_nothing(self):
        before = self._count()
        r = self.client.post("/api/netsec-audit/scan", headers=CSRF,
                             json={"config_text": CONFIG, "benchmark": "cis"})
        self.assertEqual(200, r.status_code)
        self.assertEqual(before, self._count())

    def test_a_scan_with_the_flag_stores_the_servers_own_result(self):
        r = self.client.post("/api/netsec-audit/scan", headers=CSRF,
                             json={"config_text": CONFIG, "benchmark": "cis",
                                   "save": True})
        self.assertEqual(200, r.status_code)
        row = self._latest()
        self.assertEqual(r.json()["score"], row["score"])
        self.assertEqual(r.json()["rules"], json.loads(row["result_json"])["rules"])

    def test_a_forged_score_in_the_request_is_ignored(self):
        # The score is computed server-side. A client that sends one must not
        # be able to store it — otherwise the history is worthless as evidence.
        r = self.client.post("/api/netsec-audit/scan", headers=CSRF,
                             json={"config_text": CONFIG, "benchmark": "cis",
                                   "save": True, "score": 100, "grade": "A"})
        self.assertEqual(200, r.status_code)
        self.assertEqual(r.json()["score"], self._latest()["score"])
        self.assertNotEqual(100, self._latest()["score"])

    def _count(self):
        conn = db.get_observability_connection()
        try:
            return conn.execute("SELECT COUNT(*) c FROM netsec_audit_runs").fetchone()["c"]
        finally:
            conn.close()

    def _latest(self):
        conn = db.get_observability_connection()
        try:
            return conn.execute("SELECT * FROM netsec_audit_runs "
                                "ORDER BY id DESC LIMIT 1").fetchone()
        finally:
            conn.close()

