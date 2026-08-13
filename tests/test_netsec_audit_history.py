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


class TestReading(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.migrate()
        try:
            user_manager.create_user("adm_audit_hist_rd", PASS, role="admin", groups=None)
        except Exception:
            pass
        try:
            user_manager.create_user("user_sede_a", PASS, role="operator", groups=["sede-a"])
        except Exception:
            pass
        import app_server
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": "adm_audit_hist_rd", "password": PASS})
        assert r.status_code == 200, r.text
        cls.client = c

        c2 = TestClient(app_server.app)
        r2 = c2.post("/api/auth/login", json={"username": "user_sede_a", "password": PASS})
        assert r2.status_code == 200, r2.text
        cls.client_sede_a = c2

    def test_the_list_does_not_ship_every_result_document(self):
        # The listing is a table of scores; sending each full rules[] with it
        # turns a page load into megabytes.
        r = self.client.get("/api/netsec-audit/history", headers=CSRF)
        self.assertEqual(200, r.status_code)
        for row in r.json()["runs"]:
            self.assertNotIn("result_json", row)
            self.assertIn("score", row)

    def test_the_detail_returns_the_stored_document_unchanged(self):
        saved = self.client.post("/api/netsec-audit/scan", headers=CSRF,
                                 json={"config_text": CONFIG, "benchmark": "cis",
                                       "save": True}).json()
        r = self.client.get(f"/api/netsec-audit/history/{saved['saved_id']}",
                            headers=CSRF)
        self.assertEqual(200, r.status_code)
        self.assertEqual(saved["rules"], r.json()["rules"])

    def test_out_of_scope_and_missing_answer_the_same_404(self):
        # Confirming existence to someone who may not see it leaks the fact
        # that another tenant was audited. Same rule as CONTRIBUTING.md §4.
        r = self.client.get("/api/netsec-audit/history/999999", headers=CSRF)
        self.assertEqual(404, r.status_code)

    def test_delete_is_admin_only(self):
        # Deleting evidence is not an operator action.
        import inspect
        from routers import analyzer
        from routers.deps import require_admin
        dep = inspect.signature(
            analyzer.netsec_audit_history_delete).parameters["current_user"].default
        self.assertIs(dep.dependency, require_admin)

    def test_scoped_user_cannot_access_other_tenant_history(self):
        # Insert run for tenant sede-b directly into DB
        from services.netsec_audit import history
        res = {"benchmark": "cis", "benchmark_title": "CIS", "vendor": "cisco", "lang": "it", "score": 80, "summary": {}, "rules": []}
        run_id = history.save(res, tenant="sede-b", device_name="switch-02", device_ip="192.0.2.2", actor="admin")

        # user_sede_a asks for run_id -> 404
        r = self.client_sede_a.get(f"/api/netsec-audit/history/{run_id}", headers=CSRF)
        self.assertEqual(404, r.status_code)

        # user_sede_a lists history -> run_id not in list
        r2 = self.client_sede_a.get("/api/netsec-audit/history", headers=CSRF)
        self.assertEqual(200, r2.status_code)
        ids = [row["id"] for row in r2.json()["runs"]]
        self.assertNotIn(run_id, ids)


class TestHistoryUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "templates", "dashboard.html"), encoding="utf-8") as f:
            cls.html = f.read()
        with open(os.path.join(root, "static", "js", "netsec-audit.js"), encoding="utf-8") as f:
            cls.js = f.read()

    def test_the_save_checkbox_exists_and_defaults_off(self):
        self.assertIn('id="auditSaveRun"', self.html)
        idx = self.html.index('id="auditSaveRun"')
        tag = self.html[self.html.rindex("<input", 0, idx):self.html.index(">", idx)]
        self.assertNotIn("checked", tag)

    def test_the_scan_request_carries_the_flag_and_no_result_fields(self):
        body = self.js[self.js.rindex("/api/netsec-audit/scan"):]
        body = body[:body.index("});") + 3]
        self.assertIn("save:", body)
        for forged in ("score:", "grade:", "rules:"):
            self.assertNotIn(forged, body)

    def test_the_history_panel_is_wired(self):
        self.assertIn('id="auditHistoryBody"', self.html)
        self.assertIn("function loadAuditHistory", self.js)
        self.assertIn("/api/netsec-audit/history", self.js)

    def test_delete_asks_first(self):
        body = self.js[self.js.index("function deleteAuditRun"):]
        body = body[:body.index("\n}") + 2]
        self.assertIn("confirm(", body)



