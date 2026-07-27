# -*- coding: utf-8 -*-
"""Test degli endpoint /api/incidents: scoping multi-tenant (404 identico
dentro e fuori scope), transizioni di stato e gating della narrativa AI."""

import json
import os
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_incapi_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
from core import db  # noqa: E402
from security import user_manager  # noqa: E402

PASS = "PasswordSicura1!"
CSRF = {"X-Requested-With": "SentinelNet"}
NOW = int(time.time())


def _seed_incident(conn, tenant, entity="ip:10.1.0.5", status="new"):
    cur = conn.execute(
        """INSERT INTO incidents
               (tenant, entity_key, opened_ts, last_event_ts, title, severity,
                event_count, status, cause_kind, confidence, reasoning_json)
           VALUES (?, ?, ?, ?, ?, 3, 1, ?, 'scan_bloccato', 78, ?)""",
        (tenant, entity, NOW - 600, NOW - 300, f"Test {tenant}", status,
         json.dumps({"cause": "scan_bloccato", "base_confidence": 70,
                     "confidence_step": 8, "rules_fired": ["scan_bloccato"],
                     "sources_used": ["flow_aggregates"], "evidence_refs": []})))
    return cur.lastrowid


class TestIncidentsApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()
        for user, role, groups in (("adm_inc", "admin", None),
                                   ("op_inc_a", "operator", ["sede-a"])):
            try:
                user_manager.create_user(user, PASS, role=role, groups=groups)
            except Exception:
                pass

    def setUp(self):
        conn = db.get_observability_connection()
        conn.execute("DELETE FROM incident_events")
        conn.execute("DELETE FROM incidents")
        conn.execute("DELETE FROM correlated_events")
        self.id_a = _seed_incident(conn, "sede-a")
        self.id_b = _seed_incident(conn, "sede-b", entity="ip:10.2.0.5")
        conn.commit()
        conn.close()

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200, r.text
        return c

    def test_list_is_tenant_scoped(self):
        c = self._client("op_inc_a")
        r = c.get("/api/incidents?status=new&window=24h")
        self.assertEqual(r.status_code, 200)
        tenants = {i["tenant"] for i in r.json()["incidents"]}
        self.assertEqual(tenants, {"sede-a"})

    def test_admin_sees_every_tenant(self):
        c = self._client("adm_inc")
        r = c.get("/api/incidents?status=new&window=24h")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()["incidents"]), 2)

    def test_out_of_scope_detail_is_404_like_a_missing_one(self):
        c = self._client("op_inc_a")
        out_of_scope = c.get(f"/api/incidents/{self.id_b}")
        missing = c.get("/api/incidents/999999")
        self.assertEqual(out_of_scope.status_code, 404)
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(out_of_scope.json()["detail"], missing.json()["detail"])

    def test_detail_exposes_the_reasoning_path(self):
        c = self._client("op_inc_a")
        r = c.get(f"/api/incidents/{self.id_a}")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["incident"]["cause_kind"], "scan_bloccato")
        self.assertEqual(body["incident"]["reasoning"]["rules_fired"],
                         ["scan_bloccato"])
        self.assertIn("timeline", body)

    def test_status_transition_and_optimistic_concurrency(self):
        c = self._client("op_inc_a")
        ok = c.post(f"/api/incidents/{self.id_a}/status", headers=CSRF,
                    json={"from_status": "new", "status": "ack"})
        self.assertEqual(ok.status_code, 200)
        stale = c.post(f"/api/incidents/{self.id_a}/status", headers=CSRF,
                       json={"from_status": "new", "status": "ack"})
        self.assertEqual(stale.status_code, 409)

    def test_illegal_transition_is_rejected(self):
        c = self._client("op_inc_a")
        r = c.post(f"/api/incidents/{self.id_a}/status", headers=CSRF,
                   json={"from_status": "resolved", "status": "new"})
        self.assertEqual(r.status_code, 409)

    def test_resolving_also_resolves_the_correlated_events(self):
        conn = db.get_observability_connection()
        cur = conn.execute(
            """INSERT INTO correlated_events
                   (created_ts, tenant, kind, src_ip, dst_ip, severity, status,
                    dedup_key, evidence_json)
               VALUES (?, 'sede-a', 'traffico_bloccato_alto', '10.1.0.5',
                       '8.8.8.8', 3, 'new', 'dk-res', '{}')""", (NOW - 300,))
        conn.execute("INSERT INTO incident_events VALUES (?, ?)",
                     (self.id_a, cur.lastrowid))
        conn.commit()
        conn.close()

        c = self._client("op_inc_a")
        r = c.post(f"/api/incidents/{self.id_a}/status", headers=CSRF,
                   json={"from_status": "new", "status": "resolved"})
        self.assertEqual(r.status_code, 200)

        conn = db.get_observability_connection()
        try:
            status = conn.execute(
                "SELECT status FROM correlated_events WHERE dedup_key = 'dk-res'"
            ).fetchone()["status"]
        finally:
            conn.close()
        self.assertEqual(status, "resolved")

    def test_out_of_scope_transition_is_404(self):
        c = self._client("op_inc_a")
        r = c.post(f"/api/incidents/{self.id_b}/status", headers=CSRF,
                   json={"from_status": "new", "status": "ack"})
        self.assertEqual(r.status_code, 404)

    def test_explain_without_ai_profile_writes_nothing(self):
        c = self._client("op_inc_a")
        r = c.post(f"/api/incidents/{self.id_a}/explain", headers=CSRF)
        self.assertEqual(r.status_code, 400)

        conn = db.get_observability_connection()
        try:
            row = conn.execute(
                "SELECT ai_narrative, ai_assisted FROM incidents WHERE id = ?",
                (self.id_a,)).fetchone()
        finally:
            conn.close()
        self.assertIsNone(row["ai_narrative"])
        self.assertEqual(row["ai_assisted"], 0)

    def test_explain_out_of_scope_is_404(self):
        c = self._client("op_inc_a")
        r = c.post(f"/api/incidents/{self.id_b}/explain", headers=CSRF)
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
