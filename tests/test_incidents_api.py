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
        conn.execute("DELETE FROM evidence")
        conn.execute("DELETE FROM incidents")
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

    def test_deleting_an_incident_takes_its_evidence_with_it(self):
        # Le evidenze non hanno stato proprio: seguono l'incidente, anche in
        # cancellazione (ON DELETE CASCADE). Senza, la retention lascerebbe
        # evidenze orfane che puntano a incidenti inesistenti.
        conn = db.get_observability_connection()
        conn.execute(
            """INSERT INTO evidence
                   (created_ts, ts, tenant, incident_id, entity_key, role,
                    rule_id, rule_version, dedup_key)
               VALUES (?, ?, 'sede-a', ?, 'ip:10.1.0.5', 'trigger',
                       'BLOCKED_TRAFFIC_001', '1.0.0', 'dk-cascade')""",
            (NOW - 300, NOW - 300, self.id_a))
        conn.commit()
        conn.execute("DELETE FROM incidents WHERE id = ?", (self.id_a,))
        conn.commit()
        left = conn.execute(
            "SELECT COUNT(*) AS n FROM evidence WHERE dedup_key = 'dk-cascade'"
        ).fetchone()["n"]
        conn.close()
        self.assertEqual(left, 0)

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



class TestIncidentOwnership(unittest.TestCase):
    # Ereditare da TestIncidentsApi rieseguirebbe anche i suoi test: qui
    # servono solo il suo setup (migrate + utenti + seed) e il suo client.
    setUpClass = TestIncidentsApi.setUpClass
    setUp = TestIncidentsApi.setUp
    _client = TestIncidentsApi._client

    """N3 — chi ha preso in carico, quando, e perche'.

    Lo stato diceva che qualcuno l'aveva fatto e non chi: il nome finiva solo
    nel registro di audit, cioe' in un altro file e in un'altra schermata. Con
    un motore di notifiche e' la differenza fra "ci sta lavorando Tizio" e una
    seconda sveglia alle tre di notte."""

    def _row(self, incident_id):
        conn = db.get_observability_connection()
        try:
            return dict(conn.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone())
        finally:
            conn.close()

    def test_taking_it_on_records_who_when_and_why(self):
        c = self._client("op_inc_a")
        r = c.post(f"/api/incidents/{self.id_a}/status", headers=CSRF,
                   json={"from_status": "new", "status": "ack",
                         "note": "atteso, finestra di manutenzione"})
        self.assertEqual(r.status_code, 200, r.text)
        row = self._row(self.id_a)
        self.assertEqual(row["acknowledged_by"], "op_inc_a")
        self.assertEqual(row["ack_note"], "atteso, finestra di manutenzione")
        self.assertGreater(row["acknowledged_ts"], 0)

    def test_resolving_records_who_closed_it(self):
        c = self._client("op_inc_a")
        r = c.post(f"/api/incidents/{self.id_a}/status", headers=CSRF,
                   json={"from_status": "new", "status": "resolved"})
        self.assertEqual(r.status_code, 200, r.text)
        row = self._row(self.id_a)
        self.assertEqual(row["resolved_by"], "op_inc_a")
        self.assertIsNone(row["acknowledged_by"])

    def test_resolving_keeps_the_note_written_when_it_was_taken_on(self):
        """Chiudere non cancella il perche': la nota della presa in carico e'
        spesso l'unica spiegazione che resta."""
        c = self._client("op_inc_a")
        c.post(f"/api/incidents/{self.id_a}/status", headers=CSRF,
               json={"from_status": "new", "status": "ack", "note": "atteso"})
        c.post(f"/api/incidents/{self.id_a}/status", headers=CSRF,
               json={"from_status": "ack", "status": "resolved"})
        row = self._row(self.id_a)
        self.assertEqual(row["ack_note"], "atteso")
        self.assertEqual(row["acknowledged_by"], "op_inc_a")
        self.assertEqual(row["resolved_by"], "op_inc_a")

    def test_a_note_on_resolve_overwrites_nothing_when_empty(self):
        c = self._client("op_inc_a")
        c.post(f"/api/incidents/{self.id_a}/status", headers=CSRF,
               json={"from_status": "new", "status": "ack", "note": "prima"})
        c.post(f"/api/incidents/{self.id_a}/status", headers=CSRF,
               json={"from_status": "ack", "status": "resolved", "note": "   "})
        self.assertEqual(self._row(self.id_a)["ack_note"], "prima")

    def test_a_refused_transition_records_nothing(self):
        c = self._client("op_inc_a")
        r = c.post(f"/api/incidents/{self.id_a}/status", headers=CSRF,
                   json={"from_status": "resolved", "status": "ack",
                         "note": "non deve restare"})
        self.assertEqual(r.status_code, 409)
        row = self._row(self.id_a)
        self.assertIsNone(row["acknowledged_by"])
        self.assertIsNone(row["ack_note"])

    def test_an_out_of_scope_incident_records_nothing(self):
        c = self._client("op_inc_a")
        r = c.post(f"/api/incidents/{self.id_b}/status", headers=CSRF,
                   json={"from_status": "new", "status": "ack", "note": "x"})
        self.assertEqual(r.status_code, 404)
        self.assertIsNone(self._row(self.id_b)["acknowledged_by"])

    def test_the_note_is_bounded(self):
        c = self._client("op_inc_a")
        c.post(f"/api/incidents/{self.id_a}/status", headers=CSRF,
               json={"from_status": "new", "status": "ack", "note": "x" * 900})
        self.assertEqual(len(self._row(self.id_a)["ack_note"]), 500)

    def test_the_detail_and_the_list_expose_the_owner(self):
        c = self._client("op_inc_a")
        c.post(f"/api/incidents/{self.id_a}/status", headers=CSRF,
               json={"from_status": "new", "status": "ack", "note": "atteso"})
        detail = c.get(f"/api/incidents/{self.id_a}").json()["incident"]
        self.assertEqual(detail["acknowledged_by"], "op_inc_a")
        self.assertEqual(detail["ack_note"], "atteso")
        listed = c.get("/api/incidents?status=ack&window=24h").json()["incidents"]
        self.assertEqual(listed[0]["acknowledged_by"], "op_inc_a")


if __name__ == "__main__":
    unittest.main()
