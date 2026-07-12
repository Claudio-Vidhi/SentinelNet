# -*- coding: utf-8 -*-
"""Test fase 5: transizioni di stato delle anomalie (ruoli, scope, CSRF,
concorrenza ottimistica, audit), contesto AI attach_top_flows (riassunto
server-side + redazione) e gate frontend (niente sessionStorage/Bearer nel
percorso Flussi Live)."""

import json
import os
import re
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_obsui_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
import ai_assistant  # noqa: E402
import db  # noqa: E402
import user_manager  # noqa: E402

PASS = "PasswordSicura1!"
CSRF = {"X-Requested-With": "SentinelNet"}


def _seed_event(tenant="sede-a", status="new"):
    conn = db.get_observability_connection()
    cur = conn.execute(
        "INSERT INTO correlated_events (created_ts, tenant, kind, src_ip, dst_ip, "
        "severity, status, dedup_key) VALUES (?, ?, 'traffico_bloccato_alto', "
        "'10.1.0.5', '203.0.113.7', 3, ?, ?)",
        (int(time.time()), tenant, status, f"k{time.time_ns()}"))
    conn.commit()
    conn.close()
    return cur.lastrowid


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        db.migrate()
        for user, role, groups in (("adm", "admin", None),
                                   ("op_a", "operator", ["sede-a"]),
                                   ("viewer_a", "viewer", ["sede-a"])):
            try:
                user_manager.create_user(user, PASS, role=role, groups=groups)
            except Exception:
                pass

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200
        return c


class TestAnomalyTransitions(_Base):
    def test_new_to_ack_to_resolved(self):
        eid = _seed_event()
        c = self._client("op_a")
        r = c.post(f"/api/observability/anomalies/{eid}/status", headers=CSRF,
                   json={"from_status": "new", "status": "ack"})
        self.assertEqual(r.status_code, 200)
        r = c.post(f"/api/observability/anomalies/{eid}/status", headers=CSRF,
                   json={"from_status": "ack", "status": "resolved"})
        self.assertEqual(r.status_code, 200)

    def test_invalid_transition_409(self):
        eid = _seed_event(status="resolved")
        c = self._client("op_a")
        r = c.post(f"/api/observability/anomalies/{eid}/status", headers=CSRF,
                   json={"from_status": "resolved", "status": "new"})
        self.assertEqual(r.status_code, 409)

    def test_stale_transition_409(self):
        eid = _seed_event(status="ack")  # nel frattempo qualcuno l'ha già presa
        c = self._client("op_a")
        r = c.post(f"/api/observability/anomalies/{eid}/status", headers=CSRF,
                   json={"from_status": "new", "status": "ack"})
        self.assertEqual(r.status_code, 409)
        self.assertIn("cambiato", r.json()["detail"])

    def test_out_of_scope_is_404_not_403(self):
        eid = _seed_event(tenant="sede-z")
        c = self._client("op_a")
        r = c.post(f"/api/observability/anomalies/{eid}/status", headers=CSRF,
                   json={"from_status": "new", "status": "ack"})
        self.assertEqual(r.status_code, 404)  # non conferma l'esistenza

    def test_viewer_denied(self):
        eid = _seed_event()
        c = self._client("viewer_a")
        r = c.post(f"/api/observability/anomalies/{eid}/status", headers=CSRF,
                   json={"from_status": "new", "status": "ack"})
        self.assertEqual(r.status_code, 403)

    def test_cookie_without_csrf_header_denied(self):
        eid = _seed_event()
        c = self._client("op_a")
        r = c.post(f"/api/observability/anomalies/{eid}/status",
                   json={"from_status": "new", "status": "ack"})
        self.assertEqual(r.status_code, 403)

    def test_audit_entry_emitted(self):
        eid = _seed_event()
        c = self._client("op_a")
        with patch("routers.observability.__builtins__", create=True):
            pass
        with patch("security_manager.log_audit") as mock_audit:
            r = c.post(f"/api/observability/anomalies/{eid}/status", headers=CSRF,
                       json={"from_status": "new", "status": "ack"})
        self.assertEqual(r.status_code, 200)
        joined = " ".join(str(call) for call in mock_audit.call_args_list)
        self.assertIn(str(eid), joined)


class TestAiFlowContext(_Base):
    def test_attach_top_flows_summarized_and_redacted(self):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO flow_aggregates (window_start, tenant, src_ip, dst_ip, "
            "protocol, dst_port, total_bytes, total_packets, flow_count) "
            "VALUES (?, 'sede-a', '10.1.0.5', '203.0.113.7', 6, 443, 12345, 10, 1)",
            (int(time.time()) - (int(time.time()) % 60),))
        conn.commit()
        conn.close()

        # Profilo AI fittizio + chiamata provider mockata: si verifica il
        # payload in uscita (choke-point redazione).
        with patch.object(app_server, "_get_active_ai_profile", return_value={
                "provider": "anthropic", "api_key_enc": "x", "model": "m",
                "name": "test"}), \
             patch.object(app_server.crypto_vault, "decrypt_password",
                          return_value="k"), \
             patch("ai_assistant.requests.post") as mock_post:
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"content": [{"type": "text", "text": "ok"}]}
            mock_post.return_value = resp
            c = self._client("op_a")
            r = c.post("/api/ai/chat", headers=CSRF, json={
                "messages": [{"role": "user", "content": "analizza"}],
                "attach_top_flows": True,
            })
        self.assertEqual(r.status_code, 200)
        sent = json.dumps(mock_post.call_args.kwargs["json"])
        self.assertIn("Top flussi di rete", sent)
        self.assertIn("10.1.0.5", sent)           # IP sopravvivono (per policy)
        self.assertNotIn("sede-b", sent)          # solo scope utente
        # Riassunto top-N: nessun dump di righe raw oltre il limite
        self.assertLess(len(sent), 20000)

    def test_scope_enforced_in_flow_context(self):
        from observability.summary import top_flows_context
        ctx_a = top_flows_context({"sede-a"})
        self.assertNotIn("sede-b", ctx_a)


class TestFrontendGates(_Base):
    HTML = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "templates", "dashboard.html"), encoding="utf-8").read()

    def test_no_sessionstorage_anywhere(self):
        self.assertEqual(len(re.findall(r"sessionStorage\.(get|set)Item", self.HTML)), 0)

    def test_flows_path_uses_apifetch_not_bearer(self):
        block = self.HTML[self.HTML.index("FLUSSI LIVE"):self.HTML.index("window.onload")]
        self.assertNotIn("Authorization", block)
        self.assertNotIn("Bearer", block)
        self.assertIn("apiFetch('/api/observability/top", block.replace('`', "'"))

    def test_flows_tab_registered(self):
        self.assertIn('id="tab-flows"', self.HTML)
        self.assertIn("{ id: 'tab-flows', key: 'tabFlows' }", self.HTML)
        self.assertIn("visibilitychange", self.HTML)


if __name__ == "__main__":
    unittest.main()
