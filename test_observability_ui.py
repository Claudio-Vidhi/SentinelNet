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
from test_helpers_frontend import frontend_source  # noqa: E402

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
        self.assertIn("changed", r.json()["detail"])

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
        with patch("routers.ai._get_active_ai_profile", return_value={
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


def _seed_flow(tenant, src, dst, proto, dport, tbytes, tpackets):
    conn = db.get_observability_connection()
    conn.execute(
        "INSERT INTO flow_aggregates (window_start, tenant, src_ip, dst_ip, "
        "protocol, dst_port, total_bytes, total_packets, flow_count) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
        (int(time.time()) - (int(time.time()) % 60), tenant, src, dst,
         proto, dport, tbytes, tpackets))
    conn.commit()
    conn.close()


class TestAiFlowKeys(_Base):
    """11.3: analisi AI sulle sole righe flusso selezionate (attach_flow_keys)."""

    def test_single_key_only_that_tuple(self):
        from observability.summary import top_flows_context
        _seed_flow("sede-a", "10.2.0.1", "203.0.113.10", 6, 443, 5000, 5)
        _seed_flow("sede-a", "10.2.0.2", "203.0.113.11", 17, 53, 6000, 6)
        ctx = top_flows_context({"sede-a"}, keys=[
            {"src_ip": "10.2.0.1", "dst_ip": "203.0.113.10",
             "protocol": 6, "dst_port": 443}])
        self.assertIn("10.2.0.1", ctx)
        self.assertNotIn("10.2.0.2", ctx)

    def test_multiple_keys(self):
        from observability.summary import top_flows_context
        _seed_flow("sede-a", "10.3.0.1", "203.0.113.20", 6, 80, 7000, 7)
        _seed_flow("sede-a", "10.3.0.2", "203.0.113.21", 6, 8080, 8000, 8)
        _seed_flow("sede-a", "10.3.0.3", "203.0.113.22", 6, 22, 9000, 9)
        ctx = top_flows_context({"sede-a"}, keys=[
            {"src_ip": "10.3.0.1", "dst_ip": "203.0.113.20", "protocol": 6, "dst_port": 80},
            {"src_ip": "10.3.0.2", "dst_ip": "203.0.113.21", "protocol": 6, "dst_port": 8080}])
        self.assertIn("10.3.0.1", ctx)
        self.assertIn("10.3.0.2", ctx)
        self.assertNotIn("10.3.0.3", ctx)

    def test_null_dst_port_matching(self):
        from observability.summary import top_flows_context
        _seed_flow("sede-a", "10.4.0.1", "203.0.113.30", 1, None, 4000, 4)
        ctx = top_flows_context({"sede-a"}, keys=[
            {"src_ip": "10.4.0.1", "dst_ip": "203.0.113.30",
             "protocol": 1, "dst_port": None}])
        self.assertIn("10.4.0.1", ctx)

    def test_out_of_scope_tenant_key_excluded(self):
        from observability.summary import top_flows_context
        _seed_flow("sede-b", "10.9.0.1", "203.0.113.99", 6, 443, 9999, 9)
        # Anche fornendo la key esatta, lo scope sede-a esclude il flusso sede-b.
        ctx = top_flows_context({"sede-a"}, keys=[
            {"src_ip": "10.9.0.1", "dst_ip": "203.0.113.99",
             "protocol": 6, "dst_port": 443}])
        self.assertNotIn("10.9.0.1", ctx)
        self.assertNotIn("sede-b", ctx)

    def test_totals_derived_from_db(self):
        from observability.summary import top_flows_context
        _seed_flow("sede-a", "10.5.0.1", "203.0.113.40", 6, 443, 424242, 77)
        ctx = top_flows_context({"sede-a"}, keys=[
            {"src_ip": "10.5.0.1", "dst_ip": "203.0.113.40",
             "protocol": 6, "dst_port": 443}])
        # Il totale proviene dal DB, non da valori inviati dal client.
        self.assertIn("424242", ctx)
        self.assertIn("77", ctx)

    def _chat_with(self, user, payload):
        with patch("routers.ai._get_active_ai_profile", return_value={
                "provider": "anthropic", "api_key_enc": "x", "model": "m",
                "name": "test"}), \
             patch.object(app_server.crypto_vault, "decrypt_password",
                          return_value="k"), \
             patch("ai_assistant.requests.post") as mock_post:
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"content": [{"type": "text", "text": "ok"}]}
            mock_post.return_value = resp
            c = self._client(user)
            r = c.post("/api/ai/chat", headers=CSRF, json=payload)
            sent = json.dumps(mock_post.call_args.kwargs["json"]) \
                if mock_post.call_args else ""
        return r, sent

    def test_api_attach_flow_keys(self):
        _seed_flow("sede-a", "10.6.0.1", "203.0.113.50", 6, 443, 11111, 3)
        r, sent = self._chat_with("op_a", {
            "messages": [{"role": "user", "content": "analizza"}],
            "attach_flow_keys": [{"src_ip": "10.6.0.1", "dst_ip": "203.0.113.50",
                                  "protocol": 6, "dst_port": 443}],
        })
        self.assertEqual(r.status_code, 200)
        self.assertIn("10.6.0.1", sent)
        self.assertIn("11111", sent)  # totale ri-derivato dal server

    def test_api_over_cap_400(self):
        keys = [{"src_ip": f"10.7.0.{i}", "dst_ip": "203.0.113.60",
                 "protocol": 6, "dst_port": 443} for i in range(21)]
        r, _ = self._chat_with("op_a", {
            "messages": [{"role": "user", "content": "analizza"}],
            "attach_flow_keys": keys,
        })
        self.assertEqual(r.status_code, 400)
        self.assertIn("massimo 20", r.json()["detail"])

    def test_no_selection_legacy_path(self):
        # attach_flow_keys None → percorso top-N invariato, nessun 400.
        _seed_flow("sede-a", "10.8.0.1", "203.0.113.70", 6, 443, 2222, 2)
        r, sent = self._chat_with("op_a", {
            "messages": [{"role": "user", "content": "analizza"}],
            "attach_top_flows": True,
        })
        self.assertEqual(r.status_code, 200)
        self.assertIn("Top flussi di rete", sent)


class TestObsSettingsNestedKeys(unittest.TestCase):
    """renderObsSettings deve leggere le chiavi annidate restituite da
    obs_config() (d[l].enabled / d[l].port), non le chiavi piatte."""

    def test_render_reads_nested_listener_keys(self):
        html = frontend_source()
        block = html[html.index("function renderObsSettings"):
                     html.index("async function saveObsSettings")]
        self.assertNotIn("d[`${l}_enabled`]", block)
        self.assertNotIn("d[`${l}_port`]", block)
        self.assertIn("d[l]", block)


class TestFrontendGates(_Base):
    HTML = frontend_source()

    def test_no_sessionstorage_anywhere(self):
        self.assertEqual(len(re.findall(r"sessionStorage\.(get|set)Item", self.HTML)), 0)

    def test_flows_path_uses_apifetch_not_bearer(self):
        # FLUSSI LIVE block moved to static/js/observability.js (which runs
        # entirely before window.onload, defined back in dashboard.html);
        # slice within that file directly to keep the check scoped to the
        # flows module rather than the whole concatenated frontend source.
        obs_js = open(os.path.join(os.path.dirname(__file__),
                                    "static", "js", "observability.js"),
                       encoding="utf-8").read()
        block = obs_js[obs_js.index("FLUSSI LIVE"):]
        self.assertNotIn("Authorization", block)
        self.assertNotIn("Bearer", block)
        self.assertIn("apiFetch('/api/observability/top", block.replace('`', "'"))

    def test_flows_tab_registered(self):
        self.assertIn('id="tab-flows"', self.HTML)
        self.assertIn("{ id: 'tab-flows', key: 'tabFlows' }", self.HTML)
        self.assertIn("visibilitychange", self.HTML)


if __name__ == "__main__":
    unittest.main()
