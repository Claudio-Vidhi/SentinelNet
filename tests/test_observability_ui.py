# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Test fase 5: transizioni di stato delle anomalie (ruoli, scope, CSRF,
concorrenza ottimistica, audit) e gate frontend (niente sessionStorage/Bearer nel
percorso Flussi Live)."""

import os
import re
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_obsui_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
from core import db  # noqa: E402
from security import user_manager  # noqa: E402
from tests.test_helpers_frontend import frontend_source  # noqa: E402

PASS = "PasswordSicura1!"
CSRF = {"X-Requested-With": "SentinelNet"}


def _seed_event(tenant="sede-a", status="new"):
    conn = db.get_observability_connection()
    # Dalla v7 l'anomalia su cui si agisce è un INCIDENTE: era una riga di
    # correlated_events per evento, quindi la stessa anomalia ripetuta si
    # chiudeva N volte a mano.
    now = int(time.time())
    cur = conn.execute(
        "INSERT INTO incidents (tenant, entity_key, opened_ts, last_event_ts, "
        "title, severity, event_count, status, cause_kind, confidence) "
        "VALUES (?, 'ip:10.1.0.5', ?, ?, 'test', 3, 1, ?, "
        "'BLOCKED_TRAFFIC_001', 70)",
        (tenant, now, now, status))
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
        # La rotta delega a routers.incidents, che importa log_audit a livello
        # di modulo: il patch va sul nome legato lì, non su quello d'origine.
        with patch("routers.incidents.log_audit") as mock_audit:
            r = c.post(f"/api/observability/anomalies/{eid}/status", headers=CSRF,
                       json={"from_status": "new", "status": "ack"})
        self.assertEqual(r.status_code, 200)
        joined = " ".join(str(call) for call in mock_audit.call_args_list)
        self.assertIn(str(eid), joined)


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
        obs_js = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                    "static", "js", "observability.js"),
                       encoding="utf-8").read()
        block = obs_js[obs_js.index("FLUSSI LIVE"):]
        self.assertNotIn("Authorization", block)
        self.assertNotIn("Bearer", block)
        self.assertIn("apiFetch('/api/observability/top", block.replace('`', "'"))

    def test_flows_tab_registered(self):
        self.assertIn('id="tab-flows"', self.HTML)
        # Concedibile a un non-admin: la lista non e' piu' scritta a mano in
        # settings.js, si deriva dal pulsante di navigazione (che non deve
        # quindi essere requires-admin). Vedi tests/test_assignable_tabs.py.
        self.assertIn('data-tab="tab-flows"', self.HTML)
        self.assertIn("visibilitychange", self.HTML)


if __name__ == "__main__":
    unittest.main()
