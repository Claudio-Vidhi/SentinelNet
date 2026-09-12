# -*- coding: utf-8 -*-
"""G4 — il listener syslog dell'agente si accende e si spegne dal pannello, e
il pannello dice dove l'agente scrive.

La porta era configurabile da remoto, il listener no: per spegnerlo serviva
riavviare l'agente con ``--no-syslog``, cioe' una sessione SSH nella sede. E
la cartella dati era invisibile: un operatore che cercava i file dell'agente
doveva dedurla dal comando di avvio.

``syslog_enabled`` nell'heartbeat e' lo stato REALE del collector, non quello
richiesto: una porta occupata si legge come "spento" invece di restare una
bugia nel pannello.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="sentinelnet_test_syslogtoggle_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP
os.environ.setdefault("SENTINELNET_JWT_SECRET", "test-secret-syslog-toggle")

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from services import site_agent  # noqa: E402

ADMIN, ADMIN_PW = "syslogtoggle_admin", "PasswordSicura1!"
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _agent_js() -> str:
    with open(os.path.join(_REPO_ROOT, "static", "js", "site-agent.js"),
              encoding="utf-8") as f:
        return f.read()


class TestAgentHonoursTheToggle(unittest.TestCase):
    """Il lato agente: l'RPC di configurazione deve davvero fermare il
    listener, non solo scrivere la chiave in memoria."""

    def _agent(self, with_collector=True):
        agent = site_agent.Agent.__new__(site_agent.Agent)
        agent.cfg = {"site_id": "milan", "syslog_port": 5514,
                     "syslog_enabled": True, "data_dir": _TMP}
        agent.syslog_worker_running = True
        agent.syslog_collector = None
        if with_collector:
            col = mock.MagicMock()
            col.port = 5514
            col.running = True
            agent.syslog_collector = col
        return agent

    def test_turning_it_off_frees_the_port(self):
        agent = self._agent()
        col = agent.syslog_collector
        out = agent._execute_agent_rpc('_agent_config {"syslog_enabled": false}')
        self.assertEqual(out["status"], "done", out)
        self.assertIsNone(agent.syslog_collector)
        self.assertFalse(col.running)
        col.sock.close.assert_called_once()

    def test_turning_it_on_starts_a_listener(self):
        agent = self._agent(with_collector=False)
        with mock.patch.object(site_agent, "SyslogCollector") as SC:
            out = agent._execute_agent_rpc('_agent_config {"syslog_enabled": true}')
        self.assertEqual(out["status"], "done", out)
        SC.assert_called_once_with(port=5514)
        self.assertIsNotNone(agent.syslog_collector)

    def test_turning_it_on_twice_does_not_start_a_second_listener(self):
        agent = self._agent()
        first = agent.syslog_collector
        with mock.patch.object(site_agent, "SyslogCollector") as SC:
            agent._execute_agent_rpc('_agent_config {"syslog_enabled": true}')
        SC.assert_not_called()
        self.assertIs(agent.syslog_collector, first)

    def test_a_port_change_still_rebinds(self):
        agent = self._agent()
        old = agent.syslog_collector
        with mock.patch.object(site_agent, "SyslogCollector") as SC:
            agent._execute_agent_rpc('_agent_config {"syslog_port": 5515}')
        self.assertFalse(old.running)
        SC.assert_called_once_with(port=5515)

    def test_the_heartbeat_reports_the_real_state_and_the_data_dir(self):
        agent = self._agent(with_collector=False)
        agent._start_ts = 0.0
        posted = {}

        def fake_post(path, payload):
            posted["path"], posted["payload"] = path, payload
            return mock.MagicMock(raise_for_status=lambda: None,
                                  json=lambda: {"ok": True})

        with mock.patch.object(agent, "_post", fake_post):
            agent.heartbeat()
        # Nessun collector: lo stato riportato e' "spento", non il valore
        # chiesto nella configurazione (che qui e' True).
        self.assertFalse(posted["payload"]["syslog_enabled"])
        self.assertEqual(posted["payload"]["data_dir"], os.path.abspath(_TMP))


class TestCentralStoresWhatTheAgentReports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from security import user_manager
        user_manager.create_user(ADMIN, ADMIN_PW, role="admin")
        cls.client = TestClient(app_server.app)
        r = cls.client.post("/api/auth/login",
                            json={"username": ADMIN, "password": ADMIN_PW})
        assert r.status_code == 200, r.text
        cls.h = {"Authorization": "Bearer " + r.json()["access_token"]}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP, ignore_errors=True)

    def test_the_site_row_learns_the_listener_state_and_the_directory(self):
        r = self.client.post("/api/sites", headers=self.h,
                             json={"name": "Syslog-HB", "mode": "agent",
                                   "subnets": []})
        self.assertEqual(r.status_code, 200, r.text)
        sid, token = r.json()["site"]["id"], r.json()["token"]
        hb = self.client.post("/api/agent/heartbeat",
                              headers={"X-Site-Id": sid, "X-Site-Token": token},
                              json={"version": "0.0.0", "syslog_enabled": False,
                                    "data_dir": "/opt/sentinelnet/agent-data"})
        self.assertEqual(hb.status_code, 200, hb.text)
        sites = self.client.get("/api/sites", headers=self.h).json()["sites"]
        site = next(s for s in sites if s["id"] == sid)
        self.assertIs(site["syslog_enabled"], False)
        self.assertEqual(site["agent_data_dir"], "/opt/sentinelnet/agent-data")

    def test_the_config_route_accepts_the_toggle(self):
        r = self.client.post("/api/sites", headers=self.h,
                             json={"name": "Syslog-Cfg", "mode": "agent",
                                   "subnets": []})
        sid = r.json()["site"]["id"]
        r = self.client.post(f"/api/sites/{sid}/agent/config", headers=self.h,
                             json={"syslog_enabled": False})
        self.assertEqual(r.status_code, 200, r.text)
        from services import site_manager
        job = site_manager.get_job(r.json()["job_id"])
        self.assertIn('"syslog_enabled":false', job["command"].replace(" ", ""))


class TestThePanelOffersIt(unittest.TestCase):
    def test_the_checkbox_exists_and_is_sent(self):
        js = _agent_js()
        self.assertIn('id="agentCfgSyslogEnabled"', js)
        self.assertIn("getElementById('agentCfgSyslogEnabled').checked", js)
        self.assertIn("syslog_enabled: syslogEnabled", js)

    def test_the_directory_is_shown_read_only(self):
        js = _agent_js()
        self.assertIn("site.agent_data_dir", js)
        # Nessun input: il percorso lo decide l'avvio dell'agente, non il
        # pannello.
        self.assertNotIn('id="agentCfgDataDir"', js)


if __name__ == "__main__":
    unittest.main()
