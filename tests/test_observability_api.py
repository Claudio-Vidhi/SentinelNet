# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Observability API: /syslog and /anomalies (multi-tenant scope, hostile
parameters), the correlation engine on syslog (repetition before concluding,
dedup, cross-tenant, switch/port enrichment), a correlator cycle on a seeded
database, and the MCP observability tools being off by default."""

import json
import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_obsapi_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
from core import db  # noqa: E402
from security import user_manager  # noqa: E402
from observability import correlator, incidents, rules  # noqa: E402

PASS = "PasswordSicura1!"
NOW = int(time.time())


def _seed_syslog(conn, tenant, message, ts=None, action="deny", severity=3):
    cur = conn.execute(
        "INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, "
        "message) VALUES (?, ?, '10.0.0.254', ?, ?, ?)",
        (ts or NOW, tenant, severity, action, message))
    return cur.lastrowid


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
        for user, role, groups in (("adm", "admin", None),
                                   ("op_a", "operator", ["sede-a"]),
                                   ("op_ab", "operator", ["sede-a", "sede-b"])):
            try:
                user_manager.create_user(user, PASS, role=role, groups=groups)
            except Exception:
                pass

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200
        return c


class TestSyslogEndpoint(_Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        conn = db.get_observability_connection()
        _seed_syslog(conn, "sede-a", "link down su Gi1/0/7")
        _seed_syslog(conn, "sede-b", "admin login failed")
        conn.commit()
        conn.close()

    def test_hostile_params_rejected(self):
        c = self._client("adm")
        for url in ("/api/observability/syslog?window=15m;DROP TABLE x",
                    "/api/observability/syslog?window=999999d",
                    "/api/observability/anomalies?status=x'--"):
            r = c.get(url)
            self.assertIn(r.status_code, (400, 422), url)

    def test_anonymous_401(self):
        r = TestClient(app_server.app).get("/api/observability/syslog")
        self.assertEqual(r.status_code, 401)

    def test_top_talkers_route_is_gone(self):
        # Removed with the flow collectors: no route, not an empty answer.
        r = self._client("adm").get("/api/observability/top?window=1h")
        self.assertEqual(r.status_code, 404)

    def test_syslog_endpoint_scoped(self):
        r = self._client("op_a").get("/api/observability/syslog?window=1h")
        self.assertEqual(r.status_code, 200)
        events = r.json()["events"]
        self.assertEqual({e["tenant"] for e in events}, {"sede-a"})
        r = self._client("adm").get("/api/observability/syslog?window=1h")
        self.assertEqual({e["tenant"] for e in r.json()["events"]},
                         {"sede-a", "sede-b"})


class TestCorrelator(_Base):
    FGT_MSG = ('logid="0316013057" type="utm" level="warning" '
               'action="blocked" srcip=10.1.0.5 dstip=203.0.113.7 dstport=443 '
               'msg="Malware site blocked"')

    def setUp(self):
        conn = db.get_observability_connection()
        conn.execute("DELETE FROM evidence")
        conn.execute("DELETE FROM incidents")
        conn.execute("DELETE FROM syslog_events")
        # Il correlatore consuma il modello normalizzato: la proiezione e i
        # cursori vanno azzerati insieme alle tabelle d'origine, altrimenti un
        # test eredita gli eventi normalizzati del precedente.
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM normalize_cursors")
        conn.commit()
        conn.close()
        db.start_writer()

    def tearDown(self):
        db.stop_writer()

    def _rows(self, role="trigger"):
        """Evidenze prodotte dal ciclo. Il correlatore emette anche le righe di
        supporto: i test storici contano gli INNESCHI, che sono ciò che prima
        era una riga di ``correlated_events``."""
        conn = db.get_observability_connection()
        rows = conn.execute(
            "SELECT * FROM evidence WHERE role = ? ORDER BY id", (role,)).fetchall()
        conn.close()
        return rows

    def _by_rule(self, rule_id, role="trigger"):
        conn = db.get_observability_connection()
        rows = conn.execute(
            "SELECT * FROM evidence WHERE rule_id = ? AND role = ? ORDER BY id",
            (rule_id, role)).fetchall()
        conn.close()
        return rows

    def _seed_blocks(self, tenant="sede-a", n=3, severity=4):
        conn = db.get_observability_connection()
        for _ in range(n):
            _seed_syslog(conn, tenant, self.FGT_MSG, severity=severity)
        conn.commit()
        conn.close()

    def test_repeated_blocks_give_a_trigger_with_provenance(self):
        # Severita' 4: fa scattare solo la regola sul traffico bloccato, non
        # quella sulla severita' alta.
        self._seed_blocks()
        # Soglie ai default: il test verifica la regola, non la configurazione.
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[
                {"switch_ip": "10.1.0.10", "switch_name": "SW-A1",
                 "switch_port": "Gi1/0/7"}]):
            correlator.correlate_once(NOW)

        triggers = self._by_rule("BLOCKED_TRAFFIC_001")
        self.assertEqual(len(triggers), 3)
        trigger = triggers[0]
        self.assertEqual(trigger["src_ip"], "10.1.0.5")
        self.assertEqual(trigger["switch_port"], "SW-A1:Gi1/0/7")
        self.assertEqual(trigger["entity_key"], "ip:10.1.0.5")
        # Provenienza: versione della regola E soglie effettivamente usate.
        self.assertEqual(trigger["rule_version"],
                         rules.RULES["BLOCKED_TRAFFIC_001"]["version"])
        self.assertEqual(json.loads(trigger["params_json"])["min_observations"], 3)
        # No flow corroboration any more: nothing but the triggers.
        self.assertEqual(self._by_rule("BLOCKED_TRAFFIC_001", "supporting"), [])

    def test_a_single_block_is_not_enough(self):
        # Severita' media (4) e un solo blocco: un firewall nega di continuo,
        # un fatto isolato non diventa evidenza.
        self._seed_blocks(n=1)
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            emitted = correlator.correlate_once(NOW)
        self.assertEqual(emitted, 0)
        self.assertEqual(len(self._rows()), 0)

    def test_two_rules_on_the_same_fact_reinforce_one_incident(self):
        # Severita' 2 e blocchi ripetuti: scattano ENTRAMBE le regole. Non e'
        # un doppione, sono due evidenze sullo stesso innesco, e l'incidente
        # che ne deriva deve restare uno solo, con la confidenza rinforzata.
        self._seed_blocks(severity=2)
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        self.assertEqual(len(self._by_rule("BLOCKED_TRAFFIC_001")), 3)
        self.assertEqual(len(self._by_rule("HIGH_SEVERITY_LOG_001")), 3)

        incidents.group_once(NOW)
        conn = db.get_observability_connection()
        rows = conn.execute("SELECT * FROM incidents").fetchall()
        conn.close()
        self.assertEqual(len(rows), 1)
        reasoning = json.loads(rows[0]["reasoning_json"])
        self.assertIn("piu_regole_concordi", reasoning["sources_used"])

    def test_threshold_from_settings_is_applied(self):
        # La soglia e' configurabile a runtime: con min_observations a 1 il
        # blocco singolo basta.
        settings = {"correlation_rules": {"BLOCKED_TRAFFIC_001":
                                          {"min_observations": 1}}}
        self._seed_blocks(n=1)
        with patch("observability.rules.get_app_settings", return_value=settings), \
             patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        self.assertEqual(len(self._by_rule("BLOCKED_TRAFFIC_001")), 1)

    def test_rerun_does_not_duplicate(self):
        self._seed_blocks()
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
            correlator.correlate_once(NOW)
        self.assertEqual(len(self._by_rule("BLOCKED_TRAFFIC_001")), 3)

    def test_high_severity_emits_standalone(self):
        # Severita' alta (<=3): l'evento emerge da solo, anche senza action di
        # sicurezza e senza endpoint nel messaggio.
        conn = db.get_observability_connection()
        _seed_syslog(conn, "sede-a", 'logdesc="FortiGate update failed"',
                     action=None, severity=1)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        rows = self._by_rule("HIGH_SEVERITY_LOG_001")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], 1)
        self.assertIsNone(rows[0]["src_ip"])

    def test_high_severity_rerun_does_not_duplicate(self):
        conn = db.get_observability_connection()
        _seed_syslog(conn, "sede-a", "kernel panic", action=None, severity=0)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
            correlator.correlate_once(NOW)
        self.assertEqual(len(self._by_rule("HIGH_SEVERITY_LOG_001")), 1)

    def test_no_cross_tenant_correlation(self):
        # Stessa sorgente, tenant diversi: i blocchi non si sommano.
        self._seed_blocks("sede-a", n=2)
        self._seed_blocks("sede-b", n=1)
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            emitted = correlator.correlate_once(NOW)
        self.assertEqual(emitted, 0)

    def test_missing_mac_gives_null_switch_port(self):
        self._seed_blocks()
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        rows = self._by_rule("BLOCKED_TRAFFIC_001")
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row["switch_port"] is None for row in rows))


class TestQueryPerf(_Base):
    """A correlator cycle stays bounded on a database seeded with syslog."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        conn = db.get_observability_connection()
        rows = ((NOW - (i % 3000), f"sede-{chr(97 + i % 3)}", 4, "deny",
                 f"action=deny srcip=10.{i % 200}.{(i // 200) % 200}.{i % 250} "
                 f"dstip=203.0.113.{i % 250} dstport=443")
                for i in range(100_000))
        conn.executemany(
            "INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, "
            "message) VALUES (?, ?, '10.0.0.254', ?, ?, ?)", rows)
        conn.commit()
        conn.close()

    def test_correlator_cycle_bounded_on_seeded_db(self):
        t0 = time.perf_counter()
        with patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 30, f"ciclo correlatore {elapsed:.1f}s")


class TestMcpDefaultOff(_Base):
    def test_obs_tools_disabled_by_default(self):
        settings_path = data_config.get_path("app_settings.json")
        settings = {}
        if os.path.exists(settings_path):
            settings = json.load(open(settings_path, encoding="utf-8"))
        settings.pop("mcp", None)
        json.dump(settings, open(settings_path, "w", encoding="utf-8"))
        r = self._client("adm").get("/api/mcp/tool-config")
        self.assertEqual(r.status_code, 200)
        disabled = r.json()["disabled_tools"]
        self.assertIn("get_anomalies", disabled)

    def test_explicit_admin_choice_wins(self):
        c = self._client("adm")
        r = c.post("/api/mcp/settings", json={"disabled_tools": []},
                   headers={"X-Requested-With": "SentinelNet"})
        self.assertEqual(r.status_code, 200)
        disabled = c.get("/api/mcp/tool-config").json()["disabled_tools"]
        self.assertEqual(disabled, [])

    def test_obs_tools_registered(self):
        from ai import mcp_server
        self.assertNotIn("get_top_talkers", mcp_server.TOOLS)
        self.assertIn("get_anomalies", mcp_server.TOOLS)


@classmethod
def _tearDownModule():
    shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()


class TestApiContextTenantScope(_Base):
    """The "latest snapshot per kind" subquery must be tenant-scoped too.

    Two customers may each own 192.0.2.10. With an unscoped subquery, MAX(id)
    picks whichever tenant wrote last; the outer tenant filter then drops that
    row and the scoped user sees nothing instead of their own snapshot.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        conn = db.get_observability_connection()
        for tenant, payload in (("sede-a", {"cpu": 11}), ("sede-b", {"cpu": 99})):
            conn.execute(
                "INSERT INTO api_observations (ts, tenant, device_ip, kind, "
                "summary_json) VALUES (?, ?, '192.0.2.10', 'system', ?)",
                (NOW, tenant, json.dumps(payload)))
        conn.commit()

    def test_scoped_user_sees_their_own_latest_snapshot(self):
        c = self._client("op_a")
        r = c.get("/api/observability/api-context", params={"device_ip": "192.0.2.10"})
        self.assertEqual(r.status_code, 200)
        obs = r.json()["observations"]
        self.assertEqual(len(obs), 1, "sede-b's newer row hid sede-a's own snapshot")
        self.assertEqual(obs[0]["tenant"], "sede-a")

    def test_unscoped_admin_still_sees_one_row_per_tenant_kind(self):
        c = self._client("adm")
        r = c.get("/api/observability/api-context", params={"device_ip": "192.0.2.10"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()["observations"]), 1)


class TestObsBindValidation(unittest.TestCase):
    """Security review 2026-10-12, L3: 'bind' was stored as given."""

    def test_a_non_address_bind_is_refused_before_saving(self):
        import asyncio
        from fastapi import HTTPException
        from routers import observability as obs_router
        admin = {"sub": "adm", "role": "super_admin"}
        for bad in (123, "not-an-ip", "0.0.0.0; rm"):
            with self.subTest(bind=bad), \
                 patch.object(obs_router, "save_app_settings") as save:
                with self.assertRaises(HTTPException) as ctx:
                    asyncio.run(obs_router.obs_set_config({"bind": bad}, current_user=admin))
                self.assertEqual(ctx.exception.status_code, 400)
                save.assert_not_called()


class TestObsConfigLegacyFlowKeys(_Base):
    """A tab running JS cached from before the flow removal still posts
    ipfix_* / sflow_* / netflow_* keys: they are dropped, not a 400."""

    def setUp(self):
        from unittest.mock import AsyncMock
        from observability import listener_manager
        p = patch.object(listener_manager, "apply_obs_config", new=AsyncMock())
        p.start()
        self.addCleanup(p.stop)
        # Other modules in the same worker read obs_config() defaults.
        from core.app_settings import save_app_settings
        self.addCleanup(save_app_settings, {"observability": {}})

    def _post(self, body):
        return self._client("adm").post("/api/observability/config", json=body,
                                        headers={"X-Requested-With": "SentinelNet"})

    def _saved(self):
        from core.app_settings import get_app_settings
        return get_app_settings().get("observability", {})

    def test_legacy_keys_are_dropped_and_the_rest_saved(self):
        from core.app_settings import save_app_settings
        # A key left behind in the file by an older release is cleaned too.
        save_app_settings({"observability": {"sflow_port": 6343}})
        r = self._post({
            "enabled": False, "syslog_enabled": True, "syslog_port": 5515,
            "ipfix_enabled": True, "ipfix_port": 4739,
            "sflow_enabled": False, "netflow_port": 2055})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(sorted(r.json()["ignored"]),
                         ["ipfix_enabled", "ipfix_port", "netflow_port", "sflow_enabled"])
        saved = self._saved()
        self.assertEqual(saved["syslog_port"], 5515)
        self.assertTrue(saved["syslog_enabled"])
        self.assertFalse([k for k in saved if k.startswith(("ipfix_", "sflow_", "netflow_"))])

    def test_no_legacy_keys_gives_empty_ignored(self):
        r = self._post({"enabled": False})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["ignored"], [])

    def test_unknown_non_legacy_key_still_400(self):
        r = self._post({"enabled": False, "bogus_port": 1})
        self.assertEqual(r.status_code, 400)
        self.assertIn("bogus_port", r.json()["detail"])

    def test_get_reports_platform_default_port(self):
        for platform, port in (("win32", 514), ("linux", 5514)):
            with patch.object(data_config.sys, "platform", platform):
                r = self._client("adm").get("/api/observability/config")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["syslog"]["default_port"], port)
