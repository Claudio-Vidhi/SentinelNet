# -*- coding: utf-8 -*-
"""Test fase 4: endpoint /top e /anomalies (scope multi-tenant, parametri
ostili, performance su dataset seedato), motore di correlazione (precisione,
dedup, cross-tenant, arricchimento switch/porta) e default-off dei tool MCP
observability."""

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
from observability import correlator  # noqa: E402

PASS = "PasswordSicura1!"
NOW = int(time.time())


def _seed_flow(conn, tenant, src, dst, ts=None, proto=6, dport=443,
               nbytes=1000, npkts=10, source=None):
    conn.execute(
        "INSERT INTO flow_aggregates (window_start, tenant, src_ip, dst_ip, "
        "protocol, dst_port, total_bytes, total_packets, flow_count, source) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
        ((ts or NOW) - ((ts or NOW) % 60), tenant, src, dst, proto, dport,
         nbytes, npkts, source))


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


class TestTopTalkers(_Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        conn = db.get_observability_connection()
        _seed_flow(conn, "sede-a", "10.1.0.5", "8.8.8.8", nbytes=5000)
        _seed_flow(conn, "sede-b", "10.2.0.5", "8.8.4.4", nbytes=9000)
        _seed_flow(conn, "sede-c", "10.3.0.5", "1.1.1.1", nbytes=7000)
        _seed_flow(conn, "sede-a", "10.1.0.9", "8.8.8.8", dport=53,
                   source="netflow")
        _seed_flow(conn, "sede-a", "10.1.0.9", "8.8.8.8", dport=123,
                   source="sflow")
        _seed_syslog(conn, "sede-a", "link down su Gi1/0/7")
        _seed_syslog(conn, "sede-b", "admin login failed")
        conn.commit()
        conn.close()

    def test_admin_sees_all(self):
        r = self._client("adm").get("/api/observability/top?window=1h")
        self.assertEqual(r.status_code, 200)
        tenants = {f["tenant"] for f in r.json()["flows"]}
        self.assertEqual(tenants, {"sede-a", "sede-b", "sede-c"})

    def test_single_group_scoped(self):
        r = self._client("op_a").get("/api/observability/top?window=1h")
        tenants = {f["tenant"] for f in r.json()["flows"]}
        self.assertEqual(tenants, {"sede-a"})

    def test_multi_group_scoped(self):
        r = self._client("op_ab").get("/api/observability/top?window=1h")
        tenants = {f["tenant"] for f in r.json()["flows"]}
        self.assertEqual(tenants, {"sede-a", "sede-b"})

    def test_ordering_by_metric(self):
        r = self._client("adm").get("/api/observability/top?window=1h&metric=bytes")
        flows = r.json()["flows"]
        self.assertEqual(flows[0]["total_bytes"], 9000)

    def test_hostile_params_rejected(self):
        c = self._client("adm")
        for url in ("/api/observability/top?window=15m;DROP TABLE x",
                    "/api/observability/top?window=999999d",
                    "/api/observability/top?window=15m&metric=evil",
                    "/api/observability/top?window=15m&limit=99999",
                    "/api/observability/anomalies?status=x'--"):
            r = c.get(url)
            self.assertIn(r.status_code, (400, 422), url)

    def test_anonymous_401(self):
        r = TestClient(app_server.app).get("/api/observability/top")
        self.assertEqual(r.status_code, 401)

    def test_source_filter(self):
        c = self._client("adm")
        r = c.get("/api/observability/top?window=1h&source=netflow")
        flows = r.json()["flows"]
        self.assertTrue(flows)
        self.assertTrue(all(f["source"] == "netflow" for f in flows))
        r = c.get("/api/observability/top?window=1h&source=all")
        self.assertGreater(len(r.json()["flows"]), len(flows))
        r = c.get("/api/observability/top?window=1h&source=evil")
        self.assertIn(r.status_code, (400, 422))

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
        conn.execute("DELETE FROM correlated_events")
        conn.execute("DELETE FROM syslog_events")
        conn.execute("DELETE FROM flow_aggregates")
        conn.commit()
        conn.close()
        db.start_writer()

    def tearDown(self):
        db.stop_writer()

    def _rows(self):
        time.sleep(0.6)  # drain writer
        conn = db.get_observability_connection()
        rows = conn.execute("SELECT * FROM correlated_events").fetchall()
        conn.close()
        return rows

    def test_full_match_emits_enriched_event(self):
        conn = db.get_observability_connection()
        _seed_flow(conn, "sede-a", "10.1.0.5", "203.0.113.7")
        sid = _seed_syslog(conn, "sede-a", self.FGT_MSG)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[
                {"switch_ip": "10.1.0.10", "switch_name": "SW-A1",
                 "switch_port": "Gi1/0/7"}]):
            emitted = correlator.correlate_once(NOW)
        self.assertEqual(emitted, 1)
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        ev = rows[0]
        self.assertEqual(ev["src_ip"], "10.1.0.5")
        self.assertEqual(ev["switch_port"], "SW-A1:Gi1/0/7")
        evidence = json.loads(ev["evidence_json"])
        self.assertEqual(evidence["syslog_id"], sid)
        self.assertIn("flow", evidence)

    def test_rerun_does_not_duplicate(self):
        conn = db.get_observability_connection()
        _seed_flow(conn, "sede-a", "10.1.0.5", "203.0.113.7")
        _seed_syslog(conn, "sede-a", self.FGT_MSG)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
            correlator.correlate_once(NOW)
        self.assertEqual(len(self._rows()), 1)

    def test_syslog_without_flow_no_event(self):
        # Severità media (4): senza flusso corroborante non si emette nulla.
        conn = db.get_observability_connection()
        _seed_syslog(conn, "sede-a", self.FGT_MSG, severity=4)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            emitted = correlator.correlate_once(NOW)
        self.assertEqual(emitted, 0)
        self.assertEqual(len(self._rows()), 0)

    def test_high_severity_without_flow_emits_standalone(self):
        # Severità alta (<=3): l'evento emerge anche senza flusso corroborante,
        # anche senza action di sicurezza e senza endpoint nel messaggio.
        conn = db.get_observability_connection()
        _seed_syslog(conn, "sede-a", 'logdesc="FortiGate update failed"',
                     action=None, severity=1)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            emitted = correlator.correlate_once(NOW)
        self.assertEqual(emitted, 1)
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "syslog_critico")
        self.assertEqual(rows[0]["severity"], 1)
        self.assertIsNone(rows[0]["src_ip"])
        evidence = json.loads(rows[0]["evidence_json"])
        self.assertNotIn("flow", evidence)

    def test_high_severity_with_flow_single_event(self):
        # Alta severità + flusso: UN solo evento (quello corroborato), niente doppioni.
        conn = db.get_observability_connection()
        _seed_flow(conn, "sede-a", "10.1.0.5", "203.0.113.7")
        _seed_syslog(conn, "sede-a", self.FGT_MSG, severity=2)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            emitted = correlator.correlate_once(NOW)
        self.assertEqual(emitted, 1)
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertIn("flow", json.loads(rows[0]["evidence_json"]))

    def test_high_severity_rerun_does_not_duplicate(self):
        conn = db.get_observability_connection()
        _seed_syslog(conn, "sede-a", "kernel panic", action=None, severity=0)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
            correlator.correlate_once(NOW)
        self.assertEqual(len(self._rows()), 1)

    def test_no_cross_tenant_correlation(self):
        conn = db.get_observability_connection()
        # flusso in sede-b, syslog in sede-a: stessi IP ma tenant diversi.
        _seed_flow(conn, "sede-b", "10.1.0.5", "203.0.113.7")
        _seed_syslog(conn, "sede-a", self.FGT_MSG, severity=4)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            emitted = correlator.correlate_once(NOW)
        self.assertEqual(emitted, 0)

    def test_missing_mac_gives_null_switch_port(self):
        conn = db.get_observability_connection()
        _seed_flow(conn, "sede-a", "10.1.0.5", "203.0.113.7")
        _seed_syslog(conn, "sede-a", self.FGT_MSG)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["switch_port"])

    def test_flow_outside_delta_no_event(self):
        conn = db.get_observability_connection()
        _seed_flow(conn, "sede-a", "10.1.0.5", "203.0.113.7",
                   ts=NOW - correlator.MATCH_DELTA_S - 600)
        _seed_syslog(conn, "sede-a", self.FGT_MSG, severity=4)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            emitted = correlator.correlate_once(NOW)
        self.assertEqual(emitted, 0)


class TestQueryPerf(_Base):
    """4.3: nessun full scan sulle query calde; /top < 500ms su 1M righe."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        conn = db.get_observability_connection()
        n = conn.execute("SELECT COUNT(*) AS n FROM flow_aggregates").fetchone()["n"]
        if n < 1_000_000:
            conn.execute("DELETE FROM flow_aggregates")
            base = NOW - 6 * 86400
            rows = ((base + (i % 8000) * 60, f"sede-{chr(97 + i % 3)}",
                     f"10.{i % 200}.{(i // 200) % 200}.{i % 250}",
                     f"203.0.{(i // 250) % 100}.{i % 250}", 6, 443,
                     i % 100_000, i % 1000)
                    for i in range(1_000_000))
            conn.executemany(
                "INSERT OR IGNORE INTO flow_aggregates (window_start, tenant, "
                "src_ip, dst_ip, protocol, dst_port, total_bytes, total_packets) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
            conn.commit()
        conn.close()

    def test_top_query_uses_index_no_full_scan(self):
        conn = db.get_observability_connection()
        plan = conn.execute(
            "EXPLAIN QUERY PLAN SELECT tenant, src_ip, dst_ip, "
            "SUM(total_bytes) FROM flow_aggregates WHERE window_start >= ? "
            "AND tenant IN (?, ?) GROUP BY tenant, src_ip, dst_ip "
            "ORDER BY SUM(total_bytes) DESC LIMIT 50",
            (NOW - 900, "sede-a", "sede-b")).fetchall()
        conn.close()
        text = " ".join(r["detail"] for r in plan)
        self.assertIn("idx_flow_window_tenant", text, f"piano: {text}")
        self.assertNotIn("SCAN flow_aggregates", text.replace(
            "SCAN flow_aggregates USING INDEX", ""), f"piano: {text}")

    def test_top_latency_under_500ms_on_1m_rows(self):
        c = self._client("adm")
        t0 = time.perf_counter()
        r = c.get("/api/observability/top?window=1h&limit=50")
        elapsed = time.perf_counter() - t0
        self.assertEqual(r.status_code, 200)
        self.assertLess(elapsed, 0.5, f"/top ha impiegato {elapsed:.3f}s")

    def test_correlator_cycle_bounded_on_seeded_db(self):
        t0 = time.perf_counter()
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
        self.assertIn("get_top_talkers", disabled)
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
        self.assertIn("get_top_talkers", mcp_server.TOOLS)
        self.assertIn("get_anomalies", mcp_server.TOOLS)


@classmethod
def _tearDownModule():
    shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
