# -*- coding: utf-8 -*-
"""Test Task 3: endpoint /api/observability/flowgraph — nodi/archi aggregati,
KPI, riepilogo tenant e breakdown protocolli per la vista Live Flows."""

import os
import shutil
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_obsflowgraph_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
from core import db  # noqa: E402
from security import user_manager  # noqa: E402

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


def _seed_anomaly(conn, tenant, status="new", ts=None):
    conn.execute(
        "INSERT INTO correlated_events (created_ts, tenant, kind, status) "
        "VALUES (?, ?, 'test', ?)", (ts or NOW, tenant, status))


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


class TestFlowGraph(_Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        conn = db.get_observability_connection()
        _seed_flow(conn, "sede-a", "10.1.0.5", "8.8.8.8", nbytes=5000, dport=443)
        _seed_flow(conn, "sede-a", "10.1.0.9", "8.8.8.8", nbytes=2000, dport=53, proto=17)
        _seed_flow(conn, "sede-b", "10.2.0.5", "8.8.4.4", nbytes=9000, dport=443)
        _seed_anomaly(conn, "sede-a", status="new")
        _seed_anomaly(conn, "sede-a", status="resolved")
        _seed_anomaly(conn, "sede-b", status="new")
        conn.commit()
        conn.close()

    def test_response_shape(self):
        r = self._client("adm").get("/api/observability/flowgraph?window=1h")
        self.assertEqual(r.status_code, 200)
        d = r.json()
        for key in ("nodes", "edges", "kpi", "tenant", "protocols"):
            self.assertIn(key, d)
        self.assertIsInstance(d["nodes"], list)
        self.assertIsInstance(d["edges"], list)
        self.assertIn("throughput_bps", d["kpi"])
        self.assertIn("top_path", d["kpi"])
        self.assertIn("talkers", d["kpi"])
        self.assertIn("spikes", d["kpi"])
        node0 = d["nodes"][0]
        for key in ("id", "bytes", "vlan"):
            self.assertIn(key, node0)
        edge0 = d["edges"][0]
        for key in ("src", "dst", "rate_bps", "vlan", "proto"):
            self.assertIn(key, edge0)
        proto0 = d["protocols"][0]
        for key in ("proto", "port", "rate_bps"):
            self.assertIn(key, proto0)

    def test_admin_sees_all_tenants_nodes(self):
        r = self._client("adm").get("/api/observability/flowgraph?window=1h")
        ids = {n["id"] for n in r.json()["nodes"]}
        self.assertIn("10.1.0.5", ids)
        self.assertIn("10.2.0.5", ids)

    def test_tenant_scoped_non_admin(self):
        r = self._client("op_a").get("/api/observability/flowgraph?window=1h")
        d = r.json()
        ids = {n["id"] for n in d["nodes"]}
        self.assertIn("10.1.0.5", ids)
        self.assertNotIn("10.2.0.5", ids)
        for e in d["edges"]:
            self.assertNotIn(e["src"], ("10.2.0.5",))
        self.assertEqual(d["kpi"]["spikes"], 1)  # solo l'anomalia 'new' di sede-a

    def test_multi_group_scoped(self):
        r = self._client("op_ab").get("/api/observability/flowgraph?window=1h")
        d = r.json()
        ids = {n["id"] for n in d["nodes"]}
        self.assertIn("10.1.0.5", ids)
        self.assertIn("10.2.0.5", ids)

    def test_window_validation_rejects_garbage(self):
        c = self._client("adm")
        for url in ("/api/observability/flowgraph?window=15m;DROP TABLE x",
                    "/api/observability/flowgraph?window=999999d"):
            r = c.get(url)
            self.assertIn(r.status_code, (400, 422), url)

    def test_anonymous_401(self):
        r = TestClient(app_server.app).get("/api/observability/flowgraph")
        self.assertEqual(r.status_code, 401)

    def test_nodes_edges_consistent(self):
        r = self._client("adm").get("/api/observability/flowgraph?window=1h")
        d = r.json()
        node_ids = {n["id"] for n in d["nodes"]}
        for e in d["edges"]:
            self.assertIn(e["src"], node_ids)
            self.assertIn(e["dst"], node_ids)

    def test_protocols_breakdown_present(self):
        r = self._client("adm").get("/api/observability/flowgraph?window=1h")
        protos = {p["proto"] for p in r.json()["protocols"]}
        self.assertTrue(protos)

    def test_tenant_summary_for_single_group_user(self):
        r = self._client("op_a").get("/api/observability/flowgraph?window=1h")
        t = r.json()["tenant"]
        self.assertEqual(t["name"], "sede-a")
        self.assertIn("vlans", t)
        self.assertIn("flows_shown", t)
        self.assertIn("top_talker", t)

    def test_synthetic_vlan_deterministic_across_calls(self):
        # Fix reviewer #2: la VLAN sintetica di fallback deve essere stabile
        # tra chiamate diverse (niente hash() builtin salato per processo).
        r1 = self._client("adm").get("/api/observability/flowgraph?window=1h")
        r2 = self._client("adm").get("/api/observability/flowgraph?window=1h")
        vlans1 = {n["id"]: n["vlan"] for n in r1.json()["nodes"]}
        vlans2 = {n["id"]: n["vlan"] for n in r2.json()["nodes"]}
        self.assertEqual(vlans1, vlans2)
        from routers.observability import _synthetic_vlan
        self.assertEqual(_synthetic_vlan("sede-a"), _synthetic_vlan("sede-a"))

    def test_synthetic_vlan_marked_not_real(self):
        # Nessun binding ARP seedato in questo dataset: tutte le VLAN sono
        # fallback sintetico e devono essere marcate vlan_real=False (fix #2:
        # niente fake silenzioso).
        r = self._client("adm").get("/api/observability/flowgraph?window=1h")
        d = r.json()
        self.assertTrue(all(n.get("vlan_real") is False for n in d["nodes"]))
        self.assertTrue(all(e.get("vlan_real") is False for e in d["edges"]))

    def test_dst_only_node_has_nonzero_bytes(self):
        # Fix reviewer #4: un host visto solo come dst (mai src) deve avere
        # bytes > 0, non restare a 0 e finire ingiustamente scartato dal
        # cap top-50.
        r = self._client("adm").get("/api/observability/flowgraph?window=1h")
        nodes = {n["id"]: n["bytes"] for n in r.json()["nodes"]}
        # "8.8.8.8" compare solo come dst nei flussi seedati di sede-a.
        self.assertIn("8.8.8.8", nodes)
        self.assertGreater(nodes["8.8.8.8"], 0)

    def test_protocol_breakdown_filtered_by_node_click_is_client_side(self):
        # Il filtro per nodo delle due tabelle è client-side (edges già
        # portano 'proto'): verifichiamo solo che ogni arco esponga i campi
        # necessari a ricostruire il breakdown protocolli filtrato in UI.
        r = self._client("adm").get("/api/observability/flowgraph?window=1h")
        for e in r.json()["edges"]:
            self.assertIn("proto", e)
            self.assertIn("rate_bps", e)


class TestFlowGraphRealVlan(_Base):
    """Fix reviewer #2 (product ruling): se esiste un binding ARP noto per
    l'IP (tabella arp_entries di Client Map), usare quello invece del
    fallback sintetico."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        conn = db.get_observability_connection()
        _seed_flow(conn, "sede-a", "10.1.0.5", "10.1.0.9", nbytes=4000, dport=443)
        conn.commit()
        conn.close()
        from collectors import mac_history
        mac_history.record_arp_entries(
            [{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.1.0.5", "vlan": "210"}],
            source_ip="10.1.0.254", tenant="sede-a")

    def test_real_vlan_used_when_arp_binding_known(self):
        r = self._client("adm").get("/api/observability/flowgraph?window=1h")
        d = r.json()
        node = next(n for n in d["nodes"] if n["id"] == "10.1.0.5")
        self.assertEqual(node["vlan"], 210)
        self.assertTrue(node["vlan_real"])


@classmethod
def _tearDownModule():
    shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
