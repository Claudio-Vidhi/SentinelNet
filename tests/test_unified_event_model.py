# -*- coding: utf-8 -*-
"""Test del modello eventi unificato: adapter di normalizzazione, cursori,
idempotenza, rilevamento variazioni sugli snapshot REST e scoping tenant del
feed normalizzato."""

import json
import os
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_uem_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
from core import db  # noqa: E402
from observability import fieldmap, normalize  # noqa: E402
from security import user_manager  # noqa: E402

PASS = "PasswordSicura1!"
NOW = int(time.time())
FGT_MSG = ('action="blocked" srcip=10.1.0.5 dstip=203.0.113.7 dstport=443 '
           'proto=6 sentbyte=1200 rcvdbyte=800')


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

    def setUp(self):
        conn = db.get_observability_connection()
        for table in ("events", "normalize_cursors", "syslog_events",
                      "flow_aggregates", "api_observations"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def _events(self, where="1=1", params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(
                f"SELECT * FROM events WHERE {where} ORDER BY id", params)]
        finally:
            conn.close()


class TestFieldmap(unittest.TestCase):
    """L'estrattore condiviso deve dare LO STESSO risultato a chiunque lo usi:
    prima esisteva in due copie con set di campi diversi."""

    def test_fortigate_kv(self):
        fields = fieldmap.extract(FGT_MSG)
        self.assertEqual(fields["src_ip"], "10.1.0.5")
        self.assertEqual(fields["dst_ip"], "203.0.113.7")
        self.assertEqual(fields["dst_port"], 443)
        self.assertEqual(fields["protocol"], "TCP")
        self.assertEqual(fields["bytes"], 2000)

    def test_generic_falls_back_to_first_two_ips(self):
        fields = fieldmap.extract("connection from 10.2.0.9 to 10.2.0.20 closed")
        self.assertEqual((fields["src_ip"], fields["dst_ip"]),
                         ("10.2.0.9", "10.2.0.20"))
        self.assertIsNone(fields["dst_port"])

    def test_nothing_extractable_stays_none(self):
        fields = fieldmap.extract("kernel panic")
        self.assertIsNone(fields["src_ip"])
        self.assertIsNone(fields["bytes"])


class TestAdapters(_Base):

    def test_syslog_becomes_a_normalized_event(self):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, "
            "message) VALUES (?, 'sede-a', '10.1.0.254', 4, 'blocked', ?)",
            (NOW - 60, FGT_MSG))
        conn.commit()
        conn.close()

        normalize.normalize_once(NOW)
        rows = self._events("source = 'syslog'")
        self.assertEqual(len(rows), 1)
        ev = rows[0]
        self.assertEqual(ev["event_type"], "log.security")
        self.assertEqual(ev["entity_type"], "device")
        self.assertEqual(ev["src_ip"], "10.1.0.5")
        self.assertEqual(ev["dst_port"], 443)
        self.assertEqual(json.loads(ev["attrs_json"])["action"], "blocked")

    def test_non_security_syslog_is_a_plain_event(self):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, "
            "message) VALUES (?, 'sede-a', '10.1.0.254', 6, 'accept', 'ok')",
            (NOW - 60,))
        conn.commit()
        conn.close()

        normalize.normalize_once(NOW)
        self.assertEqual(self._events("source = 'syslog'")[0]["event_type"],
                         "log.event")

    def test_flow_becomes_an_event_and_refreshes_on_reread(self):
        window = (NOW - 120) - ((NOW - 120) % 60)
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO flow_aggregates (window_start, tenant, src_ip, dst_ip, "
            "protocol, dst_port, total_bytes, total_packets, flow_count, source) "
            "VALUES (?, 'sede-a', '10.1.0.5', '8.8.8.8', 6, 443, 1000, 10, 1, 'ipfix')",
            (window,))
        conn.commit()
        conn.close()

        normalize.normalize_once(NOW)
        ev = self._events("event_type = 'flow.aggregate'")[0]
        self.assertEqual(ev["entity_id"], "10.1.0.5>8.8.8.8")
        self.assertEqual(ev["protocol"], "TCP")
        self.assertEqual(json.loads(ev["metrics_json"])["bytes"], 1000)

        # Il bucket ancora aperto viene aggiornato in place dall'ingestione:
        # la riproiezione deve aggiornare le metriche, non ignorarle.
        conn = db.get_observability_connection()
        conn.execute("UPDATE flow_aggregates SET total_bytes = 5000")
        conn.commit()
        conn.close()

        normalize.normalize_once(NOW)
        rows = self._events("event_type = 'flow.aggregate'")
        self.assertEqual(len(rows), 1)          # nessun doppione
        self.assertEqual(json.loads(rows[0]["metrics_json"])["bytes"], 5000)

    def test_rerun_is_idempotent(self):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, "
            "message) VALUES (?, 'sede-a', '10.1.0.254', 4, 'blocked', ?)",
            (NOW - 60, FGT_MSG))
        conn.commit()
        conn.close()

        normalize.normalize_once(NOW)
        counts = normalize.normalize_once(NOW)
        self.assertEqual(counts["syslog"], 0)   # cursore avanzato
        self.assertEqual(len(self._events("source = 'syslog'")), 1)

    def test_tenant_is_preserved_never_defaulted(self):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, "
            "message) VALUES (?, 'sede-b', '10.2.0.254', 3, 'deny', ?)",
            (NOW - 60, FGT_MSG))
        conn.commit()
        conn.close()

        normalize.normalize_once(NOW)
        self.assertEqual(self._events()[0]["tenant"], "sede-b")


class TestDeviceChangeDetection(_Base):

    def _snapshot(self, conn, payload, ts):
        conn.execute(
            "INSERT INTO api_observations (ts, tenant, device_ip, kind, "
            "summary_json) VALUES (?, 'sede-a', '10.1.0.254', 'system_status', ?)",
            (ts, json.dumps(payload)))

    def test_changed_stable_field_emits_device_change(self):
        conn = db.get_observability_connection()
        self._snapshot(conn, {"results": {"version": "v7.2.5", "hostname": "FGT1"}},
                       NOW - 600)
        self._snapshot(conn, {"results": {"version": "v7.4.1", "hostname": "FGT1"}},
                       NOW - 300)
        conn.commit()
        conn.close()

        normalize.normalize_once(NOW)
        changes = self._events("event_type = 'device.change'")
        self.assertEqual(len(changes), 1)
        attrs = json.loads(changes[0]["attrs_json"])
        self.assertEqual(attrs["field"], "results.version")
        self.assertEqual(attrs["before"], "v7.2.5")
        self.assertEqual(attrs["after"], "v7.4.1")

    def test_volatile_counters_do_not_produce_changes(self):
        conn = db.get_observability_connection()
        self._snapshot(conn, {"results": {"version": "v7.2.5", "uptime": 100,
                                          "tx_bytes": 10}}, NOW - 600)
        self._snapshot(conn, {"results": {"version": "v7.2.5", "uptime": 400,
                                          "tx_bytes": 999}}, NOW - 300)
        conn.commit()
        conn.close()

        normalize.normalize_once(NOW)
        self.assertEqual(self._events("event_type = 'device.change'"), [])

    def test_truncated_payload_invents_nothing(self):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO api_observations (ts, tenant, device_ip, kind, "
            "summary_json) VALUES (?, 'sede-a', '10.1.0.254', 'system_status', ?)",
            (NOW - 600, '{"results": {"version": "v7.2'))     # JSON troncato
        self._snapshot(conn, {"results": {"version": "v7.4.1"}}, NOW - 300)
        conn.commit()
        conn.close()

        normalize.normalize_once(NOW)
        self.assertEqual(self._events("event_type = 'device.change'"), [])
        self.assertEqual(len(self._events("event_type = 'device.state'")), 2)


class TestEventsApi(_Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        for user, role, groups in (("adm_uem", "admin", None),
                                   ("op_uem_a", "operator", ["sede-a"])):
            try:
                user_manager.create_user(user, PASS, role=role, groups=groups)
            except Exception:
                pass

    def setUp(self):
        super().setUp()
        conn = db.get_observability_connection()
        for tenant, device in (("sede-a", "10.1.0.254"), ("sede-b", "10.2.0.254")):
            conn.execute(
                "INSERT INTO syslog_events (ts, tenant, device_ip, severity, "
                "action, message) VALUES (?, ?, ?, 4, 'blocked', ?)",
                (NOW - 60, tenant, device, FGT_MSG))
        conn.commit()
        conn.close()
        normalize.normalize_once(NOW)

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200, r.text
        return c

    def test_feed_is_tenant_scoped(self):
        c = self._client("op_uem_a")
        r = c.get("/api/observability/events?window=1h")
        self.assertEqual(r.status_code, 200)
        self.assertEqual({e["tenant"] for e in r.json()["events"]}, {"sede-a"})

    def test_admin_sees_every_tenant(self):
        c = self._client("adm_uem")
        r = c.get("/api/observability/events?window=1h")
        self.assertEqual(len(r.json()["events"]), 2)

    def test_filter_by_event_type(self):
        c = self._client("adm_uem")
        r = c.get("/api/observability/events?window=1h&event_type=device.state")
        self.assertEqual(r.json()["events"], [])


if __name__ == "__main__":
    unittest.main()
