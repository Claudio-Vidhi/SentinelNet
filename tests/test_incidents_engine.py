# -*- coding: utf-8 -*-
"""Test del motore incidenti: raggruppamento per entità + gap, chiusura per
quiete, ragionamento deterministico (causa, confidenza, percorso) e timeline
multi-fonte."""

import json
import os
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_incidents_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import incidents, timeline  # noqa: E402

NOW = int(time.time())


def _seed_event(conn, tenant, src, dst, ts, kind="traffico_bloccato_alto",
                severity=3, switch_port=None, flow_bytes=None, dst_port=443):
    evidence = {"syslog_id": 1, "syslog_ts": ts, "action": "deny"}
    if flow_bytes is not None:
        evidence["flow"] = {"window_start": ts - ts % 60, "protocol": 6,
                            "dst_port": dst_port, "bytes": flow_bytes,
                            "packets": 10}
    cur = conn.execute(
        """INSERT INTO correlated_events
               (created_ts, tenant, kind, src_ip, dst_ip, switch_port, severity,
                status, dedup_key, evidence_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)""",
        (ts, tenant, kind, src, dst, switch_port, severity,
         f"k-{tenant}-{src}-{dst}-{ts}-{dst_port}",
         json.dumps(evidence)))
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

    def setUp(self):
        conn = db.get_observability_connection()
        for table in ("incident_events", "incidents", "correlated_events",
                      "syslog_events", "flow_aggregates", "api_observations"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def _rows(self, sql, params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()


class TestGrouping(_Base):

    def test_same_entity_within_gap_is_one_incident(self):
        conn = db.get_observability_connection()
        _seed_event(conn, "sede-a", "10.1.0.5", "8.8.8.8", NOW - 600)
        _seed_event(conn, "sede-a", "10.1.0.5", "1.1.1.1", NOW - 300)
        conn.commit()
        conn.close()

        linked = incidents.group_once(NOW)
        self.assertEqual(linked, 2)
        rows = self._rows("SELECT * FROM incidents")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_count"], 2)
        self.assertEqual(rows[0]["entity_key"], "ip:10.1.0.5")

    def test_beyond_gap_opens_a_second_incident(self):
        conn = db.get_observability_connection()
        _seed_event(conn, "sede-a", "10.1.0.5", "8.8.8.8", NOW - 3000)
        _seed_event(conn, "sede-a", "10.1.0.5", "8.8.8.8", NOW - 60,
                    dst_port=8080)
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        rows = self._rows("SELECT * FROM incidents ORDER BY opened_ts")
        self.assertEqual(len(rows), 2)
        self.assertEqual([r["event_count"] for r in rows], [1, 1])

    def test_never_merges_across_tenants(self):
        conn = db.get_observability_connection()
        _seed_event(conn, "sede-a", "10.1.0.5", "8.8.8.8", NOW - 300)
        _seed_event(conn, "sede-b", "10.1.0.5", "8.8.8.8", NOW - 240)
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        rows = self._rows("SELECT tenant FROM incidents ORDER BY tenant")
        self.assertEqual([r["tenant"] for r in rows], ["sede-a", "sede-b"])

    def test_rerun_is_idempotent(self):
        conn = db.get_observability_connection()
        _seed_event(conn, "sede-a", "10.1.0.5", "8.8.8.8", NOW - 300)
        _seed_event(conn, "sede-a", "10.1.0.5", "1.1.1.1", NOW - 200)
        conn.commit()
        conn.close()

        self.assertEqual(incidents.group_once(NOW), 2)
        self.assertEqual(incidents.group_once(NOW), 0)
        rows = self._rows("SELECT event_count FROM incidents")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_count"], 2)

    def test_close_stale_only_after_quiet_period(self):
        conn = db.get_observability_connection()
        _seed_event(conn, "sede-a", "10.1.0.5", "8.8.8.8", NOW - 60)
        _seed_event(conn, "sede-b", "10.2.0.5", "8.8.8.8",
                    NOW - incidents.QUIET_S - 120)
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        closed = incidents.close_stale(NOW)
        self.assertEqual(closed, 1)
        rows = self._rows(
            "SELECT tenant, closed_ts FROM incidents ORDER BY tenant")
        self.assertIsNone(rows[0]["closed_ts"])       # sede-a: ancora attivo
        self.assertIsNotNone(rows[1]["closed_ts"])    # sede-b: silente


class TestReasoning(_Base):

    def test_scan_is_recognised_with_reconstructible_confidence(self):
        conn = db.get_observability_connection()
        for i in range(5):
            _seed_event(conn, "sede-a", "10.1.0.5", f"8.8.8.{i}", NOW - 300 + i,
                        flow_bytes=1000, dst_port=1000 + i)
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        row = self._rows("SELECT * FROM incidents")[0]
        self.assertEqual(row["cause_kind"], "scan_bloccato")
        reasoning = json.loads(row["reasoning_json"])
        self.assertIn("scan_bloccato", reasoning["rules_fired"])
        # La confidenza deve essere ricostruibile dal percorso pubblicato.
        expected = min(reasoning["base_confidence"]
                       + reasoning["confidence_step"] * len(reasoning["sources_used"]),
                       incidents.CONFIDENCE_MAX)
        self.assertEqual(row["confidence"], expected)
        self.assertIn("flow_aggregates", reasoning["sources_used"])
        self.assertEqual(len(reasoning["evidence_refs"]), 5)

    def test_switch_port_counts_as_corroborating_source(self):
        conn = db.get_observability_connection()
        _seed_event(conn, "sede-a", "10.1.0.7", "8.8.8.8", NOW - 300,
                    switch_port="sw01:Gi1/0/12")
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        row = self._rows("SELECT * FROM incidents")[0]
        reasoning = json.loads(row["reasoning_json"])
        self.assertIn("switch_port", reasoning["sources_used"])
        self.assertEqual(row["cause_kind"], "evento_critico_isolato")
        self.assertEqual(row["confidence"],
                         45 + incidents.CONFIDENCE_STEP * len(reasoning["sources_used"]))

    def test_repeated_block_on_one_pair(self):
        conn = db.get_observability_connection()
        for i in range(3):
            _seed_event(conn, "sede-a", "10.1.0.9", "203.0.113.7", NOW - 300 + i,
                        dst_port=443 + i)
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        row = self._rows("SELECT * FROM incidents")[0]
        self.assertEqual(row["cause_kind"], "traffico_bloccato_ripetuto")


class TestTimeline(_Base):

    def test_timeline_merges_sources_in_order(self):
        conn = db.get_observability_connection()
        _seed_event(conn, "sede-a", "10.1.0.5", "8.8.8.8", NOW - 300,
                    flow_bytes=2048)
        conn.execute(
            "INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, "
            "message) VALUES (?, 'sede-a', '10.1.0.254', 3, 'deny', ?)",
            (NOW - 290, "denied srcip=10.1.0.5 dstip=8.8.8.8"))
        conn.execute(
            "INSERT INTO flow_aggregates (window_start, tenant, src_ip, dst_ip, "
            "protocol, dst_port, total_bytes, total_packets, flow_count) "
            "VALUES (?, 'sede-a', '10.1.0.5', '8.8.8.8', 6, 443, 4096, 20, 2)",
            ((NOW - 280) - ((NOW - 280) % 60),))
        conn.execute(
            "INSERT INTO api_observations (ts, tenant, device_ip, kind, "
            "summary_json) VALUES (?, 'sede-a', '10.1.0.5', 'system_status', '{}')",
            (NOW - 270,))
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        incident_id = self._rows("SELECT id FROM incidents")[0]["id"]
        entries = timeline.build(incident_id)

        self.assertEqual([e["ts"] for e in entries],
                         sorted(e["ts"] for e in entries))
        sources = {e["source"] for e in entries}
        self.assertTrue({"correlated", "syslog", "flow", "api"} <= sources)

    def test_iso_timestamps_are_converted_not_compared(self):
        # mac_history usa ISO-8601, observability.db usa unix: la conversione
        # avviene nel builder, mai un confronto diretto fra i due formati.
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(NOW - 100))
        self.assertEqual(timeline._iso_to_unix(stamp), NOW - 100)
        self.assertIsNone(timeline._iso_to_unix("non-una-data"))
        self.assertIsNone(timeline._iso_to_unix(""))

    def test_unknown_incident_has_empty_timeline(self):
        self.assertEqual(timeline.build(999999), [])


if __name__ == "__main__":
    unittest.main()
