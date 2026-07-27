# -*- coding: utf-8 -*-
"""Test dell'Incident Engine: l'incidente come vista derivata dalle EVIDENZE.

Copre raggruppamento per entità + gap, chiusura per quiete, ragionamento
basato sui RUOLI (la causa è la regola del trigger) e timeline multi-fonte.
"""

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
from observability import incidents, rules, timeline  # noqa: E402

NOW = int(time.time())


def _seed_evidence(conn, tenant, entity, ts, role="trigger",
                   rule_id="BLOCKED_TRAFFIC_001", rule_version="1.0.0",
                   severity=3, src=None, dst=None, switch_port=None,
                   summary="evidenza di test", params=None, key=None):
    cur = conn.execute(
        """INSERT INTO evidence
               (created_ts, ts, tenant, entity_key, role, rule_id, rule_version,
                params_json, weight, severity, src_ip, dst_ip, switch_port,
                summary, attrs_json, dedup_key)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, '{}', ?)""",
        (ts, ts, tenant, entity, role, rule_id, rule_version,
         json.dumps(params or {}), severity, src, dst, switch_port, summary,
         key or f"k-{tenant}-{entity}-{role}-{rule_id}-{ts}"))
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
        for table in ("evidence", "incidents", "events", "normalize_cursors",
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
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 600)
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 300,
                       role="supporting")
        conn.commit()
        conn.close()

        self.assertEqual(incidents.group_once(NOW), 2)
        rows = self._rows("SELECT * FROM incidents")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_count"], 2)
        self.assertEqual(rows[0]["entity_key"], "ip:10.1.0.5")

    def test_beyond_gap_opens_a_second_incident(self):
        conn = db.get_observability_connection()
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 3000)
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 60)
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        rows = self._rows("SELECT * FROM incidents ORDER BY opened_ts")
        self.assertEqual(len(rows), 2)

    def test_never_merges_across_tenants(self):
        conn = db.get_observability_connection()
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 300)
        _seed_evidence(conn, "sede-b", "ip:10.1.0.5", NOW - 240)
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        rows = self._rows("SELECT tenant FROM incidents ORDER BY tenant")
        self.assertEqual([r["tenant"] for r in rows], ["sede-a", "sede-b"])

    def test_rerun_is_idempotent(self):
        conn = db.get_observability_connection()
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 300)
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 200,
                       role="supporting")
        conn.commit()
        conn.close()

        self.assertEqual(incidents.group_once(NOW), 2)
        self.assertEqual(incidents.group_once(NOW), 0)
        rows = self._rows("SELECT event_count FROM incidents")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_count"], 2)

    def test_close_stale_only_after_quiet_period(self):
        conn = db.get_observability_connection()
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 60)
        _seed_evidence(conn, "sede-b", "ip:10.2.0.5",
                       NOW - incidents.QUIET_S - 120)
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        self.assertEqual(incidents.close_stale(NOW), 1)
        rows = self._rows("SELECT tenant, closed_ts FROM incidents ORDER BY tenant")
        self.assertIsNone(rows[0]["closed_ts"])       # sede-a: ancora attivo
        self.assertIsNotNone(rows[1]["closed_ts"])    # sede-b: silente


class TestReasoning(_Base):

    def test_cause_is_the_rule_of_the_trigger(self):
        conn = db.get_observability_connection()
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 300, role="trigger",
                       rule_id="CFG_CHANGE_001", severity=5)
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 280,
                       role="supporting", rule_id="TRAFFIC_SPIKE_001")
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        row = self._rows("SELECT * FROM incidents")[0]
        self.assertEqual(row["cause_kind"], "CFG_CHANGE_001")
        reasoning = json.loads(row["reasoning_json"])
        # La confidenza deve essere ricostruibile dal percorso pubblicato.
        expected = min(reasoning["base_confidence"]
                       + reasoning["confidence_step"] * len(reasoning["sources_used"]),
                       incidents.CONFIDENCE_MAX)
        self.assertEqual(row["confidence"], expected)
        self.assertEqual(reasoning["base_confidence"],
                         rules.RULES["CFG_CHANGE_001"]["base_confidence"])
        self.assertIn("evidenza_di_supporto", reasoning["sources_used"])
        self.assertIn("piu_regole_concordi", reasoning["sources_used"])

    def test_most_severe_trigger_wins(self):
        conn = db.get_observability_connection()
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 300,
                       rule_id="CFG_CHANGE_001", severity=5)
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 290,
                       rule_id="HIGH_SEVERITY_LOG_001", severity=1)
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        row = self._rows("SELECT * FROM incidents")[0]
        self.assertEqual(row["cause_kind"], "HIGH_SEVERITY_LOG_001")

    def test_roles_are_published_grouped(self):
        conn = db.get_observability_connection()
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 300, role="trigger")
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 290, role="symptom",
                       rule_id="IFACE_DOWN_001")
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        reasoning = json.loads(self._rows("SELECT * FROM incidents")[0]["reasoning_json"])
        self.assertEqual(sorted(reasoning["evidence_by_role"]), ["symptom", "trigger"])
        self.assertIn("sintomo_osservato", reasoning["sources_used"])

    def test_no_trigger_means_no_declared_cause(self):
        # Solo sintomi: non si inventa un innesco che nessuna regola ha dichiarato.
        conn = db.get_observability_connection()
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 300, role="symptom",
                       rule_id="IFACE_DOWN_001")
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        row = self._rows("SELECT * FROM incidents")[0]
        self.assertEqual(row["cause_kind"], "causa_non_determinata")

    def test_rule_provenance_travels_to_the_incident(self):
        conn = db.get_observability_connection()
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 300,
                       rule_id="BLOCKED_TRAFFIC_001", rule_version="9.9.9",
                       params={"match_delta_s": 42})
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        reasoning = json.loads(self._rows("SELECT * FROM incidents")[0]["reasoning_json"])
        self.assertEqual(reasoning["rule_version"], "9.9.9")
        self.assertEqual(reasoning["rule_params"], {"match_delta_s": 42})


class TestTimeline(_Base):

    def test_timeline_merges_sources_in_order(self):
        conn = db.get_observability_connection()
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 300,
                       src="10.1.0.5", dst="8.8.8.8")
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
        self.assertTrue({"evidence", "syslog", "flow", "api"} <=
                        {e["source"] for e in entries})

    def test_evidence_entries_carry_role_and_provenance(self):
        conn = db.get_observability_connection()
        _seed_evidence(conn, "sede-a", "ip:10.1.0.5", NOW - 300, role="symptom",
                       rule_id="IFACE_DOWN_001", rule_version="1.0.0",
                       src="10.1.0.5")
        conn.commit()
        conn.close()

        incidents.group_once(NOW)
        incident_id = self._rows("SELECT id FROM incidents")[0]["id"]
        entry = next(e for e in timeline.build(incident_id)
                     if e["source"] == "evidence")
        self.assertEqual(entry["role"], "symptom")
        self.assertEqual(entry["ref"]["rule_id"], "IFACE_DOWN_001")
        self.assertEqual(entry["ref"]["rule_version"], "1.0.0")

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
