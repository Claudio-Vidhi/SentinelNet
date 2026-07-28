# -*- coding: utf-8 -*-
"""Carico dell'apparato: la prima regola che legge uno STATO.

Tutte le altre aspettano una transizione, quindi sanno dire "è cambiato" ma non
"è troppo alto". Questa chiude la frase che il documento chiede al motore:
*CPU alta causata dall'aumento di traffico East-West* — carico come sintomo,
traffico come innesco, sulla stessa entità.
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_load_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import correlator, incidents, normalize  # noqa: E402

NOW = int(time.time())
DEVICE = "192.168.31.6"


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
        for table in ("events", "normalize_cursors", "evidence", "incidents",
                      "incident_conclusions", "api_observations",
                      "syslog_events", "flow_aggregates"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def _snapshot(self, ts, metrics, results=None):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO api_observations (ts, tenant, device_ip, kind, summary_json) "
            "VALUES (?, 'sede-a', ?, 'snmp_system', ?)",
            (ts, DEVICE, json.dumps({"results": results or {"name": "SW1"},
                                     "metrics": metrics})))
        conn.commit()
        conn.close()

    def _correlate(self):
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            return correlator.correlate_once(NOW)

    def _rows(self, sql, params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params)]
        finally:
            conn.close()


class TestMeasuresReachTheRules(_Base):

    def test_declared_metrics_land_in_the_event(self):
        self._snapshot(NOW - 60, {"cpu_pct": 91, "memory_pct": 40.5})
        normalize.normalize_once(NOW)
        ev = self._rows("SELECT * FROM events WHERE event_type = 'device.state'")[0]
        self.assertEqual(json.loads(ev["metrics_json"]),
                         {"cpu_pct": 91, "memory_pct": 40.5})

    def test_a_measure_never_counts_as_a_configuration_change(self):
        # Una misura cambia a ogni lettura: è il suo mestiere. Confrontarla
        # produrrebbe un "cambiamento" a ogni giro di polling su ogni apparato.
        self._snapshot(NOW - 300, {"cpu_pct": 10})
        self._snapshot(NOW - 60, {"cpu_pct": 97})
        normalize.normalize_once(NOW)
        self.assertEqual(
            self._rows("SELECT * FROM events WHERE event_type = 'device.change'"),
            [])

    def test_a_snapshot_without_metrics_is_fine(self):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO api_observations (ts, tenant, device_ip, kind, summary_json) "
            "VALUES (?, 'sede-a', ?, 'system_status', ?)",
            (NOW - 60, DEVICE, json.dumps({"results": {"name": "FGT"}})))
        conn.commit()
        conn.close()
        normalize.normalize_once(NOW)
        ev = self._rows("SELECT * FROM events WHERE event_type = 'device.state'")[0]
        self.assertEqual(json.loads(ev["metrics_json"]), {})


class TestLoadRule(_Base):

    def test_cpu_over_threshold_is_a_symptom(self):
        self._snapshot(NOW - 60, {"cpu_pct": 91})
        self._correlate()
        rows = self._rows("SELECT * FROM evidence WHERE rule_id = 'DEVICE_LOAD_001'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["role"], "symptom")
        self.assertIn("CPU al 91%", rows[0]["summary"])

    def test_below_threshold_says_nothing(self):
        self._snapshot(NOW - 60, {"cpu_pct": 40, "memory_pct": 55})
        self._correlate()
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'DEVICE_LOAD_001'"),
            [])

    def test_a_device_that_does_not_expose_load_is_not_reported_as_idle(self):
        # Assente e zero sono cose diverse: una soglia che le confonde tace
        # proprio dove non sta guardando.
        self._snapshot(NOW - 60, {})
        self._correlate()
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'DEVICE_LOAD_001'"),
            [])

    def test_cpu_and_memory_are_two_distinct_symptoms(self):
        self._snapshot(NOW - 60, {"cpu_pct": 95, "memory_pct": 96})
        self._correlate()
        rows = self._rows("SELECT * FROM evidence WHERE rule_id = 'DEVICE_LOAD_001' "
                          "ORDER BY id")
        self.assertEqual([json.loads(r["attrs_json"])["metric"] for r in rows],
                         ["cpu_pct", "memory_pct"])

    def test_load_alone_does_not_claim_a_cause(self):
        """Il punto architetturale: un sintomo senza innesco non inventa una
        causa. Il motore dice che vede un apparato sotto sforzo, non perché."""
        self._snapshot(NOW - 60, {"cpu_pct": 99})
        self._correlate()
        with patch("collectors.mac_history.vlans_for_ips", return_value={}):
            incidents.group_once(NOW)
        inc = self._rows("SELECT * FROM incidents")[0]
        self.assertEqual(inc["cause_kind"], "causa_non_determinata")

    def test_an_incoming_trigger_becomes_the_cause_and_load_stays_the_symptom(self):
        """La forma della frase del documento: il traffico è la causa, il
        carico è ciò che le dà peso."""
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message) "
            "VALUES (?, 'sede-a', ?, 2, 'error', 'link errors rising')",
            (NOW - 60, DEVICE))
        conn.commit()
        conn.close()
        self._snapshot(NOW - 60, {"cpu_pct": 99})
        self._correlate()
        with patch("collectors.mac_history.vlans_for_ips", return_value={}):
            incidents.group_once(NOW)

        inc = self._rows("SELECT * FROM incidents")[0]
        self.assertEqual(inc["cause_kind"], "HIGH_SEVERITY_LOG_001")
        reasoning = json.loads(inc["reasoning_json"])
        self.assertIn("DEVICE_LOAD_001", reasoning["rules_fired"])
        self.assertIn("sintomo_osservato", reasoning["sources_used"])


if __name__ == "__main__":
    unittest.main()
