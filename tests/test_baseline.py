# -*- coding: utf-8 -*-
"""Test del Baseline Engine.

Il baseline è un ADAPTER: misura e scrive un fatto (``flow.baseline``), non
conclude nulla e non ritratta niente. Sono le regole a decidere se lo
scostamento è un picco o la conferma della normalità.

Copre anche il principio del documento — niente allarmi da picchi temporanei —
che qui si realizza in due modi: senza storia sufficiente non si emette alcuna
baseline, e con storia che dice "normale" il picco di finestra viene ritrattato
invece di restare a fare rumore.
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_baseline_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import baseline, correlator, incidents, rules  # noqa: E402

HOUR = baseline.HOUR_S
# Ora conclusa su cui si misura, e "adesso" collocato nell'ora successiva.
TARGET_HOUR = (int(time.time()) // HOUR) * HOUR - HOUR
NOW = TARGET_HOUR + HOUR + 600


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
        for table in ("evidence", "incident_conclusions", "incidents", "events",
                      "normalize_cursors", "flow_aggregates", "syslog_events"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def _flow(self, conn, hour, src, nbytes, tenant="sede-a", dst="8.8.8.8"):
        # Tardi dentro l'ora: così i flussi dell'ora appena conclusa rientrano
        # anche nella finestra di normalizzazione, come accade in esercizio.
        conn.execute(
            "INSERT INTO flow_aggregates (window_start, tenant, src_ip, dst_ip, "
            "protocol, dst_port, total_bytes, total_packets, flow_count) "
            "VALUES (?, ?, ?, ?, 6, 443, ?, 10, 1)",
            (hour + 3000, tenant, src, dst, nbytes))

    def _seed_weeks(self, conn, values, src="10.1.0.5", tenant="sede-a"):
        """Un campione per ognuna delle settimane precedenti, stessa ora."""
        for week, value in enumerate(values, start=1):
            self._flow(conn, TARGET_HOUR - 7 * 86400 * week, src, value,
                       tenant=tenant)

    def _rows(self, sql, params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    def _baseline_events(self):
        return self._rows("SELECT * FROM events WHERE event_type = 'flow.baseline'")

    def _compute(self):
        conn = db.get_observability_connection()
        try:
            emitted = baseline.compute_once(conn, NOW)
            conn.commit()
            return emitted
        finally:
            conn.close()


class TestBaselineAdapter(_Base):

    def test_deviation_is_measured_against_the_same_weekday_and_hour(self):
        conn = db.get_observability_connection()
        self._seed_weeks(conn, [1000, 1000, 1000])
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 5000)
        conn.commit()
        conn.close()

        self.assertEqual(self._compute(), 1)
        ev = self._baseline_events()[0]
        m = json.loads(ev["metrics_json"])
        self.assertEqual(m["observed"], 5000)
        self.assertEqual(m["expected"], 1000)
        self.assertEqual(m["deviation_pct"], 400.0)
        self.assertEqual(m["samples"], 3)
        self.assertEqual(json.loads(ev["attrs_json"])["method"],
                         "stesso_giorno_stessa_ora")
        self.assertEqual(ev["entity_type"], "flow")
        self.assertEqual(ev["source"], "baseline")

    def test_without_enough_history_nothing_is_invented(self):
        # Un solo campione storico: sotto MIN_SAMPLES non si emette baseline.
        conn = db.get_observability_connection()
        self._seed_weeks(conn, [1000])
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 999999)
        conn.commit()
        conn.close()

        self.assertEqual(self._compute(), 0)
        self.assertEqual(self._baseline_events(), [])

    def test_falls_back_to_rolling_average_when_weeks_are_missing(self):
        conn = db.get_observability_connection()
        for day in (1, 2, 3):
            self._flow(conn, TARGET_HOUR - 86400 * day, "10.1.0.5", 2000)
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 2000)
        conn.commit()
        conn.close()

        self.assertEqual(self._compute(), 1)
        ev = self._baseline_events()[0]
        self.assertEqual(json.loads(ev["attrs_json"])["method"],
                         "media_mobile_stessa_ora")
        self.assertEqual(json.loads(ev["metrics_json"])["deviation_pct"], 0.0)

    def test_hours_without_collection_are_not_counted_as_zero(self):
        # Due settimane con dati, due senza NULLA (collettore fermo): i
        # campioni validi sono due, non quattro, e la mediana non crolla.
        conn = db.get_observability_connection()
        self._seed_weeks(conn, [1000, 1000])
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 3000)
        conn.commit()
        conn.close()

        self._compute()
        m = json.loads(self._baseline_events()[0]["metrics_json"])
        self.assertEqual(m["samples"], 2)
        self.assertEqual(m["expected"], 1000)

    def test_a_host_absent_in_a_live_hour_counts_as_zero(self):
        # Il collettore c'era (un altro talker trasmetteva) ma questo host no:
        # quello è uno zero VERO, non un buco di raccolta, e va contato come
        # campione. Con [1000, 1000, 0] la mediana resta 1000.
        conn = db.get_observability_connection()
        for week in (1, 2, 3):
            self._flow(conn, TARGET_HOUR - 7 * 86400 * week, "10.1.0.9", 500)
        for week in (1, 2):
            self._flow(conn, TARGET_HOUR - 7 * 86400 * week, "10.1.0.5", 1000)
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 1000)
        conn.commit()
        conn.close()

        self._compute()
        target = [e for e in self._baseline_events() if e["src_ip"] == "10.1.0.5"]
        self.assertEqual(len(target), 1)
        m = json.loads(target[0]["metrics_json"])
        self.assertEqual(m["samples"], 3)       # tre ore vive, una a zero
        self.assertEqual(m["expected"], 1000)
        self.assertEqual(m["deviation_pct"], 0.0)

    def test_new_talker_is_not_reported_as_a_deviation(self):
        # Atteso zero: non è uno scostamento da un'abitudine, è una cosa che
        # prima non c'era. Fatto diverso, non lo si spaccia per questo.
        conn = db.get_observability_connection()
        for week in (1, 2, 3):
            self._flow(conn, TARGET_HOUR - 7 * 86400 * week, "10.1.0.9", 500)
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 9000)
        conn.commit()
        conn.close()

        self._compute()
        self.assertEqual([e for e in self._baseline_events()
                          if e["src_ip"] == "10.1.0.5"], [])

    def test_current_hour_is_not_measured_while_still_open(self):
        current = (NOW // HOUR) * HOUR
        conn = db.get_observability_connection()
        self._seed_weeks(conn, [1000, 1000, 1000])
        self._flow(conn, current, "10.1.0.5", 50)
        conn.commit()
        conn.close()

        self._compute()
        self.assertEqual([e for e in self._baseline_events() if e["ts"] == current],
                         [])

    def test_rerun_is_idempotent(self):
        conn = db.get_observability_connection()
        self._seed_weeks(conn, [1000, 1000, 1000])
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 5000)
        conn.commit()
        conn.close()

        self.assertEqual(self._compute(), 1)
        self.assertEqual(self._compute(), 0)   # cursore avanzato
        self.assertEqual(len(self._baseline_events()), 1)

    def test_tenants_never_share_a_baseline(self):
        conn = db.get_observability_connection()
        self._seed_weeks(conn, [1000, 1000, 1000])
        for week in (1, 2, 3):
            self._flow(conn, TARGET_HOUR - 7 * 86400 * week, "10.1.0.5", 50000,
                       tenant="sede-b")
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 5000)
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 50000, tenant="sede-b")
        conn.commit()
        conn.close()

        self._compute()
        by_tenant = {e["tenant"]: json.loads(e["metrics_json"])
                     for e in self._baseline_events()}
        self.assertEqual(by_tenant["sede-a"]["expected"], 1000)
        self.assertEqual(by_tenant["sede-b"]["expected"], 50000)


class TestBaselineRules(_Base):

    def _correlate(self):
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            return correlator.correlate_once(NOW)

    def test_spike_against_history_becomes_a_trigger(self):
        conn = db.get_observability_connection()
        self._seed_weeks(conn, [1000, 1000, 1000])
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 5000)
        conn.commit()
        conn.close()

        self._correlate()
        rows = self._rows(
            "SELECT * FROM evidence WHERE rule_id = 'BASELINE_SPIKE_001'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["role"], "trigger")
        self.assertEqual(rows[0]["entity_key"], "ip:10.1.0.5")
        self.assertIn("abitudine", rows[0]["summary"])

    def test_deviation_below_threshold_produces_no_evidence(self):
        conn = db.get_observability_connection()
        self._seed_weeks(conn, [1000, 1000, 1000])
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 1200)   # +20%
        conn.commit()
        conn.close()

        self._correlate()
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'BASELINE_SPIKE_001'"),
            [])

    def test_history_saying_normal_retracts_the_window_spike(self):
        """Lo scenario del documento: un picco apparente che lo storico smonta.

        Il picco di finestra (TRAFFIC_SPIKE_001) guarda solo i vicini; il
        baseline dice che per quell'ora è normale. L'evidenza non sparisce:
        diventa ritrattata, con il motivo.
        """
        conn = db.get_observability_connection()
        # Storia: quel talker fa sempre 100k in quell'ora.
        self._seed_weeks(conn, [100000, 100000, 100000])
        # Ora corrente: stesso volume di sempre, ma molto sopra i vicini di
        # finestra, quindi TRAFFIC_SPIKE_001 lo segnala.
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 100000)
        for i, ip in enumerate(("10.1.0.6", "10.1.0.7", "10.1.0.8", "10.1.0.9")):
            self._flow(conn, TARGET_HOUR, ip, 100)
        conn.commit()
        conn.close()

        self._correlate()
        spike = self._rows(
            "SELECT * FROM evidence WHERE rule_id = 'TRAFFIC_SPIKE_001' "
            "AND entity_key = 'ip:10.1.0.5'")
        self.assertEqual(len(spike), 1)
        self.assertEqual(spike[0]["status"], "retracted")
        self.assertEqual(spike[0]["retracted_by_rule_id"],
                         "BASELINE_NORMAL_RETRACT_001")
        self.assertIn("norma", spike[0]["retracted_reason"])

    def test_retracted_spike_does_not_support_the_conclusion(self):
        conn = db.get_observability_connection()
        self._seed_weeks(conn, [100000, 100000, 100000])
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 100000)
        for ip in ("10.1.0.6", "10.1.0.7", "10.1.0.8", "10.1.0.9"):
            self._flow(conn, TARGET_HOUR, ip, 100)
        conn.commit()
        conn.close()

        self._correlate()
        incidents.group_once(NOW)
        for row in self._rows("SELECT * FROM incidents WHERE entity_key = 'ip:10.1.0.5'"):
            reasoning = json.loads(row["reasoning_json"] or "{}")
            self.assertNotIn("TRAFFIC_SPIKE_001", reasoning.get("rules_fired", []))

    def test_baseline_rules_are_in_the_catalog(self):
        catalog = {r["id"]: r for r in rules.catalog()}
        self.assertIn("flow.baseline", catalog["BASELINE_SPIKE_001"]["inputs"])
        self.assertIn("retraction",
                      catalog["BASELINE_NORMAL_RETRACT_001"]["outputs"])
        names = {p["name"] for p in catalog["BASELINE_SPIKE_001"]["parameters"]}
        self.assertEqual(names, {"min_deviation_pct", "min_samples"})


if __name__ == "__main__":
    unittest.main()
