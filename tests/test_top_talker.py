# -*- coding: utf-8 -*-
"""Principale contributore: l'evidenza che risponde a "perché?".

Terza forma statistica accanto a scostamento ed emergenza, e fenomeno distinto
da entrambe: un host può dominare il traffico restando perfettamente nella
propria abitudine — nessuno scostamento, nessuna emergenza, eppure è lui la
risposta.

Non è un dettaglio di UI: passa dal bus come tutti gli altri fatti, quindi
entra nel ragionamento, nella timeline e nell'API senza percorsi speciali.
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_top_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import baseline, correlator, incidents  # noqa: E402

NOW = int(time.time())
HOUR = (NOW // 3600) * 3600 - 3600      # ora conclusa
BIG = 50_000_000


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
                      "incident_conclusions", "flow_aggregates", "syslog_events"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def _flow(self, src, nbytes, dst="10.1.0.200", tenant="sede-a"):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO flow_aggregates (window_start, tenant, src_ip, dst_ip, "
            "protocol, dst_port, total_bytes, total_packets, flow_count) "
            "VALUES (?, ?, ?, ?, 6, 443, ?, 10, 1)",
            (HOUR + 1800, tenant, src, dst, nbytes))
        conn.commit()
        conn.close()

    def _measure(self):
        conn = db.get_observability_connection()
        try:
            n = baseline.detect_top_contributors(conn, HOUR, NOW)
            conn.commit()
            return n
        finally:
            conn.close()

    def _rows(self, sql, params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params)]
        finally:
            conn.close()


class TestTheMeasure(_Base):
    """L'adapter misura e basta: nessuna soglia, nessun giudizio."""

    def test_the_share_is_computed_over_the_hour(self):
        self._flow("10.1.0.5", 680)
        self._flow("10.1.0.6", 320)
        self._measure()
        rows = self._rows("SELECT * FROM events WHERE event_type = 'flow.top_talker' "
                          "ORDER BY id")
        shares = {r["src_ip"]: json.loads(r["metrics_json"]) for r in rows}
        self.assertEqual(shares["10.1.0.5"]["share_pct"], 68.0)
        self.assertEqual(shares["10.1.0.5"]["rank"], 1)
        self.assertEqual(shares["10.1.0.6"]["rank"], 2)

    def test_it_emits_regardless_of_how_small_the_share_is(self):
        # La soglia di dominanza vive nella regola: l'adapter non decide.
        for i in range(4):
            self._flow(f"10.1.0.{10 + i}", 250)
        self._measure()
        rows = self._rows("SELECT * FROM events WHERE event_type = 'flow.top_talker'")
        self.assertEqual(len(rows), baseline.TOP_CONTRIBUTORS)
        self.assertEqual(json.loads(rows[0]["metrics_json"])["share_pct"], 25.0)

    def test_multicast_chatter_is_not_a_contributor(self):
        """Su una rete reale gli annunci dominano quasi sempre: chiamarli
        'principale contributore' sarebbe vero e inutile."""
        self._flow("224.0.0.251", 9000)
        self._flow("10.1.0.5", 1000)
        self._measure()
        rows = self._rows("SELECT src_ip FROM events "
                          "WHERE event_type = 'flow.top_talker'")
        self.assertEqual([r["src_ip"] for r in rows], ["10.1.0.5"])

    def test_tenants_are_measured_separately(self):
        self._flow("10.1.0.5", 900, tenant="sede-a")
        self._flow("10.2.0.5", 900, tenant="sede-b")
        self._measure()
        rows = self._rows("SELECT * FROM events WHERE event_type = 'flow.top_talker'")
        for r in rows:
            self.assertEqual(json.loads(r["metrics_json"])["share_pct"], 100.0)

    def test_reprojection_updates_instead_of_duplicating(self):
        self._flow("10.1.0.5", 1000)
        self._measure()
        self._flow("10.1.0.6", 1000)
        self._measure()
        rows = self._rows("SELECT * FROM events WHERE event_type = 'flow.top_talker' "
                          "AND src_ip = '10.1.0.5'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]["metrics_json"])["share_pct"], 50.0)


class TestTheRule(_Base):
    """La regola decide cosa sia dominanza, e con quale ruolo entra."""

    def _correlate(self):
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("observability.suppression.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            return correlator.correlate_once(NOW)

    def test_a_dominant_share_becomes_supporting_evidence(self):
        self._flow("10.1.0.5", BIG)
        self._flow("10.1.0.6", BIG // 10)
        self._correlate()
        rows = self._rows("SELECT * FROM evidence WHERE rule_id = 'TOP_TALKER_001'")
        self.assertEqual(len(rows), 1)
        # Una quota alta non è un problema: un backup notturno fa il 90% ed è
        # quello che deve fare. È contesto, non innesco.
        self.assertEqual(rows[0]["role"], "supporting")
        self.assertIn("% del traffico osservato", rows[0]["summary"])

    def test_a_balanced_network_produces_nothing(self):
        for i in range(4):
            self._flow(f"10.1.0.{10 + i}", BIG)
        self._correlate()
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'TOP_TALKER_001'"),
            [])

    def test_a_dominant_share_of_nothing_is_not_a_contribution(self):
        """Su una rete quasi ferma il primo host fa il 90% di pochissimo: la
        quota senza volume descrive il silenzio."""
        self._flow("10.1.0.5", 900)
        self._flow("10.1.0.6", 100)
        self._correlate()
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'TOP_TALKER_001'"),
            [])

    def test_it_explains_an_incident_without_becoming_its_cause(self):
        """La forma che il documento chiede: la causa resta l'innesco, il
        contributore dice PERCHÉ.

        L'innesco è datato all'inizio dell'ora misurata come il contributore:
        due fatti della stessa ora appartengono allo stesso incidente."""
        conn = db.get_observability_connection()
        conn.execute(
            """INSERT INTO evidence (created_ts, ts, tenant, entity_key, role,
                   rule_id, rule_version, params_json, severity, summary, dedup_key)
               VALUES (?, ?, 'sede-a', 'ip:10.1.0.5', 'trigger',
                       'BASELINE_SPIKE_001', '1.0.0', '{}', 4,
                       'traffico +900% rispetto all abitudine', 'spike-test')""",
            (NOW, HOUR))
        conn.commit()
        conn.close()
        self._flow("10.1.0.5", BIG)
        self._flow("10.1.0.6", BIG // 10)
        self._correlate()
        with patch("collectors.mac_history.vlans_for_ips", return_value={}):
            incidents.group_once(NOW)

        inc = next(i for i in self._rows("SELECT * FROM incidents")
                   if i["entity_key"] == "ip:10.1.0.5")
        reasoning = json.loads(inc["reasoning_json"])
        self.assertEqual(inc["cause_kind"], "BASELINE_SPIKE_001")
        self.assertIn("TOP_TALKER_001", reasoning["rules_fired"])
        self.assertIn("evidenza_di_supporto", reasoning["sources_used"])

    def test_hourly_evidence_reaches_an_incident_at_all(self):
        """Regressione: le evidenze orarie portano il timestamp dell'INIZIO
        dell'ora misurata, sempre 60-120 minuti nel passato. Finché il
        raggruppamento le cercava per tempo del FATTO invece che per tempo
        della CONCLUSIONE, non ne raccoglieva nessuna."""
        self._flow("10.1.0.5", BIG)
        self._flow("10.1.0.6", BIG // 10)
        self._correlate()
        with patch("collectors.mac_history.vlans_for_ips", return_value={}):
            self.assertEqual(incidents.group_once(NOW), 1)
        self.assertTrue(self._rows(
            "SELECT * FROM evidence WHERE rule_id = 'TOP_TALKER_001' "
            "AND incident_id IS NOT NULL"))


if __name__ == "__main__":
    unittest.main()
