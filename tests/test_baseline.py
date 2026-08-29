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
        """Ritorna quante misure di BASELINE sono state emesse.

        Non il totale di ``compute_once``: l'adapter statistico emette anche
        emergenze e contributori principali, che sono fenomeni distinti e non
        devono far cambiare i conti di questi test."""
        conn = db.get_observability_connection()
        try:
            baseline.compute_once(conn, NOW)
            conn.commit()
            return conn.execute(
                "SELECT COUNT(*) FROM events WHERE event_type = 'flow.baseline'"
            ).fetchone()[0] - getattr(self, "_seen_baselines", 0)
        finally:
            self._seen_baselines = conn.execute(
                "SELECT COUNT(*) FROM events WHERE event_type = 'flow.baseline'"
            ).fetchone()[0]
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


class TestBaselineQuality(_Base):
    """La qualità deve essere SPIEGABILE: fra sei mesi la domanda 'perché
    quality è 0.41?' deve avere la risposta già nei dati."""

    def test_quality_carries_the_factors_that_produced_it(self):
        conn = db.get_observability_connection()
        self._seed_weeks(conn, [1000, 1000, 1000, 1000])
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 5000)
        conn.commit()
        conn.close()

        self._compute()
        ev = self._baseline_events()[0]
        m = json.loads(ev["metrics_json"])
        attrs = json.loads(ev["attrs_json"])
        self.assertEqual(m["quality"], 0.5)          # 1.0 * 4/8
        self.assertEqual(attrs["quality_label"], "MEDIUM")
        reason = attrs["quality_reason"]
        self.assertEqual(reason["samples"], 4)
        self.assertEqual(reason["method"], "stesso_giorno_stessa_ora")
        self.assertEqual(reason["method_weight"], 1.0)
        # Il valore è ricalcolabile dai soli fattori pubblicati.
        self.assertEqual(
            round(reason["method_weight"] * reason["sample_score"], 2),
            m["quality"])

    def test_rolling_average_is_worth_less_than_seasonal(self):
        conn = db.get_observability_connection()
        for day in (1, 2, 3, 4):
            self._flow(conn, TARGET_HOUR - 86400 * day, "10.1.0.5", 1000)
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 1000)
        conn.commit()
        conn.close()

        self._compute()
        m = json.loads(self._baseline_events()[0]["metrics_json"])
        self.assertEqual(m["quality"], 0.35)         # 0.7 * 4/8
        self.assertEqual(
            json.loads(self._baseline_events()[0]["attrs_json"])["quality_label"],
            "LOW")


class TestEmergence(_Base):
    """Un host che compare dal nulla non è una deviazione: non ha un'abitudine
    da cui discostarsi."""

    def test_never_seen_host_produces_an_emergence_fact(self):
        conn = db.get_observability_connection()
        # Storia profonda del tenant, ma prodotta da un ALTRO host.
        for day in range(1, 15):
            self._flow(conn, TARGET_HOUR - 86400 * day, "10.1.0.9", 500)
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 90000)
        conn.commit()
        conn.close()

        self._compute()
        rows = self._rows("SELECT * FROM events WHERE event_type = 'flow.emergence'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["src_ip"], "10.1.0.5")
        self.assertEqual(json.loads(rows[0]["metrics_json"])["observed"], 90000)

    def test_host_known_at_another_hour_is_not_new(self):
        """La trappola evitata: chi parla alle 09:00 ma mai a quest'ora NON è
        nuovo. La domanda è 'mai visto', non 'mai visto in quest'ora'."""
        conn = db.get_observability_connection()
        for day in range(1, 15):
            self._flow(conn, TARGET_HOUR - 86400 * day, "10.1.0.9", 500)
            # Stesso host, ma sempre in un'ora diversa da quella misurata.
            self._flow(conn, TARGET_HOUR - 86400 * day - 5 * HOUR,
                       "10.1.0.5", 700)
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 90000)
        conn.commit()
        conn.close()

        self._compute()
        self.assertEqual(
            self._rows("SELECT * FROM events WHERE event_type = 'flow.emergence'"),
            [])

    def test_fresh_install_does_not_flood(self):
        # Senza storia alle spalle sarebbe nuovo tutto, e non vorrebbe dir nulla.
        conn = db.get_observability_connection()
        self._flow(conn, TARGET_HOUR - 600, "10.1.0.9", 500)
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 90000)
        conn.commit()
        conn.close()

        self._compute()
        self.assertEqual(
            self._rows("SELECT * FROM events WHERE event_type = 'flow.emergence'"),
            [])

    def test_new_talker_rule_turns_it_into_a_trigger(self):
        conn = db.get_observability_connection()
        for day in range(1, 15):
            self._flow(conn, TARGET_HOUR - 86400 * day, "10.1.0.9", 500)
        self._flow(conn, TARGET_HOUR, "10.1.0.5", 90000)
        conn.commit()
        conn.close()

        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        rows = self._rows("SELECT * FROM evidence WHERE rule_id = 'NEW_TALKER_001'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["role"], "trigger")
        self.assertIn("mai osservato", rows[0]["summary"])


class TestCatalogKnowledge(_Base):
    """Il catalogo dice quali regole esistono E cosa farci: è la knowledge base
    per gli eventi a runtime, derivata dal codice invece che scritta a parte."""

    def test_every_rule_declares_investigation_and_remediation(self):
        for entry in rules.catalog():
            self.assertTrue(entry["investigation"],
                            f"{entry['id']} senza indicazioni di verifica")
            self.assertTrue(entry["remediation"],
                            f"{entry['id']} senza rimedio")

    def test_catalog_supports_italian_and_english(self):
        it_cat = {r["id"]: r for r in rules.catalog(lang="it")}
        en_cat = {r["id"]: r for r in rules.catalog(lang="en")}
        self.assertEqual(len(it_cat), len(en_cat))
        for rule_id, it_rule in it_cat.items():
            en_rule = en_cat[rule_id]
            self.assertTrue(en_rule["title"])
            self.assertTrue(en_rule["description"])
            self.assertTrue(en_rule["investigation"])
            self.assertTrue(en_rule["remediation"])
            self.assertNotEqual(it_rule["title"], en_rule["title"],
                                f"{rule_id} title not localized in English")

    def test_a_rule_can_only_produce_what_it_declares(self):
        self.assertTrue(rules.declares_output("IFACE_RECOVERED_001", "retraction"))
        self.assertFalse(rules.declares_output("IFACE_DOWN_001", "retraction"))
        self.assertTrue(rules.declares_output("BLOCKED_TRAFFIC_001", "supporting"))
        self.assertFalse(rules.declares_output("BLOCKED_TRAFFIC_001", "symptom"))

    def test_undeclared_output_is_refused_not_stored(self):
        """Il catalogo è una promessa verificata: se una regola producesse un
        ruolo non dichiarato, l'evidenza viene scartata invece di contraddire
        ciò che UI, AI e documentazione leggono dal catalogo."""
        rogue = dict(rules.RULES["IFACE_DOWN_001"])
        rogue["outputs"] = ["symptom"]
        rogue["check"] = lambda events, p: [rules.Finding(
            event_id=None, ts=NOW - 60, tenant="sede-a", role="trigger",
            entity_key="ip:10.1.0.5", summary="ruolo non dichiarato")]
        with patch.dict(rules.RULES, {"ROGUE_001": rogue}), \
             patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'ROGUE_001'"), [])


class TestBaselineRules(_Base):

    def _correlate(self):
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            return correlator.correlate_once(NOW)

    def test_a_multicast_burst_is_not_a_conversation(self):
        """Un annuncio verso multicast è traffico reale, ma non è due host che
        si parlano: da solo non deve diventare un picco."""
        conn = db.get_observability_connection()
        for i in range(6):
            self._flow(conn, TARGET_HOUR, f"10.1.0.{10 + i}", 100,
                       dst="224.0.0.251")
        self._flow(conn, TARGET_HOUR, "10.1.0.99", 100000, dst="224.0.0.251")
        conn.commit()
        conn.close()

        self._correlate()
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'TRAFFIC_SPIKE_001'"),
            [])

    def test_chatter_no_longer_sets_the_reference(self):
        """Il difetto vero: con la chiacchiera dentro il confronto, la mediana
        descrive gli annunci e un picco reale fra due host ci sparisce sotto."""
        conn = db.get_observability_connection()
        for i in range(6):
            self._flow(conn, TARGET_HOUR, f"10.1.0.{10 + i}", 100,
                       dst="10.1.0.200")
        self._flow(conn, TARGET_HOUR, "10.1.0.99", 100000, dst="10.1.0.200")
        # Dieci bucket di scoperta molto più grossi: se entrassero nel
        # confronto, la mediana passerebbe da 100 a 50.000 e il picco reale
        # (100.000, cioè 10x su 100) non raggiungerebbe più la soglia.
        for i in range(10):
            self._flow(conn, TARGET_HOUR, f"10.2.0.{10 + i}", 50000,
                       dst="239.255.255.250")
        conn.commit()
        conn.close()

        self._correlate()
        rows = self._rows(
            "SELECT * FROM evidence WHERE rule_id = 'TRAFFIC_SPIKE_001'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["entity_key"], "ip:10.1.0.99")
        self.assertEqual(json.loads(rows[0]["attrs_json"])["direction"],
                         "east_west")

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
        # Quattro campioni stagionali: qualità 0.5, il minimo per RITRATTARE.
        # Con tre (qualità 0.375) la regola di scoperta scatterebbe comunque,
        # ma quella di ritrattazione no — è l'asimmetria voluta.
        self._seed_weeks(conn, [100000, 100000, 100000, 100000])
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
        # Quattro campioni stagionali: qualità 0.5, il minimo per RITRATTARE.
        # Con tre (qualità 0.375) la regola di scoperta scatterebbe comunque,
        # ma quella di ritrattazione no — è l'asimmetria voluta.
        self._seed_weeks(conn, [100000, 100000, 100000, 100000])
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
        self.assertEqual(names, {"min_deviation_pct", "min_quality"})
        # Ritrattare richiede più fiducia che concludere.
        def _min_quality(rule_id):
            return next(p["default"] for p in catalog[rule_id]["parameters"]
                        if p["name"] == "min_quality")
        self.assertGreater(_min_quality("BASELINE_NORMAL_RETRACT_001"),
                           _min_quality("BASELINE_SPIKE_001"))


if __name__ == "__main__":
    unittest.main()
