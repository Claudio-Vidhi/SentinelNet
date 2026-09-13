# -*- coding: utf-8 -*-
"""Conferma prima di concludere (roadmap §1, voce 3).

Il punto su cui la roadmap non e' d'accordo con Nagios: la ritrattazione
agisce DOPO aver concluso, e con un motore di notifiche "ho concluso, poi ho
ritrattato" vuol dire che qualcuno e' gia' stato svegliato. Non serve la
macchina a stati HARD/SOFT: basta che una regola dichiari quante osservazioni
le servono, con un parametro in piu' nel catalogo.

Il dettaglio che decide se funziona: un'osservazione e' un EVENTO distinto, non
un ciclo. Il correlatore rilegge l'intera finestra a ogni giro, quindi lo
stesso fatto ricompare a ogni ciclo, e contarlo per cicli confermerebbe un
datagramma isolato a forza di rileggerlo.
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_confirm_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import correlator, metrics, rules  # noqa: E402

NOW = int(time.time())
RULE = "DEVICE_LOAD_001"


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
                      "incident_conclusions", "api_observations"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def _high_cpu(self, device="192.168.31.7", times=1):
        """``times`` snapshot DISTINTI con la CPU oltre soglia."""
        conn = db.get_observability_connection()
        for i in range(times):
            conn.execute(
                "INSERT INTO api_observations "
                "(ts, tenant, device_ip, kind, summary_json) "
                "VALUES (?, 'test_cml', ?, 'snmp_system', ?)",
                (NOW - 600 + i * 60, device,
                 json.dumps({"results": {"sysName": "switch-01"},
                             "metrics": {"cpu_pct": 97}})))
        conn.commit()
        conn.close()

    def _correlate(self, min_obs=None):
        settings = {}
        if min_obs is not None:
            settings = {"correlation_rules": {RULE: {"min_observations": min_obs}}}
        with patch("observability.rules.get_app_settings", return_value=settings), \
             patch("collectors.mac_history.client_map", return_value=[]):
            return correlator.correlate_once(NOW)

    def _evidence(self):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM evidence WHERE rule_id = ?", (RULE,))]
        finally:
            conn.close()


class TestTheDefaultChangesNothing(_Base):

    def test_one_observation_still_concludes_by_default(self):
        """Default 1: il comportamento di prima, identico. Alzarlo e' una
        scelta dell'amministratore, non un effetto collaterale."""
        self._high_cpu(times=1)
        self._correlate()
        self.assertEqual(len(self._evidence()), 1)


class TestConfirmation(_Base):

    def test_a_single_observation_does_not_conclude_when_two_are_required(self):
        self._high_cpu(times=1)
        self._correlate(min_obs=2)
        self.assertEqual(self._evidence(), [])

    def test_rereading_the_same_event_is_not_a_second_observation(self):
        """Il caso che rende la conferma una finzione se contata per cicli:
        lo stesso fatto rientra nella finestra a ogni giro."""
        self._high_cpu(times=1)
        for _ in range(4):
            self._correlate(min_obs=2)
        self.assertEqual(self._evidence(), [],
                         "quattro riletture dello stesso evento hanno "
                         "confermato una conclusione")

    def test_enough_distinct_observations_conclude(self):
        self._high_cpu(times=2)
        self._correlate(min_obs=2)
        # Entrambe le osservazioni diventano evidenza: la timeline deve
        # mostrare cio' che ha confermato la conclusione, non solo l'ultima.
        self.assertEqual(len(self._evidence()), 2)

    def test_observations_on_different_devices_do_not_add_up(self):
        """Due apparati con un picco ciascuno non sono un apparato con due
        picchi."""
        self._high_cpu(device="192.168.31.7", times=1)
        self._high_cpu(device="192.168.31.8", times=1)
        self._correlate(min_obs=2)
        self.assertEqual(self._evidence(), [])

    def test_an_unconfirmed_finding_is_counted_not_silent(self):
        """Una soglia di conferma troppo alta spegne una regola senza che
        nessuno se ne accorga: dev'essere visibile da qualche parte."""
        before = metrics.snapshot()["counters"].get("findings_unconfirmed", 0)
        self._high_cpu(times=1)
        self._correlate(min_obs=3)
        after = metrics.snapshot()["counters"].get("findings_unconfirmed", 0)
        self.assertGreater(after, before)


class TestTheCatalogDeclaresIt(unittest.TestCase):

    def test_every_rule_declares_the_confirmation_threshold(self):
        for rule_id in rules.RULES:
            names = [p["name"] for p in rules.parameter_specs(rule_id)]
            self.assertIn(rules.CONFIRMATION_PARAM, names, rule_id)

    def test_it_is_declared_once_not_duplicated(self):
        for rule_id in rules.RULES:
            names = [p["name"] for p in rules.parameter_specs(rule_id)]
            self.assertEqual(1, names.count(rules.CONFIRMATION_PARAM), rule_id)

    def test_the_default_is_one(self):
        with patch("observability.rules.get_app_settings", return_value={}):
            self.assertEqual(1, rules.min_observations(RULE))

    def test_an_out_of_range_value_is_clamped_not_ignored(self):
        with patch("observability.rules.get_app_settings", return_value={
                "correlation_rules": {RULE: {"min_observations": 999}}}):
            self.assertEqual(20, rules.min_observations(RULE))

    def _description(self, lang):
        rule = next(r for r in rules.catalog(lang) if r["id"] == RULE)
        return next(p for p in rule["parameters"]
                    if p["name"] == rules.CONFIRMATION_PARAM)["description"]

    def test_the_description_exists_in_both_languages(self):
        with patch("observability.rules.get_app_settings", return_value={}):
            it, en = self._description("it"), self._description("en")
        self.assertTrue(it)
        self.assertTrue(en)
        self.assertNotEqual(it, en, "la descrizione inglese e' quella italiana")


if __name__ == "__main__":
    unittest.main()
