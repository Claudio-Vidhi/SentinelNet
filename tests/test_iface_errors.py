# -*- coding: utf-8 -*-
"""IFACE_ERRORS_001: errori in crescita su una porta.

``in_errors``/``out_errors`` erano raccolti dal poller SNMP e li leggeva solo
la diagnosi di un client, su richiesta. Una porta che accumulava errori non
diceva niente a nessuno finche' qualcuno non andava a cercarla: un guasto del
livello fisico che degrada senza far cadere il link non produce nessuna
transizione da vedere, quindi nessuna delle regole esistenti lo guardava.

Il punto delicato e' che i contatori sono CUMULATIVI: il valore assoluto di
uno switch acceso da due anni non dice niente, e un solo campione non e'
valutabile.
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_ifaceerr_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import correlator, rules  # noqa: E402

NOW = int(time.time())
DEVICE = "192.168.31.7"


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

    def _samples(self, iface, counters, start=None):
        """Una serie di snapshot con i contatori indicati.

        ``counters`` e' una lista di ``(in_errors, out_errors)`` oppure di
        dict, per i casi in cui il contatore manca del tutto.
        """
        conn = db.get_observability_connection()
        base = start if start is not None else NOW - 60 * (len(counters) + 1)
        for i, c in enumerate(counters):
            fields = c if isinstance(c, dict) else {"in_errors": c[0],
                                                    "out_errors": c[1]}
            fields = {"link": "up", **fields}
            # Forma vera dello snapshot del poller: i contatori stanno anche
            # sotto ``metrics``, prefissati col nome della porta, perche' i
            # ``results`` non arrivano a metrics_json (vedi _stable_fields).
            measured = {f"{iface}.{f}": fields[f]
                        for f in ("in_errors", "out_errors") if f in fields}
            conn.execute(
                "INSERT INTO api_observations (ts, tenant, device_ip, kind, summary_json) "
                "VALUES (?, 'test_cml', ?, 'snmp_interfaces', ?)",
                (base + i * 60, DEVICE,
                 json.dumps({"results": {iface: fields}, "metrics": measured})))
        conn.commit()
        conn.close()

    def _correlate(self):
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            return correlator.correlate_once(NOW)

    def _evidence(self):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM evidence WHERE rule_id = 'IFACE_ERRORS_001'")]
        finally:
            conn.close()


class TestRisingErrorsAreDetected(_Base):

    def test_a_high_but_static_counter_is_not_a_fault(self):
        """Uno switch acceso da due anni ha errori diversi da zero e sta
        benissimo: e' la CRESCITA il segnale."""
        self._samples("Et0/1", [(50000, 0), (50000, 0), (50000, 0)])
        self._correlate()
        self.assertEqual(self._evidence(), [])

    def test_a_single_sample_is_not_evaluable(self):
        # Un contatore cumulativo senza un secondo campione non ha una
        # differenza: confrontarlo con la soglia direbbe "guasto" su ogni
        # apparato con qualche errore storico.
        self._samples("Et0/1", [(999999, 0)])
        self._correlate()
        self.assertEqual(self._evidence(), [])

    def test_growth_over_the_threshold_becomes_a_trigger(self):
        self._samples("Et0/1", [(10, 0), (200, 0), (500, 0)])
        self._correlate()
        rows = self._evidence()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["role"], "trigger")
        self.assertEqual(rows[0]["severity"], 4)
        attrs = json.loads(rows[0]["attrs_json"])
        self.assertEqual(attrs["errors_delta"], 490)
        self.assertEqual(attrs["interface"], "Et0/1")

    def test_growth_below_the_threshold_stays_quiet(self):
        """Il fondo di rumore di un collegamento in rame non e' un guasto."""
        self._samples("Et0/1", [(10, 0), (12, 0), (15, 0)])
        self._correlate()
        self.assertEqual(self._evidence(), [])

    def test_inbound_and_outbound_are_counted_together(self):
        # Nessuno dei due da solo supera la soglia; il collegamento e' comunque
        # da guardare.
        self._samples("Et0/1", [(0, 0), (60, 0), (60, 60)])
        self._correlate()
        self.assertEqual(len(self._evidence()), 1)

    def test_a_counter_reset_is_not_a_fault(self):
        """Un riavvio azzera i contatori: la differenza diventa negativa e non
        deve diventare un incidente al primo riavvio di uno switch."""
        self._samples("Et0/1", [(90000, 0), (5, 0), (7, 0)])
        self._correlate()
        self.assertEqual(self._evidence(), [])

    def test_a_port_without_the_counter_is_not_reported_as_clean(self):
        # Assente non e' zero: una porta che non espone il contatore non deve
        # ne' allarmare ne' sembrare pulita.
        self._samples("Et0/2", [{"link": "up"}, {"link": "up"}])
        self._correlate()
        self.assertEqual(self._evidence(), [])

    def test_two_ports_with_errors_are_two_conclusions(self):
        # Stesso apparato, stessa entita', stessa regola: senza discriminante
        # la deduplica ne perderebbe una.
        self._samples("Et0/1", [(0, 0), (500, 0)])
        self._samples("Et0/3", [(0, 0), (900, 0)])
        self._correlate()
        rows = self._evidence()
        self.assertEqual(len(rows), 2)
        self.assertEqual({json.loads(r["attrs_json"])["interface"] for r in rows},
                         {"Et0/1", "Et0/3"})


class TestTheRuleDescribesItself(_Base):

    def test_the_catalog_carries_it_in_both_languages(self):
        for lang in ("it", "en"):
            ids = {r["id"] for r in rules.catalog(lang)}
            self.assertIn("IFACE_ERRORS_001", ids, lang)

    def test_the_threshold_is_a_declared_parameter(self):
        params = rules.params_for("IFACE_ERRORS_001")
        self.assertIn("min_errors", params)
        self.assertGreater(params["min_errors"], 0)


if __name__ == "__main__":
    unittest.main()
