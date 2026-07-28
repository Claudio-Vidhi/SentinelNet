# -*- coding: utf-8 -*-
"""Stato atteso di una interfaccia: conoscenza dell'operatore, non della rete.

Una Loopback, una Null o una VLAN dismessa sono giù per progetto. Il fatto
resta — l'evento non sparisce da ``events`` — ma smette di essere letto come un
sintomo. È il punto in cui chi gestisce la rete entra nel ragionamento senza
riscrivere una regola.
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_ifexp_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import correlator, normalize, rules  # noqa: E402

NOW = int(time.time())
DEVICE = "192.168.31.6"
TENANT = "test_cml"


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

    def _observe(self, ts, interfaces):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO api_observations (ts, tenant, device_ip, kind, summary_json) "
            "VALUES (?, ?, ?, 'snmp_interfaces', ?)",
            (ts, TENANT, DEVICE, json.dumps({"results": interfaces})))
        conn.commit()
        conn.close()

    def _shut(self, iface):
        """Due snapshot: la porta era su, ora è giù."""
        self._observe(NOW - 300, {iface: {"link": "up"}})
        self._observe(NOW - 60, {iface: {"link": "down"}})

    def _correlate(self, expectations=None):
        settings = {"interface_expectations": expectations or {}}
        with patch("observability.rules.get_app_settings", return_value=settings), \
             patch("collectors.mac_history.client_map", return_value=[]):
            return correlator.correlate_once(NOW)

    def _rows(self, sql, params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params)]
        finally:
            conn.close()


class TestExpectationSilencesTheSymptom(_Base):

    def test_without_confirmation_a_port_going_down_is_a_symptom(self):
        self._shut("Vl20")
        self._correlate()
        self.assertEqual(
            len(self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_DOWN_001'")),
            1)

    def test_a_confirmed_interface_produces_no_symptom(self):
        self._shut("Vl20")
        self._correlate({rules.expectation_key(TENANT, DEVICE, "Vl20"): {"note": "dismessa"}})
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_DOWN_001'"),
            [])

    def test_the_fact_survives_the_confirmation(self):
        # Non è soppressione: l'evento resta, e resta visibile nel feed.
        # Sparisce l'interpretazione, non l'osservazione.
        self._shut("Vl20")
        self._correlate({rules.expectation_key(TENANT, DEVICE, "Vl20"): {}})
        events = self._rows(
            "SELECT * FROM events WHERE event_type = 'interface.change'")
        self.assertEqual(len(events), 1)
        self.assertEqual(json.loads(events[0]["attrs_json"])["after"], "down")

    def test_the_confirmation_is_per_interface_not_per_device(self):
        self._observe(NOW - 300, {"Vl20": {"link": "up"}, "Et0/1": {"link": "up"}})
        self._observe(NOW - 60, {"Vl20": {"link": "down"}, "Et0/1": {"link": "down"}})
        self._correlate({rules.expectation_key(TENANT, DEVICE, "Vl20"): {}})
        rows = self._rows(
            "SELECT * FROM evidence WHERE rule_id = 'IFACE_DOWN_001'")
        self.assertEqual([r["summary"] for r in rows],
                         ["Interfaccia Et0/1 passata a down"])

    def test_the_same_name_on_another_tenant_is_not_silenced(self):
        # La chiave porta il tenant: confermare Vl20 in una sede non deve
        # zittire la Vl20 di un'altra.
        self._shut("Vl20")
        self._correlate({rules.expectation_key("altra-sede", DEVICE, "Vl20"): {}})
        self.assertEqual(
            len(self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_DOWN_001'")),
            1)


class TestExpectationStorage(unittest.TestCase):

    def test_key_is_stable_and_scoped(self):
        self.assertEqual(rules.expectation_key("t", "10.0.0.1", "Vl20"),
                         "t|10.0.0.1|Vl20")

    def test_a_broken_settings_section_does_not_break_the_engine(self):
        with patch("observability.rules.get_app_settings",
                   return_value={"interface_expectations": "non-un-dizionario"}):
            self.assertEqual(rules.expected_down(), {})


if __name__ == "__main__":
    unittest.main()
