# -*- coding: utf-8 -*-
"""Soppressioni: ciò che l'operatore si aspetta, con o senza scadenza.

Un'unica domanda con due forme che altrove sono due funzionalità separate:
"questa porta è giù per progetto" e "questo apparato è in manutenzione
stanotte". 'Per sempre' non è un caso speciale — è il caso senza scadenza.

Il fatto resta: l'evento non sparisce da ``events``. Sparisce l'evidenza, cioè
l'interpretazione, che è dove la conoscenza dell'operatore deve entrare.
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_suppr_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import correlator, suppression  # noqa: E402

NOW = int(time.time())
DEVICE = "192.168.31.6"
TENANT = "test_cml"
ENTITY = f"ip:{DEVICE}"


def _rule(interface=None, from_ts=None, to_ts=None, tenant=TENANT):
    return {"tenant": tenant, "entity_key": ENTITY, "device_ip": DEVICE,
            "interface": interface, "from_ts": from_ts, "to_ts": to_ts,
            "note": "", "by": "test", "created_ts": NOW}


def _saved(*rules):
    return {suppression.key(r["tenant"], r["entity_key"], r["interface"]): r
            for r in rules}


class TestMatching(unittest.TestCase):
    """La logica pura, senza database."""

    def _with(self, *rules):
        return patch("observability.suppression.get_app_settings",
                     return_value={"suppressions": _saved(*rules)})

    def test_no_window_means_always(self):
        with self._with(_rule(interface="Vl20")):
            self.assertIsNotNone(
                suppression.active(TENANT, ENTITY, "Vl20", NOW - 86400 * 365))
            self.assertIsNotNone(
                suppression.active(TENANT, ENTITY, "Vl20", NOW + 86400 * 365))

    def test_a_window_covers_only_its_own_time(self):
        with self._with(_rule(interface="Et0/0", from_ts=NOW - 600,
                              to_ts=NOW + 600)):
            self.assertIsNone(suppression.active(TENANT, ENTITY, "Et0/0", NOW - 900))
            self.assertIsNotNone(suppression.active(TENANT, ENTITY, "Et0/0", NOW))
            self.assertIsNone(suppression.active(TENANT, ENTITY, "Et0/0", NOW + 900))

    def test_an_open_ended_window_has_a_start_but_no_end(self):
        with self._with(_rule(from_ts=NOW - 60)):
            self.assertIsNone(suppression.active(TENANT, ENTITY, "Et0/0", NOW - 120))
            self.assertIsNotNone(
                suppression.active(TENANT, ENTITY, "Et0/0", NOW + 86400))

    def test_a_device_suppression_covers_every_interface(self):
        with self._with(_rule(interface=None)):
            for iface in ("Et0/0", "Vl20", None):
                self.assertIsNotNone(
                    suppression.active(TENANT, ENTITY, iface, NOW), iface)

    def test_an_interface_suppression_covers_only_that_one(self):
        with self._with(_rule(interface="Vl20")):
            self.assertIsNotNone(suppression.active(TENANT, ENTITY, "Vl20", NOW))
            self.assertIsNone(suppression.active(TENANT, ENTITY, "Et0/0", NOW))

    def test_tenants_do_not_bleed(self):
        with self._with(_rule(interface="Vl20", tenant="altra-sede")):
            self.assertIsNone(suppression.active(TENANT, ENTITY, "Vl20", NOW))

    def test_a_broken_settings_section_does_not_break_the_engine(self):
        with patch("observability.suppression.get_app_settings",
                   return_value={"suppressions": "non-un-dizionario"}):
            self.assertEqual(suppression.all_rules(), {})
            self.assertIsNone(suppression.active(TENANT, ENTITY, "Vl20", NOW))

    def test_expired_is_about_the_end_not_the_start(self):
        self.assertTrue(suppression.expired(_rule(to_ts=NOW - 1), NOW))
        self.assertFalse(suppression.expired(_rule(to_ts=NOW + 1), NOW))
        self.assertFalse(suppression.expired(_rule(), NOW))


class TestAppliedToTheEngine(unittest.TestCase):
    """Applicata in un posto solo: deve zittire QUALUNQUE regola, non solo
    quella a cui qualcuno si è ricordato di aggiungere il controllo."""

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

    def _shut(self, iface="Vl20", ts=None):
        base = ts if ts is not None else NOW - 120
        conn = db.get_observability_connection()
        for offset, state in ((0, "up"), (60, "down")):
            conn.execute(
                "INSERT INTO api_observations (ts, tenant, device_ip, kind, summary_json) "
                "VALUES (?, ?, ?, 'snmp_interfaces', ?)",
                (base + offset, TENANT, DEVICE,
                 json.dumps({"results": {iface: {"link": state}}})))
        conn.commit()
        conn.close()

    def _correlate(self, rules_saved=None):
        with patch("observability.suppression.get_app_settings",
                   return_value={"suppressions": rules_saved or {}}), \
             patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            return correlator.correlate_once(NOW)

    def _rows(self, sql, params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params)]
        finally:
            conn.close()

    def test_without_suppression_the_symptom_exists(self):
        self._shut()
        self._correlate()
        self.assertTrue(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_DOWN_001'"))

    def test_a_permanent_suppression_silences_it(self):
        self._shut()
        self._correlate(_saved(_rule(interface="Vl20")))
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_DOWN_001'"),
            [])

    def test_the_fact_survives_the_suppression(self):
        self._shut()
        self._correlate(_saved(_rule(interface="Vl20")))
        events = self._rows(
            "SELECT * FROM events WHERE event_type = 'interface.change'")
        self.assertEqual(len(events), 1)
        self.assertEqual(json.loads(events[0]["attrs_json"])["after"], "down")

    def test_a_maintenance_window_silences_the_whole_device(self):
        # Nessuna regola è stata modificata per saperlo: il filtro è a valle.
        self._shut("Et0/0")
        self._correlate(_saved(_rule(from_ts=NOW - 600, to_ts=NOW + 600)))
        self.assertEqual(self._rows("SELECT * FROM evidence"), [])

    def test_a_closed_window_no_longer_silences(self):
        self._shut("Et0/0")
        self._correlate(_saved(_rule(from_ts=NOW - 7200, to_ts=NOW - 3600)))
        self.assertTrue(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_DOWN_001'"))

    def test_the_window_is_judged_on_the_event_time_not_on_now(self):
        """Una manutenzione di ieri notte copre i fatti di ieri notte anche se
        la correlazione li rilegge stamattina."""
        self._shut("Et0/0", ts=NOW - 800)
        self._correlate(_saved(_rule(from_ts=NOW - 900, to_ts=NOW - 600)))
        self.assertEqual(self._rows("SELECT * FROM evidence"), [])


if __name__ == "__main__":
    unittest.main()
