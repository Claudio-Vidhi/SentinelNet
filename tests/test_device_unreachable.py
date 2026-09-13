# -*- coding: utf-8 -*-
"""DEVICE_UNREACHABLE_001: il silenzio diventa un fatto.

Prima un apparato che smetteva di rispondere al polling non produceva NIENTE:
``_poll_device`` tornava una lista vuota e il giro passava oltre. Nessun
evento, nessuna regola poteva vederlo.

I due casi da non confondere, e che fanno tutta la differenza fra una regola
utile e una che apre un incidente per ogni apparato con SNMP filtrato:

- un apparato che **rispondeva e ha smesso** -> caduto;
- un apparato che **non ha mai risposto** (una ACL non contempla il collector,
  che su UDP e' il caso piu' comune) -> non e' caduto niente.
"""

import asyncio
import json
import os
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_unreach_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import correlator, rules  # noqa: E402
from observability.ingesters import snmp_poller  # noqa: E402

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

    def _rounds(self, pattern, device=DEVICE, start=None):
        """Una sequenza di giri di polling. 'A' = ha risposto, '.' = muto.

        I giri muti usano lo stesso tipo che scrive il poller, cosi' il test
        passa dalla stessa proiezione in normalize e non da una copia."""
        conn = db.get_observability_connection()
        base = start if start is not None else NOW - 60 * (len(pattern) + 1)
        for i, ch in enumerate(pattern):
            answered = ch == "A"
            kind = "snmp_system" if answered else snmp_poller.SILENT_KIND
            summary = ('{"results": {"sysName": "switch-01"}}'
                       if answered else "{}")
            conn.execute(
                "INSERT INTO api_observations "
                "(ts, tenant, device_ip, kind, summary_json) "
                "VALUES (?, 'test_cml', ?, ?, ?)",
                (base + i * 60, device, kind, summary))
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
                "SELECT * FROM evidence "
                "WHERE rule_id = 'DEVICE_UNREACHABLE_001'")]
        finally:
            conn.close()

    def _event_types(self):
        conn = db.get_observability_connection()
        try:
            return [r["event_type"] for r in conn.execute(
                "SELECT event_type FROM events ORDER BY ts, id")]
        finally:
            conn.close()


class TestSilenceBecomesAFact(_Base):

    def test_a_silent_round_is_projected_as_its_own_event(self):
        """Non come device.state: direbbe "ecco lo stato" di un apparato che
        non ne ha riportato nessuno."""
        self._rounds("A.")
        self._correlate()
        kinds = self._event_types()
        self.assertIn("device.unreachable", kinds)
        self.assertIn("device.state", kinds)

    def test_a_device_that_answered_and_stopped_is_down(self):
        self._rounds("AAA...")
        self._correlate()
        rows = self._evidence()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["role"], "trigger")
        self.assertEqual(rows[0]["severity"], 2)
        self.assertEqual(json.loads(rows[0]["attrs_json"])["silent_rounds"], 3)

    def test_a_device_that_never_answered_is_not_down(self):
        """Il caso piu' comune su UDP: una ACL non contempla il collector.
        Senza questa condizione la regola aprirebbe un incidente per ogni
        apparato con SNMP filtrato, per sempre."""
        self._rounds("......")
        self._correlate()
        self.assertEqual(self._evidence(), [])

    def test_one_lost_datagram_does_not_wake_anyone(self):
        # Conferma prima di concludere: una conclusione notificata non si
        # ritira.
        self._rounds("AAA.")
        self._correlate()
        self.assertEqual(self._evidence(), [])

    def test_a_device_that_skipped_and_came_back_is_not_down(self):
        """Si contano solo i giri muti DOPO l'ultima risposta: tre giri persi
        seguiti da una risposta non sono un apparato caduto."""
        self._rounds("A...A")
        self._correlate()
        self.assertEqual(self._evidence(), [])

    def test_the_rounds_must_be_consecutive(self):
        self._rounds("A.A.A.")
        self._correlate()
        self.assertEqual(self._evidence(), [])

    def test_two_devices_down_are_two_conclusions(self):
        self._rounds("AA...", device="192.168.31.7")
        self._rounds("AA...", device="192.168.31.8")
        self._correlate()
        self.assertEqual({r["entity_key"] for r in self._evidence()},
                         {"ip:192.168.31.7", "ip:192.168.31.8"})


class TestTheCursorKeepsMoving(_Base):

    def test_a_batch_of_only_silent_rounds_does_not_block_the_projection(self):
        """Saltare una riga muta senza avanzare il cursore rileggerebbe gli
        stessi giri a ogni ciclo, e un lotto fatto solo di giri muti non
        lascerebbe mai passare le righe successive.

        Il lotto va ridotto perche' il blocco si vede solo quando e' INTERO
        fatto di giri muti: con il limite di produzione la risposta finisce
        nello stesso lotto e il difetto non si manifesta. La prima versione di
        questo test passava anche senza la correzione -- una guardia che non
        e' mai stata vista fallire non e' una guardia."""
        from observability import normalize
        with patch.object(normalize, "MAX_ROWS_PER_SOURCE", 5):
            self._rounds("." * 5)
            self._correlate()
            self._rounds("A", start=NOW - 30)
            self._correlate()
        self.assertEqual(self._event_types().count("device.state"), 1,
                         "la risposta dopo un lotto di giri muti non e' mai "
                         "stata proiettata: il cursore non avanza")


class TestThePollerWritesTheSilence(unittest.TestCase):

    def _run(self, answer):
        written = []
        with patch.object(snmp_poller, "_snmp_devices",
                          return_value=[{"ip": "192.0.2.9", "tenant": "t",
                                         "community": "c"}]), \
             patch.object(snmp_poller, "_poll_device",
                          new=AsyncMock(return_value=answer)), \
             patch("core.db.enqueue_write",
                   side_effect=lambda sql, params: written.append(params)):
            n = asyncio.run(snmp_poller.poll_once())
        return n, written

    def test_a_device_that_returns_nothing_leaves_a_row(self):
        n, written = self._run([])
        self.assertEqual(n, 1)
        self.assertEqual(written[0][2], "192.0.2.9")
        self.assertEqual(written[0][3], snmp_poller.SILENT_KIND)

    def test_a_device_that_answers_leaves_no_silent_row(self):
        _n, written = self._run([("snmp_system", "{}")])
        self.assertNotIn(snmp_poller.SILENT_KIND, [p[3] for p in written])


class TestTheRuleDescribesItself(_Base):

    def test_the_catalog_carries_it_in_both_languages(self):
        for lang in ("it", "en"):
            ids = {r["id"] for r in rules.catalog(lang)}
            self.assertIn("DEVICE_UNREACHABLE_001", ids, lang)

    def test_the_confirmation_threshold_is_a_declared_parameter(self):
        params = rules.params_for("DEVICE_UNREACHABLE_001")
        self.assertGreaterEqual(params["min_silent_rounds"], 2,
                                "un solo giro muto non e' una conclusione")


if __name__ == "__main__":
    unittest.main()
