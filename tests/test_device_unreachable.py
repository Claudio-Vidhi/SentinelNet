# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""A silent SNMP round becomes a fact: the poller writes it and normalize
projects it as ``device.unreachable``.

Prima un apparato che smetteva di rispondere al polling non produceva NIENTE:
``_poll_device`` tornava una lista vuota e il giro passava oltre.
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
from observability import normalize  # noqa: E402
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
        for table in ("events", "normalize_cursors", "api_observations"):
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
        normalize.normalize_once(NOW)
        kinds = self._event_types()
        self.assertIn("device.unreachable", kinds)
        self.assertIn("device.state", kinds)



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
        with patch.object(normalize, "MAX_ROWS_PER_SOURCE", 5):
            self._rounds("." * 5)
            normalize.normalize_once(NOW)
            self._rounds("A", start=NOW - 30)
            normalize.normalize_once(NOW)
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



if __name__ == "__main__":
    unittest.main()
