# -*- coding: utf-8 -*-
"""Salute della piattaforma: gli exporter fuori inventario diventano evidenza.

I record di un exporter non censito vengono scartati di proposito (attribuirli
a una sede sbagliata è peggio che perderli), ma la perdita non deve restare in
una tabella di diagnostica che nessuno guarda. Il fatto passa dal bus eventi
come tutti gli altri, quindi eredita regole, evidenze, incidenti e timeline.
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_platform_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import correlator, incidents, normalize, rules  # noqa: E402

NOW = int(time.time())
ROGUE = "192.168.31.224"


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
                      "incident_conclusions", "quarantined_exporters",
                      "syslog_events", "flow_aggregates", "api_observations"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def _quarantine(self, ip=ROGUE, first_seen=None, last_seen=None, packets=227):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO quarantined_exporters "
            "(exporter_ip, first_seen, last_seen, packet_count) VALUES (?,?,?,?)",
            (ip, first_seen if first_seen is not None else NOW - 7200,
             last_seen if last_seen is not None else NOW - 60, packets))
        conn.commit()
        conn.close()

    def _rows(self, sql, params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params)]
        finally:
            conn.close()

    def _correlate(self):
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            return correlator.correlate_once(NOW)


class TestQuarantineAdapter(_Base):

    def test_a_quarantined_exporter_becomes_an_event(self):
        self._quarantine()
        normalize.normalize_once(NOW)
        events = self._rows("SELECT * FROM events "
                            "WHERE event_type = 'platform.exporter_unknown'")
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["entity_type"], "exporter")
        self.assertEqual(ev["entity_id"], ROGUE)
        self.assertEqual(ev["source"], "platform")
        metrics = json.loads(ev["metrics_json"])
        self.assertEqual(metrics["packets"], 227)
        self.assertEqual(metrics["persisted_s"], 7140)

    def test_the_tenant_is_reserved_not_borrowed(self):
        # Un exporter non attribuibile non può prendere in prestito la sede di
        # qualcun altro: è esattamente il motivo per cui viene scartato.
        self._quarantine()
        normalize.normalize_once(NOW)
        self.assertEqual(
            self._rows("SELECT DISTINCT tenant FROM events")[0]["tenant"],
            normalize.PLATFORM_TENANT)

    def test_an_exporter_that_stopped_produces_nothing(self):
        self._quarantine(last_seen=NOW - normalize.LOOKBACK_S - 600)
        normalize.normalize_once(NOW)
        self.assertEqual(
            self._rows("SELECT * FROM events "
                       "WHERE event_type = 'platform.exporter_unknown'"), [])

    def test_reprojection_within_a_bucket_updates_instead_of_duplicating(self):
        self._quarantine(packets=10)
        normalize.normalize_once(NOW)
        conn = db.get_observability_connection()
        conn.execute("UPDATE quarantined_exporters SET packet_count = 99")
        conn.commit()
        conn.close()
        normalize.normalize_once(NOW + 30)

        events = self._rows("SELECT * FROM events "
                            "WHERE event_type = 'platform.exporter_unknown'")
        self.assertEqual(len(events), 1)
        self.assertEqual(json.loads(events[0]["metrics_json"])["packets"], 99)

    def test_a_new_bucket_refreshes_the_knowledge_time(self):
        # Il correlatore guarda una finestra di 15 minuti: un fatto emesso una
        # volta sola e poi solo aggiornato in place gli uscirebbe di vista.
        self._quarantine(last_seen=NOW - 900)
        normalize.normalize_once(NOW)
        self._quarantine_touch(NOW - 60)
        normalize.normalize_once(NOW)

        events = self._rows("SELECT ts FROM events "
                            "WHERE event_type = 'platform.exporter_unknown' "
                            "ORDER BY ts")
        self.assertEqual(len(events), 2)
        self.assertNotEqual(events[0]["ts"], events[1]["ts"])

    def _quarantine_touch(self, last_seen):
        conn = db.get_observability_connection()
        conn.execute("UPDATE quarantined_exporters SET last_seen = ?", (last_seen,))
        conn.commit()
        conn.close()


class TestUnknownExporterRule(_Base):

    def test_a_persistent_exporter_becomes_evidence(self):
        self._quarantine()
        self._correlate()
        ev = self._rows("SELECT * FROM evidence "
                        "WHERE rule_id = 'FLOW_EXPORTER_UNKNOWN_001'")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["role"], "trigger")
        self.assertEqual(ev[0]["entity_key"], f"exporter:{ROGUE}")
        self.assertIn("fuori inventario", ev[0]["summary"])
        self.assertIn("227", ev[0]["summary"])

    def test_a_freshly_added_device_is_not_reported_yet(self):
        # Soglia sulla DURATA: qualche minuto di quarantena su un apparato
        # appena aggiunto è normale, non un guasto.
        self._quarantine(first_seen=NOW - 120, last_seen=NOW - 60)
        self._correlate()
        self.assertEqual(
            self._rows("SELECT * FROM evidence "
                       "WHERE rule_id = 'FLOW_EXPORTER_UNKNOWN_001'"), [])

    def test_a_handful_of_stray_datagrams_is_noise(self):
        self._quarantine(packets=3)
        self._correlate()
        self.assertEqual(
            self._rows("SELECT * FROM evidence "
                       "WHERE rule_id = 'FLOW_EXPORTER_UNKNOWN_001'"), [])

    def test_it_reaches_an_incident_with_its_own_conclusion(self):
        self._quarantine()
        self._correlate()
        with patch("collectors.mac_history.vlans_for_ips", return_value={}):
            incidents.group_once(NOW)
        inc = self._rows("SELECT * FROM incidents")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["tenant"], normalize.PLATFORM_TENANT)
        self.assertEqual(inc[0]["cause_kind"], "FLOW_EXPORTER_UNKNOWN_001")
        # Fatto misurato, non inferito: nessun margine di errore da scontare.
        self.assertGreaterEqual(inc[0]["confidence"], 90)

    def test_the_catalog_documents_the_rule(self):
        entry = next(r for r in rules.catalog()
                     if r["id"] == "FLOW_EXPORTER_UNKNOWN_001")
        self.assertEqual(entry["inputs"], ["platform.exporter_unknown"])
        self.assertEqual(entry["outputs"], ["trigger"])
        self.assertTrue(entry["investigation"])
        self.assertTrue(entry["remediation"])
        self.assertEqual(entry["effective"]["min_persistence_s"], 3600)


if __name__ == "__main__":
    unittest.main()
