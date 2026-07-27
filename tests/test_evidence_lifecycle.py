# -*- coding: utf-8 -*-
"""Test del ciclo di vita delle evidenze e del catalogo regole.

Il ciclo di vita è deliberatamente minimo: ``active`` → ``retracted``, nient'altro.
Ciò che conta è che una ritrattazione sia SPIEGABILE (quale evidenza, quale
regola, quando, perché) e che l'incidente possa raccontare di aver cambiato
idea invece di riscrivere la conclusione in silenzio.

La ritrattazione la decide sempre una REGOLA, mai un adapter: gli adapter
osservano e normalizzano, le regole interpretano.
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_lifecycle_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
from core import db  # noqa: E402
from observability import correlator, incidents, normalize, rules, timeline  # noqa: E402
from security import user_manager  # noqa: E402

PASS = "PasswordSicura1!"
CSRF = {"X-Requested-With": "SentinelNet"}
NOW = int(time.time())


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
                      "normalize_cursors", "api_observations", "syslog_events",
                      "flow_aggregates"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def _rows(self, sql, params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    def _snapshot(self, conn, link, ts):
        conn.execute(
            "INSERT INTO api_observations (ts, tenant, device_ip, kind, "
            "summary_json) VALUES (?, 'sede-a', '10.1.0.254', 'interfaces', ?)",
            (ts, json.dumps({"results": {"port1": {"link": link}}})))


class TestRetraction(_Base):

    def _down_then_up(self):
        """Ciclo completo: la porta cade, si forma l'incidente, poi torna su."""
        conn = db.get_observability_connection()
        self._snapshot(conn, "up", NOW - 900)
        self._snapshot(conn, "down", NOW - 600)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        incidents.group_once(NOW)

        conn = db.get_observability_connection()
        self._snapshot(conn, "up", NOW - 120)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        incidents.group_once(NOW)

    def test_symptom_is_retracted_not_deleted(self):
        self._down_then_up()
        rows = self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_DOWN_001'")
        self.assertEqual(len(rows), 1)          # non cancellata
        self.assertEqual(rows[0]["status"], "retracted")

    def test_retraction_says_which_evidence_and_which_rule(self):
        self._down_then_up()
        row = self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_DOWN_001'")[0]
        self.assertEqual(row["retracted_by_rule_id"], "IFACE_RECOVERED_001")
        self.assertIsNotNone(row["retracted_at"])
        self.assertIn("tornata su", row["retracted_reason"])
        # L'evidenza concreta che ha invalidato, non solo la regola.
        witness = self._rows("SELECT * FROM evidence WHERE id = ?",
                             (row["retracted_by_evidence_id"],))
        self.assertEqual(len(witness), 1)
        self.assertEqual(witness[0]["rule_id"], "IFACE_RECOVERED_001")
        self.assertEqual(witness[0]["role"], "consequence")

    def test_retracted_evidence_no_longer_supports_the_conclusion(self):
        self._down_then_up()
        incident = self._rows("SELECT * FROM incidents")[0]
        reasoning = json.loads(incident["reasoning_json"] or "{}")
        self.assertNotIn("IFACE_DOWN_001", reasoning.get("rules_fired", []))
        self.assertEqual(reasoning.get("retracted_count"), 1)

    def test_incident_keeps_the_superseded_conclusion(self):
        self._down_then_up()
        incident_id = self._rows("SELECT id FROM incidents")[0]["id"]
        history = self._rows(
            "SELECT * FROM incident_conclusions WHERE incident_id = ? "
            "ORDER BY concluded_ts", (incident_id,))
        # Almeno una conclusione superata: quella basata sul sintomo caduto.
        superseded = [h for h in history if h["superseded_ts"] is not None]
        self.assertTrue(superseded)
        self.assertEqual(len([h for h in history if h["superseded_ts"] is None]), 1)

    def test_retracted_evidence_still_appears_in_the_timeline(self):
        self._down_then_up()
        incident_id = self._rows("SELECT id FROM incidents")[0]["id"]
        entries = [e for e in timeline.build(incident_id)
                   if e.get("ref", {}).get("rule_id") == "IFACE_DOWN_001"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status"], "retracted")
        self.assertIn("tornata su", entries[0]["ref"]["retracted_reason"])

    def test_nothing_to_retract_emits_nothing(self):
        # La porta torna su senza che fosse mai caduta: nessun testimone,
        # nessuna ritrattazione a vuoto.
        conn = db.get_observability_connection()
        self._snapshot(conn, "down", NOW - 900)
        self._snapshot(conn, "up", NOW - 600)
        conn.commit()
        conn.close()
        # Si normalizza SENZA correlare, così il sintomo non esiste come evidenza.
        normalize.normalize_once(NOW)
        conn = db.get_observability_connection()
        conn.execute("DELETE FROM events WHERE event_type = 'interface.change' "
                     "AND json_extract(attrs_json, '$.after') = 'down'")
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_RECOVERED_001'"),
            [])

    def test_conclusion_history_does_not_grow_on_identical_recalculation(self):
        conn = db.get_observability_connection()
        self._snapshot(conn, "up", NOW - 900)
        self._snapshot(conn, "down", NOW - 600)
        conn.commit()
        conn.close()
        with patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        incidents.group_once(NOW)
        incidents.group_once(NOW)
        incidents.group_once(NOW)
        rows = self._rows("SELECT * FROM incident_conclusions")
        self.assertEqual(len(rows), 1)


class TestRuleCatalogAndThresholds(_Base):
    """Nota: app_settings.json è condiviso fra i moduli di test nello stesso
    processo di discovery. Una soglia salvata davvero qui cambierebbe il
    comportamento del correlatore nei test di un altro file, quindi la
    scrittura viene intercettata invece di essere ripulita a posteriori."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        for user, role in (("adm_rules", "admin"), ("op_rules", "operator")):
            try:
                user_manager.create_user(user, PASS, role=role, groups=None)
            except Exception:
                pass

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200, r.text
        return c

    def test_catalog_describes_every_rule(self):
        # Config vuota fissata: il test descrive il catalogo, non l'ambiente.
        c = self._client("op_rules")
        with patch("observability.rules.get_app_settings", return_value={}):
            r = c.get("/api/incidents/rules")
        self.assertEqual(r.status_code, 200)
        catalog = {x["id"]: x for x in r.json()["rules"]}
        self.assertEqual(set(catalog), set(rules.RULES))
        blocked = catalog["BLOCKED_TRAFFIC_001"]
        self.assertIn("log.security", blocked["inputs"])
        self.assertIn("trigger", blocked["outputs"])
        param = blocked["parameters"][0]
        self.assertEqual(
            {param["name"], "min" in param, "max" in param, "default" in param},
            {"match_delta_s", True, True, True})
        self.assertEqual(blocked["effective"]["match_delta_s"], 120)

    def test_threshold_is_saved_and_becomes_effective(self):
        stored = {}

        def _fake_save(settings):
            stored.update(settings)

        c = self._client("adm_rules")
        with patch("core.app_settings.save_app_settings", _fake_save):
            r = c.post("/api/incidents/rules/BLOCKED_TRAFFIC_001/parameters",
                       headers=CSRF, json={"match_delta_s": 300})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(stored["correlation_rules"]["BLOCKED_TRAFFIC_001"],
                         {"match_delta_s": 300})
        # E ciò che è stato salvato diventa davvero la soglia effettiva.
        with patch("observability.rules.get_app_settings", return_value=stored):
            self.assertEqual(
                rules.params_for("BLOCKED_TRAFFIC_001")["match_delta_s"], 300)

    def test_unknown_parameter_is_rejected(self):
        c = self._client("adm_rules")
        r = c.post("/api/incidents/rules/BLOCKED_TRAFFIC_001/parameters",
                   headers=CSRF, json={"qualsiasi_cosa": 1})
        self.assertEqual(r.status_code, 400)

    def test_out_of_range_is_rejected(self):
        c = self._client("adm_rules")
        r = c.post("/api/incidents/rules/BLOCKED_TRAFFIC_001/parameters",
                   headers=CSRF, json={"match_delta_s": 999999})
        self.assertEqual(r.status_code, 400)

    def test_non_numeric_is_rejected(self):
        c = self._client("adm_rules")
        r = c.post("/api/incidents/rules/BLOCKED_TRAFFIC_001/parameters",
                   headers=CSRF, json={"match_delta_s": "molto"})
        self.assertEqual(r.status_code, 400)

    def test_unknown_rule_is_404(self):
        c = self._client("adm_rules")
        r = c.post("/api/incidents/rules/NON_ESISTE/parameters",
                   headers=CSRF, json={})
        self.assertEqual(r.status_code, 404)

    def test_operator_cannot_change_thresholds(self):
        c = self._client("op_rules")
        r = c.post("/api/incidents/rules/BLOCKED_TRAFFIC_001/parameters",
                   headers=CSRF, json={"match_delta_s": 200})
        self.assertEqual(r.status_code, 403)

    def test_value_saved_out_of_range_is_clamped_not_ignored(self):
        # Se un valore fuori range arriva comunque nel file di configurazione,
        # la regola gira con l'estremo più vicino invece di spegnersi in silenzio.
        settings = {"correlation_rules": {"BLOCKED_TRAFFIC_001":
                                          {"match_delta_s": 10 ** 9}}}
        with patch("observability.rules.get_app_settings", return_value=settings):
            self.assertEqual(rules.params_for("BLOCKED_TRAFFIC_001")["match_delta_s"],
                             3600)


if __name__ == "__main__":
    unittest.main()
