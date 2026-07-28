# -*- coding: utf-8 -*-
"""Flapping: il pattern è il segnale, la singola caduta è rumore.

Finché ogni caduta resta un sintomo isolato l'ingegnere vede dieci incidenti e
nessuna causa. Il guasto non è la caduta di stanotte, è il collegamento
instabile.
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_flap_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import correlator, incidents  # noqa: E402

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

    def _snapshots(self, iface, states, start=None):
        """Una serie di snapshot con il link che assume gli stati indicati."""
        conn = db.get_observability_connection()
        base = start if start is not None else NOW - 60 * (len(states) + 1)
        for i, state in enumerate(states):
            conn.execute(
                "INSERT INTO api_observations (ts, tenant, device_ip, kind, summary_json) "
                "VALUES (?, 'test_cml', ?, 'snmp_interfaces', ?)",
                (base + i * 60, DEVICE,
                 json.dumps({"results": {iface: {"link": state}}})))
        conn.commit()
        conn.close()

    def _correlate(self):
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            return correlator.correlate_once(NOW)

    def _rows(self, sql, params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params)]
        finally:
            conn.close()


class TestFlappingDetection(_Base):

    def test_a_single_drop_is_not_flapping(self):
        self._snapshots("Et0/0", ["up", "down"])
        self._correlate()
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_FLAPPING_001'"),
            [])

    def test_one_full_cycle_is_still_not_flapping(self):
        # down + up = due transizioni: è una caduta con il suo ripristino,
        # non instabilità. Con la soglia a 4 non deve scattare.
        self._snapshots("Et0/0", ["up", "down", "up"])
        self._correlate()
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_FLAPPING_001'"),
            [])

    def test_repeated_oscillation_becomes_a_trigger(self):
        self._snapshots("Et0/0", ["up", "down", "up", "down", "up"])
        self._correlate()
        rows = self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_FLAPPING_001'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["role"], "trigger")
        self.assertEqual(rows[0]["severity"], 3)
        self.assertIn("Et0/0 instabile", rows[0]["summary"])
        self.assertEqual(json.loads(rows[0]["attrs_json"])["transitions"], 4)

    def test_two_unstable_ports_are_two_conclusions(self):
        # Stesso apparato, stessa entità, stessa regola: senza discriminante
        # la deduplica ne perderebbe una.
        self._snapshots("Et0/0", ["up", "down", "up", "down", "up"])
        self._snapshots("Et0/1", ["up", "down", "up", "down", "up"])
        self._correlate()
        rows = self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_FLAPPING_001' "
                          "ORDER BY id")
        self.assertEqual(
            sorted(json.loads(r["attrs_json"])["interface"] for r in rows),
            ["Et0/0", "Et0/1"])

    def test_it_fills_the_hole_left_by_the_recovery_rule(self):
        """Il buco che questa regola riempie, mostrato dai dati.

        Su una porta che oscilla ogni caduta viene ritrattata dalla risalita
        successiva: restano evidenze ritrattate e nessuna conclusione in piedi.
        Il flapping è l'unica che resta attiva."""
        self._snapshots("Et0/0", ["up", "down", "up", "down", "up"])
        self._correlate()
        downs = self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_DOWN_001'")
        self.assertTrue(downs)
        self.assertTrue(all(d["status"] == "retracted" for d in downs))
        self.assertTrue(all(d["retracted_by_rule_id"] == "IFACE_RECOVERED_001"
                            for d in downs))
        flap = self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_FLAPPING_001'")
        self.assertEqual([f["status"] for f in flap], ["active"])


class TestFlappingBecomesTheCause(_Base):

    def test_the_incident_blames_instability_not_the_last_drop(self):
        self._snapshots("Et0/0", ["up", "down", "up", "down", "up"])
        self._correlate()
        with patch("collectors.mac_history.vlans_for_ips", return_value={}):
            incidents.group_once(NOW)
        inc = self._rows("SELECT * FROM incidents")[0]
        # Prima restava indeterminata: i sintomi erano tutti ritrattati, e
        # un'evidenza ritrattata prima di essere raggruppata non arriva mai a
        # un incidente. Restava un incidente senza causa dichiarata.
        self.assertEqual(inc["cause_kind"], "IFACE_FLAPPING_001")
        reasoning = json.loads(inc["reasoning_json"])
        # Restano attivi il flapping e i testimoni delle ritrattazioni: il
        # ripristino è un fatto vero, ma è una conseguenza, non l'innesco.
        self.assertEqual(reasoning["rules_fired"],
                         ["IFACE_FLAPPING_001", "IFACE_RECOVERED_001"])
        self.assertEqual(inc["severity"], 3)

    def test_a_lone_drop_is_a_symptom_without_a_declared_cause(self):
        """Una caduta sola resta ciò che è: un sintomo. Il motore non inventa
        un innesco che nessuna regola ha dichiarato."""
        self._snapshots("Et0/0", ["up", "down"])
        self._correlate()
        with patch("collectors.mac_history.vlans_for_ips", return_value={}):
            incidents.group_once(NOW)
        inc = self._rows("SELECT * FROM incidents")[0]
        self.assertEqual(inc["cause_kind"], "causa_non_determinata")

    def test_a_link_drop_is_not_a_configuration_change(self):
        """Un cavo che si stacca non è una modifica: è qualcosa che è successo
        all'apparato, non qualcosa che qualcuno gli ha fatto."""
        self._snapshots("Et0/0", ["up", "down"])
        self._correlate()
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'CFG_CHANGE_001'"),
            [])



class TestInstabilityIsVisibleEvenWithoutAnIncident(unittest.TestCase):
    """Una porta che oscilla PIANO non raggiunge mai la soglia nella finestra
    di correlazione, quindi non diventa mai un incidente — ma è instabile lo
    stesso. Il pannello guarda un giorno intero e la mostra."""

    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()
        db.start_writer()

    @classmethod
    def tearDownClass(cls):
        db.stop_writer()

    def setUp(self):
        conn = db.get_observability_connection()
        for table in ("events", "normalize_cursors", "evidence", "incidents",
                      "api_observations"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def tearDown(self):
        # Gli override sono globali sull'app e altri moduli ne installano di
        # propri: si rimettono a posto SOLO quelli toccati qui. Svuotare la
        # mappa farebbe passare per admin i test di scoping altrui.
        import app_server
        for dep, previous in getattr(self, "_previous", {}).items():
            if previous is None:
                app_server.app.dependency_overrides.pop(dep, None)
            else:
                app_server.app.dependency_overrides[dep] = previous

    def _client(self):
        from fastapi.testclient import TestClient
        import app_server
        from routers import deps
        overrides = app_server.app.dependency_overrides
        self._previous = {
            deps.get_current_user: overrides.get(deps.get_current_user),
            deps.user_group_scope: overrides.get(deps.user_group_scope),
        }
        overrides[deps.get_current_user] = lambda: {"sub": "admin", "role": "admin"}
        overrides[deps.user_group_scope] = lambda: None
        return TestClient(app_server.app)

    def _slow_flap(self, iface="Et0/2", cycles=3):
        """Transizioni sparse su ore: mai quattro dentro la stessa finestra."""
        conn = db.get_observability_connection()
        for i in range(cycles * 2):
            conn.execute(
                """INSERT INTO events (ts, ingested_ts, tenant, source, event_type,
                       entity_type, entity_id, device_ip, interface, attrs_json,
                       dedup_key)
                   VALUES (?, ?, 'test_cml', 'snmp', 'interface.change',
                           'interface', ?, ?, ?, ?, ?)""",
                (NOW - 3600 * (cycles * 2 - i), NOW, f"{DEVICE}:{iface}", DEVICE,
                 iface,
                 json.dumps({"field": f"results.{iface}.link",
                             "before": "up" if i % 2 == 0 else "down",
                             "after": "down" if i % 2 == 0 else "up"}),
                 f"slow:{iface}:{i}"))
        # Stato corrente, perché la vista parte da interface.state.
        conn.execute(
            """INSERT INTO events (ts, ingested_ts, tenant, source, event_type,
                   entity_type, entity_id, device_ip, interface, attrs_json,
                   dedup_key)
               VALUES (?, ?, 'test_cml', 'snmp', 'interface.state', 'interface',
                       ?, ?, ?, ?, ?)""",
            (NOW - 60, NOW, f"{DEVICE}:{iface}", DEVICE, iface,
             json.dumps({"link": "up", "admin_status": "up"}),
             f"slowstate:{iface}"))
        conn.commit()
        conn.close()

    def test_the_panel_counts_transitions_the_rule_never_saw(self):
        self._slow_flap()
        r = self._client().get("/api/incidents/interfaces")
        self.assertEqual(r.status_code, 200, r.text)
        data = r.json()
        row = next(i for i in data["interfaces"] if i["interface"] == "Et0/2")
        self.assertEqual(row["transitions"], 6)
        self.assertGreaterEqual(row["transitions"], data["min_transitions"])
        # Nessun incidente: la regola non ha mai visto quattro transizioni
        # insieme.
        conn = db.get_observability_connection()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 0)
        conn.close()

    def test_an_administrative_shutdown_is_not_instability(self):
        """Spegnere una porta è una decisione, non un guasto: contarla qui
        farebbe sembrare inaffidabile una porta semplicemente disattivata."""
        conn = db.get_observability_connection()
        for i in range(4):
            conn.execute(
                """INSERT INTO events (ts, ingested_ts, tenant, source, event_type,
                       entity_type, entity_id, device_ip, interface, attrs_json,
                       dedup_key)
                   VALUES (?, ?, 'test_cml', 'snmp', 'interface.change',
                           'interface', ?, ?, 'Et0/3', ?, ?)""",
                (NOW - 600 * i, NOW, f"{DEVICE}:Et0/3", DEVICE,
                 json.dumps({"field": "results.Et0/3.admin_status",
                             "before": "up", "after": "down"}),
                 f"adm:{i}"))
        conn.execute(
            """INSERT INTO events (ts, ingested_ts, tenant, source, event_type,
                   entity_type, entity_id, device_ip, interface, attrs_json,
                   dedup_key)
               VALUES (?, ?, 'test_cml', 'snmp', 'interface.state', 'interface',
                       ?, ?, 'Et0/3', ?, 'admstate')""",
            (NOW - 60, NOW, f"{DEVICE}:Et0/3", DEVICE,
             json.dumps({"link": "down", "admin_status": "down"})))
        conn.commit()
        conn.close()

        r = self._client().get("/api/incidents/interfaces")
        row = next(i for i in r.json()["interfaces"] if i["interface"] == "Et0/3")
        self.assertEqual(row["transitions"], 0)


if __name__ == "__main__":
    unittest.main()
