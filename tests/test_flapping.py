# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Flapping in the Interfaces view: link transitions counted over a whole day.

The fault is not last night's drop, it is the unstable link.
"""

import json
import os
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_flap_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402

NOW = int(time.time())
DEVICE = "192.168.31.7"


class TestInstabilityOverADay(unittest.TestCase):
    """A port that flaps SLOWLY is still unstable: the panel looks at a whole
    day and shows it."""

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
        for table in ("events", "normalize_cursors", "api_observations"):
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

    def test_the_panel_counts_slow_transitions(self):
        self._slow_flap()
        r = self._client().get("/api/observability/interfaces")
        self.assertEqual(r.status_code, 200, r.text)
        data = r.json()
        row = next(i for i in data["interfaces"] if i["interface"] == "Et0/2")
        self.assertEqual(row["transitions"], 6)
        self.assertGreaterEqual(row["transitions"], data["min_transitions"])
        self.assertEqual(row["state"], "flapping")

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

        r = self._client().get("/api/observability/interfaces")
        row = next(i for i in r.json()["interfaces"] if i["interface"] == "Et0/3")
        self.assertEqual(row["transitions"], 0)


if __name__ == "__main__":
    unittest.main()
