# -*- coding: utf-8 -*-
"""Test dedicated interfaces monitoring endpoint, metrics counts, and batch expected state."""
import json
import time
import unittest
from fastapi.testclient import TestClient

import app_server
from core import db
from core.app_settings import save_app_settings
from routers.deps import require_operator, get_current_user


class TestInterfacesMonitoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.migrate()

    def setUp(self):
        self.client = TestClient(app_server.app)
        save_app_settings({"suppressions": {}})
        conn = db.get_observability_connection()
        for table in ("events", "api_observations", "evidence", "incidents"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

        user_mock = lambda: {"sub": "admin", "role": "admin", "groups": []}
        app_server.app.dependency_overrides[get_current_user] = user_mock
        app_server.app.dependency_overrides[require_operator] = user_mock

    def tearDown(self):
        app_server.app.dependency_overrides.clear()

    def test_interfaces_counts_and_batch_suppression(self):
        now = int(time.time())
        conn = db.get_observability_connection()
        conn.execute(
            """INSERT INTO events (ts, ingested_ts, tenant, source, event_type, entity_type, entity_id, device_ip, interface, attrs_json)
               VALUES (?, ?, 'default', 'snmp', 'interface.state', 'interface', '10.0.0.1:GigabitEthernet0/1', '10.0.0.1', 'GigabitEthernet0/1', ?),
                      (?, ?, 'default', 'snmp', 'interface.state', 'interface', '10.0.0.1:GigabitEthernet0/2', '10.0.0.1', 'GigabitEthernet0/2', ?)""",
            (now, now, json.dumps({"link": "up"}),
             now, now, json.dumps({"link": "down"}))
        )
        conn.commit()
        conn.close()

        # 1. Fetch interfaces & verify counts
        res = self.client.get("/api/incidents/interfaces")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("counts", data)
        counts = data["counts"]
        self.assertEqual(counts["total"], 2)
        self.assertEqual(counts["up"], 1)
        self.assertEqual(counts["down"], 1)
        self.assertEqual(counts["in_maintenance"], 0)
        self.assertEqual(counts["by_design"], 0)

        # 2. Set batch suppression
        batch_payload = {
            "items": [
                {
                    "tenant": "default",
                    "device_ip": "10.0.0.1",
                    "interface": "GigabitEthernet0/2",
                    "suppressed": True,
                    "to_ts": now + 3600,
                    "note": "Scheduled maintenance"
                }
            ]
        }
        res_post = self.client.post("/api/incidents/interfaces/expected", json=batch_payload)
        self.assertEqual(res_post.status_code, 200)
        post_data = res_post.json()
        self.assertEqual(post_data["status"], "success")
        self.assertEqual(post_data["count"], 1)

        # 3. Verify counts updated: down is now in_maintenance
        res2 = self.client.get("/api/incidents/interfaces")
        self.assertEqual(res2.status_code, 200)
        counts2 = res2.json()["counts"]
        self.assertEqual(counts2["total"], 2)
        self.assertEqual(counts2["up"], 1)
        self.assertEqual(counts2["down"], 0)
        self.assertEqual(counts2["in_maintenance"], 1)

        # 4. Clear batch suppression
        clear_payload = {
            "items": [
                {
                    "tenant": "default",
                    "device_ip": "10.0.0.1",
                    "interface": "GigabitEthernet0/2",
                    "suppressed": False
                }
            ]
        }
        res_clear = self.client.post("/api/incidents/interfaces/expected", json=clear_payload)
        self.assertEqual(res_clear.status_code, 200)

        # 5. Verify back to down
        res3 = self.client.get("/api/incidents/interfaces")
        self.assertEqual(res3.json()["counts"]["down"], 1)
        self.assertEqual(res3.json()["counts"]["in_maintenance"], 0)


if __name__ == "__main__":
    unittest.main()
