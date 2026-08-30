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
        self.assertEqual(counts["outage"], 1)
        self.assertEqual(counts["maint"], 0)
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
        self.assertEqual(counts2["outage"], 0)
        self.assertEqual(counts2["maint"], 1)

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
        self.assertEqual(res3.json()["counts"]["outage"], 1)
        self.assertEqual(res3.json()["counts"]["maint"], 0)



    def _seed(self, links):
        """One interface.state event per link value, newest wins per entity."""
        now = int(time.time())
        conn = db.get_observability_connection()
        for i, link in enumerate(links):
            attrs = {} if link is None else {"link": link}
            conn.execute(
                "INSERT INTO events (ts, ingested_ts, tenant, source, event_type,"
                " entity_type, entity_id, device_ip, interface, attrs_json)"
                " VALUES (?,?,'default','snmp','interface.state','interface',?,?,?,?)",
                (now, now, f"192.0.2.1:Gi0/{i}", "192.0.2.1", f"Gi0/{i}",
                 json.dumps(attrs)))
        conn.commit()
        conn.close()
        return now

    def test_a_port_that_is_not_up_is_never_counted_as_up(self):
        """ifOperStatus has seven values, not two.

        Only "down"/"0"/"false" used to count as down and everything else fell
        through to up, so a port whose transceiver had been pulled
        (notPresent), or whose lower layer had failed (lowerLayerDown), was
        reported operational on the one view whose job is saying what broke.
        """
        self._seed(["up", "down", "lowerLayerDown", "notPresent",
                    "dormant", "testing", None])

        counts = self.client.get("/api/incidents/interfaces").json()["counts"]

        self.assertEqual(counts["total"], 7)
        self.assertEqual(counts["up"], 1, "only 'up' means the port carries traffic")
        self.assertEqual(counts["outage"], 3, "down, lowerLayerDown, notPresent")
        # Neither up nor broken, and above all not silently green.
        self.assertEqual(counts["unknown"], 3, "dormant, testing, missing link")

    def test_every_row_carries_the_state_the_counts_were_made_of(self):
        """The classifier is server-side and shipped, not re-derived client
        side: that duplication is how the KPI cards and the table drift."""
        self._seed(["up", "notPresent", None])

        data = self.client.get("/api/incidents/interfaces").json()

        states = sorted(r["state"] for r in data["interfaces"])
        self.assertEqual(states, ["outage", "unknown", "up"])
        tally = {}
        for row in data["interfaces"]:
            tally[row["state"]] = tally.get(row["state"], 0) + 1
        for state, n in tally.items():
            self.assertEqual(data["counts"][state], n,
                             f"counts[{state}] disagrees with the rows")

    def test_the_response_says_when_it_is_capped(self):
        """Past the cap every count describes the first page and nothing said
        so, while the UI presented 'Total Ports' as the truth."""
        data = self.client.get("/api/incidents/interfaces").json()
        self.assertIn("truncated", data)
        self.assertFalse(data["truncated"])
        self.assertGreater(data["limit"], 0)

    def test_a_batch_writes_the_settings_once(self):
        """It used to read-modify-write the whole settings blob per item, so a
        concurrent operator's save was lost to whoever finished last."""
        now = self._seed(["down", "down", "down"])
        items = [{"tenant": "default", "device_ip": "192.0.2.1",
                  "interface": f"Gi0/{i}", "suppressed": True,
                  "to_ts": now + 3600, "note": "window"} for i in range(3)]

        calls = []
        from core import app_settings as _app_settings
        original = _app_settings.save_app_settings

        def _counting_save(payload):
            calls.append(payload)
            return original(payload)

        _app_settings.save_app_settings = _counting_save
        try:
            res = self.client.post("/api/incidents/interfaces/expected",
                                   json={"items": items})
        finally:
            _app_settings.save_app_settings = original
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["count"], 3)
        self.assertEqual(len(calls), 1, f"saved {len(calls)} times for 3 items")

        counts = self.client.get("/api/incidents/interfaces").json()["counts"]
        self.assertEqual(counts["maint"], 3, "all three declarations survived")


if __name__ == "__main__":
    unittest.main()
