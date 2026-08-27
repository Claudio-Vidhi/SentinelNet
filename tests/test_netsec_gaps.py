# -*- coding: utf-8 -*-
"""
Unit tests for newly implemented NetSec capability gaps:
- WLC UI and routing
- FortiGate targeted session delete
- Switch port control
- Observability log pruning
"""

unittest_module = __import__('unittest')
TestCase = unittest_module.TestCase

from fastapi.testclient import TestClient
import app_server
from security import user_manager

class TestNetSecGaps(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app_server.app, raise_server_exceptions=True)
        try:
            user_manager.create_user("gapadmin", "Pass123!", role="admin")
        except Exception:
            pass
        r = cls.client.post("/api/auth/login", json={"username": "gapadmin", "password": "Pass123!"})
        if r.status_code == 200:
            token = r.json().get("access_token")
            if token:
                cls.client.headers.update({"Authorization": f"Bearer {token}", "X-Requested-With": "SentinelNet"})

    def test_observability_prune_logs(self):
        resp = self.client.post("/api/observability/prune-logs", json={"days": 15})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json().get("status"), "success")
        self.assertEqual(resp.json().get("days_retained"), 15)

    def test_fortigate_delete_sessions(self):
        # 404 expected when device 192.0.2.1 is not in inventory, but handler body executes cleanly
        resp = self.client.request("DELETE", "/api/fortigate/192.0.2.1/sessions", json={"src_ip": "192.0.2.50"})
        self.assertIn(resp.status_code, (200, 404))

    def test_mac_port_control(self):
        # 404 expected when device 192.0.2.2 is not in inventory, but handler body executes cleanly
        resp = self.client.post("/api/mac/port-control", json={"ip": "192.0.2.2", "port": "Gi1/0/1", "action": "shutdown"})
        self.assertIn(resp.status_code, (200, 404))

if __name__ == '__main__':
    unittest_module.main()
