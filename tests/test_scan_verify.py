# -*- coding: utf-8 -*-
"""Subnet scan is discovery-only; the login step is a separate, explicit
endpoint gated on an identity the caller is allowed to use."""

import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_scanverify_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from security import user_manager  # noqa: E402

ADMIN, ADMIN_PASS = "scanadmin", "PasswordSicura1!"


class ScanApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        user_manager.create_user(ADMIN, ADMIN_PASS, role="admin")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def _client(self):
        client = TestClient(app_server.app)
        r = client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        self.assertEqual(r.status_code, 200)
        token = r.json()["access_token"]
        client.headers.update({"Authorization": f"Bearer {token}"})
        return client


class TestScanPortValidation(ScanApiTestCase):
    """Ports are user input: 254 hosts x 65535 ports is one POST away."""

    # Patch the name in routers.scan's namespace, not threading.Thread itself:
    # the real threading module is what TestClient's portal thread runs on.
    def _post(self, body):
        with mock.patch("routers.scan.threading"):
            return self._client().post("/api/scan-subnet", json=body)

    def test_default_is_port_22(self):
        with mock.patch("routers.scan.threading") as thread:
            r = self._client().post("/api/scan-subnet", json={"network": "192.0.2.0/29"})
        self.assertEqual(r.status_code, 200)
        payload = thread.Thread.call_args.kwargs["args"][1]
        self.assertEqual(payload.ports, [22])

    def test_empty_port_list_is_accepted(self):
        r = self._post({"network": "192.0.2.0/29", "ports": []})
        self.assertEqual(r.status_code, 200)

    def test_port_out_of_range_is_rejected(self):
        self.assertEqual(self._post({"network": "192.0.2.0/29", "ports": [0]}).status_code, 422)
        self.assertEqual(self._post({"network": "192.0.2.0/29", "ports": [65536]}).status_code, 422)

    def test_too_many_ports_is_rejected(self):
        r = self._post({"network": "192.0.2.0/29", "ports": list(range(1, 20))})
        self.assertEqual(r.status_code, 422)

    def test_invalid_network_is_400(self):
        r = self._post({"network": "not-a-network", "ports": [22]})
        self.assertEqual(r.status_code, 400)

    def test_vendor_and_auto_add_are_gone(self):
        # Extra keys must not resurrect the old behaviour by accident.
        import inspect
        from routers import scan
        source = inspect.getsource(scan)
        self.assertNotIn("auto_add", source)
        self.assertNotIn("use_default_creds", source)
        self.assertNotIn("DEFAULT_PASSWORD", source)


if __name__ == "__main__":
    unittest.main()
