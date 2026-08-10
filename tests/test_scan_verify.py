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


class TestScanVerify(ScanApiTestCase):
    """The only step that authenticates. It runs on the rows a human ticked,
    with an identity that human chose."""

    def setUp(self):
        from security import identity_manager
        self.im = identity_manager
        self.ident_id = self.im.add_identity("scan-test", "all", "u", "p", "s")["id"]

    def tearDown(self):
        self.im.delete_identity(self.ident_id)

    def _verify(self, body, probe_result=None):
        from core import core_engine
        probe_result = probe_result or {"status": "success", "hostname": "switch-01"}
        with mock.patch.object(core_engine, "probe_device", return_value=probe_result) as probe:
            r = self._client().post("/api/scan-verify", json=body)
            if r.status_code == 200:
                job_id = r.json()["job_id"]
                # The job runs on a real thread; poll until it settles.
                for _ in range(100):
                    poll = self._client().get(f"/api/scan-subnet/{job_id}")
                    if poll.json()["status"] != "running":
                        return r, probe, poll.json()
                    time.sleep(0.05)
                self.fail("verify job never finished")
        return r, probe, None

    def test_successful_verify_returns_hostname(self):
        _, probe, job = self._verify({
            "ips": ["192.0.2.10"], "vendor": "cisco", "identity_id": self.ident_id,
        })
        probe.assert_called_once()
        self.assertEqual(job["results"], [
            {"ip": "192.0.2.10", "ok": True, "hostname": "switch-01", "error": None},
        ])

    def test_failed_login_reports_the_reason(self):
        _, _, job = self._verify(
            {"ips": ["192.0.2.10"], "vendor": "cisco", "identity_id": self.ident_id},
            probe_result={"status": "error", "message": "Authentication failed"},
        )
        row = job["results"][0]
        self.assertFalse(row["ok"])
        self.assertIsNone(row["hostname"])
        self.assertEqual(row["error"], "Authentication failed")

    def test_probe_receives_the_chosen_vendor_and_encrypted_credentials(self):
        _, probe, _ = self._verify({
            "ips": ["192.0.2.10"], "vendor": "linux", "identity_id": self.ident_id,
        })
        device = probe.call_args.args[0]
        self.assertEqual(device["Vendor"], "linux")
        self.assertEqual(device["IP"], "192.0.2.10")
        # probe_device -> get_device_credentials decrypts, so it must get ciphertext.
        self.assertNotEqual(device["Password"], "p")

    def test_identity_outside_scope_is_404_and_never_decrypts(self):
        from routers import scan
        scoped = self.im.add_identity("altra-sede", "SiteZ", "u", "p", "s")["id"]
        try:
            with mock.patch.object(scan, "user_group_scope", return_value={"SiteA"}), \
                 mock.patch.object(self.im, "get_identity_credentials") as creds:
                r = self._client().post("/api/scan-verify", json={
                    "ips": ["192.0.2.10"], "vendor": "cisco", "identity_id": scoped,
                })
            self.assertEqual(r.status_code, 404)
            creds.assert_not_called()
        finally:
            self.im.delete_identity(scoped)

    def test_unknown_identity_is_404(self):
        r, _, _ = self._verify({
            "ips": ["192.0.2.10"], "vendor": "cisco", "identity_id": "deadbeef",
        })
        self.assertEqual(r.status_code, 404)

    def test_malformed_ip_is_rejected(self):
        r, _, _ = self._verify({
            "ips": ["not-an-ip"], "vendor": "cisco", "identity_id": self.ident_id,
        })
        self.assertEqual(r.status_code, 422)

    def test_empty_ip_list_is_rejected(self):
        r, _, _ = self._verify({"ips": [], "vendor": "cisco", "identity_id": self.ident_id})
        self.assertEqual(r.status_code, 422)


class TestIdentityVisibility(unittest.TestCase):
    """A caller restricted to some sites must not borrow another site's
    credentials by guessing an identity id."""

    def setUp(self):
        from security import identity_manager
        self.im = identity_manager
        self.global_id = self.im.add_identity("globale", "all", "u", "p", "s")["id"]
        self.site_a_id = self.im.add_identity("sede-a", "SiteA", "u", "p", "s")["id"]
        self.multi_id = self.im.add_identity("multi", ["SiteA", "SiteB"], "u", "p", "s")["id"]

    def tearDown(self):
        for ident in (self.global_id, self.site_a_id, self.multi_id):
            self.im.delete_identity(ident)

    def test_none_scope_sees_everything(self):
        for ident in (self.global_id, self.site_a_id, self.multi_id):
            self.assertTrue(self.im.identity_visible_to(ident, None))

    def test_global_identity_is_visible_to_any_scope(self):
        self.assertTrue(self.im.identity_visible_to(self.global_id, {"SiteC"}))

    def test_scoped_identity_hidden_from_other_site(self):
        self.assertFalse(self.im.identity_visible_to(self.site_a_id, {"SiteC"}))

    def test_scoped_identity_visible_to_its_own_site(self):
        self.assertTrue(self.im.identity_visible_to(self.site_a_id, {"SiteA"}))

    def test_multi_tenant_identity_matches_any_of_its_sites(self):
        self.assertTrue(self.im.identity_visible_to(self.multi_id, {"SiteB"}))
        self.assertFalse(self.im.identity_visible_to(self.multi_id, {"SiteC"}))

    def test_unknown_id_is_not_visible(self):
        self.assertFalse(self.im.identity_visible_to("deadbeef", None))


if __name__ == "__main__":
    unittest.main()
