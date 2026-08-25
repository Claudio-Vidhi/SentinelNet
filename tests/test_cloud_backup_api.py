# -*- coding: utf-8 -*-
"""Routes of the offsite mirror: RBAC, redaction, failure reporting."""
import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app_server
from security import user_manager
from services.cloud_backup.sftp import HostKeyMismatch


class TestCloudBackupApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app_server.app, raise_server_exceptions=True)
        for name, role in (("cbadmin", "admin"), ("cbviewer", "viewer")):
            try:
                user_manager.create_user(name, "Pass123!", role=role)
            except Exception:
                pass
        cls.tokens = {}
        for name in ("cbadmin", "cbviewer"):
            r = cls.client.post("/api/auth/login",
                                json={"username": name, "password": "Pass123!"})
            cls.tokens[name] = r.json().get("access_token", "")

    def _headers(self, who):
        return {"Authorization": f"Bearer {self.tokens[who]}",
                "X-Requested-With": "SentinelNet"}

    def test_settings_require_admin(self):
        r = self.client.get("/api/cloud-backup/settings", headers=self._headers("cbviewer"))
        self.assertEqual(403, r.status_code)

    def test_settings_never_return_a_secret(self):
        r = self.client.get("/api/cloud-backup/settings", headers=self._headers("cbadmin"))
        self.assertEqual(200, r.status_code)
        body = r.json()
        self.assertEqual("", body["password"])
        self.assertNotIn("password_enc", body)

    def test_invalid_config_is_rejected_before_being_stored(self):
        r = self.client.put("/api/cloud-backup/settings", headers=self._headers("cbadmin"),
                            json={"enabled": True, "kind": "sftp", "host": "",
                                  "port": 22, "username": "", "auth": "key",
                                  "key_path": "", "remote_root": ""})
        self.assertEqual(400, r.status_code)
        self.assertIn("host", r.text)

    def test_status_reports_age_and_pending(self):
        r = self.client.get("/api/cloud-backup/status", headers=self._headers("cbadmin"))
        self.assertEqual(200, r.status_code)
        for key in ("enabled", "pending", "hours_since_success", "last_run"):
            self.assertIn(key, r.json())

    def test_run_reports_the_failure_instead_of_raising(self):
        with mock.patch("services.cloud_backup.run_mirror",
                        return_value={"ok": False, "error": "connection refused",
                                      "uploaded": 0, "skipped": 0, "failed": 1,
                                      "verified": 0, "files": {}}):
            r = self.client.post("/api/cloud-backup/run", headers=self._headers("cbadmin"))
        self.assertEqual(200, r.status_code)
        self.assertFalse(r.json()["ok"])
        self.assertIn("connection refused", r.json()["error"])

    def test_partial_put_preserves_unset_fields(self):
        # Seed a full config, including a pinned host key and enabled=True.
        full = {"enabled": True, "kind": "sftp", "host": "203.0.113.5", "port": 22,
                "username": "backup", "auth": "key",
                "key_path": "/etc/sentinelnet/id_ed25519", "remote_root": "/mirror",
                "host_key_fingerprint": "SHA256:pinnedvalue", "encrypt_payload": False,
                "run_after_backup": True, "stale_after_hours": 48}
        r = self.client.put("/api/cloud-backup/settings", headers=self._headers("cbadmin"), json=full)
        self.assertEqual(200, r.status_code)

        # A client resending only `host` must not blank the pinned host key,
        # nor flip `enabled` back to the schema default of False.
        r = self.client.put("/api/cloud-backup/settings", headers=self._headers("cbadmin"),
                            json={"host": "203.0.113.6"})
        self.assertEqual(200, r.status_code)
        body = r.json()
        self.assertEqual("203.0.113.6", body["host"])
        self.assertEqual("SHA256:pinnedvalue", body["host_key_fingerprint"])
        self.assertTrue(body["enabled"])
        self.assertEqual(48, body["stale_after_hours"])

    def test_remote_filters_files_to_caller_group_scope(self):
        try:
            user_manager.create_user("cbscoped", "Pass123!", role="viewer", groups=["site-a"])
        except Exception:
            pass
        r = self.client.post("/api/auth/login",
                             json={"username": "cbscoped", "password": "Pass123!"})
        headers = {"Authorization": f"Bearer {r.json().get('access_token', '')}",
                   "X-Requested-With": "SentinelNet"}
        manifest = {"updated_at": "2026-08-25T00:00:00Z", "encrypted": False,
                    "files": {"site-a/switch-01.cfg": {"sha256": "sha256:aaa"},
                              "site-b/switch-02.cfg": {"sha256": "sha256:bbb"}}}

        class FakeTarget:
            def get(self, path):
                return json.dumps(manifest).encode("utf-8")

            def close(self):
                pass

        with mock.patch("services.cloud_backup.sftp.open_target", return_value=FakeTarget()):
            r = self.client.get("/api/cloud-backup/remote", headers=headers)
        self.assertEqual(200, r.status_code)
        files = r.json()["files"]
        self.assertIn("site-a/switch-01.cfg", files)
        self.assertNotIn("site-b/switch-02.cfg", files)

    def test_test_route_reports_fingerprint_on_success(self):
        class FakeTarget:
            fingerprint = "SHA256:observedvalue"

            def ensure_dir(self, remote_dir):
                pass

            def put(self, data, remote_path):
                pass

            def close(self):
                pass

        with mock.patch("services.cloud_backup.sftp.open_target", return_value=FakeTarget()):
            r = self.client.post("/api/cloud-backup/test", headers=self._headers("cbadmin"))
        self.assertEqual(200, r.status_code)
        body = r.json()
        self.assertTrue(body["ok"])
        self.assertEqual("SHA256:observedvalue", body["fingerprint"])

    def test_test_route_reports_host_key_mismatch_cleanly(self):
        with mock.patch("services.cloud_backup.sftp.open_target",
                        side_effect=HostKeyMismatch(
                            "host key SHA256:aaa does not match pinned SHA256:bbb")):
            r = self.client.post("/api/cloud-backup/test", headers=self._headers("cbadmin"))
        self.assertEqual(200, r.status_code)
        body = r.json()
        self.assertFalse(body["ok"])
        self.assertIn("does not match pinned", body["error"])


if __name__ == "__main__":
    unittest.main()
