# -*- coding: utf-8 -*-
"""Routes of the offsite mirror: RBAC, redaction, failure reporting."""
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app_server
from security import user_manager


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


if __name__ == "__main__":
    unittest.main()
