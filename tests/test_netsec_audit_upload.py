# -*- coding: utf-8 -*-
"""Test del flusso di upload file per l'auditing di configurazione."""

import os
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_auditupload_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402
from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
from core import db  # noqa: E402
from security import user_manager  # noqa: E402

PASS = "PasswordSicura1!"
CSRF = {"X-Requested-With": "SentinelNet"}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestNetSecAuditUpload(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()
        try:
            user_manager.create_user("adm_upload", PASS, role="admin", groups=None)
        except Exception:
            pass
        with open(os.path.join(ROOT, "static", "js", "netsec-audit.js"), encoding="utf-8") as f:
            cls.js = f.read()
        with open(os.path.join(ROOT, "templates", "dashboard.html"), encoding="utf-8") as f:
            cls.html = f.read()

    def _client(self):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login",
                   json={"username": "adm_upload", "password": PASS})
        assert r.status_code == 200, r.text
        return c

    def test_upload_scan_with_filename_sets_device_name(self):
        c = self._client()
        cfg = "config system global\n    set admintimeout 5\nend\n"
        r = c.post("/api/netsec-audit/scan", headers=CSRF,
                   json={"benchmark": "cis", "config_text": cfg, "device_name": "firewall-hq.conf"})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertIn("score", body)
        self.assertTrue(body["rules"])
        self.assertEqual(body["rules"][0]["device"], "firewall-hq.conf")

    def test_upload_scan_defaults_device_name_if_omitted(self):
        c = self._client()
        cfg = "hostname router-edge\nservice password-encryption\n"
        r = c.post("/api/netsec-audit/scan", headers=CSRF,
                   json={"benchmark": "cis", "config_text": cfg})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["rules"][0]["device"], "Uploaded Config")

    def test_frontend_dropzone_and_file_input_structure(self):
        self.assertIn('id="auditDropZone"', self.html)
        self.assertIn('id="auditFileInput"', self.html)
        self.assertIn('accept=".conf,.cfg,.txt,.xml"', self.html)

    def test_frontend_dropzone_prevents_recursion_and_handles_events(self):
        self.assertIn("function setupConfigDropzone", self.js)
        self.assertIn("e.stopPropagation()", self.js)
        self.assertIn("if (e.target === fileInput) return;", self.js)
        self.assertIn("handleFile", self.js)

    def test_frontend_restore_uploaded_option_logic(self):
        body = self.js[self.js.index("function restoreUploadedOption"):]
        body = body[:body.index("function syncDropzoneHint")]
        self.assertIn("UPLOADED_VALUE", body)
        self.assertIn("_droppedConfigText", body)

    def test_frontend_payload_includes_device_name(self):
        self.assertIn("device_name: uploaded ? _droppedConfigName", self.js)


if __name__ == "__main__":
    unittest.main()
