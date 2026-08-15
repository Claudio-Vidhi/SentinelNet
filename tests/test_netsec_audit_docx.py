# -*- coding: utf-8 -*-
"""Test per l'esportazione DOCX del report NetSec Audit."""

import unittest
from fastapi.testclient import TestClient
from app_server import app
from routers.deps import get_current_user


def mock_user():
    return {"sub": "admin", "role": "admin", "groups": ["*"]}


class TestNetSecAuditDocxExport(unittest.TestCase):

    def setUp(self):
        app.dependency_overrides[get_current_user] = mock_user
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()

    def test_export_docx_endpoint(self):
        payload = {
            "device_name": "FortiGate-Core",
            "benchmark_title": "CIS Fortinet FortiGate 7.4.x Benchmark",
            "vendor": "fortios",
            "score": 75,
            "summary": {"total": 20, "passed": 15, "failed": 4, "warned": 1, "unknown": 0},
            "rules": [
                {
                    "id": "AUD-CIS-01",
                    "title": "Protocolli di gestione non sicuri",
                    "detail": "Telnet/HTTP abilitati su interfaccia",
                    "severity": "CRITICAL",
                    "status": "FAIL",
                    "remediation": "config system interface / edit port1 / set allowaccess ssh https",
                    "guidance": {
                        "why": "Telnet e HTTP trasmettono in chiaro",
                        "impact": "Nessuno",
                        "default": "disable"
                    },
                    "evidence": [
                        {"line": 100, "context": "firewall policy / 5", "text": "set allowaccess telnet http"}
                    ]
                }
            ]
        }
        res = self.client.post("/api/netsec-audit/export/docx", json=payload)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("content-type"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        self.assertTrue(len(res.content) > 1000)
        # Verifica firma ZIP/DOCX PK\x03\x04
        self.assertTrue(res.content.startswith(b"PK\x03\x04"))


if __name__ == "__main__":
    unittest.main()
