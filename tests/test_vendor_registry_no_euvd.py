# -*- coding: utf-8 -*-
"""Vendor registry no longer carries the obsolete euvd_term field.

The vulnerability scanner uses NVD NIST directly and resolves vendor search
terms via VENDOR_NVD_MAP in inventory_manager.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

from services import inventory_manager


class VendorRegistryNoEuvd(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._vendors_file = os.path.join(self._tmp.name, "vendors.json")
        patcher = mock.patch("services.inventory_manager.get_vendors_file",
                             return_value=self._vendors_file)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_default_vendors_have_no_euvd_term(self):
        vendors = inventory_manager.get_all_vendors()
        self.assertIn("cisco", vendors)
        for vname, vmeta in vendors.items():
            self.assertNotIn("euvd_term", vmeta, f"Vendor {vname} still contains euvd_term")

    def test_legacy_vendors_json_with_euvd_term_loads_cleanly(self):
        legacy = {
            "cisco": {"euvd_term": "cisco", "driver": "cisco_ios"},
            "custom_vendor": {"euvd_term": "custom", "driver": None},
        }
        with open(self._vendors_file, "w", encoding="utf-8") as fh:
            json.dump(legacy, fh)

        vendors = inventory_manager.get_all_vendors()
        self.assertIn("custom_vendor", vendors)
        for vname, vmeta in vendors.items():
            self.assertNotIn("euvd_term", vmeta, f"Vendor {vname} still has euvd_term after loading legacy file")

    def test_resolve_euvd_term_still_resolves_nvd_terms(self):
        self.assertEqual("palo alto", inventory_manager.resolve_euvd_term("paloalto"))
        self.assertEqual("cisco", inventory_manager.resolve_euvd_term("cisco_cbs"))
        self.assertEqual("hpe", inventory_manager.resolve_euvd_term("hpe"))


class SearchApiPayloadNoEuvd(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from app_server import app
        from security import user_manager
        self.client = TestClient(app)
        try:
            user_manager.create_user("operator_search_test", "Pass123!", role="operator")
        except Exception:
            pass
        from security.security_manager import create_access_token
        token = create_access_token({"sub": "operator_search_test", "role": "operator", "groups": ["*"]})
        self._headers = {"Authorization": f"Bearer {token}", "X-Requested-With": "SentinelNet"}

    def test_search_api_item_has_no_euvd_key_and_carries_cve_and_cwe(self):
        nvd_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-1234",
                        "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                        },
                        "weaknesses": [
                            {"description": [{"value": "CWE-79"}]}
                        ],
                        "published": "2026-01-01T00:00:00.000",
                        "references": []
                    }
                }
            ]
        }
        mock_resp = mock.MagicMock()
        mock_resp.json.return_value = nvd_response
        mock_resp.status_code = 200

        with mock.patch("requests.get", return_value=mock_resp):
            res = self.client.get("/api/search?vendor=cisco", headers=self._headers)
            self.assertEqual(200, res.status_code)
            data = res.json()
            self.assertIn("items", data)
            self.assertEqual(1, len(data["items"]))
            item = data["items"][0]
            self.assertNotIn("euvd", item, "item payload must not contain euvd key")
            self.assertEqual("CVE-2026-1234", item.get("cve"))
            self.assertEqual("CWE-79", item.get("cwe"))


if __name__ == "__main__":
    unittest.main()
