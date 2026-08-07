"""
Unit tests for UI Variant setting endpoints GET/POST /api/settings/ui-variant
"""
import unittest
from fastapi.testclient import TestClient

import app_server
from security import user_manager


class TestUiVariantApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app_server.app, raise_server_exceptions=True)
        try:
            user_manager.create_user("uivariantuser", "Pass123!", role="operator")
        except Exception:
            pass
        r = cls.client.post("/api/auth/login", json={"username": "uivariantuser", "password": "Pass123!"})
        if r.status_code == 200:
            token = r.json().get("access_token")
            if token:
                cls.client.headers.update({"Authorization": f"Bearer {token}", "X-Requested-With": "SentinelNet"})

    def test_ui_variant_get_default(self):
        res = self.client.get("/api/settings/ui-variant")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("ui_variant", data)

    def test_ui_variant_set_valid_and_retrieve(self):
        for variant in ["default", "design-1", "design-2", "design-3", "design-4"]:
            res = self.client.post("/api/settings/ui-variant", json={"ui_variant": variant})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json().get("ui_variant"), variant)

            get_res = self.client.get("/api/settings/ui-variant")
            self.assertEqual(get_res.status_code, 200)
            self.assertEqual(get_res.json().get("ui_variant"), variant)

    def test_ui_variant_invalid(self):
        res = self.client.post("/api/settings/ui-variant", json={"ui_variant": "invalid-theme-xyz"})
        self.assertEqual(res.status_code, 400)


if __name__ == '__main__':
    unittest.main()
