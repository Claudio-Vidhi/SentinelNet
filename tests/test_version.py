# -*- coding: utf-8 -*-
import os
import re
import unittest
from fastapi.testclient import TestClient

from app_server import app
from core.version import __version__


class TestAppVersion(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_version_format(self):
        """Version must follow Semantic Versioning (X.Y.Z[-tag])."""
        self.assertTrue(re.match(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$", __version__),
                        f"Invalid SemVer: {__version__}")

    def test_api_version_endpoint(self):
        """GET /api/version should return app name and version."""
        res = self.client.get("/api/version")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("app"), "SentinelNet")
        self.assertEqual(data.get("version"), __version__)

    def test_pyproject_version_matches(self):
        """pyproject.toml version should match core.version.__version__."""
        pyproject_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "pyproject.toml")
        with open(pyproject_path, "r", encoding="utf-8") as f:
            content = f.read()
        m = re.search(r'version\s*=\s*"([^"]+)"', content)
        self.assertIsNotNone(m, "version not found in pyproject.toml")
        self.assertEqual(m.group(1), __version__)

    def test_ui_contains_version_badge(self):
        """dashboard.html must have #appVersionBadge."""
        tpl_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates", "dashboard.html")
        with open(tpl_path, "r", encoding="utf-8") as f:
            html = f.read()
        self.assertIn('id="appVersionBadge"', html)


if __name__ == "__main__":
    unittest.main()
