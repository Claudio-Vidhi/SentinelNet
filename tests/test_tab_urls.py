# -*- coding: utf-8 -*-
"""Every tab has its own address (/devices, /settings, ...), so a reload or a
shared link lands on the same tab instead of the overview."""
import os
import re
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_taburls_"))

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class TabAddressesAreServed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app_server.app)

    def test_a_tab_address_serves_the_dashboard(self):
        for path in ("/devices", "/settings", "/config-drift", "/map-interactive"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, path)
            self.assertIn('id="appSidebar"', r.text, path)

    def test_every_tab_panel_has_an_address(self):
        slugs = re.findall(r'<div id="tab-([a-z0-9-]+)" class="tab-content', _read("templates", "dashboard.html"))
        self.assertGreater(len(slugs), 20)
        self.assertEqual(set(slugs), set(app_server.TAB_SLUGS))

    def test_an_unknown_address_is_still_a_404(self):
        self.assertEqual(self.client.get("/definitely-not-a-tab").status_code, 404)

    def test_the_catch_all_does_not_swallow_the_api_or_the_docs(self):
        self.assertEqual(self.client.get("/api/version").status_code, 200)
        self.assertEqual(self.client.get("/openapi.json").status_code, 200)

    def test_tab_addresses_stay_out_of_the_api_schema(self):
        self.assertNotIn("/{slug}", app_server.app.openapi()["paths"])


class TheBrowserFollowsTheAddress(unittest.TestCase):
    def setUp(self):
        self.core = _read("static", "js", "core.js")

    def test_switching_tab_writes_the_address(self):
        start = self.core.index("async function switchTab(")
        body = self.core[start:self.core.index("await ensureTabScripts", start)]
        self.assertIn("syncAddressToTab(tabId", body)

    def test_boot_and_back_button_read_the_address(self):
        self.assertIn("tabFromAddress()", self.core[self.core.index("async function appInit("):])
        self.assertIn("addEventListener('popstate'", self.core)


if __name__ == "__main__":
    unittest.main()
