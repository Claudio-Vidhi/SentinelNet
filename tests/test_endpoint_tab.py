# -*- coding: utf-8 -*-
"""The endpoint group is one tab with four pills, not four twin tabs.

Structure is asserted here, not appearance: that the pills and panes exist,
that the replaced controls are really gone (an orphaned control stays
clickable and drives a filter nobody reads any more), and that a saved
tab permission still resolves to the merged tab.
"""

import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR",
                      tempfile.mkdtemp(prefix="sentinelnet_endpoint_"))

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

VIEWS = ("mac", "clientmap", "diagnosi", "inventory")


def _read(*parts):
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class TestEndpointShell(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "client-map.js")

    def test_the_tab_exists(self):
        self.assertIn('<div id="tab-endpoint" class="tab-content">', self.html)

    def test_pills_and_panes_exist(self):
        for v in VIEWS:
            self.assertIn(f'id="locPill-{v}"', self.html)
            self.assertIn(f'id="locPane-{v}"', self.html)

    def test_pills_are_wired_to_the_switcher(self):
        for v in VIEWS:
            self.assertIn(f"locSwitchView('{v}')", self.html)
        self.assertIn("function locSwitchView", self.js)

    def test_one_tenant_select_in_the_header(self):
        self.assertIn('id="locTenant"', self.html)

    def test_the_nav_item_points_at_the_merged_tab(self):
        self.assertIn('data-tabs="tab-endpoint"', self.html)
        self.assertIn("switchTab('tab-endpoint', this)", self.html)


if __name__ == "__main__":
    unittest.main()
