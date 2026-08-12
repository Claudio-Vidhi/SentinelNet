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


class TestPanesHoldTheContent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")

    def test_the_old_tabs_are_gone(self):
        for old in ("tab-mac", "tab-clientmap", "tab-diagnosi", "tab-endpoints"):
            self.assertNotIn(f'<div id="{old}" class="tab-content">', self.html)

    def test_the_subtab_bar_is_not_duplicated_any_more(self):
        # The bar was copy-pasted into all four tabs; one pill bar replaces it.
        # Do NOT count the 'ti-subtab' class globally: Provisioning, Topologia
        # and Threat Intel share it. Assert instead that no button anywhere
        # still switches to one of the four merged tabs.
        for old in ("tab-mac", "tab-clientmap", "tab-diagnosi", "tab-endpoints"):
            self.assertNotIn(f"switchTab('{old}')", self.html)

    def _pane(self, view):
        start = self.html.index(f'id="locPane-{view}"')
        rest = self.html.find('id="locPane-', start + 1)
        return self.html[start:rest if rest != -1 else len(self.html)]

    def test_each_pane_holds_its_own_panels(self):
        self.assertIn('id="macScanGroup"', self._pane("mac"))
        self.assertIn('id="kpiMacSightings"', self._pane("mac"))
        self.assertIn('id="arpTenantMenu"', self._pane("clientmap"))
        self.assertIn('id="kpiArpBindings"', self._pane("clientmap"))
        self.assertIn('id="diagClientInput"', self._pane("diagnosi"))
        self.assertIn('id="epFilterTenant"', self._pane("inventory"))


if __name__ == "__main__":
    unittest.main()
