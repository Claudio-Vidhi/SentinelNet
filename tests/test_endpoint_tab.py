# -*- coding: utf-8 -*-
"""The endpoint group is one tab with four pills, not four twin tabs.

Structure is asserted here, not appearance: that the pills and panes exist,
that the replaced controls are really gone (an orphaned control stays
clickable and drives a filter nobody reads any more), and that a saved
tab permission still resolves to the merged tab.
"""

import os
import shutil
import subprocess
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
        # macScanGroup/arpTenantMenu/epFilterTenant were the four per-pane
        # tenant controls Task 3 replaced with the single #locTenant; the
        # markers here moved to other pane-specific ids that Task 3 leaves
        # untouched.
        self.assertIn('id="macDeviceMenu"', self._pane("mac"))
        self.assertIn('id="kpiMacSightings"', self._pane("mac"))
        self.assertIn('id="arpDeviceMenu"', self._pane("clientmap"))
        self.assertIn('id="kpiArpBindings"', self._pane("clientmap"))
        self.assertIn('id="diagClientInput"', self._pane("diagnosi"))
        self.assertIn('id="epFilterQ"', self._pane("inventory"))


class TestOneTenantSelector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.cm = _read("static", "js", "client-map.js")
        cls.ei = _read("static", "js", "endpoint-inventory.js")

    def test_the_four_old_controls_are_gone(self):
        # An orphaned select stays clickable and filters nothing.
        for old in ("macScanGroup", "arpScanGroup", "arpTenantMenu",
                    "arpTenantSummary", "arpTenantList", "epFilterTenant"):
            self.assertNotIn(f'id="{old}"', self.html)

    def test_nothing_reads_them_any_more(self):
        for old in ("macScanGroup", "arpScanGroup", "arpTenantSummary",
                    "arpTenantList", "epFilterTenant"):
            self.assertNotIn(old, self.cm, f"{old} still read in client-map.js")
            self.assertNotIn(old, self.ei, f"{old} still read in endpoint-inventory.js")

    def test_the_accessor_exists(self):
        self.assertIn("function locTenant(", self.cm)


class TestEntryPoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = _read("static", "js", "core.js")
        cls.settings = _read("static", "js", "settings.js")

    def test_no_entry_point_names_the_old_tabs(self):
        for src, name in ((_read("static", "js", "diagnosi.js"), "diagnosi.js"),
                          (_read("static", "js", "endpoint-inventory.js"), "endpoint-inventory.js"),
                          (self.core, "core.js")):
            self.assertNotIn("switchTab('tab-diagnosi')", src, name)
            self.assertNotIn("tabId === 'tab-mac'", src, name)

    def test_assignable_tabs_offers_the_merged_tab(self):
        self.assertIn("{ id: 'tab-endpoint', key: 'tabEndpointLoc' }", self.settings)
        self.assertNotIn("{ id: 'tab-mac'", self.settings)

    @unittest.skipUnless(shutil.which("node"), "node non disponibile")
    def test_a_saved_permission_still_resolves(self):
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_loc_permission.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


class TestTheTwoCountersAreDistinguishable(unittest.TestCase):
    """Both counters were labelled 'MAC Univoci' and both were correct: one
    counts MACs seen in switch MAC tables, the other MACs with a known ARP
    binding. The merge puts them in different panes, which hides the clash
    instead of resolving it."""

    def test_the_labels_differ_in_both_languages(self):
        src = _read("static", "js", "i18n.js")
        for line in src.splitlines():
            if "macKpiUniqueLabel" in line or "arpKpiUniqueLabel" in line:
                self.assertNotIn("MAC Univoci", line)
                self.assertNotIn("Unique MACs", line)
        self.assertIn("MAC visti sugli switch", src)
        self.assertIn("MACs seen on switches", src)
        self.assertIn("MAC con un IP noto", src)
        self.assertIn("MACs with a known IP", src)


if __name__ == "__main__":
    unittest.main()
