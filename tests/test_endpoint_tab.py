# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
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

VIEWS = ("endpoint", "porte", "diagnosi", "raccolta")


def _read(*parts):
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class TestEndpointShell(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "client-map.js")

    def test_the_tab_exists(self):
        self.assertRegex(self.html, r'<div id="tab-endpoint" class="tab-content"[^>]*>')

    def test_page_head_and_search(self):
        tab = self.html[self.html.index('id="tab-endpoint"'):self.html.index('id="tab-wlc"')]
        self.assertIn('class="page-head"', tab)
        self.assertIn('id="locSearch"', tab)
        self.assertIn('id="locSearchMsg"', tab)
        self.assertNotIn('class="hero"', tab)
        self.assertNotIn('id="locPills"', tab)

    def test_tabs_and_panes_exist(self):
        self.assertIn('id="locTabs" class="loc-tabs" role="tablist"', self.html)
        for v in VIEWS:
            self.assertIn(f'id="locTab-{v}"', self.html)
            self.assertIn(f'aria-controls="locPane-{v}"', self.html)
            self.assertIn(f'id="locPane-{v}"', self.html)

    def test_tabs_are_wired_to_the_switcher(self):
        for v in VIEWS:
            self.assertIn(f'data-loc-view="{v}"', self.html)
        self.assertIn("function locSwitchView", self.js)
        self.assertIn("getElementById('locTabs')", self.js)

    def test_no_tenant_select_of_its_own(self):
        self.assertNotIn('id="locTenant"', self.html)
        self.assertIn("window.globalSelectedTenant", self.js)

    def test_the_nav_item_points_at_the_merged_tab(self):
        self.assertIn('data-tabs="tab-endpoint"', self.html)
        self.assertIn('data-tab="tab-endpoint"', self.html)


class TestPanesHoldTheContent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "client-map.js")

    def test_the_old_tabs_are_gone(self):
        for old in ("tab-mac", "tab-clientmap", "tab-diagnosi", "tab-endpoints"):
            self.assertNotIn(f'<div id="{old}" class="tab-content">', self.html)
            self.assertNotIn(f"switchTab('{old}')", self.html)

    def test_the_old_mac_search_is_gone(self):
        # The inventory lists every endpoint; a second search over the raw
        # sightings was a second answer to the same question.
        for old in ("macSearchMac", "macSearchVlan", "macSearchIface",
                    "macSearchSwitch", "btnMacSearch", "macResults", "kpiMacUniqueWrap"):
            self.assertNotIn(f'id="{old}"', self.html)
        for fn in ("function macSearch(", "function renderMacResults(", "function focusMacResults("):
            self.assertNotIn(fn, self.js)

    def _pane(self, view):
        start = self.html.index(f'id="locPane-{view}"')
        rest = self.html.find('id="locPane-', start + 1)
        return self.html[start:rest if rest != -1 else len(self.html)]

    def test_each_pane_holds_its_own_panels(self):
        self.assertIn('id="btnMacScan"', self._pane("raccolta"))
        self.assertIn('id="kpiMacSightings"', self._pane("raccolta"))
        self.assertIn('id="btnArpScan"', self._pane("raccolta"))
        self.assertIn('id="diagClientInput"', self._pane("diagnosi"))
        self.assertIn('id="epResults"', self._pane("endpoint"))


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
        # La lista non e' piu' scritta a mano: viene derivata dalla barra di
        # navigazione (vedi tests/test_assignable_tabs.py), quindi la tab
        # concedibile e' quella che il template dichiara.
        self.assertIn('data-tab="tab-endpoint"', _read("templates", "dashboard.html"))
        self.assertNotIn("{ id: 'tab-mac'", self.settings)

    @unittest.skipUnless(shutil.which("node"), "node non disponibile")
    def test_a_saved_permission_still_resolves(self):
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_loc_permission.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


class TestTheTwoCountersAreDistinguishable(unittest.TestCase):
    """Both counters were labelled 'MAC Univoci' and both were correct: one
    counted MACs seen in switch MAC tables, the other MACs with a known ARP
    binding. The ARP counter went with the Client Map search surface, so only
    the switch-table one is left — it keeps the label that says which MACs it
    counts, because the clash returns the moment a second MAC counter appears."""

    def test_the_label_says_which_macs_it_counts(self):
        src = _read("static", "js", "i18n.js")
        for line in src.splitlines():
            if "macKpiUniqueLabel" in line:
                self.assertNotIn("MAC Univoci", line)
                self.assertNotIn("Unique MACs", line)
        self.assertIn("MAC visti sugli switch", src)
        self.assertIn("MACs seen on switches", src)


class TestEndpointView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "endpoint-inventory.js")

    def test_toolbar_controls(self):
        for _id in ("epFilterSwitch", "epFilterVlan", "epFilterProbe", "epFilterStale",
                    "epFilterFrom", "epFilterTo", "btnEpReset", "epExportMenu",
                    "btnEpExportCsv", "btnEpExportJson", "epQueryChip"):
            self.assertIn(f'id="{_id}"', self.html)
        for gone in ("epFilterQ", "btnEpFilter", "btnEpResetTime"):
            self.assertNotIn(f'id="{gone}"', self.html)

    def test_the_search_drives_the_list(self):
        self.assertIn("function locSearchSubmit(", self.js)
        self.assertIn("getElementById('locSearchForm')", self.js)
        # One hit opens the drawer straight away.
        body = self.js[self.js.index("function locSearchSubmit("):]
        self.assertIn("openEpDrawer(", body[:body.index("\n}\n")])


class TestPortsView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "endpoint-inventory.js")

    def test_one_toolbar_one_host(self):
        for _id in ("ptSwitch", "ptWindow", "ptBad", "ptRefresh", "ptRead",
                    "ptLegendBtn", "ptLegend", "ptResults"):
            self.assertIn(f'id="{_id}"', self.html)
        for gone in ("peDevice", "peShow", "peResults", "epModeListBtn", "epPortsSwitch"):
            self.assertNotIn(f'id="{gone}"', self.html)
        self.assertNotIn("function endpointsMode(", self.js)

    def test_read_now_is_a_write_action(self):
        start = self.html.index('id="ptRead"')
        tag = self.html[self.html.rindex("<button", 0, start):self.html.index(">", start)]
        self.assertIn("requires-write", tag)


if __name__ == "__main__":
    unittest.main()
