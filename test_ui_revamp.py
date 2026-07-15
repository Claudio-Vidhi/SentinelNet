# -*- coding: utf-8 -*-
import os, tempfile
_TMP = tempfile.mkdtemp(prefix="sentinelnet_uirevamp_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP
import unittest
from html.parser import HTMLParser  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
import data_config  # noqa: E402
data_config.DATA_DIR = _TMP
import app_server  # noqa: E402


def _html():
    return TestClient(app_server.app).get("/").text


# ---------------------------------------------------------------------------
# HTML nesting/balance guard (Task 14 finding)
#
# Every other test in this file only checks substring presence (an id, a
# class, an onclick hook). That cannot catch a *nesting* bug: deleting a
# single </div> leaves every id/class/hook byte-for-byte present, just
# parented under the wrong ancestor. A reviewer proved this by deleting the
# </div> that closes #provFgtSection -- #provCiscoSection silently becomes
# its child, breaking the runtime vendor toggle -- and the whole suite
# still passed. _NestingParser below drives stdlib html.parser.HTMLParser
# over the *rendered* HTML to check real nesting, not text membership.
# ---------------------------------------------------------------------------

class _NestingParser(HTMLParser):
    """Generic tag-nesting/balance checker built on stdlib HTMLParser.

    - <script>/<style> bodies are never scanned for tags: HTMLParser's
      built-in CDATA_CONTENT_ELEMENTS handling treats everything up to the
      matching </script>/</style> as opaque text, so the many HTML-shaped
      template-literal strings inside this file's inline JS (e.g. the SVG
      markup built by the topology renderer) are never mistaken for real
      markup.
    - Void/self-closing elements (<br>, <img>, <input>, <meta>, <link>,
      <hr>, <source>, ...) never require a closing tag and are therefore
      never pushed onto the nesting stack.
    - For any id passed in `watch_ids`, records the (line, col) position of
      its opening tag and, once the LIFO stack pops it, the position of
      whichever closing tag actually popped it. That "whichever" is the
      crux: browsers (and this parser) resolve a bare </div> against the
      *nearest* open <div> regardless of id, which is exactly the mechanism
      that lets one missing </div> silently re-parent a sibling as a child
      instead of raising a hard parse error.
    """

    VOID_ELEMENTS = {
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr",
    }

    def __init__(self, watch_ids=()):
        super().__init__(convert_charrefs=True)
        self.watch_ids = set(watch_ids)
        self.stack = []        # [{"tag":str, "id":str|None}, ...]
        self.errors = []       # stray/mismatched closing tags
        self.spans = {}        # id -> {"start": (line,col), "end": (line,col)|None}
        self.push_counts = {}  # id -> number of times an element with that id opened

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self.VOID_ELEMENTS:
            return
        _id = dict(attrs).get("id")
        self.stack.append({"tag": tag, "id": _id})
        if _id in self.watch_ids:
            self.push_counts[_id] = self.push_counts.get(_id, 0) + 1
            self.spans[_id] = {"start": self.getpos(), "end": None}

    def handle_startendtag(self, tag, attrs):
        # Explicitly self-closed, e.g. `<path d="..."/>` in inline SVG --
        # balanced by construction, never pushed (mirrors handle_starttag's
        # void-element skip so we don't double-count).
        return

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self.VOID_ELEMENTS:
            return
        if not self.stack:
            self.errors.append(f"stray closing tag </{tag}> at {self.getpos()}")
            return
        top = self.stack[-1]
        if top["tag"] != tag:
            self.errors.append(
                f"mismatch at {self.getpos()}: expected </{top['tag']}> "
                f"(id={top['id']!r}) but found </{tag}>")
            return
        self.stack.pop()
        if top["id"] in self.watch_ids:
            self.spans[top["id"]]["end"] = self.getpos()


def _parse(html, watch_ids=()):
    p = _NestingParser(watch_ids)
    p.feed(html)
    p.close()
    return p


# All #tab-* bodies, in the order they actually appear in the rendered
# document (verified against templates/dashboard.html).
TAB_IDS_IN_DOC_ORDER = [
    "tab-home", "tab-devices", "tab-groups", "tab-map", "tab-map-interactive",
    "tab-categories", "tab-security", "tab-mac", "tab-clientmap", "tab-flows",
    "tab-config", "tab-ai", "tab-provisioner", "tab-import", "tab-users",
    "tab-sites", "tab-mcp", "tab-settings",
]


class TestTabNestingBalance(unittest.TestCase):
    """Task 14 finding: regression guard for HTML element nesting/balance.

    Deleting the </div> that closes #provFgtSection (so #provCiscoSection
    nests inside it instead of being its sibling) passed all 55 pre-existing
    tests. These tests parse the rendered HTML with html.parser and check
    real nesting -- verified locally to fail against that exact mutation and
    pass once the file is restored.
    """

    @classmethod
    def setUpClass(cls):
        cls.html = _html()
        cls.watch_ids = set(TAB_IDS_IN_DOC_ORDER) | {"provFgtSection", "provCiscoSection"}
        cls.parsed = _parse(cls.html, watch_ids=cls.watch_ids)
        # cumulative char offset of the start of each line, for slicing.
        cls.line_offsets = []
        total = 0
        for line in cls.html.splitlines(keepends=True):
            cls.line_offsets.append(total)
            total += len(line)
        cls.line_offsets.append(total)

    def _offset(self, pos):
        line, col = pos
        return self.line_offsets[line - 1] + col

    def test_document_has_no_stray_or_mismatched_closing_tags(self):
        # A single deleted </div> doesn't necessarily raise an immediate
        # tag-name mismatch (div still matches div) -- but the deficit it
        # creates always surfaces by end-of-document, either as an explicit
        # mismatch (a later real tag colliding with the missing close) or
        # as unclosed tags left on the stack at EOF. Both are asserted.
        self.assertEqual(self.parsed.errors, [],
                          "stray/mismatched closing tag(s) found while parsing "
                          "the rendered dashboard -- see positions above")
        self.assertEqual(self.parsed.stack, [],
                          f"document ends with unclosed tag(s): {self.parsed.stack}")

    def test_every_tab_body_opens_once_and_closes(self):
        for tab_id in TAB_IDS_IN_DOC_ORDER:
            with self.subTest(tab=tab_id):
                self.assertEqual(self.parsed.push_counts.get(tab_id), 1,
                                  f"#{tab_id} should open exactly once")
                span = self.parsed.spans.get(tab_id)
                self.assertIsNotNone(span, f"#{tab_id} not found in rendered HTML")
                self.assertIsNotNone(
                    span["end"],
                    f"#{tab_id} <div> is never closed before end-of-document -- "
                    f"a missing </div> upstream is swallowing its close tag")

    def test_each_tab_body_is_internally_balanced(self):
        # Re-parse each tab's own slice in isolation, so an internal
        # imbalance (not just the outer wrapper) is caught and localized to
        # the specific tab, independent of the whole-document check above.
        for tab_id in TAB_IDS_IN_DOC_ORDER:
            with self.subTest(tab=tab_id):
                span = self.parsed.spans[tab_id]
                if span["end"] is None:
                    self.fail(f"#{tab_id} <div> never closes -- cannot slice "
                              f"it for an internal-balance re-check (see "
                              f"test_every_tab_body_opens_once_and_closes)")
                start = self._offset(span["start"])
                end = self._offset(span["end"])
                end = self.html.index(">", end) + 1  # include the closing </div>
                fragment = self.html[start:end]
                sub = _parse(fragment)
                self.assertEqual(sub.errors, [],
                                  f"#{tab_id} internal markup has mismatched tags: {sub.errors}")
                self.assertEqual(sub.stack, [],
                                  f"#{tab_id} internal markup left tag(s) open: {sub.stack}")

    def test_tabs_are_siblings_never_nested(self):
        # The invariant that actually catches the Task 14 mutation: each
        # tab body must close before the next one opens. HTMLParser.getpos()
        # positions are (line, col) tuples that compare in document order.
        for a, b in zip(TAB_IDS_IN_DOC_ORDER, TAB_IDS_IN_DOC_ORDER[1:]):
            with self.subTest(prev=a, next=b):
                end_a = self.parsed.spans[a]["end"]
                start_b = self.parsed.spans[b]["start"]
                self.assertIsNotNone(
                    end_a, f"#{a} never closes, so #{b} can't be verified as its sibling")
                self.assertLess(
                    end_a, start_b,
                    f"#{a} closes at {end_a} but #{b} opens at {start_b} -- "
                    f"#{b} is nested inside #{a} instead of being its sibling")

    def test_prov_fgt_and_cisco_sections_are_siblings(self):
        # Pins the exact Task 14 mutation target: deleting the </div> that
        # closes #provFgtSection nests #provCiscoSection inside it. Both
        # ids are toggled independently at runtime by provVendorIsFgt()'s
        # style.display swap, so neither may be an ancestor of the other.
        fgt = self.parsed.spans.get("provFgtSection")
        cisco = self.parsed.spans.get("provCiscoSection")
        self.assertIsNotNone(fgt, "#provFgtSection not found in rendered HTML")
        self.assertIsNotNone(cisco, "#provCiscoSection not found in rendered HTML")
        self.assertIsNotNone(fgt["end"], "#provFgtSection <div> is never closed")
        self.assertIsNotNone(cisco["end"], "#provCiscoSection <div> is never closed")
        nested = (fgt["start"] < cisco["start"] < fgt["end"]) or \
                 (cisco["start"] < fgt["start"] < cisco["end"])
        self.assertFalse(
            nested,
            "#provFgtSection and #provCiscoSection must be siblings (neither "
            "an ancestor of the other) -- provVendorIsFgt() sets "
            "style.display on both independently at runtime")


class TestComponentLayer(unittest.TestCase):
    def test_component_classes_present(self):
        html = _html()
        for cls in (".hero-card", ".kpi-grid", ".filterbar",
                    ".status", ".led-success", ".split-footer",
                    ".nav-group", ".preview-badge"):
            self.assertIn(cls, html, f"missing component class {cls}")


class TestSidebarIA(unittest.TestCase):
    def test_nav_groups_present_and_flat_strip_gone(self):
        html = _html()
        for grp in (">Operations<", ">Analysis<", ">Provisioning<", ">Administration<"):
            self.assertIn(grp, html)
        # every existing tab still reachable (tab-home is deferred to Task 3)
        for tab in ("tab-devices", "tab-mac", "tab-clientmap", "tab-flows",
                    "tab-map", "tab-map-interactive", "tab-categories", "tab-security",
                    "tab-config", "tab-ai", "tab-provisioner", "tab-import", "tab-groups",
                    "tab-users", "tab-sites", "tab-mcp", "tab-settings"):
            self.assertIn(f"switchTab('{tab}'", html)
        # RBAC preserved on gated nav
        self.assertIn('requires-admin', html)
        self.assertIn('requires-write', html)
        # compound onclicks preserved verbatim
        self.assertIn("switchTab('tab-clientmap', this); loadClientMapTab();", html)
        self.assertIn("switchTab('tab-flows', this); flowsTabShown();", html)
        # old flat tab strip is gone
        self.assertNotIn('class="tab-nav"', html)


class TestHomeTab(unittest.TestCase):
    def test_home_tab_exists_and_default(self):
        html = _html()
        # Home tab body + startup default
        self.assertIn('id="tab-home"', html)
        self.assertIn('<div id="tab-home" class="tab-content active">', html)
        # loadHome function present
        self.assertIn('function loadHome', html)
        # Home nav-item present and active
        self.assertIn("switchTab('tab-home'", html)
        self.assertIn('data-i18n="tabHome"', html)
        # runtime-populated ids
        for eid in ('homeKpiOnline', 'homeKpiAttention',
                    'homeAttentionBody', 'homeAnomBody'):
            self.assertIn(f'id="{eid}"', html)
        # Home wires only to REAL endpoints
        self.assertIn('/api/local-devices', html)
        self.assertIn('/api/run-triage', html)
        self.assertIn("startGroupTriage('all')", html)
        self.assertIn('/api/observability/anomalies', html)
        # no fabricated prototype-only controls
        self.assertNotIn('Open design language', html)
        self.assertNotIn('Customize view', html)

    def test_home_tab_i18n_keys_both_langs(self):
        html = _html()
        # tabHome defined in both maps (label appears twice: it + en)
        self.assertGreaterEqual(html.count('tabHome:'), 2)


class TestFormRelocation(unittest.TestCase):
    def test_device_form_ids_preserved(self):
        html = _html()
        for _id in ('devIp','devGroupSelect','devVendor','btnSaveDevice',
                    'newGroupName','btnCreateGroup','trSshEnabled'):
            self.assertIn(f'id="{_id}"', html)


class TestDevicesTabRestyle(unittest.TestCase):
    def test_preserve_ids_and_bulk_actions(self):
        html = _html()
        for _id in ('deviceTableBody', 'deviceSearch', 'filterGroupSelect',
                    'btnRunTriage', 'btnTriageSite', 'btnPingCheck'):
            self.assertIn(f'id="{_id}"', html)
        # bulk-action controls (no id, but onclick hooks must survive verbatim)
        for hook in ('openSubnetScanModal()', 'openBulkCommandModal()', 'exportDeviceCsv()'):
            self.assertIn(hook, html)

    def test_endpoint_contract_present(self):
        html = _html()
        for endpoint in ('/api/local-devices', '/api/run-triage', '/api/triage-status',
                          '/api/export/devices', '/api/ping-check', '/api/ping/',
                          '/api/scan-subnet', '/api/bulk-command', '/api/config-analyzer',
                          '/api/triage/', '/api/delete-device', '/api/rename-device',
                          '/api/reassign-device'):
            self.assertIn(endpoint, html)

    def test_devices_tab_uses_component_classes(self):
        html = _html()
        tab_start = html.index('<div id="tab-devices"')
        tab_end = html.index('<!-- TAB 2:')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"', 'class="kpi-grid"',
                    'class="kpi"', 'class="filterbar"', 'class="search-wrap"',
                    'class="table-wrap"'):
            self.assertIn(cls, tab_html)

    def test_kpi_ids_and_i18n_both_langs(self):
        html = _html()
        for _id in ('invKpiOnline', 'invKpiOffline', 'invKpiAuthFailed'):
            self.assertIn(f'id="{_id}"', html)
        for key in ('invHeroTitle:', 'invHeroSubtitle:', 'invKpiOnlineLabel:',
                    'invKpiOfflineLabel:', 'invKpiAuthFailedLabel:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")
        self.assertIn('Network Device Inventory', html)


class TestGroupsTabRestyle(unittest.TestCase):
    def test_preserve_ids(self):
        html = _html()
        for _id in ('groupsTableBody', 'vendorTableBody'):
            self.assertIn(f'id="{_id}"', html)
        # add-vendor form + rename/delete hooks preserved
        for hook in ('addVendor()', 'renameGroup(', 'deleteGroup(', 'deleteVendor('):
            self.assertIn(hook, html)

    def test_endpoint_contract_present(self):
        html = _html()
        # /api/groups, /api/groups/rename, /api/groups/delete, /api/vendors,
        # /api/vendors/delete all reached verbatim via apiFetch(...)
        for endpoint in ('/api/groups', '/api/groups/rename', '/api/groups/delete',
                          '/api/vendors', '/api/vendors/delete'):
            self.assertIn(endpoint, html)
        # /api/models + /api/models/delete: real server routes (app_server.py),
        # but pre-existing state (before this restyle) has NO frontend wiring in
        # #tab-groups (no models table/JS calls it) -- confirmed by tracing
        # app_server.py's list_models/create_model/remove_model handlers, which
        # have zero callers in templates/dashboard.html. Per shared per-tab
        # rules ("restyle, not rewire" / don't fabricate wiring), relaxed to
        # asserting the handler function names exist server-side instead of
        # fabricating a UI table for them.
        import app_server as _app_server
        self.assertTrue(hasattr(_app_server, 'list_models'))
        self.assertTrue(hasattr(_app_server, 'create_model'))
        self.assertTrue(hasattr(_app_server, 'remove_model'))

    def test_groups_tab_uses_component_classes(self):
        html = _html()
        tab_start = html.index('<div id="tab-groups"')
        tab_end = html.index('<!-- TAB 3:')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"'):
            self.assertIn(cls, tab_html)
        self.assertEqual(tab_html.count('class="panel"'), 2)
        self.assertGreaterEqual(tab_html.count('class="table-wrap"'), 2)
        self.assertNotIn('table-container', tab_html)

    def test_i18n_keys_both_langs(self):
        html = _html()
        for key in ('groupsEyebrow:', 'titleGroupsRegistry:', 'descGroupsRegistry:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")


class TestMapTabRestyle(unittest.TestCase):
    def test_preserve_ids(self):
        html = _html()
        for _id in ('mapViewClassicBtn', 'mapViewMinimalBtn', 'networkGraphContainer',
                    'topologyGroupSelect', 'interactiveGroupSelect', 'portchannelReport'):
            self.assertIn(f'id="{_id}"', html)
        # view-toggle + reset/export hooks preserved verbatim
        for hook in ("setMapView('classic')", "setMapView('minimal')", 'resetTopology()',
                     'loadInteractiveMap()', 'downloadTopology()', 'exportVisioMap()',
                     'exportPdfMap()'):
            self.assertIn(hook, html)

    def test_endpoint_contract_present(self):
        html = _html()
        # /api/portchannels (Port-Channel report) and /api/network-map (interactive
        # map) are both reached verbatim via apiFetch(...) calls.
        for endpoint in ('/api/portchannels', '/api/network-map'):
            self.assertIn(endpoint, html)
        # /api/topology (GET, get_topology_adjacency) is a real server route but,
        # confirmed by tracing dashboard.html, the frontend only ever calls
        # /api/topology/reset (POST) -- the bare GET has no frontend caller.
        # Relaxed to asserting the handler exists server-side (same precedent as
        # /api/models in TestGroupsTabRestyle) rather than fabricating wiring.
        self.assertIn('/api/topology/reset', html)
        import app_server as _app_server
        self.assertTrue(hasattr(_app_server, 'get_topology_adjacency'))

    def test_map_tabs_use_component_classes(self):
        html = _html()
        tab_start = html.index('<!-- TAB 3:')
        tab_end = html.index('<!-- TAB: Dispositivi & Categorie -->')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"'):
            self.assertGreaterEqual(tab_html.count(cls), 2, f"{cls} expected once per tab (tab-map + tab-map-interactive)")
        self.assertGreaterEqual(tab_html.count('class="panel"'), 2)
        # view-toggle buttons carry the .chip class alongside their existing marker class
        self.assertIn('class="map-view-btn chip"', tab_html)
        # vis-network render target untouched: still a bare div, no restyle wrapper classes on it
        self.assertIn('<div id="networkGraphContainer"></div>', tab_html)

    def test_i18n_keys_both_langs(self):
        html = _html()
        for key in ('portchannelsEyebrow:', 'mapEyebrow:', 'titlePortchannels:', 'title2DMap:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")


class TestTopologyTabRestyle(unittest.TestCase):
    """Task 8: #tab-map-interactive legend polish + wiring guard.

    Task 7 already restyled the toolbar (.panel wrapper, .chip view-toggle
    buttons, hero header) -- covered by TestMapTabRestyle above. This class
    only guards the remaining preserve-IDs and the export/reset contract for
    this specific tab.
    """

    def test_preserve_ids(self):
        html = _html()
        for _id in ('networkGraphWrapper', 'networkGraphContainer', 'networkLegend',
                    'mapViewClassicBtn', 'mapViewMinimalBtn'):
            self.assertIn(f'id="{_id}"', html)

    def test_endpoint_contract_present(self):
        html = _html()
        # /api/topology/reset (POST) is called verbatim by resetTopology().
        self.assertIn('/api/topology/reset', html)
        # /api/topology (bare GET, get_topology_adjacency) has no frontend
        # caller in dashboard.html -- traced exportVisioMap()/downloadTopology()
        # and neither hits it. Relaxed to the server-side handler name, same
        # precedent as TestMapTabRestyle.test_endpoint_contract_present above.
        import app_server as _app_server
        self.assertTrue(hasattr(_app_server, 'get_topology_adjacency'))
        # exportVisioMap() posts to /api/map/export/vsdx -- traced the handler
        # in app_server.py: only a POST route exists (export_map_vsdx), there
        # is no GET variant, so only the POST endpoint is asserted here.
        self.assertIn('/api/map/export/vsdx', html)
        self.assertIn("apiFetch('/api/map/export/vsdx'", html)
        self.assertTrue(hasattr(_app_server, 'export_map_vsdx'))

    def test_legend_present_and_unmoved(self):
        html = _html()
        tab_start = html.index('<div id="tab-map-interactive"')
        tab_end = html.index('<!-- TAB: Dispositivi & Categorie -->')
        tab_html = html[tab_start:tab_end]
        # legend lives inside its tab body, still inside the graph wrapper,
        # and keeps its overlay positioning class untouched.
        self.assertIn('id="networkLegend"', tab_html)
        self.assertIn('class="network-legend" id="networkLegend"', tab_html)
        self.assertIn('id="legendBody"', tab_html)


class TestCategoriesTabRestyle(unittest.TestCase):
    """Task 9: #tab-categories (Devices & Categories) restyle + wiring guard."""

    def test_preserve_ids(self):
        html = _html()
        for _id in ('categoriesGroupSelect', 'categoriesCatFilter', 'catKeyList',
                    'categoryColumnsMenu', 'categoryColumnsList', 'categoryCountCards',
                    'categoriesDeviceList', 'btnSaveCatEdits', 'btnDiscardCatEdits',
                    'newCatKey', 'newCatLabel', 'newSubcat'):
            self.assertIn(f'id="{_id}"', html)
        # onclick hooks preserved verbatim
        for hook in ('renderCategoriesPanel()', 'saveCategoryEdits()', 'discardCategoryEdits()',
                     'exportCategoriesCsv()', 'loadCategoriesData()', 'createCategory()'):
            self.assertIn(hook, html)
        # RBAC gating preserved on write-gated controls
        self.assertIn('id="btnSaveCatEdits"', html)
        save_start = html.index('id="btnSaveCatEdits"')
        save_tag = html.rindex('<button', 0, save_start)
        self.assertIn('requires-write', html[save_tag:save_start])

    def test_endpoint_contract_present(self):
        html = _html()
        # GET /api/device-classification -- loadCategoriesData()
        self.assertIn('/api/device-classification', html)
        # POST /api/device-categories/assign -- saveCategoryEdits()/confirmConflict()
        self.assertIn('/api/device-categories/assign', html)
        # POST /api/device-categories/delete -- deleteCategory()
        self.assertIn('/api/device-categories/delete', html)
        # POST /api/device-categories/delete-subcategory -- deleteSubcategory()
        self.assertIn('/api/device-categories/delete-subcategory', html)
        # Brief's contract table lists "GET /api/device-categories", but tracing
        # createCategory() -> apiFetch("/api/device-categories", {method:"POST"...})
        # and app_server.py confirms only @app.post("/api/device-categories") exists
        # (create_device_category) -- there is no GET route. The bare path string
        # is still asserted verbatim (it's how the frontend actually calls it);
        # additionally assert the real server-side handler exists, per Task 6/7/8
        # precedent, rather than fabricating a GET wiring that doesn't exist.
        self.assertIn('"/api/device-categories"', html)
        import app_server as _app_server
        self.assertTrue(hasattr(_app_server, 'create_device_category'))

    def test_categories_tab_uses_component_classes(self):
        html = _html()
        tab_start = html.index('<div id="tab-categories"')
        tab_end = html.index('<!-- TAB 5: Threat Intel')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"', 'class="filterbar"'):
            self.assertIn(cls, tab_html)
        self.assertGreaterEqual(tab_html.count('class="panel'), 4)

    def test_i18n_keys_both_langs(self):
        html = _html()
        for key in ('categoriesEyebrow:', 'titleCategories:', 'descCategories:', 'titleNewCategory:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")


class TestThreatIntelTabRestyle(unittest.TestCase):
    """Task 10: #tab-security (Threat Intel / EUVD ENISA) restyle + wiring guard."""

    def test_preserve_ids(self):
        html = _html()
        # Preserve-ID list: result container used by loadThreatIntel() (via
        # startThreatScan()), plus the filter controls that feed it.
        for _id in ('threatGroupSelect', 'threatIncludeDiscovered', 'securityTriageContainer'):
            self.assertIn(f'id="{_id}"', html)
        # onclick hooks preserved verbatim
        for hook in ('startThreatScan()',):
            self.assertIn(hook, html)

    def test_endpoint_contract_present(self):
        html = _html()
        # loadThreatIntel() -> startThreatScan() -> apiFetch('/api/local-devices')
        # to list online devices, then (if "include discovered" is checked)
        # apiFetch('/api/network-map?group=...') for CDP/LLDP neighbors. Per-device
        # "Analizza" clicks (runManagedVulnCheck/runDiscoveredVulnCheck) funnel into
        # runEuvdQuery(), which hits the local EUVD proxy at '/api/search' -- this
        # is the "external/EUVD path" the brief anticipated, but it does resolve to
        # a real local endpoint (not a bare external URL), so it is asserted like
        # any other contract endpoint rather than relaxed to a JS function name.
        self.assertIn("apiFetch('/api/local-devices')", html)
        self.assertIn("apiFetch('/api/network-map?group=", html)
        self.assertIn("/api/search?", html)

    def test_security_tab_uses_component_classes(self):
        html = _html()
        tab_start = html.index('<div id="tab-security"')
        tab_end = html.index('<!-- TAB: MAC Address Tracker')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"', 'class="filterbar"', 'class="panel'):
            self.assertIn(cls, tab_html)

    def test_i18n_keys_both_langs(self):
        html = _html()
        for key in ('threatEyebrow:', 'titleThreatIntel:', 'descThreatIntel:',
                    'lblThreatGroup:', 'lblThreatDiscovered:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")


class TestMacTrackerTabRestyle(unittest.TestCase):
    """Task 11: #tab-mac (MAC Tracker) + #tab-clientmap (Client Map / ARP)
    restyle + wiring guard. The two tabs are one feature area (MAC Tracker's
    scans feed switch/port data that Client Map cross-references against ARP),
    so both are covered here per the brief's ARP-target-selection preserve-IDs."""

    def test_preserve_ids_mac(self):
        html = _html()
        for _id in ('macScanGroup', 'macDeviceMenu', 'macDeviceSummary', 'macDeviceList',
                    'macScanTransport', 'btnMacScan', 'macRetentionDays',
                    'macOvDevice', 'macOvCommand', 'macOvFmt', 'macOverridesList',
                    'macSearchMac', 'macSearchVlan', 'macSearchIface', 'macSearchSwitch',
                    'macStats', 'macResults',
                    'kpiMacSightings', 'kpiMacUniqueMacs', 'kpiMacSwitches', 'kpiMacRetention'):
            self.assertIn(f'id="{_id}"', html)
        for hook in ('runMacScan()', 'macSearch()', 'macSearchReset()', 'saveMacOverride()',
                     'saveMacRetention()', 'populateMacScanDevices(); macSearch(); refreshMacStats(false);'):
            self.assertIn(hook, html)
        # RBAC preserved: scan is requires-write, retention is requires-admin
        self.assertIn('id="btnMacScan"', html)
        scan_start = html.index('id="btnMacScan"')
        scan_tag = html.rindex('<button', 0, scan_start)
        self.assertIn('requires-write', html[scan_tag:scan_start])
        self.assertIn('id="macRetentionDays"', html)
        ret_idx = html.index('id="macRetentionDays"')
        admin_wrap = html.rindex('class="requires-admin"', 0, ret_idx)
        self.assertLess(ret_idx - admin_wrap, 400)
        # Ad-hoc overrides panel stays write-gated
        adhoc_idx = html.index('titleMacAdhoc')
        details_tag = html.rindex('<details', 0, adhoc_idx)
        self.assertIn('requires-write', html[details_tag:adhoc_idx])

    def test_preserve_ids_clientmap_arp_multiselect(self):
        html = _html()
        for _id in ('arpScanGroup', 'arpDeviceMenu', 'arpDeviceSummary', 'arpDeviceList',
                    'btnArpScan', 'arpSearchMac', 'arpSearchIp', 'arpFilterTenant',
                    'arpFilterGateway', 'arpStats', 'arpScanSummary', 'arpResults',
                    'kpiArpBindings', 'kpiArpUniqueMacs', 'kpiArpGateways'):
            self.assertIn(f'id="{_id}"', html)
        for hook in ('runArpScan()', 'arpClientSearch()', 'arpSearchReset()',
                     'populateArpScanDevices()',
                     'populateArpGatewayFilter(); arpClientSearch();'):
            self.assertIn(hook, html)
        # RBAC: the scan action stays write-gated
        self.assertIn('id="btnArpScan"', html)
        scan_start = html.index('id="btnArpScan"')
        scan_tag = html.rindex('<button', 0, scan_start)
        self.assertIn('requires-write', html[scan_tag:scan_start])
        # SAFETY CONSTRAINT: ARP-target selection must remain an EXPLICIT
        # multi-select (checkbox list the user picks specific gateways from),
        # never a fire-against-all control. Verify the checkbox-list machinery
        # (class + per-item onchange + JS helpers) survived the restyle.
        self.assertIn('class="arp-dev-cb"', html)
        self.assertIn('id="arpDevAll"', html)
        self.assertIn('onchange="toggleAllArpDevices(this.checked)"', html)
        self.assertIn('function selectedArpDevices()', html)
        self.assertIn("querySelectorAll('#arpDeviceList .arp-dev-cb:checked')", html)

    def test_endpoint_contract_present(self):
        html = _html()
        # runMacScan() -> apiFetch('/api/mac/scan', {method:'POST', ...})
        self.assertIn('/api/mac/scan', html)
        # macSearch() -> apiFetch('/api/mac/search?' + ...)
        self.assertIn('/api/mac/search', html)
        # macLocate() -> apiFetch('/api/mac/locate?mac=' + ...). Brief's contract
        # table lists this as POST, but tracing the JS call and app_server.py
        # (@app.get("/api/mac/locate")) shows it is actually a GET -- the literal
        # path string is still asserted verbatim, matching the real call.
        self.assertIn('/api/mac/locate', html)
        # loadMacOverrides()/saveMacOverride()/removeMacOverride() -> GET/POST
        # /api/mac/overrides + POST /api/mac/overrides/delete
        self.assertIn('/api/mac/overrides', html)
        self.assertIn('/api/mac/overrides/delete', html)
        # saveMacRetention() -> POST /api/mac/settings. Brief lists "GET/POST",
        # but app_server.py only defines @app.post("/api/mac/settings") -- the
        # current retention value is instead read back from /api/mac/stats
        # (retention_days field), not a GET on /api/mac/settings. Asserting the
        # real POST call rather than fabricating a GET wiring, per Task 6/9/10
        # precedent for contract-table entries that don't match the real route.
        self.assertIn('/api/mac/settings', html)
        # refreshMacStats() -> GET /api/mac/stats
        self.assertIn('/api/mac/stats', html)
        # runArpScan() -> POST /api/arp/scan (the explicit-multi-select target)
        self.assertIn('/api/arp/scan', html)
        # Brief's "Switch drill-down: GET /api/mac/switch/{ip}" has no frontend
        # caller anywhere in dashboard.html (traced: no JS references
        # '/api/mac/switch'). This mirrors the Task 6 "/api/models has no
        # frontend UI" precedent -- it's a real backend route, just not wired
        # to any control, so relax the assertion to the handler existing
        # server-side instead of fabricating a UI wiring that isn't there.
        self.assertNotIn('/api/mac/switch', html)
        import app_server as _app_server
        self.assertTrue(hasattr(_app_server, 'mac_switch'))

    def test_mac_and_clientmap_tabs_use_component_classes(self):
        html = _html()
        tab_start = html.index('<div id="tab-mac"')
        tab_end = html.index('<!-- TAB: Config Analyzer')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"', 'class="filterbar"', 'class="table-wrap"'):
            self.assertIn(cls, tab_html)
        self.assertGreaterEqual(tab_html.count('class="kpi-grid"'), 2)
        self.assertGreaterEqual(tab_html.count('class="panel'), 4)
        # both tabs individually still present within that combined span
        self.assertIn('<div id="tab-clientmap"', tab_html)

    def test_i18n_keys_both_langs(self):
        html = _html()
        for key in ('macEyebrow:', 'titleMacTracker:', 'descMacTracker:',
                    'macKpiSightingsLabel:', 'macKpiUniqueLabel:', 'macKpiSwitchesLabel:',
                    'macKpiRetentionLabel:', 'titleMacScanPanel:', 'titleMacSearchPanel:',
                    'clientmapEyebrow:', 'titleClientMap:', 'descClientMap:',
                    'arpKpiBindingsLabel:', 'arpKpiUniqueLabel:', 'arpKpiGatewaysLabel:',
                    'titleArpCollectPanel:', 'titleArpSearchPanel:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")


class TestConfigAnalyzerTabRestyle(unittest.TestCase):
    """Task 12: #tab-config (Config Analyzer) restyle + wiring guard.

    The tab body is thin static markup (group filter, refresh, view pills, an
    empty #caResults container); every table/accordion is rendered into
    #caResults by loadConfigAnalyzer()->fetchConfigAnalyzer()->renderCaResults()
    and its ca* helpers. So the preserve-IDs are the JS-touched containers/inputs
    plus the raw-route modal those helpers write into.
    """

    def test_preserve_ids(self):
        html = _html()
        # configGroupSelect (filter), caPills (view switcher container queried by
        # caSwitchView), caResults (render target). caRawRouteModal/Content are
        # the modal caShowRawRoute()/caCloseRawRouteModal() write into.
        for _id in ('configGroupSelect', 'caPills', 'caResults',
                    'caRawRouteModal', 'caRawRouteContent'):
            self.assertIn(f'id="{_id}"', html)
        # onclick / onchange hooks preserved verbatim
        for hook in ('loadConfigAnalyzer()', 'loadConfigAnalyzer(true)',
                     "caSwitchView('vlan')", "caSwitchView('routing')",
                     "caSwitchView('acl')", "caSwitchView('iface')",
                     "caSwitchView('validation')", 'caCloseRawRouteModal()'):
            self.assertIn(hook, html)
        # the five view pills keep their data-view markers
        for view in ('vlan', 'routing', 'acl', 'iface', 'validation'):
            self.assertIn(f'data-view="{view}"', html)

    def test_endpoint_contract_present(self):
        html = _html()
        # fetchConfigAnalyzer() -> apiFetch('/api/config-analyzer?group='+...)
        self.assertIn('/api/config-analyzer', html)
        self.assertIn("apiFetch('/api/config-analyzer?group=", html)
        # downloadBackup(ip) -> apiFetch(`/api/download-backup/${ip}`). This is
        # a path-parameterized route; assert the literal prefix (matches the real
        # template-literal call). The button lives in the inventory tab but is
        # part of this tab's config/backup contract.
        self.assertIn('/api/download-backup/', html)
        self.assertIn('apiFetch(`/api/download-backup/${ip}`)', html)
        # GET /api/config-analyzer/{ip} (per-device) is a real server route
        # (config_analyzer_device) but has NO frontend caller in dashboard.html
        # -- traced: the only frontend call is the group-scoped
        # /api/config-analyzer?group=... ; the per-device path is consumed by
        # mcp_server.py instead. Per Task 6-11 precedent, relax to asserting the
        # server-side handler exists rather than fabricating a UI wiring.
        self.assertNotIn('/api/config-analyzer/', html)
        import app_server as _app_server
        self.assertTrue(hasattr(_app_server, 'config_analyzer_device'))
        self.assertTrue(hasattr(_app_server, 'config_analyzer_all'))
        self.assertTrue(hasattr(_app_server, 'download_backup'))

    def test_config_tab_uses_component_classes(self):
        html = _html()
        tab_start = html.index('<div id="tab-config"')
        tab_end = html.index('<!-- TAB: AI Assistant -->')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"',
                    'class="filterbar"', 'class="panel'):
            self.assertIn(cls, tab_html)
        # input-filter panel + results panel
        self.assertGreaterEqual(tab_html.count('class="panel'), 2)
        # render target untouched: still a bare div inside its panel
        self.assertIn('<div id="caResults"></div>', tab_html)

    def test_i18n_keys_both_langs(self):
        html = _html()
        for key in ('configEyebrow:', 'titleConfigAnalyzer:', 'descConfigAnalyzer:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")


class TestAiAssistantTabRestyle(unittest.TestCase):
    """Task 13: #tab-ai (AI Assistant) restyle + wiring guard.

    Highest-risk preservation of any tab: the chat send path plus a
    single-use WebSocket OTP (/api/ws-token) live in this file. The restyle
    only reclasses the STATIC layout (hero header + .panel cards); the chat
    render container (#aiChatMessages, with its scroll/overflow inline style),
    the send handler, the model <select>, the profile CRUD controls, and the
    device multi-select dropdown are all preserved verbatim.
    """

    def test_preserve_ids(self):
        html = _html()
        # Active-profile + admin provider-config controls read/written by
        # loadAiProfiles()/onAiProfile*Change()/saveAiSettings()/deleteAiProfile()
        # /refreshAiModels(), the device multi-select machinery, and the chat
        # container/input the send handler touches.
        for _id in ('aiProfileSelect', 'aiActiveProfileBadge', 'aiSettingsPanel',
                    'aiProfileEditSelect', 'aiProfileName', 'aiProvider',
                    'aiModelSelect', 'aiModel', 'aiApiKeyLabel', 'aiApiKey',
                    'aiBaseUrl', 'aiRateLimitRpm', 'aiAllowUnredacted',
                    'btnAiDeleteProfile', 'aiSettingsStatus', 'aiAttachInventory',
                    'aiAttachTenant', 'aiAttachDeviceBtn', 'aiAttachDeviceBtnLabel',
                    'aiAttachDeviceDropdown', 'aiAttachDeviceList',
                    'aiChatMessages', 'aiChatInput', 'btnAiSend'):
            self.assertIn(f'id="{_id}"', html)

    def test_onclick_hooks_preserved(self):
        html = _html()
        for hook in ('onAiProfileSelectChange()', 'onAiProfileEditSelectChange()',
                     'resetAiModelList()', 'refreshAiModels()', 'saveAiSettings()',
                     'deleteAiProfile()', 'populateAiAttachDevices()',
                     'toggleAiDeviceDropdown()', 'setAllAiAttachDevices(true)',
                     'setAllAiAttachDevices(false)', 'clearAiChat()', 'sendAiChat()'):
            self.assertIn(hook, html)

    def test_rbac_admin_gating_on_provider_config(self):
        html = _html()
        # The provider/profile CRUD panel stays admin-gated: requires-admin must
        # sit on the #aiSettingsPanel <details> element itself.
        self.assertIn('id="aiSettingsPanel"', html)
        panel_idx = html.index('id="aiSettingsPanel"')
        details_tag = html.rindex('<details', 0, panel_idx)
        self.assertIn('requires-admin', html[details_tag:panel_idx])

    def test_endpoint_contract_present(self):
        html = _html()
        # sendAiChat() -> apiFetch('/api/ai/chat', {method:'POST', ...})
        self.assertIn('/api/ai/chat', html)
        # refreshAiModels() -> apiFetch('/api/ai/models?' + ...)
        self.assertIn('/api/ai/models', html)
        # loadAiProfiles()/saveAiSettings() -> GET+POST /api/ai/profiles
        self.assertIn('/api/ai/profiles', html)
        # PUT/DELETE /api/ai/profiles/{id} and POST /api/ai/profiles/{id}/activate
        # are path-parameterized template-literal calls; assert the literal call
        # forms (Task 6-12 precedent for path-param routes).
        self.assertIn('`/api/ai/profiles/${encodeURIComponent(profileId)}/activate`', html)
        self.assertIn('`/api/ai/profiles/${encodeURIComponent(editingId)}`', html)
        self.assertIn('`/api/ai/profiles/${encodeURIComponent(id)}`', html)
        # STREAMING/WEBSOCKET WIRING GUARD: the single-use OTP endpoint that
        # authorizes the WebSocket must still be present verbatim -- proving the
        # ws-token fetch survived the restyle. (In this codebase /api/ws-token is
        # consumed by the terminal WebSocket, not the AI chat POST path; asserted
        # here per the brief's explicit streaming-preservation requirement.)
        self.assertIn('/api/ws-token', html)
        self.assertIn('apiFetch("/api/ws-token", { method: "POST" })', html)

    def test_chat_container_untouched(self):
        html = _html()
        # The chat render target keeps its exact id + scroll/overflow inline
        # style that appendAiMessage()/renderAiConfigProposal() depend on for
        # box.scrollTop = box.scrollHeight. Assert the div is byte-identical.
        self.assertIn(
            '<div id="aiChatMessages" style="border:1px solid var(--border); '
            'border-radius:10px; background:var(--surface); min-height:280px; '
            'max-height:480px; overflow-y:auto; padding:14px; margin-bottom:12px;"></div>',
            html)

    def test_device_multiselect_preserved(self):
        html = _html()
        # The AI device multi-select dropdown (prior feature) keeps its ids and
        # per-item checkbox class + onchange used by getAiAttachDeviceIps().
        self.assertIn('id="aiAttachDeviceDropdown"', html)
        self.assertIn('id="aiAttachDeviceList"', html)
        self.assertIn("querySelectorAll('#aiAttachDeviceList .ai-attach-device:checked')", html)
        self.assertIn("class=\"ai-attach-device\"", html)
        self.assertIn('onchange="updateAiDeviceBtnLabel()"', html)

    def test_ai_tab_uses_component_classes(self):
        html = _html()
        tab_start = html.index('<div id="tab-ai"')
        tab_end = html.index('<!-- TAB: Switch da Zero (Provisioner) -->')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"',
                    'class="filterbar"', 'class="panel'):
            self.assertIn(cls, tab_html)
        # three panel cards: profile controls, context/device selector, chat
        self.assertGreaterEqual(tab_html.count('class="panel"'), 3)
        # active-profile badge reclassed to the .chip state-badge component
        self.assertIn('id="aiActiveProfileBadge" class="chip"', tab_html)

    def test_i18n_keys_both_langs(self):
        html = _html()
        for key in ('aiEyebrow:', 'titleAiContext:', 'titleAiChat:',
                    'titleAiAssistant:', 'descAiAssistant:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")


class TestProvisionerTabRestyle(unittest.TestCase):
    """Task 14: #tab-provisioner (Zero-Touch Provisioner) restyle guard.

    The flagship form: two vendor sections toggled at runtime, an admin-gated
    inline FortiGate token model, and dual endpoint families reached through a
    computed base path.
    """

    def _tab(self, html):
        start = html.index('<div id="tab-provisioner"')
        end = html.index('<!-- TAB 6: Importazione CSV -->')
        return html[start:end]

    def test_preserve_ids(self):
        html = _html()
        for _id in ('fgtTokenPanel', 'fgtTokensTable', 'fgtTokensTableBody',
                    'provFgtSection', 'provCiscoSection', 'provVendor', 'provRole',
                    'btnProvGenerate', 'btnProvDownload', 'provDeliveryMode',
                    'provSshFields', 'provSerialFields', 'provOutput'):
            self.assertIn(f'id="{_id}"', html, f"lost preserve-ID {_id}")

    def test_endpoint_contract_present(self):
        html = _html()
        # Both vendor bases are chosen by provPayloadAndBase(); the four verbs
        # are then reached as `${base}/<verb>` template literals, so assert the
        # bases and the suffixes rather than concatenated literals that never
        # appear in the source.
        self.assertIn("base: '/api/provisioner/fgt'", html)
        self.assertIn("base: '/api/provisioner'", html)
        for suffix in ('generate', 'download', 'push-ssh', 'push-serial'):
            self.assertIn('apiFetch(`${base}/%s`' % suffix, html,
                          f"lost the {suffix} call site")
        self.assertIn("apiFetch('/api/provisioner/serial-ports')", html)
        # FortiGate token model: list (plural) + create/delete (singular).
        self.assertIn("apiFetch('/api/fortigate/tokens')", html)
        self.assertIn("apiFetch('/api/fortigate/token'", html)

    def test_vendor_toggle_intact(self):
        html = _html()
        # Restyling must not break which vendor section is visible.
        self.assertIn("function provVendorIsFgt()", html)
        self.assertIn("getElementById('provCiscoSection').style.display = fgt ? 'none' : ''", html)
        self.assertIn("getElementById('provFgtSection').style.display = fgt ? '' : 'none'", html)

    def test_rbac_preserved(self):
        html = _html()
        tab = self._tab(html)
        # The token panel stays admin-gated; the tab itself is gated at the nav
        # entry (requires-write), which is why the body carries no write gate.
        self.assertIn('class="panel requires-admin" id="fgtTokenPanel"', tab)
        self.assertEqual(tab.count('requires-admin'), 1)

    def test_tab_uses_component_classes(self):
        html = _html()
        tab = self._tab(html)
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"',
                    'class="table-wrap"'):
            self.assertIn(cls, tab)
        # token panel + device/params card + generate/deliver card
        self.assertGreaterEqual(tab.count('class="panel'), 3)

    def test_i18n_keys_both_langs(self):
        html = _html()
        for key in ('provisionerEyebrow:', 'provPanelDevice:', 'provPanelDeploy:',
                    'titleProvisioner:', 'descProvisioner:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")


class TestImportTabRestyle(unittest.TestCase):
    """Task 15: #tab-import (CSV Import) restyle guard.

    Small tab: a single file input + submit button POSTing the parsed CSV
    text to /api/import-csv, with the result (imported/failed counts, one
    line per failed row) surfaced via alert() -- there is no "result
    container" DOM node in this codebase. The brief's preserve-ID list names
    one, but it does not exist; no results panel is rendered, since a card
    captioned "Import result" that can never show a result reads as a
    permanently-empty results area. The restyle is a hero header + one
    .panel around the existing controls, handler untouched.
    """

    def _tab(self, html):
        start = html.index('<div id="tab-import"')
        end = html.index('<!-- TAB 7: Gestione Utenti (solo admin) -->')
        return html[start:end]

    def test_preserve_ids(self):
        html = _html()
        # csvFileInput is read by the click handler; btnUploadCsv is the
        # element the handler is attached to via addEventListener.
        for _id in ('csvFileInput', 'btnUploadCsv'):
            self.assertIn(f'id="{_id}"', html, f"lost preserve-ID {_id}")

    def test_endpoint_contract_present(self):
        html = _html()
        self.assertIn("apiFetch('/api/import-csv'", html)

    def test_upload_handler_untouched(self):
        html = _html()
        # The click handler (addEventListener, not onclick) and its reporting
        # path must survive byte-for-byte -- restyle must not touch JS here.
        self.assertIn("document.getElementById('btnUploadCsv').addEventListener('click'", html)
        self.assertIn("document.getElementById('csvFileInput')", html)
        self.assertIn('body: JSON.stringify({ csv_data: text })', html)

    def test_rbac_preserved(self):
        html = _html()
        # Precedent from Task 14 (provisioner): the tab is gated at the nav
        # entry (`nav-item requires-write` on the switchTab('tab-import', ...)
        # button), so the tab body itself carries no write-gate class.
        self.assertIn(
            "class=\"nav-item requires-write\" onclick=\"switchTab('tab-import', this)\"",
            html)

    def test_tab_uses_component_classes(self):
        html = _html()
        tab = self._tab(html)
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"'):
            self.assertIn(cls, tab)
        # the upload-form panel
        self.assertGreaterEqual(tab.count('class="panel"'), 1)

    def test_i18n_keys_both_langs(self):
        html = _html()
        for key in ('importEyebrow:', 'titleImportCsv:', 'descImportCsv:',
                    'importPanelUpload:', 'lblSelectCsv:', 'btnUploadCsv:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")


class TestUsersTabRestyle(unittest.TestCase):
    """Task 16: #tab-users (User & Privilege Management) restyle guard.

    Admin-only tab: users table (role select, per-user tenant-scope editor,
    per-user allowed-tabs editor, disable/delete) + a create-user form.
    """

    def _tab(self, html):
        start = html.index('<div id="tab-users"')
        end = html.index('<div id="tab-sites"')
        return html[start:end]

    def test_preserve_ids(self):
        html = _html()
        # usersTableBody (brief) + the create-user form fields read directly
        # by createUser().
        for _id in ('usersTableBody', 'newUserName', 'newUserPass', 'newUserRole'):
            self.assertIn(f'id="{_id}"', html, f"lost preserve-ID {_id}")

    def test_endpoint_contract_present(self):
        html = _html()
        # GET /api/users (list) and POST /api/users (create) share one literal.
        self.assertIn("apiFetch('/api/users')", html)
        self.assertIn("apiFetch('/api/users', {", html)
        for endpoint in ('/api/users/delete', '/api/users/disable', '/api/users/role',
                          '/api/users/groups', '/api/users/tabs'):
            self.assertIn(endpoint, html)
        # Brief lists "GET /api/users/groups" and "GET/POST /api/users/tabs",
        # but app_server.py defines ONLY POST for both -- confirmed by tracing
        # app_server.py (@app.post("/api/users/groups"), @app.post("/api/users/tabs"),
        # no matching @app.get). There is no separate read endpoint: the scope
        # (u.groups) and allowed-tabs (u.allowed_tabs) data ride along on the
        # single GET /api/users listing consumed by renderUsersTable(). Per
        # shared per-tab rules, relaxed to asserting the real POST routes
        # exist server-side rather than fabricating a GET call that isn't made.
        import app_server as _app_server
        routes = {(r.path, m) for r in _app_server.app.routes
                  for m in getattr(r, 'methods', set()) or set()}
        self.assertIn(('/api/users/groups', 'POST'), routes)
        self.assertIn(('/api/users/tabs', 'POST'), routes)
        self.assertNotIn(('/api/users/groups', 'GET'), routes)
        self.assertNotIn(('/api/users/tabs', 'GET'), routes)

    def test_admin_gated_functions_untouched(self):
        html = _html()
        # loadUsers() and all mutating handlers must survive byte-for-byte.
        self.assertIn("async function loadUsers()", html)
        self.assertIn("if (currentRole !== 'admin') return;", html)
        for hook in ('createUser()', 'deleteUser(', 'toggleUserDisabled(',
                      'changeUserRole(', 'saveUserGroups(', 'saveUserTabs(', 'markTabsDirty('):
            self.assertIn(hook, html)

    def test_rbac_preserved(self):
        html = _html()
        # Precedent from Task 14/15 (provisioner/import): the tab is gated at
        # the nav entry, so the tab body itself carries no requires-admin gate.
        self.assertIn(
            "class=\"nav-item requires-admin\" onclick=\"switchTab('tab-users', this)\"",
            html)
        tab = self._tab(html)
        self.assertNotIn('requires-admin', tab)

    def test_tab_uses_component_classes(self):
        html = _html()
        tab = self._tab(html)
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"',
                    'class="table-wrap"'):
            self.assertIn(cls, tab)
        # users-table panel + create-user-form panel
        self.assertEqual(tab.count('class="panel"'), 2)
        self.assertNotIn('table-container', tab)

    def test_i18n_keys_both_langs(self):
        html = _html()
        for key in ('usersEyebrow:', 'titleUsers:', 'descUsers:', 'thUserName:',
                    'thUserRole:', 'thUserGroups:', 'thUserTabs:', 'thUserActions:',
                    'titleAddUser:', 'lblNewUserName:', 'lblNewUserPass:',
                    'lblNewUserRole:', 'roleViewer:', 'roleOperator:', 'roleAdmin:',
                    'btnAddUser:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")


class TestSitesTabRestyle(unittest.TestCase):
    """Task 17: #tab-sites (Multi-site locations) restyle guard -- ENGLISH RELABEL.

    Admin-only tab: sites table (mode badge, last-contact, per-site
    regenerate-token/delete actions) + a create-site form. Before this task,
    "Rigenera token" / "Elimina" / "predefinita" were hardcoded Italian
    literals baked straight into renderSitesTable()'s template string, with
    NO data-i18n mechanism at all -- the relabel converts them to i18n keys
    (EN copy canonical, IT retained) looked up via the file's established
    `const L = i18n[currentLang];` render-fn pattern.
    """

    def _tab(self, html):
        start = html.index('<div id="tab-sites"')
        end = html.index('<div id="tab-mcp"')
        return html[start:end]

    def test_preserve_ids(self):
        html = _html()
        # sitesTableBody (brief) + the create-site form fields read directly
        # by createSite().
        for _id in ('sitesTableBody', 'newSiteName', 'newSiteMode', 'newSiteSubnets'):
            self.assertIn(f'id="{_id}"', html, f"lost preserve-ID {_id}")

    def test_endpoint_contract_present(self):
        html = _html()
        # GET /api/sites (list) and POST /api/sites (create) share one literal.
        self.assertIn("apiFetch('/api/sites')", html)
        self.assertIn("apiFetch('/api/sites', {", html)
        for endpoint in ('/api/sites/delete', '/api/sites/regenerate-token'):
            self.assertIn(endpoint, html)
        # Brief also lists POST /api/sites/update, POST /api/sites/{id}/command
        # and GET /api/sites/{id}/command-jobs. Traced app_server.py (routes
        # exist: update_site_ep, site_command_ep, list_site_command_jobs_ep)
        # AND dashboard.html (grepped for updateSite/editSite/site command
        # runner/command-jobs poller): there is NO JS caller for any of the
        # three anywhere in the file -- no edit-site form, no per-site CLI
        # command runner, no command-jobs poller. Per shared per-tab rules
        # ("do NOT fabricate UI"), this is reported rather than invented;
        # relaxed to asserting the real routes exist server-side by handler
        # name, and asserting no fabricated hook was added for them.
        import app_server as _app_server
        for fn in ('update_site_ep', 'site_command_ep', 'list_site_command_jobs_ep'):
            self.assertTrue(hasattr(_app_server, fn), f"expected server route {fn} to exist")
        for hook in ('updateSite(', 'editSite(', 'runSiteCommand(', 'siteCommand(', 'commandJobs('):
            self.assertNotIn(hook, html)

    def test_admin_gated_functions_untouched(self):
        html = _html()
        # loadSites() and all mutating handlers must survive byte-for-byte.
        self.assertIn("async function loadSites()", html)
        self.assertIn("if (currentRole !== 'admin') return;", html)
        for hook in ('createSite()', 'regenSiteToken(', 'deleteSite('):
            self.assertIn(hook, html)

    def test_rbac_preserved(self):
        html = _html()
        # Precedent from Task 14-16: the tab is gated at the nav entry, so the
        # tab body itself carries no requires-admin gate.
        self.assertIn(
            "class=\"nav-item requires-admin\" onclick=\"switchTab('tab-sites', this)\"",
            html)
        tab = self._tab(html)
        self.assertNotIn('requires-admin', tab)

    def test_tab_uses_component_classes(self):
        html = _html()
        tab = self._tab(html)
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"',
                    'class="table-wrap"'):
            self.assertIn(cls, tab)
        # sites-table panel + create-site-form panel
        self.assertEqual(tab.count('class="panel"'), 2)
        self.assertNotIn('table-container', tab)

    def test_i18n_keys_both_langs(self):
        html = _html()
        for key in ('sitesEyebrow:', 'titleSites:', 'descSites:', 'lblSiteName:',
                    'lblSiteMode:', 'thSiteLastContact:', 'titleNewSite:',
                    'lblSiteSubnets:', 'btnCreateSite:', 'btnRegenSiteToken:',
                    'btnDeleteSite:', 'lblSiteDefault:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")

    def test_relabel_keys_english_default(self):
        html = _html()
        # The three previously-unlocalized strings: EN copy is now the map's
        # canonical/default value, IT retained for the it map.
        self.assertIn('btnRegenSiteToken: "Regenerate token"', html)
        self.assertIn('btnDeleteSite: "Delete"', html)
        self.assertIn('lblSiteDefault: "Default"', html)
        self.assertIn('btnRegenSiteToken: "Rigenera token"', html)
        self.assertIn('btnDeleteSite: "Elimina"', html)
        self.assertIn('lblSiteDefault: "predefinita"', html)
        # renderSitesTable() looks these up via the established i18n[currentLang]
        # render-fn pattern (const L = i18n[currentLang]; ... L.btnDeleteSite),
        # not a newly-invented mechanism.
        self.assertIn('const L = i18n[currentLang];', html)
        self.assertIn('L.btnRegenSiteToken', html)
        self.assertIn('L.btnDeleteSite', html)
        self.assertIn('L.lblSiteDefault', html)


class TestMcpTabRestyle(unittest.TestCase):
    """Task 18: #tab-mcp (MCP Server) restyle + wiring guard.

    Two panels: a client-config snippet (copy-to-clipboard) and a per-tool
    enable/disable list rendered by loadMcpTab() -> GET /api/mcp/settings,
    saved via saveMcpSettings() -> POST /api/mcp/settings. The brief also
    lists GET/POST /api/mcp/tool-config: traced app_server.py -- only a GET
    handler exists (get_mcp_tool_config), no POST, and it's read by the
    separate mcp_server.py bridge process (see mcp_server.py:426), not by
    dashboard.html. No frontend caller exists for it. Per shared per-tab
    rules ("do NOT fabricate UI"), relaxed to asserting the real GET handler
    exists server-side rather than inventing a dashboard control for it.
    """

    def _tab(self, html):
        start = html.index('<div id="tab-mcp"')
        end = html.index('<div id="tab-settings"')
        return html[start:end]

    def test_preserve_ids(self):
        html = _html()
        for _id in ('mcpConfigSnippet', 'mcpToolList', 'mcpSettingsStatus'):
            self.assertIn(f'id="{_id}"', html, f"lost preserve-ID {_id}")
        # class used by saveMcpSettings()'s querySelectorAll, not an id, but
        # equally load-bearing wiring that must survive the restyle.
        self.assertIn('class="mcp-tool-toggle"', html)

    def test_endpoint_contract_present(self):
        html = _html()
        self.assertIn("apiFetch('/api/mcp/settings')", html)
        self.assertIn("apiFetch('/api/mcp/settings', {", html)
        # /api/mcp/tool-config: no POST route, no dashboard.html caller --
        # only mcp_server.py's own GET request against the running server.
        # Relax to the handler name rather than fabricating a UI wiring.
        self.assertNotIn('/api/mcp/tool-config', html)
        import app_server as _app_server
        self.assertTrue(hasattr(_app_server, 'get_mcp_tool_config'))
        self.assertTrue(hasattr(_app_server, 'get_mcp_settings'))
        self.assertTrue(hasattr(_app_server, 'set_mcp_settings'))

    def test_hooks_preserved(self):
        html = _html()
        for hook in ('loadMcpTab()', 'copyMcpConfig()', 'saveMcpSettings()'):
            self.assertIn(hook, html)

    def test_rbac_preserved(self):
        html = _html()
        # Precedent from Task 14-17: gated at the nav entry, tab body itself
        # carries no requires-admin gate.
        self.assertIn(
            "class=\"nav-item requires-admin\" onclick=\"switchTab('tab-mcp', this)\"",
            html)
        tab = self._tab(html)
        self.assertNotIn('requires-admin', tab)

    def test_tab_uses_component_classes(self):
        html = _html()
        tab = self._tab(html)
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"',
                    'class="panel"'):
            self.assertIn(cls, tab)
        # client-config panel + tool-list panel
        self.assertEqual(tab.count('class="panel"'), 2)

    def test_status_chip_classes_present_in_render_fn(self):
        html = _html()
        # loadMcpTab()'s per-tool row now surfaces a .status badge reflecting
        # the same enabled/disabled state the checkbox already carries.
        self.assertIn('class="status ${isEnabled ? \'ok\' : \'bad\'}"', html)
        self.assertIn("class=\"led ${isEnabled ? 'led-success' : 'led-danger'}\"", html)
        self.assertIn('const L = i18n[currentLang];', html)

    def test_i18n_keys_both_langs(self):
        html = _html()
        for key in ('mcpEyebrow:', 'titleMcp:', 'descMcp:', 'titleMcpClientConfig:',
                    'btnCopyJson:', 'descMcpClientConfig:', 'titleMcpTools:',
                    'descMcpTools:', 'btnSave:', 'mcpStEnabled:', 'mcpStDisabled:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")


class TestSettingsTabRestyle(unittest.TestCase):
    """Task 19: #tab-settings restyle + wiring guard.

    The tab body itself holds only ONE real input (cliBlacklistToggle); every
    other setting is rendered into a container by a JS render function, so the
    preserve-ID list below is enumerated from the JS (loadAppSettings and the
    three render/save handlers it fans out to), not from the static markup:

      renderAppSettings   -> netSettingsBody   : netHostSelect, netSettingsNotice
      loadCliBlacklist*   -> (static)          : cliBlacklistToggle, cliBlacklistStatus
      renderObsSettings   -> obsSettingsBody   : obs_enabled, obs_bind,
                                                 obs_api_poll_s, obsSettingsError,
                                                 obs_<l>_enabled / obs_<l>_port
      renderAppAdvSettings-> appAdvBody        : appadv_<key> x7, appadv_no_browser,
                                                 appAdvError

    Some ids are built by interpolation (`obs_${l}_port`, `appadv_${f.key}`) so
    they never appear literally in the served HTML; those are asserted via the
    template form plus the driving array, which is what actually determines them.
    """

    def _tab(self, html):
        start = html.index('<div id="tab-settings"')
        return html[start:html.index("</main>", start)]

    def test_preserve_ids_static(self):
        html = _html()
        for _id in ("netSettingsBody", "cliBlacklistToggle", "cliBlacklistStatus",
                    "obsRestartBanner", "obsSettingsBody",
                    "appAdvRestartBanner", "appAdvBody"):
            self.assertIn(f'id="{_id}"', self._tab(html), f"lost preserve-ID {_id}")

    def test_preserve_ids_rendered_by_js(self):
        html = _html()
        for _id in ("netHostSelect", "netSettingsNotice",
                    "obs_enabled", "obs_bind", "obs_api_poll_s", "obsSettingsError",
                    "appadv_no_browser", "appAdvError"):
            self.assertIn(f'id="{_id}"', html, f"lost preserve-ID {_id}")

    def test_preserve_interpolated_ids(self):
        html = _html()
        # obs_<listener>_enabled / obs_<listener>_port for all four listeners.
        self.assertIn('id="obs_${l}_enabled"', html)
        self.assertIn('id="obs_${l}_port"', html)
        self.assertIn("const OBS_LISTENERS = ['ipfix', 'sflow', 'syslog', 'netflow'];", html)
        # saveObsSettings() reads back the same interpolated ids.
        self.assertIn("document.getElementById(`obs_${l}_enabled`)", html)
        self.assertIn("document.getElementById(`obs_${l}_port`)", html)
        # appadv_<key> for every APP_ADV_FIELDS entry.
        self.assertIn('id="appadv_${f.key}"', html)
        self.assertIn("document.getElementById(`appadv_${f.key}`)", html)
        for key in ("port", "ssl_certfile", "ssl_keyfile", "cors_origins",
                    "retention_flows_days", "retention_syslog_days",
                    "retention_events_days"):
            self.assertIn(f"key: '{key}'", html, f"lost APP_ADV_FIELDS entry {key}")

    def test_endpoint_contract_present(self):
        html = _html()
        # GET + POST for each of the brief's three contract endpoints.
        self.assertIn("apiFetch('/api/settings/network')", html)
        self.assertIn("apiFetch('/api/settings/network', {", html)
        self.assertIn("apiFetch('/api/settings/app')", html)
        self.assertIn("apiFetch('/api/settings/app', {", html)
        self.assertIn("apiFetch('/api/settings/cli-blacklist')", html)
        self.assertIn("apiFetch('/api/settings/cli-blacklist', {", html)
        # The observability card is driven by a 4th endpoint the brief omits.
        self.assertIn("apiFetch('/api/observability/config')", html)

    def test_hooks_preserved(self):
        html = _html()
        for hook in ("loadAppSettings()", "saveAppSettings()",
                     "saveCliBlacklistSetting()", "saveObsSettings()",
                     "saveAppAdvSettings()"):
            self.assertIn(hook, html)

    def test_rbac_preserved(self):
        html = _html()
        self.assertIn(
            "class=\"nav-item requires-admin\" onclick=\"switchTab('tab-settings', this)\"",
            html)
        # The observability and application panels stay admin-gated in-body,
        # exactly as before the restyle (2 gates, no more, no fewer).
        self.assertEqual(self._tab(html).count("requires-admin"), 2)
        self.assertIn('class="panel requires-admin"', self._tab(html))
        # Every loader is also role-gated server-side of the render.
        self.assertIn("if (currentRole !== 'admin') return;", html)

    def test_tab_uses_component_classes(self):
        html = _html()
        tab = self._tab(html)
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"'):
            self.assertIn(cls, tab)
        # Four one-concern cards: network exposure, command safety,
        # observability, application (general).
        self.assertEqual(tab.count("class=\"panel"), 4)

    def test_i18n_icon_not_clobbered_by_innerhtml(self):
        # applyI18n does `el.innerHTML = i18n[lang][key]`, so a data-i18n key
        # whose value carries no icon markup must not sit on an element that
        # wraps an <i> icon -- it would erase the icon on language switch.
        # Card titles keep the icon outside and the key on an inner <span>.
        tab = self._tab(_html())
        for key in ("titleNetExpose", "titleCliBlacklist", "titleObsSettings",
                    "titleAppAdvanced"):
            self.assertIn(f'<span data-i18n="{key}">', tab)
        self.assertNotIn('<h3 style="font-size:15px; margin-bottom:8px;" data-i18n=', tab)

    def test_i18n_keys_both_langs(self):
        html = _html()
        for key in ("settingsEyebrow:", "titleSettings:", "descSettingsHero:",
                    "titleNetExpose:", "descNetExpose:", "titleCliBlacklist:",
                    "descCliBlacklist:", "lblCliBlacklistOperators:",
                    "titleObsSettings:", "descObsSettings:", "msgObsRestartRequired:",
                    "titleAppAdvanced:", "descAppAdvanced:",
                    "appAdvGrpServer:", "appAdvGrpRetention:", "appAdvGrpStartup:"):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")

    def test_app_adv_fields_grouped_by_concern(self):
        html = _html()
        # The general card mixes three concerns; each field declares the
        # subsection it renders under. Presentation only -- saveAppAdvSettings()
        # still posts one combined payload to /api/settings/app.
        self.assertEqual(html.count("grp: 'appAdvGrpServer'"), 4)
        self.assertEqual(html.count("grp: 'appAdvGrpRetention'"), 3)
        self.assertIn("subhead('appAdvGrpStartup', 'Avvio')", html)
        self.assertIn("const L = i18n[currentLang];", html)


if __name__ == "__main__":
    unittest.main()
