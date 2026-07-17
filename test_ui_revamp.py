# -*- coding: utf-8 -*-
import os, re, tempfile
_TMP = tempfile.mkdtemp(prefix="sentinelnet_uirevamp_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP
import unittest
from html.parser import HTMLParser  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
import data_config  # noqa: E402
data_config.DATA_DIR = _TMP
import app_server  # noqa: E402
import routers.inventory, routers.topology, routers.catalog, routers.mac, routers.analyzer, routers.backup, routers.sites, routers.mcp
from test_helpers_frontend import frontend_source  # noqa: E402


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
        # Task 2: CSS selectors live in static/css/dashboard.css now, not
        # inline in dashboard.html -- frontend_source() concatenates both.
        html = frontend_source()
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
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
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
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
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
        self.assertTrue(hasattr(routers.catalog, 'list_models'))
        self.assertTrue(hasattr(routers.catalog, 'create_model'))
        self.assertTrue(hasattr(routers.catalog, 'remove_model'))

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
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
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
        self.assertTrue(hasattr(routers.topology, 'get_topology_adjacency'))

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
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
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
        self.assertTrue(hasattr(routers.topology, 'get_topology_adjacency'))
        # exportVisioMap() posts to /api/map/export/vsdx -- traced the handler
        # in app_server.py: only a POST route exists (export_map_vsdx), there
        # is no GET variant, so only the POST endpoint is asserted here.
        self.assertIn('/api/map/export/vsdx', html)
        self.assertIn("apiFetch('/api/map/export/vsdx'", html)
        self.assertTrue(hasattr(routers.topology, 'export_map_vsdx'))

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
        self.assertTrue(hasattr(routers.catalog, 'create_device_category'))

    def test_categories_tab_uses_component_classes(self):
        html = _html()
        tab_start = html.index('<div id="tab-categories"')
        tab_end = html.index('<!-- TAB 5: Threat Intel')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"', 'class="filterbar"'):
            self.assertIn(cls, tab_html)
        self.assertGreaterEqual(tab_html.count('class="panel'), 4)

    def test_i18n_keys_both_langs(self):
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
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
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
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
        self.assertTrue(hasattr(routers.mac, 'mac_switch'))

    def test_mac_and_clientmap_tabs_use_component_classes(self):
        html = _html()
        tab_start = html.index('<div id="tab-mac"')
        # Bound on the next tab's own div, not on a comment: the comment that
        # used to sit here was mislabelled ("Config Analyzer" above #tab-flows)
        # and Task 20 corrected it, which silently broke this slice.
        tab_end = html.index('<div id="tab-flows"')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"', 'class="filterbar"', 'class="table-wrap"'):
            self.assertIn(cls, tab_html)
        self.assertGreaterEqual(tab_html.count('class="kpi-grid"'), 2)
        self.assertGreaterEqual(tab_html.count('class="panel'), 4)
        # both tabs individually still present within that combined span
        self.assertIn('<div id="tab-clientmap"', tab_html)

    def test_i18n_keys_both_langs(self):
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
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
        self.assertTrue(hasattr(routers.analyzer, 'config_analyzer_device'))
        self.assertTrue(hasattr(routers.analyzer, 'config_analyzer_all'))
        self.assertTrue(hasattr(routers.backup, 'download_backup'))

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
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
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
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
        for key in ('aiEyebrow:', 'titleAiContext:', 'titleAiChat:',
                    'titleAiAssistant:', 'descAiAssistant:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")


class TestProvisionerTabRestyle(unittest.TestCase):
    """Task 14 + ZTP W2: #tab-provisioner (Zero-Touch Provisioner) guard.

    The flagship form: two vendor sections toggled at runtime, an admin-gated
    inline FortiGate token model, and dual endpoint families reached through a
    computed base path.

    W2 restructure: the FortiGate token UI was deliberately moved OUT of the
    top-level `<details id="fgtTokenPanel">` accordion and into an inline
    section (`#provFgtTokenSection`) directly under the Device Type control,
    shown only when FortiGate is the selected vendor. Device Type is now a chip
    selector skinning the still-authoritative `<select id="provVendor">`.
    Assertions below pin the NEW structure; `fgtTokenPanel` is gone by design.
    """

    def _tab(self, html):
        start = html.index('<div id="tab-provisioner"')
        end = html.index('<!-- TAB 6: Importazione CSV -->')
        return html[start:end]

    def test_preserve_ids(self):
        html = _html()
        for _id in ('fgtTokensTable', 'fgtTokensTableBody',
                    'provFgtSection', 'provCiscoSection', 'provVendor', 'provRole',
                    'btnProvGenerate', 'btnProvDownload', 'provDeliveryMode',
                    'provSshFields', 'provSerialFields', 'provOutput',
                    # W2: the inline token section + chip selector.
                    'provFgtTokenSection', 'provVendorChips', 'provCiscoTokenHint',
                    'fgtTokenValue', 'fgtTokenReveal', 'fgtTokenStatus'):
            self.assertIn(f'id="{_id}"', html, f"lost preserve-ID {_id}")

    def test_token_accordion_replaced_by_inline_section(self):
        html = _html()
        tab = self._tab(html)
        # The old top-level accordion is intentionally gone: the token UI must
        # not reappear as a tab-level panel above the Device Type control.
        self.assertNotIn('id="fgtTokenPanel"', html)
        self.assertNotIn('<details', tab, 'token UI must no longer be an accordion')
        # ...and the whole token model must have survived the move.
        self.assertIn('id="provFgtTokenSection"', tab)
        self.assertIn('class="table-wrap"', tab)
        self.assertIn('id="fgtTokensTable"', tab)
        self.assertIn('function initFgtTokenPanel()', html)
        # Inline == rendered inside the Device & parameters panel, below the
        # Device Type control rather than above it.
        self.assertLess(tab.index('id="provVendorChips"'),
                        tab.index('id="provFgtTokenSection"'),
                        'token section must sit BELOW the Device Type control')

    def test_token_section_hidden_by_default(self):
        # Task 2: CSS moved to static/css/dashboard.css; frontend_source()
        # concatenates dashboard.html + all static/*.js|css so both the CSS
        # and JS assertions below still resolve against one string.
        html = frontend_source()
        # Hidden via CSS class, never inline style: the requires-admin gate uses
        # display:none!important and must be able to win over the shown state.
        self.assertIn('#provFgtTokenSection{display:none}', html)
        self.assertIn('#provFgtTokenSection.is-visible{display:block}', html)
        self.assertIn("body:not(.role-admin) .requires-admin { display: none !important; }", html)
        # The show/hide must be a classList toggle driven by the vendor flag.
        self.assertIn("tokenSec.classList.toggle('is-visible', fgt)", html)
        self.assertNotIn("provFgtTokenSection').style.display", html,
                         'inline display would fight the !important RBAC gate')

    def test_vendor_select_remains_source_of_truth(self):
        html = _html()
        tab = self._tab(html)
        # The select is hidden, NOT removed: provVendorIsFgt() still reads it.
        self.assertIn(
            '<select id="provVendor" class="visually-hidden" aria-hidden="true" tabindex="-1">',
            tab,
        )
        self.assertIn("document.getElementById('provVendor')?.value === 'fortigate'", html)
        for value in ('value="cisco"', 'value="fortigate"'):
            self.assertIn(value, tab)
        # Chips drive the select and re-fire the real change event rather than
        # duplicating the vendor wiring.
        self.assertIn("sel.value = chip.dataset.vendor", html)
        self.assertIn("sel.dispatchEvent(new Event('change'))", html)
        # ...and reflect the select's value back (two-way sync).
        self.assertIn("chip.setAttribute('aria-pressed', String(chip.dataset.vendor === sel.value))", html)
        self.assertIn('provSyncVendorChips();', html)

    def test_vendor_select_out_of_tab_order(self):
        """W2 a11y fix: the hidden select is no longer a keyboard trap. Chips
        are the sole accessible control -- the select must be pulled out of
        the accessibility tree and the tab order, and no longer carry a
        `for=` label association that would let a mouse click on the label
        focus the invisible control."""
        html = _html()
        tab = self._tab(html)
        select_tag = re.search(r'<select id="provVendor" class="visually-hidden"[^>]*>', tab).group(0)
        self.assertIn('aria-hidden="true"', select_tag)
        self.assertIn('tabindex="-1"', select_tag)
        # The visible label must no longer point `for=` at the hidden select --
        # it now only labels the chip group via aria-labelledby.
        self.assertNotIn('for="provVendor"', tab)
        self.assertIn('<label id="provVendorLabel" data-i18n="lblProvVendor">', tab)

    def test_vendor_chips_expose_selected_state(self):
        """The chips are the real control: each carries aria-pressed and it is
        actually flipped (not a static true/false pair) whenever the vendor
        selection changes."""
        html = _html()
        tab = self._tab(html)
        # Radiogroup-like semantics: one labelled group, real <button>s (not
        # divs/spans faking a control), each with an aria-pressed state.
        self.assertIn('id="provVendorChips" role="group" aria-labelledby="provVendorLabel"', tab)
        self.assertEqual(tab.count('<button type="button" class="chip chip-choice"'), 2,
                          'both vendor chips must be real, focusable <button>s')
        self.assertIn('data-vendor="cisco" aria-pressed="true"', tab)
        self.assertIn('data-vendor="fortigate" aria-pressed="false"', tab)
        # The state is not static markup: provSyncVendorChips() rewrites
        # aria-pressed on every chip from the live select value, both on
        # click and on init, so a re-sync (e.g. programmatic vendor change)
        # keeps the exposed state correct.
        self.assertIn(
            "chip.setAttribute('aria-pressed', String(chip.dataset.vendor === sel.value))",
            html,
        )
        self.assertIn('function provSyncVendorChips()', html)
        self.assertIn('provSyncVendorChips();', html)  # called from provInitVendorChips()
        # Visible focus indicator reuses design tokens (var(--primary)), not a
        # new invented color.
        # Task 2: this selector lives in static/css/dashboard.css now.
        self.assertIn('.chip-choice:focus-visible{outline:2px solid var(--primary);outline-offset:2px}',
                      frontend_source())

    def test_token_input_credential_hygiene(self):
        html = _html()
        tab = self._tab(html)
        # Stays a password field and must not be autofilled with a credential
        # saved for a different device.
        self.assertIn('<input id="fgtTokenValue" type="password" autocomplete="new-password"', tab)
        # Switching away from FortiGate clears the typed token and re-masks it.
        self.assertIn("if (tokenInput) { tokenInput.value = ''; tokenInput.type = 'password'; }", html)
        # Reveal toggle flips the input type both ways.
        self.assertIn('function toggleFgtTokenReveal()', html)
        self.assertIn("inp.type = show ? 'text' : 'password'", html)
        self.assertIn('fa-eye-slash', html)

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
        # The token UI stays admin-gated after the move inline; the tab itself is
        # gated at the nav entry (requires-write), which is why the body carries
        # no write gate. Still exactly one admin gate in the tab -- now on the
        # inline section instead of the deleted accordion.
        self.assertIn('class="requires-admin" id="provFgtTokenSection"', tab)
        self.assertEqual(tab.count('requires-admin'), 1)
        # Everything credential-bearing must live INSIDE the gated section, so a
        # non-admin cannot reach it even with FortiGate selected.
        start = tab.index('id="provFgtTokenSection"')
        end = tab.index('id="provFgtSection"')
        self.assertLess(start, end)
        gated = tab[start:end]
        for _id in ('fgtTokenValue', 'fgtTokenDevice', 'fgtTokenPort',
                    'fgtTokenVerifyTls', 'fgtTokensTable', 'fgtTokenReveal'):
            self.assertIn(f'id="{_id}"', gated,
                          f'{_id} escaped the requires-admin section')

    def test_tab_uses_component_classes(self):
        html = _html()
        tab = self._tab(html)
        for cls in ('class="hero"', 'class="hero-card"', 'class="eyebrow"',
                    'class="table-wrap"'):
            self.assertIn(cls, tab)
        # device/params card + generate/deliver card. Was 3 before the token
        # accordion (itself a .panel) became an inline block inside the first.
        self.assertGreaterEqual(tab.count('class="panel'), 2)
        # Device type chips reuse the existing .chip component.
        self.assertEqual(tab.count('class="chip chip-choice"'), 2)
        # Task 2: CSS estratto in static/css/dashboard.css, non piu' inline.
        self.assertIn('.chip-choice[aria-pressed="true"]', frontend_source())

    def test_i18n_keys_both_langs(self):
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
        for key in ('provisionerEyebrow:', 'provPanelDevice:', 'provPanelDeploy:',
                    'titleProvisioner:', 'descProvisioner:',
                    # W2 additions.
                    'chipVendorCisco:', 'chipVendorFortigate:',
                    'msgProvCiscoNoToken:', 'titleFgtTokenReveal:'):
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
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
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
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
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
            self.assertTrue(hasattr(routers.sites, fn), f"expected server route {fn} to exist")
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
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
        for key in ('sitesEyebrow:', 'titleSites:', 'descSites:', 'lblSiteName:',
                    'lblSiteMode:', 'thSiteLastContact:', 'titleNewSite:',
                    'lblSiteSubnets:', 'btnCreateSite:', 'btnRegenSiteToken:',
                    'btnDeleteSite:', 'lblSiteDefault:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")

    def test_relabel_keys_english_default(self):
        # i18n dict e stato spostato in static/js/i18n.js (Task 3).
        html = frontend_source()
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
        self.assertTrue(hasattr(routers.mcp, 'get_mcp_tool_config'))
        self.assertTrue(hasattr(routers.mcp, 'get_mcp_settings'))
        self.assertTrue(hasattr(routers.mcp, 'set_mcp_settings'))

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
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
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
        # (The general, document-wide regression guard for this bug class is
        # TestI18nIconWipeGuard below -- it supersedes the exact-style-string
        # assertNotIn this test used to carry, which broke the moment the
        # h3's inline style changed for unrelated reasons.)
        tab = self._tab(_html())
        for key in ("titleNetExpose", "titleCliBlacklist", "titleObsSettings",
                    "titleAppAdvanced"):
            self.assertIn(f'<span data-i18n="{key}">', tab)

    def test_i18n_keys_both_langs(self):
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
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


class TestLiveFlowsTabRestyle(unittest.TestCase):
    """Task 20: #tab-flows (Live Flows) restyle + English relabel + wiring guard.

    Client Map (#tab-clientmap) was already restyled in Task 11 and is guarded
    by TestMacTrackerTabRestyle; this class covers Live Flows only, plus one
    structural guard for the Client Map tenant filter (see the last test).

    Most of this tab's controls are rendered from JS (renderFlowsThead,
    renderFlowsTable, renderSyslogTable, renderFlowsSourceChips, loadAnomalies),
    so the preserve-ID list is enumerated from that JS, not from static markup.
    """

    def _tab(self, html):
        # #flowDetailPanel is a fixed-position sibling that follows the tab body.
        start = html.index('<div id="tab-flows"')
        return html[start:html.index('<div id="flowDetailPanel"', start)]

    def test_preserve_ids(self):
        html = _html()
        for _id in ('flowsTableHead', 'flowsTableBody', 'anomTableBody',
                    'flowsWindow', 'flowsMetric', 'flowsTenantBtn',
                    'flowsTenantDropdown', 'flowsTenantAll', 'flowsTenantList',
                    'flowsAutoRefresh', 'flowsLastUpdate', 'flowsObsBanner',
                    'flowsAiNote', 'flowsSourceChips', 'flowsColsBtn',
                    'flowsColsDropdown', 'anomStatus', 'anomIpFilterChip',
                    'flowDetailPanel', 'flowDetailPanelBody'):
            self.assertIn(f'id="{_id}"', html)
        for hook in ('flowsTabShown()', 'loadTopTalkers()', 'loadAnomalies()',
                     'toggleFlowsTenantDropdown()', 'toggleFlowsTenantAll()',
                     'toggleFlowsColsDropdown()', 'analyzeFlowsWithAi()',
                     'clearAnomIpFilter()', 'closeFlowDetailPanel()'):
            self.assertIn(hook, html)
        # Ids created only by JS (never literal in the static markup).
        for _id in ('flowsSelectAll',):
            self.assertIn(f"id=\\\"{_id}\\\"", html.replace('"', '\\"'))
        # RBAC: the two AI actions stay write-gated.
        idx = html.index('analyzeFlowsWithAi()')
        self.assertIn('requires-write', html[html.rindex('<button', 0, idx):idx])
        self.assertIn('class="btn requires-write" style="text-align:left;" '
                      'onclick="analyzeSingleFlowWithAi()"', html)
        # Anomaly transitions stay write-gated.
        self.assertIn('<button class="btn requires-write" style="font-size:11px; '
                      'padding:3px 8px;" onclick="anomTransition(', html)

    def test_source_filter_chips_and_column_toggle_survive(self):
        html = _html()
        # Source chips (incl. the syslog view) are data-driven; the array is
        # what actually determines the chips, so assert the array itself.
        self.assertIn("const FLOWS_SOURCES = ['all', 'netflow', 'ipfix', 'sflow', 'syslog'];", html)
        self.assertIn("function renderFlowsSourceChips()", html)
        self.assertIn('onclick="setFlowsSource(', html)
        # Syslog view swaps thead + tbody renderers.
        self.assertIn("if (_flowsSource === 'syslog')", html)
        # Dual-target: main table (syslog view) or the all-sources section below the flows.
        self.assertIn("function renderSyslogTable(tbodyId = 'flowsTableBody')", html)
        # Column-visibility toggle + its persistence.
        self.assertIn("const FLOW_TOGGLE_COLS = [", html)
        self.assertIn("onchange=\"toggleFlowsCol('${c.id}', this.checked)\"", html)
        self.assertIn("localStorage.setItem('sentinelnet_flows_hidden_cols'", html)

    def test_endpoint_contract_present(self):
        html = _html()
        for ep in ('/api/observability/top?window=',
                   '/api/observability/syslog?window=',
                   '/api/observability/anomalies?status=',
                   '/api/observability/anomalies/${id}/status',
                   '/api/observability/health'):
            self.assertIn(ep, html)

    def test_english_relabel(self):
        html = _html()
        tab = self._tab(html)
        # EN default in the markup...
        self.assertIn('data-i18n="titleFlows">Live Flows (Top Talkers)', tab)
        self.assertNotIn('Flussi Live', tab)
        # ...EN canonical in the en map, Italian retained in the it map.
        # i18n dict e stato spostato in static/js/i18n.js (Task 3).
        src = frontend_source()
        self.assertIn("titleFlows: 'Live Flows (Top Talkers)',", src)
        self.assertIn("titleFlows: 'Flussi Live (Top Talker)',", src)
        self.assertIn('tabFlows: \'<i class="fa-solid fa-wave-square"></i> Live Flows\',', src)
        self.assertIn('tabFlows: \'<i class="fa-solid fa-wave-square"></i> Flussi Live\',', src)

    def test_no_hardcoded_italian_left_in_tab(self):
        tab = self._tab(_html())
        # Strings that previously shipped without a data-i18n key.
        self.assertNotIn('>Dettaglio flusso<', _html())
        self.assertNotIn('title="Chiudi"', _html())
        self.assertNotIn('title="Evidenzia nella topologia"', _html())
        # ...now routed through keys / the file's existing `const L` pattern.
        self.assertIn('data-i18n="titleFlowDetail"', _html())
        self.assertIn('data-i18n-title="titleClose"', _html())
        self.assertIn("const hlTitle = escapeHtml(L.titleHighlightTopology", _html())
        # Every remaining user-visible string in the tab body carries a key.
        self.assertNotIn('Anomalie correlate', tab)

    def test_component_classes_applied(self):
        tab = self._tab(_html())
        self.assertIn('<div class="hero" style="grid-template-columns:1fr;', tab)
        self.assertIn('<span class="eyebrow" data-i18n="flowsEyebrow"', tab)
        # Two cards: top talkers, then correlated anomalies.
        self.assertEqual(tab.count('<div class="panel"'), 2)
        self.assertEqual(tab.count('<div class="panel" style="margin-bottom:18px;">'), 1)
        # All tables wrapped: flows, syslog-in-all-sources, correlated anomalies.
        self.assertEqual(tab.count('class="table-wrap"'), 3)
        self.assertIn('class="filterbar"', tab)
        self.assertIn('id="anomIpFilterChip" class="chip"', tab)
        # Severity/status badges use the component status/chip classes.
        html = _html()
        # Severity buckets mirror sevColor() in the syslog table: 0-3 bad,
        # 4 warn, 5+ neutral .chip. 5+ is "medio" (_SEVERITY_KIND in
        # observability/correlator.py), so it must NOT render as .status ok --
        # a medium anomaly badged green would read as healthy.
        self.assertIn('s <= 3 ? `<span class="status bad">${s}</span>`', html)
        self.assertIn('s <= 4 ? `<span class="status warn">${s}</span>`', html)
        self.assertIn(': `<span class="chip">${s}</span>`', html)
        self.assertNotIn('<span class="status ok">${s}</span>', html)
        self.assertIn('`<span class="status ok">${escapeHtml(st)}</span>`', html)
        # Preview badge in the sidebar survives (Task 2).
        nav = html[html.index("switchTab('tab-flows'"):]
        self.assertIn('<span class="preview-badge">preview</span>', nav[:400])

    def test_i18n_keys_both_langs(self):
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
        for key in ("tabFlows:", "titleFlows:", "descFlows:", "flowsEyebrow:",
                    "titleFlowDetail:", "titleClose:", "titleHighlightTopology:",
                    "titleCorrelatedAnomalies:", "chipAllSources:", "msgNoFlows:",
                    "msgNoSyslog:", "msgNoAnomalies:"):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")

    def test_anomalies_scroll_anchor_is_explicit(self):
        """jumpToAnomaliesForFlow() used to scroll via `#tab-flows h4`, i.e. the
        FIRST h4 in the tab -- which was the anomalies heading only by accident of
        source order. The restyle promotes that heading to <h3> inside a .panel,
        which would have silently made the selector match nothing (`?.` swallows
        it) and killed the flow-detail -> anomalies jump. Anchor it to an id."""
        html = _html()
        self.assertIn('id="anomSectionTitle"', html)
        self.assertIn("document.getElementById('anomSectionTitle')?.scrollIntoView(", html)
        self.assertNotIn("querySelector('#tab-flows h4')", html)

    def test_clientmap_tenant_filter_drives_grouped_and_rows_from_one_path(self):
        """Task 20 brief lists a 'known bug': the Client Map tenant filter is
        said to update the grouped results but not the row details.

        IT DOES NOT REPRODUCE -- the structure makes it impossible, and this
        test pins that structure so a future refactor cannot reintroduce it:

          #arpFilterTenant onchange -> populateArpGatewayFilter(); arpClientSearch();
          arpClientSearch()  -> ONE server-filtered GET /api/arp/client-map
                             -> renderArpResults(d.results)
          renderArpResults() -> derives BOTH the per-tenant grouping (byTenant)
                                and the detail rows (rowHtml) from the SAME rows
                                array, in the SAME `box.innerHTML =` write.

        There is exactly one Client Map results container (#arpResults) and no
        separate row-details element, so grouping and rows cannot diverge.

        LIMIT: no test here executes JS, so this asserts the *source wiring*,
        not runtime behaviour. It proves the single-render-path property that
        makes the reported bug unrepresentable; it cannot prove the rendered
        DOM is correct. Runtime confirmation is the manual gate's job.
        """
        html = _html()
        # One filter-application path: the tenant filter reconciles the gateway
        # list and then re-runs the single search.
        self.assertIn('onchange="populateArpGatewayFilter(); arpClientSearch();"', html)
        # The tenant is applied SERVER-side, on the one fetch the renderer feeds on.
        search = html[html.index('async function arpClientSearch()'):
                      html.index('function arpSearchReset()')]
        self.assertIn("params.set('tenant', tenant)", search)
        self.assertEqual(search.count("apiFetch('/api/arp/client-map?"), 1)
        self.assertEqual(search.count('renderArpResults('), 1)
        # The renderer derives grouping AND rows from the same `rows` argument.
        render = html[html.index('function renderArpResults(rows)'):
                      html.index('function renderMacResults(rows)')]
        self.assertIn('rows.forEach(r => {', render)      # byTenant grouping
        self.assertIn('byTenant[t].map(rowHtml)', render)  # rows, same source
        self.assertIn("table(rows.map(rowHtml).join(''))", render)
        # Exactly one results sink; no second detail container to fall stale.
        self.assertEqual(html.count('id="arpResults"'), 1)
        self.assertEqual(render.count("getElementById('arpResults')"), 1)


# ---------------------------------------------------------------------------
# i18n EN/IT parity + structural icon-wipe guard (Task 21)
#
# The i18n object in the inline <script> is a hand-written JS object literal,
# not JSON (keys are bare identifiers, values are single/double-quoted
# strings, some carrying embedded HTML like '<i class="..."></i> Text').
# The helpers below are a tiny bespoke tokenizer -- not a regex scan -- so
# they can't silently match zero keys and pass vacuously: they walk the
# actual `it: { ... }` / `en: { ... }` blocks brace-by-brace (respecting
# string/comment literals) and raise if the shape they expect is violated.
# ---------------------------------------------------------------------------

def _find_matching_brace(s, open_idx):
    """Return the index of the '}' matching the '{' at s[open_idx], walking
    forward and skipping over // line comments and '/"/`-quoted strings
    (honouring backslash-escapes) so braces inside JS string literals are
    never mistaken for structural braces."""
    depth = 0
    i = open_idx
    n = len(s)
    in_str = None
    in_line_comment = False
    while i < n:
        ch = s[i]
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch == "/" and i + 1 < n and s[i + 1] == "/":
            in_line_comment = True
            i += 2
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise AssertionError(f"no matching '}}' found for '{{' at offset {open_idx}")


def _extract_object_keys(sub):
    """Tokenize a flat `key: 'value'|"value",` JS object body (as found
    inside i18n's `it { ... }` / `en { ... }`) into a {key: value} dict.
    Every i18n value in this file is a single quoted-string literal -- no
    nested objects/arrays -- so this is intentionally not a general JS
    parser, just enough of one to walk this exact shape robustly."""
    i = 0
    n = len(sub)
    keys = {}
    while i < n:
        ch = sub[i]
        if ch in " \t\r\n,":
            i += 1
            continue
        if ch == "/" and i + 1 < n and sub[i + 1] == "/":
            i = sub.index("\n", i) if "\n" in sub[i:] else n
            continue
        m = re.match(r"[A-Za-z_$][A-Za-z0-9_$]*", sub[i:])
        assert m, f"expected an object key at offset {i}: {sub[i:i+40]!r}"
        key = m.group(0)
        i += m.end()
        while sub[i] in " \t\r\n":
            i += 1
        assert sub[i] == ":", f"expected ':' after key {key!r} at offset {i}"
        i += 1
        while sub[i] in " \t\r\n":
            i += 1
        quote = sub[i]
        assert quote in ("'", '"', "`"), (
            f"expected a quoted string value for key {key!r} at offset {i}: "
            f"{sub[i:i+40]!r}")
        i += 1
        val_start = i
        while True:
            c2 = sub[i]
            if c2 == "\\":
                i += 2
                continue
            if c2 == quote:
                break
            i += 1
        value = sub[val_start:i]
        i += 1  # skip closing quote
        keys[key] = value  # JS semantics: last literal wins on duplicate key
        while i < n and sub[i] in " \t\r":
            i += 1
        if i < n and sub[i] == ",":
            i += 1
    return keys


def _extract_i18n_maps(html):
    """Return (it_dict, en_dict) parsed out of `const i18n = { it: {...},
    en: {...} }` in the rendered page."""
    start = html.index("const i18n = {")
    brace_start = html.index("{", start)
    end = _find_matching_brace(html, brace_start)
    block = html[brace_start + 1:end]

    def lang_block(name):
        m = re.search(r"\b" + name + r"\s*:\s*\{", block)
        assert m, f"'{name}: {{' block not found inside the i18n object"
        idx = m.end() - 1
        close = _find_matching_brace(block, idx)
        return block[idx + 1:close]

    it = _extract_object_keys(lang_block("it"))
    en = _extract_object_keys(lang_block("en"))
    assert it, "parsed zero keys out of i18n.it -- parser is matching vacuously"
    assert en, "parsed zero keys out of i18n.en -- parser is matching vacuously"
    return it, en


class _I18nUsageCollector(HTMLParser):
    """Collects every element in the rendered document carrying a
    data-i18n / data-i18n-placeholder / data-i18n-title attribute, and (for
    every attribute) whether that same element wraps an <i> icon tag before
    its own closing tag -- the specific shape applyI18n's
    `el.innerHTML = i18n[lang][key]` would clobber for data-i18n. <script>/
    <style> bodies are opaque to HTMLParser (CDATA_CONTENT_ELEMENTS), so the
    i18n object's own JS-string HTML fragments are never mistaken for real
    markup.
    """

    VOID_ELEMENTS = {
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.usages = []  # (attr, key, wraps_icon)

    def handle_starttag(self, tag, attrs):
        tagl = tag.lower()
        d = dict(attrs)
        pairs = [(a, d[a]) for a in
                 ("data-i18n", "data-i18n-placeholder", "data-i18n-title")
                 if d.get(a)]
        if tagl == "i":
            for anc in self.stack:
                anc["wraps_icon"] = True
        if tagl in self.VOID_ELEMENTS:
            for a, k in pairs:
                self.usages.append((a, k, False))
            return
        self.stack.append({"tag": tagl, "pairs": pairs, "wraps_icon": tagl == "i"})

    def handle_startendtag(self, tag, attrs):
        if tag.lower() == "i":
            for anc in self.stack:
                anc["wraps_icon"] = True

    def handle_endtag(self, tag):
        tagl = tag.lower()
        if tagl in self.VOID_ELEMENTS or not self.stack:
            return
        frame = self.stack.pop()
        for a, k in frame["pairs"]:
            self.usages.append((a, k, frame["wraps_icon"]))


def _collect_i18n_usage(html):
    c = _I18nUsageCollector()
    c.feed(html)
    c.close()
    return c.usages


class TestI18nParity(unittest.TestCase):
    """Task 21: EN/IT completeness regression guard.

    Every data-i18n / data-i18n-placeholder / data-i18n-title key used
    anywhere in the rendered markup must resolve in BOTH the `it` and `en`
    maps of the i18n object, and the two maps must carry the identical key
    set in both directions (no asymmetry). Parses the real object literal
    with a bespoke tokenizer (see _extract_i18n_maps/_extract_object_keys
    above) rather than a regex scan, specifically so a broken/rewritten
    parser that matches zero keys fails loudly instead of passing vacuously
    (see test_parser_found_the_expected_key_counts).
    """

    @classmethod
    def setUpClass(cls):
        cls.html = _html()
        # i18n dict e stato spostato in static/js/i18n.js (Task 3):
        # frontend_source() lo concatena, _html() no.
        cls.it, cls.en = _extract_i18n_maps(frontend_source())
        cls.usages = _collect_i18n_usage(cls.html)

    def test_parser_found_the_expected_key_counts(self):
        # Guards against the tokenizer silently degrading into a no-op --
        # a regression here would let every other assertion in this class
        # pass vacuously against empty dicts.
        self.assertGreater(len(self.it), 100,
                            "parsed suspiciously few keys out of i18n.it")
        self.assertGreater(len(self.en), 100,
                            "parsed suspiciously few keys out of i18n.en")

    def test_every_used_key_resolves_in_both_maps(self):
        used_keys = sorted({k for _, k, _ in self.usages})
        self.assertGreater(
            len(used_keys), 100,
            "collected suspiciously few data-i18n* usages from the "
            "rendered markup -- HTMLParser collection may be broken")
        missing_it = [k for k in used_keys if k not in self.it]
        missing_en = [k for k in used_keys if k not in self.en]
        self.assertEqual(
            missing_it, [],
            f"key(s) used in markup but missing from i18n.it: {missing_it}")
        self.assertEqual(
            missing_en, [],
            f"key(s) used in markup but missing from i18n.en: {missing_en}")

    def test_it_and_en_key_sets_are_identical(self):
        it_only = sorted(set(self.it) - set(self.en))
        en_only = sorted(set(self.en) - set(self.it))
        self.assertEqual(
            it_only, [],
            f"key(s) present in i18n.it but missing from i18n.en: {it_only}")
        self.assertEqual(
            en_only, [],
            f"key(s) present in i18n.en but missing from i18n.it: {en_only}")

    def test_no_key_resolves_to_an_empty_or_blank_value(self):
        # A key that exists but resolves to "" (or whitespace-only) would
        # render as a blank label -- just as broken as a missing key.
        empty_it = sorted(k for k, v in self.it.items() if not v.strip())
        empty_en = sorted(k for k, v in self.en.items() if not v.strip())
        self.assertEqual(
            empty_it, [], f"key(s) with an empty/blank value in i18n.it: {empty_it}")
        self.assertEqual(
            empty_en, [], f"key(s) with an empty/blank value in i18n.en: {empty_en}")


class TestI18nIconWipeGuard(unittest.TestCase):
    """Task 21: structural guard for the icon-wipe bug class.

    changeLanguage() does `el.innerHTML = i18n[lang][key]` for every
    `[data-i18n]` element. If such an element wraps its own <i> icon while
    the key's value is plain text with no <i> markup, the icon is silently
    erased on every language switch. Two established fix patterns coexist in
    this file: icon outside the data-i18n element with the key on an inner
    <span> (e.g. titleObsSettings), or the icon markup folded directly into
    the key's own value (e.g. titleProvisioning). Either satisfies this
    test -- it only requires that at least one hold.

    Deliberately built on html.parser.HTMLParser (real DOM nesting), not a
    style-string/line-shape regex -- a prior per-tab guard
    (test_i18n_icon_not_clobbered_by_innerhtml) asserted an exact `<h3
    style="...">` string was absent, which would silently stop catching
    anything the moment that inline style changed for unrelated reasons.
    This test instead asks the structural question directly: does the
    element that carries data-i18n contain an <i> descendant, and if so,
    does the key's value contain <i> markup in both languages?

    NOTE: data-i18n-placeholder and data-i18n-title are collected but NOT
    checked here -- changeLanguage() sets `.placeholder`/`.title` for those,
    never `.innerHTML`, so an <i> icon nested under one of those elements is
    never touched by a language switch and cannot be wiped by it.
    """

    @classmethod
    def setUpClass(cls):
        cls.html = _html()
        # i18n dict e stato spostato in static/js/i18n.js (Task 3):
        # frontend_source() lo concatena, _html() no.
        cls.it, cls.en = _extract_i18n_maps(frontend_source())
        cls.usages = _collect_i18n_usage(cls.html)

    def test_data_i18n_elements_wrapping_an_icon_carry_icon_markup_in_value(self):
        victims = sorted({
            key for attr, key, wraps_icon in self.usages
            if attr == "data-i18n" and wraps_icon
            and ("<i" not in self.it.get(key, "") or "<i" not in self.en.get(key, ""))
        })
        self.assertEqual(
            victims, [],
            "data-i18n key(s) wrap their own <i> icon in the markup but the "
            "key's value has no <i> markup in (at least) one language -- "
            "changeLanguage()'s `el.innerHTML = i18n[lang][key]` will erase "
            "the icon on language switch. Fix: move the icon outside the "
            "data-i18n element (key on an inner <span>) or fold the <i> "
            "markup into the value -- match whichever pattern neighbouring "
            f"code already uses. Offending key(s): {victims}")


class TestTransportsCollapsible(unittest.TestCase):
    """Part A/B guard: checkbox-stretch CSS regression + the collapsible
    #devTransports panel that replaced the plain always-open <div>.
    """

    @classmethod
    def setUpClass(cls):
        cls.html = _html()

    def test_all_transport_ids_present(self):
        for _id in ('devTransports', 'trSshEnabled', 'trSshPort',
                    'trTelnetEnabled', 'trTelnetPort', 'trTelnetWarn',
                    'trNetconfEnabled', 'trNetconfPort',
                    'trRestconfEnabled', 'trRestconfPort'):
            self.assertIn(f'id="{_id}"', self.html)
        for proto in ('ssh', 'telnet', 'netconf', 'restconf'):
            self.assertIn(f'data-proto="{proto}"', self.html)

    def test_checkbox_stretch_regression_guard(self):
        # Pin the Part A fix: the .form-group input/select rule must exclude
        # checkboxes and radios, otherwise width:100% + padding-left:36px
        # (meant to clear the .input-wrapper icon) stretches every checkbox
        # row in #devTransports (and any other checkbox living inside a
        # .form-group, e.g. #aiAllowUnredacted) across the full row width.
        # CSS estratto in static/css/dashboard.css (Task 2): niente piu'
        # inline in dashboard.html, quindi si cerca nel file statico.
        css_path = os.path.join(os.path.dirname(__file__), "static", "css",
                                 "dashboard.css")
        css = open(css_path, encoding="utf-8").read()
        m = re.search(
            r'\.form-group\s+input([^,{]*),\s*\.form-group\s+select\s*\{([^}]*)\}',
            css)
        self.assertIsNotNone(m, "could not find the .form-group input/select CSS rule")
        selector_suffix, body = m.group(1), m.group(2)
        self.assertIn('[type="checkbox"]', selector_suffix)
        self.assertIn('[type="radio"]', selector_suffix)
        self.assertIn('width: 100%', body)
        self.assertIn('padding: 10px 12px 10px 36px', body)

    def test_devtransports_is_a_collapsible_details_with_summary(self):
        # <details id="devTransports"> ... <summary>...</summary> ... </details>
        m = re.search(r'<details[^>]*id="devTransports"[^>]*>(.*?)</details>',
                      self.html, re.S)
        self.assertIsNotNone(m, "#devTransports must be a <details> element")
        body = m.group(1)
        self.assertIn('<summary', body)
        self.assertIn('id="devTransportsSummary"', body)
        # the actual checkbox/port rows must still live inside the <details>
        for _id in ('trSshEnabled', 'trTelnetEnabled', 'trNetconfEnabled', 'trRestconfEnabled'):
            self.assertIn(f'id="{_id}"', body)

    def test_devtransports_summary_i18n_keys_both_langs(self):
        # i18n dict e stato spostato in static/js/i18n.js (Task 3).
        src = frontend_source()
        for key in ('lblTransportsEnabled', 'lblTransportsNone'):
            self.assertGreaterEqual(src.count(f'{key}:'), 2,
                f"i18n key {key} must be defined in both it and en maps")

    def test_telnet_warning_wiring_intact(self):
        # Same wiring the pre-existing feature relied on: a change listener
        # on trTelnetEnabled toggling trTelnetWarn's visibility, untouched by
        # the collapsible refactor.
        self.assertIn("document.getElementById('trTelnetEnabled').addEventListener('change', updateTelnetWarn)",
                      self.html)
        self.assertIn("function updateTelnetWarn()", self.html)
        self.assertIn("document.getElementById('trTelnetWarn').style.display", self.html)

    def test_summary_updates_on_checkbox_and_port_change(self):
        self.assertIn("function updateTransportsSummary()", self.html)
        # wired for every protocol's checkbox (change) and port (input)
        self.assertIn(
            "document.getElementById('tr' + _trCap(p) + 'Enabled').addEventListener('change', updateTransportsSummary)",
            self.html)
        self.assertIn(
            "document.getElementById('tr' + _trCap(p) + 'Port').addEventListener('input', updateTransportsSummary)",
            self.html)
        # setTransportsForm() must refresh the summary after populating the form
        start = self.html.index('function setTransportsForm(')
        end = self.html.index('function ', start + len('function setTransportsForm('))
        set_form = self.html[start:end]
        self.assertIn('updateTransportsSummary()', set_form)

    def test_auto_expand_on_non_default_transports(self):
        # setTransportsForm() must open <details> when the device's transports
        # deviate from the SSH:22-only default -- never hide non-default state.
        start = self.html.index('function setTransportsForm(')
        end = self.html.index('function ', start + len('function setTransportsForm('))
        set_form = self.html[start:end]
        self.assertIn("getElementById('devTransports').open", set_form)


class TestSidebarRail(unittest.TestCase):
    """Collapsible sidebar icon rail + design-language scrollbar.

    The rail hides labels via `font-size:0` rather than `display:none`
    precisely so it never competes with the RBAC gate
    (`body:not(.role-admin) .requires-admin{display:none!important}`), which
    must stay the ONLY thing deciding whether a .nav-item is visible.
    test_collapsed_css_never_sets_display_on_nav_item asserts that invariant
    structurally instead of trusting the comment.
    """

    @classmethod
    def setUpClass(cls):
        # CSS estratto in static/css/dashboard.css (Task 2): non piu' inline
        # in dashboard.html, quindi si legge direttamente il file statico.
        cls.html = _html()
        css_path = os.path.join(os.path.dirname(__file__), "static", "css",
                                 "dashboard.css")
        cls.css = open(css_path, encoding="utf-8").read()
        # The template is served with CRLF line endings, so whitespace is
        # normalised via \s+ (not a bare '\n' strip) before shape assertions;
        # the optional trailing `;` before `}` is dropped too, so assertions
        # pin declarations rather than punctuation style.
        cls.flat = re.sub(r';+\}', '}', re.sub(r'\s+', '', cls.css))

    # --- helpers -----------------------------------------------------------

    def _rules(self, css=None):
        """[(selector, body)] for every rule in the stylesheet (flat scan;
        at-rule preludes are skipped since they carry no declarations)."""
        css = self.css if css is None else css
        out = []
        for sel, body in re.findall(r'([^{}]+)\{([^{}]*)\}', css):
            sel = sel.strip()
            if not sel or sel.startswith('@'):
                continue
            out.append((sel.split('@media')[-1].strip(), body))
        return out

    def _rule(self, selector):
        for sel, body in self._rules():
            if sel == selector:
                return body
        return None

    # --- toggle button -----------------------------------------------------

    def test_toggle_button_exists_with_aria_attributes(self):
        m = re.search(r'<button[^>]*id="sidebarToggle"[^>]*>', self.html)
        self.assertIsNotNone(m, "#sidebarToggle button not found in markup")
        tag = m.group(0)
        self.assertIn('onclick="toggleSidebar()"', tag)
        self.assertIn('aria-expanded="true"', tag)
        # aria-controls must point at an element that actually exists
        ac = re.search(r'aria-controls="([^"]+)"', tag)
        self.assertIsNotNone(ac, "toggle must declare aria-controls")
        self.assertIn(f'<aside id="{ac.group(1)}"', self.html,
                      "aria-controls must reference the real <aside> id")
        # icon-only control => needs a non-empty accessible name.
        # The lookbehind matters: a bare `aria-label="..."` search also matches
        # inside `data-i18n-aria-label="..."`, which would make this vacuous.
        self.assertRegex(tag, r'(?<![-\w])aria-label="[^"]+"')

    def test_toggle_accessible_name_is_i18n_in_both_maps(self):
        tag = re.search(r'<button[^>]*id="sidebarToggle"[^>]*>', self.html).group(0)
        for attr in ('data-i18n-title', 'data-i18n-aria-label'):
            m = re.search(attr + r'="([^"]+)"', tag)
            self.assertIsNotNone(m, f"toggle must carry {attr}")
            self.assertEqual(m.group(1), 'titleSidebarToggle')
        # i18n dict e stato spostato in static/js/i18n.js (Task 3):
        # frontend_source() lo concatena, self.html (_html()) no.
        it, en = _extract_i18n_maps(frontend_source())
        for lang_name, mp in (('it', it), ('en', en)):
            self.assertIn('titleSidebarToggle', mp,
                          f"titleSidebarToggle missing from i18n.{lang_name}")
            self.assertTrue(mp['titleSidebarToggle'].strip())
        self.assertNotEqual(it['titleSidebarToggle'], en['titleSidebarToggle'],
                            "IT and EN copy should actually differ")

    def test_aria_label_attribute_is_translated_at_runtime(self):
        # data-i18n-title was already handled by changeLanguage(); the
        # aria-label variant is new and must be wired too, or the accessible
        # name silently stays Italian after switching to EN.
        # changeLanguage() e stato spostato in static/js/i18n.js (Task 3).
        src = frontend_source()
        self.assertIn('document.querySelectorAll("[data-i18n-aria-label]")', src)
        self.assertIn('el.setAttribute("aria-label", i18n[lang][key])', src)

    # --- collapsed state drives the grid ------------------------------------

    def test_collapsed_css_drives_the_body_grid(self):
        body = self._rule('body')
        self.assertIsNotNone(body, "could not isolate the `body` CSS rule")
        # the grid must be expressed through the variable, not a literal width,
        # otherwise collapsing the rail cannot reflow <main>
        gtc = re.search(r'grid-template-columns:\s*([^;]+);', body)
        self.assertIsNotNone(gtc)
        self.assertIn('var(--sidebar-w)', gtc.group(1))
        self.assertNotIn('340px', gtc.group(1))
        expanded = re.search(r'--sidebar-w:\s*(\d+)px', body)
        self.assertIsNotNone(expanded, "body must define the expanded --sidebar-w")
        self.assertEqual(int(expanded.group(1)), 340)
        # The collapse must be animated, but scoped to the column only.
        # --transition is "all 0.25s", so using the bare token here would also
        # animate body's background/color/padding on every theme/state change.
        tr = re.search(r'transition:\s*([^;]+);', body)
        self.assertIsNotNone(tr, "body must animate the rail collapse")
        self.assertIn('grid-template-columns', tr.group(1))
        self.assertNotIn('var(--transition)', tr.group(1))
        self.assertNotRegex(tr.group(1), r'\ball\b')

    def test_collapsed_rule_shrinks_the_rail(self):
        m = re.search(r'body\.sidebar-collapsed\s*\{\s*--sidebar-w:\s*(\d+)px\s*\}', self.css)
        self.assertIsNotNone(
            m, "body.sidebar-collapsed must redefine --sidebar-w")
        width = int(m.group(1))
        self.assertLess(width, 340)
        self.assertLessEqual(width, 80, "collapsed rail should be an icon rail (~72px)")
        self.assertGreaterEqual(width, 56, "rail must stay wide enough to click icons")

    def test_collapsed_rail_hides_the_role_pill(self):
        # .user-badge hides its label text with font-size:0, but .role-pill sets
        # its own font-size:10px so it does NOT inherit that 0 -- uncollapsed it
        # is fine, collapsed it rendered 114px wide inside a 72px rail and spilled
        # out both sides (found in the browser gate, invisible to string asserts).
        pill = re.search(r'^\s*\.role-pill\s*\{([^}]*)\}', self.css, re.M)
        self.assertIsNotNone(pill, "could not isolate the .role-pill rule")
        self.assertRegex(
            pill.group(1), r'font-size:\s*\d',
            "if .role-pill stops setting its own font-size this guard is moot")
        self.assertRegex(
            self.css,
            r'body\.sidebar-collapsed\s+\.user-badge\s+\.role-pill\s*\{[^}]*display:\s*none',
            "collapsed rail must explicitly hide the sidebar role pill")
        # Scoped to .user-badge: .role-pill is reused in the users table and the
        # client map, which must keep rendering while the rail is collapsed.
        self.assertNotRegex(
            self.css, r'body\.sidebar-collapsed\s+\.role-pill\s*\{',
            "hiding .role-pill unscoped would also blank the table pills")

    def test_collapsed_state_is_desktop_only(self):
        # The <=1000px breakpoint stacks the sidebar full-width above the
        # content; an icon rail there would just be a full-width row of
        # unlabelled icons. So the collapsed block must be gated >=1001px.
        m = re.search(r'@media\s*\(min-width:\s*1001px\)\s*\{', self.css)
        self.assertIsNotNone(m, "collapsed rules must live in a min-width:1001px block")
        # walk to the matching close brace and assert the rail rules are inside
        start = m.end()
        depth, i = 1, start
        while i < len(self.css) and depth:
            depth += (self.css[i] == '{') - (self.css[i] == '}')
            i += 1
        block = self.css[start:i - 1]
        self.assertIn('--sidebar-w:72px', block.replace(' ', ''))
        self.assertIn('.nav-item', block)
        # mobile layout must still collapse to a single column
        self.assertRegex(self.css, r'@media\s*\(max-width:\s*1000px\)')

    def test_labels_and_chrome_hide_in_the_rail(self):
        flat = self.flat
        # group headers / badges / wordmark / lang select are display:none'd
        for target in ('.brand-chip', '.aside-tagline', '#langSelect',
                       '.nav-group>h3', '.preview-badge', '.count-badge'):
            self.assertIn('body.sidebar-collapsed' + target, flat,
                          f"{target} is not addressed by the collapsed rules")
        # nav labels are bare text nodes -> zeroed via font-size, icon restored
        self.assertIn('body.sidebar-collapsed.nav-item.nav-left{font-size:0', flat)
        m = re.search(r'body\.sidebar-collapsed\.nav-item\.nav-lefti\{([^}]*)\}', flat)
        self.assertIsNotNone(m, "collapsed rail must restore the nav icon font-size")
        icon_rule = m.group(1)
        self.assertRegex(icon_rule, r'font-size:\d+px')
        # Regression (caught in Chromium): overriding the base rule's fixed
        # `width:16px` with `width:auto` collapses the icon box onto the glyph
        # -- measured width went 16px -> 0px -- and the rail loses its
        # alignment. The collapsed rule must not touch width at all.
        self.assertNotIn('width:auto', icon_rule)
        self.assertIn('width:16px', self._rule('.nav-item .nav-left i'),
                      "base rule must keep the fixed icon box the rail relies on")

    # --- RBAC must survive the rail ----------------------------------------

    def test_rbac_gate_css_still_present(self):
        self.assertIn('body.role-viewer.requires-write{display:none!important}', self.flat)
        self.assertIn('body:not(.role-admin).requires-admin{display:none!important}', self.flat)

    def test_collapsed_css_never_sets_display_on_nav_item(self):
        """A `body.sidebar-collapsed .nav-item{display:...}` rule would fight
        the RBAC gate (same specificity + later in the sheet would win for
        anything the gate does not mark !important, and would in any case make
        the rail's visibility logic compete with authorization)."""
        offenders = []
        for sel, body in self._rules():
            if 'sidebar-collapsed' not in sel or 'display' not in body:
                continue
            for one in sel.split(','):
                if one.strip().endswith('.nav-item'):
                    offenders.append((one.strip(), body.strip()))
        self.assertEqual(offenders, [], f"collapsed CSS sets display on .nav-item: {offenders}")

    def test_gated_nav_items_keep_their_gate_classes_and_hooks(self):
        # the rail must not have rewritten the nav away from switchTab()
        for tab, gate in (('tab-provisioner', 'requires-write'),
                          ('tab-import', 'requires-write'),
                          ('tab-users', 'requires-admin'),
                          ('tab-sites', 'requires-admin'),
                          ('tab-mcp', 'requires-admin'),
                          ('tab-settings', 'requires-admin')):
            m = re.search(
                r'<button class="nav-item ([^"]*)"[^>]*onclick="switchTab\(\'' + tab + r'\'',
                self.html)
            self.assertIsNotNone(m, f"nav item for {tab} lost its switchTab onclick")
            self.assertIn(gate, m.group(1), f"{tab} nav item lost its {gate} gate")

    def test_active_tab_cue_survives_in_the_rail(self):
        active = self._rule('.nav-item.active')
        self.assertIsNotNone(active)
        self.assertIn('inset 3px 0 0 var(--primary)', active)

    # --- persistence --------------------------------------------------------

    def test_localstorage_persistence_wired(self):
        # Task 4: sidebar rail JS moved to static/js/core.js; frontend_source()
        # concatenates dashboard.html + static js/css so the assertions still hold.
        html = frontend_source()
        self.assertIn("const SIDEBAR_COLLAPSED_KEY = 'sidebarCollapsed'", html)
        self.assertIn("localStorage.setItem(SIDEBAR_COLLAPSED_KEY, collapsed ? '1' : '0')",
                      html)
        # toggle flips the class and keeps aria-expanded in sync
        self.assertIn("function applySidebarCollapsed(collapsed)", html)
        self.assertIn("document.body.classList.toggle('sidebar-collapsed', collapsed)", html)
        self.assertIn("btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true')", html)

    def test_state_restored_before_first_paint(self):
        # Restoring at DOMContentLoaded would paint the expanded sidebar and
        # then animate it shut. The restore must run in markup order BEFORE
        # the <aside> is parsed.
        restore = self.html.find("localStorage.getItem('sidebarCollapsed') === '1'")
        self.assertNotEqual(restore, -1, "no pre-paint restore of the collapsed state")
        self.assertIn("document.body.classList.add('sidebar-collapsed')",
                      self.html[restore:restore + 250])
        self.assertLess(restore, self.html.find('<aside'),
                        "collapsed state must be restored before <aside> is parsed")

    # --- tooltips -----------------------------------------------------------

    def test_tooltips_are_derived_from_the_translated_label(self):
        # syncNavTooltips()/changeLanguage() sono in static/js/i18n.js (Task 3).
        src = frontend_source()
        start = src.index('function syncNavTooltips()')
        end = src.index('function ', start + len('function syncNavTooltips()'))
        fn = src[start:end]
        # derived from the live label, never a second hardcoded copy
        self.assertIn("btn.querySelector('.nav-left')", fn)
        self.assertIn('label.textContent', fn)
        self.assertIn("btn.setAttribute('title', text)", fn)
        # only while collapsed -- expanded labels are already visible
        self.assertIn("btn.removeAttribute('title')", fn)
        # and refreshed whenever the language changes, or EN users would keep
        # seeing Italian tooltips
        cl_start = src.index('function changeLanguage(lang)')
        cl_end = src.index('function initLanguageSelector()')
        self.assertIn('syncNavTooltips()', src[cl_start:cl_end])

    # --- scrollbar ----------------------------------------------------------

    def test_scrollbar_is_token_driven_with_transparent_track(self):
        track = self._rule('::-webkit-scrollbar-track')
        self.assertIsNotNone(track)
        self.assertIn('transparent', track)
        self.assertNotIn('var(--bg)', track)
        thumb = self._rule('::-webkit-scrollbar-thumb')
        self.assertIsNotNone(thumb)
        self.assertIn('background: var(--border)', thumb)
        self.assertNotIn('--surface-3', thumb)
        hover = self._rule('::-webkit-scrollbar-thumb:hover')
        self.assertIsNotNone(hover)
        self.assertIn('var(--primary)', hover)

    def test_no_raw_colors_anywhere_in_the_scrollbar_rules(self):
        offenders = []
        for sel, body in self._rules():
            if 'scrollbar' not in sel and 'scrollbar-color' not in body:
                continue
            for decl in re.findall(r'#[0-9a-fA-F]{3,8}\b|\brgb a?\([^)]*\)', body):
                offenders.append((sel, decl))
        self.assertEqual(offenders, [],
                         f"scrollbar rules must use tokens, found raw colors: {offenders}")

    def test_scrollbar_styled_for_both_engines(self):
        # Firefox ignores ::-webkit-* entirely; without scrollbar-color the
        # restyle silently does nothing there.
        self.assertIn('scrollbar-color: var(--border) transparent', self.css)
        self.assertIn('scrollbar-width: thin', self.css)

    def test_sidebar_thumb_is_invisible_at_rest_but_tables_keep_theirs(self):
        self.assertIn('aside::-webkit-scrollbar-thumb{background:transparent',
                      self.flat, "sidebar thumb must fade out at rest")
        self.assertIn(
            'aside:hover::-webkit-scrollbar-thumb,aside:focus-within::-webkit-scrollbar-thumb'
            '{background:var(--border)}',
            self.flat, "sidebar thumb must come back on hover/focus-within")
        self.assertIn('aside{scrollbar-color:transparenttransparent}', self.flat)
        self.assertIn('aside:hover,aside:focus-within{scrollbar-color:var(--border)transparent}',
                      self.flat)
        # The rest-invisible treatment must stay scoped to `aside`: a bare
        # `::-webkit-scrollbar-thumb{background:transparent}` would make every
        # table and modal scrollbar invisible too.
        thumb = self._rule('::-webkit-scrollbar-thumb')
        self.assertNotIn('background: transparent', thumb)


class TestCaSearch(unittest.TestCase):
    """Il Config Analyzer deve avere una ricerca client-side (#caSearch)
    riapplicata dopo ogni render (caApplySearch)."""

    def test_search_input_and_filter_present(self):
        html = frontend_source()
        self.assertIn('id="caSearch"', html)
        self.assertIn("function caApplySearch", html)
        # riapplicata a ogni render
        block = html[html.index("function renderCaResults"):]
        self.assertIn("caApplySearch()", block[:200])


if __name__ == "__main__":
    unittest.main()
