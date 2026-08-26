# -*- coding: utf-8 -*-
import os, re, tempfile
_TMP = tempfile.mkdtemp(prefix="sentinelnet_uirevamp_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP
import unittest
from html.parser import HTMLParser  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP
import app_server  # noqa: E402
import routers.inventory, routers.topology, routers.catalog, routers.mac, routers.analyzer, routers.backup, routers.sites, routers.mcp
from tests.test_helpers_frontend import frontend_source  # noqa: E402


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
    "tab-categories", "tab-security", "tab-endpoint", "tab-flows",
    "tab-config", "tab-ai", "tab-provisioner", "tab-import", "tab-users",
    "tab-sites", "tab-mcp", "tab-settings",
]

# #tab-endpoint used to be four sibling tabs (#tab-mac, #tab-clientmap,
# #tab-diagnosi, #tab-endpoints). The merge replaced them with four sibling
# panes inside one tab, in this doc order (verified against
# templates/dashboard.html). A dropped </div> could re-nest one pane inside
# another exactly as the Task 14 mutation re-nested #provCiscoSection --
# these panes get the same three-way guard as the top-level tabs.
PANE_IDS_IN_DOC_ORDER = [
    "locPane-mac", "locPane-clientmap", "locPane-diagnosi", "locPane-inventory",
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
        cls.watch_ids = (set(TAB_IDS_IN_DOC_ORDER) | set(PANE_IDS_IN_DOC_ORDER)
                          | {"provFgtSection", "provCiscoSection"})
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

    def test_every_pane_opens_once_and_closes(self):
        # Pane-level equivalent of test_every_tab_body_opens_once_and_closes:
        # the four old tab bodies became four panes, not four fewer things
        # to guard.
        for pane_id in PANE_IDS_IN_DOC_ORDER:
            with self.subTest(pane=pane_id):
                self.assertEqual(self.parsed.push_counts.get(pane_id), 1,
                                  f"#{pane_id} should open exactly once")
                span = self.parsed.spans.get(pane_id)
                self.assertIsNotNone(span, f"#{pane_id} not found in rendered HTML")
                self.assertIsNotNone(
                    span["end"],
                    f"#{pane_id} <div> is never closed before end-of-document -- "
                    f"a missing </div> upstream is swallowing its close tag")

    def test_each_pane_is_internally_balanced(self):
        # Pane-level equivalent of test_each_tab_body_is_internally_balanced.
        for pane_id in PANE_IDS_IN_DOC_ORDER:
            with self.subTest(pane=pane_id):
                span = self.parsed.spans[pane_id]
                if span["end"] is None:
                    self.fail(f"#{pane_id} <div> never closes -- cannot slice "
                              f"it for an internal-balance re-check (see "
                              f"test_every_pane_opens_once_and_closes)")
                start = self._offset(span["start"])
                end = self._offset(span["end"])
                end = self.html.index(">", end) + 1  # include the closing </div>
                fragment = self.html[start:end]
                sub = _parse(fragment)
                self.assertEqual(sub.errors, [],
                                  f"#{pane_id} internal markup has mismatched tags: {sub.errors}")
                self.assertEqual(sub.stack, [],
                                  f"#{pane_id} internal markup left tag(s) open: {sub.stack}")

    def test_panes_are_siblings_never_nested_inside_tab_endpoint(self):
        # Pane-level equivalent of test_tabs_are_siblings_never_nested: no
        # pane may be an ancestor of another, and all four must fall inside
        # #tab-endpoint's own span (they're panes OF that tab, not stray
        # top-level content).
        tab = self.parsed.spans["tab-endpoint"]
        self.assertIsNotNone(tab["end"], "#tab-endpoint never closes")
        for pane_id in PANE_IDS_IN_DOC_ORDER:
            span = self.parsed.spans[pane_id]
            with self.subTest(pane=pane_id):
                self.assertGreater(span["start"], tab["start"],
                                    f"#{pane_id} opens before #tab-endpoint does")
                self.assertLess(span["end"], tab["end"],
                                 f"#{pane_id} closes after #tab-endpoint does -- "
                                 f"it isn't contained in the tab")
        for a, b in zip(PANE_IDS_IN_DOC_ORDER, PANE_IDS_IN_DOC_ORDER[1:]):
            with self.subTest(prev=a, next=b):
                end_a = self.parsed.spans[a]["end"]
                start_b = self.parsed.spans[b]["start"]
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
        # .kpi-grid was dropped with the last markup that carried it: the
        # endpoint tiles sit in #epKpis, which grids itself inline.
        for cls in (".hero-card", ".filterbar",
                    ".status", ".led-success", ".split-footer",
                    ".nav-group", ".preview-badge"):
            self.assertIn(cls, html, f"missing component class {cls}")


class TestSidebarIA(unittest.TestCase):
    def test_nav_groups_present_and_flat_strip_gone(self):
        html = _html()
        # I gruppi sono organizzati per DOMANDA a cui si risponde e le
        # intestazioni seguono il selettore di lingua: si fissano le chiavi
        # i18n, non il testo, che altrimenti fallirebbe in inglese.
        for key in ("navInvestigate", "navInventory", "navAssess",
                    "navChange", "navAdminister"):
            self.assertIn(f'data-i18n="{key}"', html,
                          f"gruppo di nav {key} assente")
        # every existing tab still reachable (tab-home is deferred to Task 3).
        # tab-mac and tab-clientmap merged into tab-endpoint (with tab-diagnosi
        # and tab-endpoints, which were never individually listed here).
        # CSP senza 'unsafe-inline': i controlli non portano piu' onclick ma
        # data-tab (nav) / data-switch-tab (altri pulsanti); il click e'
        # delegato in core.js.
        for tab in ("tab-devices", "tab-endpoint", "tab-flows",
                    "tab-map", "tab-map-interactive", "tab-categories", "tab-security",
                    "tab-config", "tab-ai", "tab-provisioner", "tab-import", "tab-groups",
                    "tab-users", "tab-sites", "tab-mcp", "tab-settings"):
            self.assertTrue(
                f'data-tab="{tab}"' in html or f'data-switch-tab="{tab}"' in html,
                f"nessun controllo apre piu' {tab}")
        # RBAC preserved on gated nav
        self.assertIn('requires-admin', html)
        self.assertIn('requires-write', html)
        # Hook di caricamento: tab-flows ha centralizzato l'hook dentro
        # switchTab() (stesso pattern gia' documentato sotto per tab-endpoint):
        # il dispatch in core.js garantisce che OGNI punto d'ingresso inizi
        # la tab, incluso il richiamo interno di observability.js. Prima
        # l'hook viveva nell'onclick del nav e bastava un secondo punto
        # d'ingresso per perderlo.
        self.assertIn("tab-flows') flowsTabShown()", frontend_source(),
                      "switchTab non dispatcha flowsTabShown() per tab-flows")
        # tab-endpoint centralised its load hook inside switchTab() itself
        # (dispatch on tabId, not one onclick-embedded hook per caller), so
        # every plain switchTab('tab-endpoint') always redraws the open pane.
        # But callers that need a SPECIFIC pane (not whatever was last open)
        # must still carry that pane's hook with them explicitly -- the same
        # multi-entry-point risk the comment above describes, just moved from
        # markup onclick attributes into JS function bodies.
        js = frontend_source()
        for fn, view in (("function diagnoseClientInTab(", "diagnosi"),
                          ("function endpointsDiagnose(", "diagnosi")):
            start = js.index(fn)
            body_end = js.index("\n}", start)
            body = js[start:body_end]
            self.assertIn("switchTab('tab-endpoint')", body,
                          f"{fn}: non apre piu' il tab endpoint")
            self.assertIn(
                f"locSwitchView('{view}')", body,
                f"{fn}: non porta esplicitamente sulla pillola {view} -- "
                f"atterrerebbe su qualunque pannello fosse aperto prima")
        # old flat tab strip is gone
        self.assertNotIn('class="tab-nav"', html)


class TestHomeTab(unittest.TestCase):
    def test_home_tab_exists_and_default(self):
        html = _html()
        # Home tab body + startup default
        self.assertIn('id="tab-home"', html)
        self.assertIn('<div id="tab-home" class="tab-content active">', html)
        # loadHome function present -- moved to static/js/home.js (blocco
        # inline estratto per la CSP senza 'unsafe-inline'): si asserts sul
        # frontend concatenato, non sul solo HTML.
        js = frontend_source()
        self.assertIn('function loadHome', js)
        # Home nav-item present and active (CSP: data-tab, click delegato)
        self.assertIn('data-tab="tab-home"', html)
        self.assertIn('data-i18n="tabHome"', html)
        # runtime-populated ids
        for eid in ('homeKpiOnline', 'homeKpiAttention',
                    'homeAttentionBody', 'homeAnomSummary'):
            self.assertIn(f'id="{eid}"', html)
        # Home wires only to REAL endpoints
        self.assertIn('/api/local-devices', js)
        self.assertIn('/api/observability/anomalies', js)
        # startGroupTriage('all') moved to static/js/devices.js -- frontend_source()
        # concatenates dashboard.html + all static js/css.
        js = frontend_source()
        self.assertIn('/api/run-triage', js)
        self.assertIn("startGroupTriage('all')", js)
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
                    'btnRunTriage', 'btnTriageSite', 'btnPingCheck',
                    'btnSubnetScan', 'btnBulkCommand', 'btnExportDevices'):
            self.assertIn(f'id="{_id}"', html)
        # bulk-action controls wired via addEventListener in static/js/devices.js
        js = frontend_source()
        for hook in ('openSubnetScanModal()', 'openBulkCommandModal()', 'exportDeviceCsv()'):
            self.assertIn(hook, js)

    def test_endpoint_contract_present(self):
        # Most of these apiFetch(...) calls now live in static/js/devices.js --
        # frontend_source() concatenates dashboard.html + all static js/css.
        html = frontend_source()
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
        # La striscia KPI ora e' un cartiglio oneline-foot, non card .kpi-grid
        for cls in ('class="hero"', 'class="hero-card"', 'class="oneline-foot"',
                    'class="filterbar"', 'class="search-wrap"',
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
        for _id in ('groupsTableBody', 'vendorTableBody', 'btnAddVendor'):
            self.assertIn(f'id="{_id}"', html)
        js = frontend_source()
        self.assertIn('addVendor()', js)
        for hook in ('renameGroup(', 'deleteGroup(', 'deleteVendor('):
            self.assertIn(hook, js)

    def test_endpoint_contract_present(self):
        # /api/groups, /api/groups/rename, /api/groups/delete, /api/vendors,
        # /api/vendors/delete all reached verbatim via apiFetch(...) in
        # static/js/devices.js -- frontend_source() concatenates dashboard.html
        # + all static js/css.
        html = frontend_source()
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
        for cls in ('class="hero"', 'class="hero-card"'):
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
        # view-toggle + reset/export hooks preserved in frontend
        for hook in ('setMapView', 'resetTopology',
                     'loadInteractiveMap', 'downloadTopology', 'exportVisioMap',
                     'exportPdfMap'):
            self.assertIn(hook, frontend_source())

    def test_endpoint_contract_present(self):
        # loadPortchannelReport/loadInteractiveMap/resetTopology moved to
        # static/js/topology.js -- frontend_source() concatenates dashboard.html
        # + all static js/css so the assertions still hold.
        html = frontend_source()
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
        for cls in ('class="hero"', 'class="hero-card"'):
            self.assertGreaterEqual(tab_html.count(cls), 2, f"{cls} expected once per tab (tab-map + tab-map-interactive)")
        self.assertGreaterEqual(tab_html.count('class="panel"'), 2)
        # view-toggle buttons carry the .chip class alongside their existing marker class
        self.assertIn('class="map-view-btn chip"', tab_html)
        # vis-network render target untouched: no restyle wrapper classes on it.
        # Gli attributi di accessibilita' (tabindex/role/aria-label) SONO ammessi:
        # il canvas altrimenti non e' raggiungibile da tastiera.
        target = tab_html[tab_html.index('<div id="networkGraphContainer"'):]
        target = target[:target.index('>') + 1]
        self.assertNotIn('class=', target)
        self.assertIn('tabindex="0"', target)

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
        # resetTopology/exportVisioMap moved to static/js/topology.js --
        # frontend_source() concatenates dashboard.html + all static js/css.
        html = frontend_source()
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
        # action hooks preserved in frontend
        for hook in ('renderCategoriesPanel', 'saveCategoryEdits', 'discardCategoryEdits',
                     'exportCategoriesCsv', 'loadCategoriesData', 'createCategory'):
            self.assertIn(hook, frontend_source())
        # RBAC gating preserved on write-gated controls
        self.assertIn('id="btnSaveCatEdits"', html)
        save_start = html.index('id="btnSaveCatEdits"')
        save_tag = html.rindex('<button', 0, save_start)
        self.assertIn('requires-write', html[save_tag:save_start])

    def test_endpoint_contract_present(self):
        # loadCategoriesData/saveCategoryEdits/createCategory/deleteCategory/
        # deleteSubcategory/confirmConflict moved to static/js/topology.js --
        # frontend_source() concatenates dashboard.html + all static js/css.
        html = frontend_source()
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
        for cls in ('class="hero"', 'class="hero-card"', 'class="filterbar"'):
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
        src = frontend_source()
        for hook in ('startThreatScan',):
            self.assertIn(hook, src)

    def test_endpoint_contract_present(self):
        # loadThreatIntel/startThreatScan/runEuvdQuery moved to
        # static/js/threat-intel.js -- frontend_source() concatenates it.
        html = frontend_source()
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
        # Bound on the next tab's own div: the endpoint group (formerly the
        # MAC Address Tracker tab) directly follows Threat Intel.
        tab_end = html.index('<div id="tab-endpoint"')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"', 'class="filterbar"', 'class="panel'):
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
        # macScanGroup was replaced by the single #locTenant select (Task 3,
        # endpoint tab merge) shared across all four panes.
        html = _html()
        for _id in ('macDeviceMenu', 'macDeviceSummary', 'macDeviceList',
                    'macScanTransport', 'btnMacScan', 'macRetentionDays',
                    'macOvDevice', 'macOvCommand', 'macOvFmt', 'macOverridesList',
                    'macSearchMac', 'macSearchVlan', 'macSearchIface', 'macSearchSwitch',
                    'macResults',
                    'kpiMacSightings', 'kpiMacUniqueMacs', 'kpiMacSwitches', 'kpiMacRetention'):
            self.assertIn(f'id="{_id}"', html)
        src = frontend_source()
        for hook in ('runMacScan', 'macSearch', 'macSearchReset', 'saveMacOverride',
                     'saveMacRetention'):
            self.assertIn(hook, src)
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
        # Tenant filter for the Client Map search used to be its own multi-select
        # (arpTenantList / arpTenantSummary, checkbox-driven via onArpTenantToggle).
        # Task 3 (endpoint tab merge) replaced it with the single #locTenant select
        # shared across all four panes. The ARP-target device multiselect this
        # test guards (arpDeviceList / arp-dev-cb) is untouched by that change.
        html = frontend_source()
        for _id in ('arpDeviceMenu', 'arpDeviceSummary', 'arpDeviceList',
                    'btnArpScan', 'arpSearchMac', 'arpSearchIp',
                    'arpFilterGateway', 'arpStats', 'arpScanSummary',
                    'arpResults', 'kpiArpBindings', 'kpiArpUniqueMacs', 'kpiArpGateways'):
            self.assertIn(f'id="{_id}"', html)
        for hook in ('runArpScan', 'arpClientSearch', 'arpSearchReset',
                     'populateArpScanDevices'):
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
        self.assertIn('toggleAllArpDevices', html)
        self.assertIn('function selectedArpDevices()', html)
        self.assertIn("querySelectorAll('#arpDeviceList .arp-dev-cb:checked')", html)

    def test_endpoint_contract_present(self):
        html = frontend_source()  # MAC tracker/Client Map JS moved to static/js/client-map.js
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
        # #tab-mac and #tab-clientmap merged into two of the four panes
        # inside #tab-endpoint (Task 1/2 of the endpoint tab merge).
        tab_start = html.index('<div id="tab-endpoint"')
        # Bound on the next tab's own div, not on a comment: the comment that
        # used to sit here was mislabelled ("Config Analyzer" above #tab-flows)
        # and Task 20 corrected it, which silently broke this slice. #tab-wlc
        # (not #tab-flows) now directly follows the merged endpoint tab.
        tab_end = html.index('<div id="tab-wlc"')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"', 'class="filterbar"', 'class="table-wrap"'):
            self.assertIn(cls, tab_html)
        # una striscia oneline-foot per pane (mac + clientmap)
        self.assertGreaterEqual(tab_html.count('class="oneline-foot"'), 2)
        self.assertGreaterEqual(tab_html.count('class="panel'), 4)
        # both panes individually still present within the merged tab
        self.assertIn('<div id="locPane-mac"', tab_html)
        self.assertIn('<div id="locPane-clientmap"', tab_html)

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
        # IDs preserved
        for _id in ('configGroupSelect', 'caPills', 'caResults',
                    'caRawRouteModal', 'caRawRouteContent'):
            self.assertIn(f'id="{_id}"', html)
        # JS handlers in frontend source
        js = frontend_source()
        for hook in ('loadConfigAnalyzer', 'caSwitchView', 'caCloseRawRouteModal'):
            self.assertIn(hook, js)
        # the five view pills keep their data-view markers
        for view in ('vlan', 'routing', 'acl', 'iface', 'validation'):
            self.assertIn(f'data-view="{view}"', html)

    def test_endpoint_contract_present(self):
        # These endpoint calls now live in static/js/config-analyzer.js (extracted
        # out of dashboard.html) -- use the combined frontend source, not the bare
        # rendered template, so the check still exercises the real wiring.
        html = frontend_source()
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
        # (config_analyzer_device); it IS called from static/js/core.js
        # (showPortConfig -> apiFetch('/api/config-analyzer/' + switchIp)) for the
        # port-config deep-link, in addition to being consumed by mcp_server.py.
        self.assertIn("apiFetch('/api/config-analyzer/' + encodeURIComponent(switchIp))", html)
        import app_server as _app_server
        self.assertTrue(hasattr(routers.analyzer, 'config_analyzer_device'))
        self.assertTrue(hasattr(routers.analyzer, 'config_analyzer_all'))
        self.assertTrue(hasattr(routers.backup, 'download_backup'))

    def test_config_tab_uses_component_classes(self):
        html = _html()
        tab_start = html.index('<div id="tab-config"')
        tab_end = html.index('<!-- TAB: AI Assistant -->')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"',
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
        html = frontend_source()
        for hook in ('onAiProfileSelectChange', 'onAiProfileEditSelectChange',
                     'resetAiModelList', 'refreshAiModels', 'saveAiSettings',
                     'deleteAiProfile', 'populateAiAttachDevices',
                     'toggleAiDeviceDropdown', 'setAllAiAttachDevices',
                     'sendAiChat'):
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
        # sendAiChat()/refreshAiModels() moved to static/js/ai.js -- frontend_source()
        # concatenates dashboard.html + all static js/css.
        html = frontend_source()
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
        # Il thread non è più un riquadro alto 480px in fondo alla pagina: è la
        # colonna destra di una chat a tutta altezza, quindi cresce con `flex:1`
        # invece che con una max-height fissa. Ciò che DEVE restare è l'id e il
        # contenitore di scorrimento su cui appendAiMessage() e
        # renderAiConfigProposal() fanno box.scrollTop = box.scrollHeight.
        self.assertIn(
            '<div id="aiChatMessages" style="flex:1 1 0; min-height:0; '
            'overflow-y:auto; padding:16px; background:var(--surface);"></div>',
            html)
        # `min-height:0` inline non è cosmetico e non va rimesso a un valore
        # fisso: con una min-height l'area messaggi non si comprime, spinge il
        # composer oltre il fondo del panel e l'overflow:hidden lo taglia —
        # la casella di testo sparisce e la chat diventa inutilizzabile.
        css = frontend_source()   # concatena anche static/css/dashboard.css
        self.assertIn('#tab-ai .ai-chat-composer', css)
        composer = css[css.index('#tab-ai .ai-chat-composer'):]
        self.assertIn('flex:0 0 auto', composer[:composer.index('}')])

    def test_device_multiselect_preserved(self):
        # populateAiAttachDevices()/getAiAttachDeviceIps() moved to
        # static/js/ai.js -- frontend_source() concatenates it.
        html = frontend_source()
        # The AI device multi-select dropdown (prior feature) keeps its ids and
        # per-item checkbox class + onchange used by getAiAttachDeviceIps().
        self.assertIn('id="aiAttachDeviceDropdown"', html)
        self.assertIn('id="aiAttachDeviceList"', html)
        self.assertIn("querySelectorAll('#aiAttachDeviceList .ai-attach-device:checked')", html)
        self.assertIn("class=\"ai-attach-device\"", html)
        self.assertIn('updateAiDeviceBtnLabel', html)

    def test_ai_tab_uses_component_classes(self):
        html = _html()
        tab_start = html.index('<div id="tab-ai"')
        tab_end = html.index('<!-- TAB: Switch da Zero (Provisioner) -->')
        tab_html = html[tab_start:tab_end]
        for cls in ('class="hero"', 'class="hero-card"',
                    'class="filterbar', 'class="panel'):
            self.assertIn(cls, tab_html)
        # due panel card in #tab-ai: profili e chat (il generatore di config
        # e' stato spostato nella scheda Provisioner)
        self.assertGreaterEqual(tab_html.count('class="panel'), 2)
        # active-profile badge reclassed to the .chip state-badge component
        self.assertIn('id="aiActiveProfileBadge" class="chip"', tab_html)

    def test_i18n_keys_both_langs(self):
        html = frontend_source()  # Task 3: i18n dict e' in static/js/i18n.js
        for key in ('aiEyebrow:', 'titleAiChat:',
                    'titleAiAssistant:', 'descAiAssistant:',
                    'msgAiNoConversations:', 'lblAiProfileActive:'):
            self.assertGreaterEqual(html.count(key), 2, f"{key} missing from a language map")

    def test_conversation_sidebar_wired(self):
        """La cronologia conversazioni: elenco a sinistra + CRUD verso
        /api/ai/conversations. Senza il contenitore la sidebar non renderizza."""
        html = _html()
        self.assertIn('id="aiConvList"', html)
        self.assertIn('id="aiChatTitle"', html)
        self.assertIn('id="btnAiNewChat"', html)
        self.assertIn('id="btnAiRenameChat"', html)
        self.assertIn('id="btnAiDeleteChat"', html)
        # La sidebar della chat NON deve essere un <aside>: la regola globale
        # `aside { position:sticky; height:calc(100vh - 40px) }` la renderebbe
        # alta quanto il viewport, sfondando la griglia della chat e spingendo
        # il composer sotto il bordo del panel, dove l'overflow lo taglia via.
        tab = html[html.index('<div id="tab-ai"'):
                   html.index('<!-- TAB: Switch da Zero (Provisioner) -->')]
        self.assertNotIn('<aside', tab)
        self.assertIn('<div class="ai-conv-sidebar">', tab)
        js = frontend_source()
        for hook in ('newAiConversation', 'renameAiConversation',
                     'deleteCurrentAiConversation'):
            self.assertIn(hook, js)
        self.assertIn("apiFetch('/api/ai/conversations')", js)
        self.assertIn('`/api/ai/conversations/${Number(id)}`', js)
        self.assertIn('`/api/ai/conversations/${Number(aiConvId)}`', js)

    def test_profile_cards_drive_the_hidden_selects(self):
        """Le card sono una vista sulle due <select>, che restano la sorgente
        di verità: se sparissero, saveAiSettings()/onAiProfileEditSelectChange()
        leggerebbero il vuoto."""
        html = _html()
        self.assertIn('id="aiProfileCards"', html)
        self.assertIn('id="aiProfileSelect"', html)
        self.assertIn('id="aiProfileEditSelect"', html)
        js = frontend_source()
        self.assertIn("editSel.value = id;", js)
        self.assertIn("activeSel.value = id;", js)


class TestProvisionerTabRestyle(unittest.TestCase):
    """Task 14 + ZTP W2: #tab-provisioner (Zero-Touch Provisioner) guard.

    The flagship form: two vendor sections toggled at runtime, and dual
    endpoint families reached through a computed base path.

    W2 restructure: the FortiGate token UI was moved out of the top-level
    `<details id="fgtTokenPanel">` accordion and into an inline section.
    That inline section was later removed entirely (it duplicated the
    dedicated Fortigate Management tab, static/js/fortigate-management.js,
    which is now the sole owner of the token/live-objects UI). Device Type
    remains a chip selector skinning the still-authoritative
    `<select id="provVendor">`. Assertions below pin the current structure;
    `fgtTokenPanel` and the inline token/objects sections are gone by design.
    """

    def _tab(self, html):
        start = html.index('<div id="tab-provisioner"')
        end = html.index('<!-- TAB 6: Importazione CSV -->')
        return html[start:end]

    def test_preserve_ids(self):
        html = _html()
        for _id in ('provFgtSection', 'provCiscoSection', 'provVendor', 'provRole',
                    'btnProvGenerate', 'btnProvDownload', 'provDeliveryMode',
                    'provSshFields', 'provSerialFields', 'provOutput',
                    'provVendorChips', 'provCiscoTokenHint'):
            self.assertIn(f'id="{_id}"', html, f"lost preserve-ID {_id}")

    def test_token_ui_removed_duplicate(self):
        """The inline FortiGate token/objects UI that used to live in
        #tab-provisioner was a duplicate of the Fortigate Management
        tab (static/js/fortigate-management.js) and has been removed. Only
        the Fortigate Management tab owns that UI now."""
        html = _html()
        tab = self._tab(html)
        self.assertNotIn('id="fgtTokenPanel"', html)
        self.assertNotIn('id="provFgtTokenSection"', tab)
        self.assertNotIn('id="provFgtObjectsSection"', tab)
        self.assertNotIn('id="fgtTokensTable"', tab)
        self.assertNotIn('id="fgtTokenValue"', tab)
        src = frontend_source()
        self.assertNotIn('function initFgtTokenPanel()', src)
        self.assertNotIn('function toggleFgtTokenReveal()', src)

    def test_vendor_select_remains_source_of_truth(self):
        html = _html()
        tab = self._tab(html)
        # provVendorIsFgt/provSyncVendorChips/provInitVendorChips: moved to
        # static/js/provisioning.js -- frontend_source() concatenates
        # dashboard.html + all static/*.js|css.
        src = frontend_source()
        # The select is hidden, NOT removed: provVendorIsFgt() still reads it.
        self.assertIn(
            '<select id="provVendor" class="visually-hidden" aria-hidden="true" tabindex="-1">',
            tab,
        )
        self.assertIn("document.getElementById('provVendor')?.value === 'fortigate'", src)
        for value in ('value="cisco"', 'value="fortigate"'):
            self.assertIn(value, tab)
        # Chips drive the select and re-fire the real change event rather than
        # duplicating the vendor wiring.
        self.assertIn("sel.value = chip.dataset.vendor", src)
        self.assertIn("sel.dispatchEvent(new Event('change'))", src)
        # ...and reflect the select's value back (two-way sync).
        self.assertIn("chip.setAttribute('aria-pressed', String(chip.dataset.vendor === sel.value))", src)
        self.assertIn('provSyncVendorChips();', src)

    def test_vendor_select_out_of_tab_order(self):
        """W2 a11y fix: the hidden select is no longer a keyboard trap. Chips
        are the sole accessible control -- the select must be pulled out of
        the accessibility tree and the tab order, and no longer carry a
        `for=` label association that would let a mouse click on the label
        focus the invisible control."""
        html = _html()
        tab = self._tab(html)
        m_sel = re.search(r'<select id="provVendor" class="visually-hidden"[^>]*>', tab)
        self.assertIsNotNone(m_sel)
        select_tag = m_sel.group(0) if m_sel else ""
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
        # provSyncVendorChips/provInitVendorChips: moved to static/js/provisioning.js.
        src = frontend_source()
        self.assertIn(
            "chip.setAttribute('aria-pressed', String(chip.dataset.vendor === sel.value))",
            src,
        )
        self.assertIn('function provSyncVendorChips()', src)
        self.assertIn('provSyncVendorChips();', src)  # called from provInitVendorChips()
        # Visible focus indicator reuses design tokens (var(--primary)), not a
        # new invented color.
        # Task 2: this selector lives in static/css/dashboard.css now.
        self.assertIn('.chip-choice:focus-visible{outline:2px solid var(--focus);outline-offset:2px}',
                      src)

    def test_endpoint_contract_present(self):
        # provCollectPayload/fgtCollectPayload/provInitToggles' fetch call
        # sites: moved to static/js/provisioning.js.
        html = frontend_source()
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
        # FortiGate token model: now owned solely by static/js/fortigate-management.js.
        self.assertIn("apiFetch('/api/fortigate/tokens')", html)
        self.assertIn("apiFetch('/api/fortigate/token'", html)

    def test_vendor_toggle_intact(self):
        # provVendorIsFgt/provInitToggles: moved to static/js/provisioning.js.
        html = frontend_source()
        # Restyling must not break which vendor section is visible.
        self.assertIn("function provVendorIsFgt()", html)
        self.assertIn("getElementById('provCiscoSection').style.display = fgt ? 'none' : ''", html)
        self.assertIn("getElementById('provFgtSection').style.display = fgt ? '' : 'none'", html)

    def test_tab_uses_component_classes(self):
        html = _html()
        tab = self._tab(html)
        # table-wrap left with the removed inline token/objects section -- that
        # UI now lives solely in #tab-fortigate (Fortigate Management tab).
        for cls in ('class="hero"', 'class="hero-card"'):
            self.assertIn(cls, tab)
        # device/params card + generate/deliver card.
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
                    'msgProvCiscoNoToken:'):
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
        # CSV upload JS moved to static/js/devices.js -- frontend_source()
        # concatenates dashboard.html + all static js/css.
        html = frontend_source()
        self.assertIn("apiFetch('/api/import-csv'", html)

    def test_upload_handler_untouched(self):
        # CSV upload JS moved to static/js/devices.js -- frontend_source()
        # concatenates dashboard.html + all static js/css.
        html = frontend_source()
        # The click handler (addEventListener, not onclick) and its reporting
        # path must survive byte-for-byte -- restyle must not touch JS here.
        self.assertIn("document.getElementById('btnUploadCsv').addEventListener('click'", html)
        self.assertIn("document.getElementById('csvFileInput')", html)
        self.assertIn('body: JSON.stringify({ csv_data: text })', html)

    def test_rbac_preserved(self):
        html = _html()
        # Precedent from Task 14 (provisioner): the tab is gated at the nav
        # entry (`nav-item requires-write` on the button that opens
        # tab-import), so the tab body itself carries no write-gate class.
        # CSP: la nav porta data-tab invece di onclick.
        self.assertIn(
            "class=\"nav-item requires-write\" data-tab=\"tab-import\"",
            html)

    def test_tab_uses_component_classes(self):
        html = _html()
        tab = self._tab(html)
        for cls in ('class="hero"', 'class="hero-card"'):
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
        # loadUsers()/createUser()/etc. moved to static/js/settings.js.
        html = frontend_source()
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
        routes = {(getattr(r, "path", ""), m) for r in _app_server.app.routes
                  for m in getattr(r, 'methods', set()) or set()}
        self.assertIn(('/api/users/groups', 'POST'), routes)
        self.assertIn(('/api/users/tabs', 'POST'), routes)
        self.assertNotIn(('/api/users/groups', 'GET'), routes)
        self.assertNotIn(('/api/users/tabs', 'GET'), routes)

    def test_admin_gated_functions_untouched(self):
        # loadUsers() and friends moved to static/js/settings.js.
        html = frontend_source()
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
            "class=\"nav-item requires-admin\" data-tab=\"tab-users\"",
            html)
        tab = self._tab(html)
        self.assertNotIn('requires-admin', tab)

    def test_tab_uses_component_classes(self):
        html = _html()
        tab = self._tab(html)
        for cls in ('class="hero"', 'class="hero-card"',
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
        # loadSites()/createSite()/etc. moved to static/js/settings.js.
        html = frontend_source()
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
        # loadSites() and friends moved to static/js/settings.js.
        html = frontend_source()
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
            "class=\"nav-item requires-admin\" data-tab=\"tab-sites\"",
            html)
        tab = self._tab(html)
        self.assertNotIn('requires-admin', tab)

    def test_tab_uses_component_classes(self):
        html = _html()
        tab = self._tab(html)
        for cls in ('class="hero"', 'class="hero-card"',
                    'class="table-wrap"'):
            self.assertIn(cls, tab)
        # sites-table panel + create-site-form panel + jump-site limitations
        # panel (jump-host-sites Task 5, nested inside the create-site panel).
        self.assertEqual(tab.count('class="panel"'), 3)
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

    Three panels: a client-config snippet (copy-to-clipboard), a per-tool
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
        # NOT '<div id="tab-settings"': the MCP client preview tab
        # (#tab-mcp-client) sits between #tab-mcp and #tab-settings, so that
        # boundary would leak its panels into this tab's slice.
        end = html.index('<div id="tab-mcp-client"')
        return html[start:end]

    def test_preserve_ids(self):
        # loadMcpTab()'s .mcp-tool-toggle template moved to static/js/settings.js.
        html = frontend_source()
        for _id in ('mcpConfigSnippet', 'mcpToolList', 'mcpSettingsStatus'):
            self.assertIn(f'id="{_id}"', html, f"lost preserve-ID {_id}")
        # class used by saveMcpSettings()'s querySelectorAll, not an id, but
        # equally load-bearing wiring that must survive the restyle.
        self.assertIn('class="mcp-tool-toggle"', html)

    def test_endpoint_contract_present(self):
        # loadMcpTab()/saveMcpSettings() moved to static/js/settings.js.
        html = frontend_source()
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
        # loadMcpTab() is invoked from core.js's switchTab dispatcher, not
        # from static markup, so use the concatenated frontend source.
        html = frontend_source()
        for hook in ('loadMcpTab()', 'copyMcpConfig()', 'saveMcpSettings()'):
            self.assertIn(hook, html)

    def test_rbac_preserved(self):
        html = _html()
        # Precedent from Task 14-17: gated at the nav entry, tab body itself
        # carries no requires-admin gate.
        # La voce di nav puo' portare attributi in mezzo (data-tabs, per i tab
        # accorpati): si fissa il gate sulla voce che apre tab-mcp, non la forma
        # esatta della stringa.
        self.assertRegex(
            html,
            r'<button class="nav-item requires-admin"[^>]*'
            r'data-tab="tab-mcp"')
        tab = self._tab(html)
        self.assertNotIn('requires-admin', tab)

    def test_tab_uses_component_classes(self):
        html = _html()
        tab = self._tab(html)
        for cls in ('class="hero"', 'class="hero-card"',
                    'class="panel"'):
            self.assertIn(cls, tab)
        # client-config panel + tool-list panel + MCP Client preview-toggle panel.
        # La Checklist Audit Firewall e Fortigate Management non sono piu' in
        # preview: i loro toggle sono stati rimossi.
        self.assertEqual(tab.count('class="panel"'), 3)

    def test_status_chip_classes_present_in_render_fn(self):
        # loadMcpTab() moved to static/js/settings.js.
        html = frontend_source()
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
        # Il confine era #tab-flow-siem, che non esiste piu' dopo la fusione
        # del tab Traffico: senza un confine valido la fetta si mangiava anche
        # Incidenti e NetSec Audit, e il conteggio dei pannelli saliva a 14.
        end = html.find('<div id="tab-incidents"', start)
        if end == -1:
            end = html.index("</main>", start)
        return html[start:end]

    def test_preserve_ids_static(self):
        html = _html()
        for _id in ("netSettingsBody", "cliBlacklistToggle", "cliBlacklistStatus",
                    "obsRestartBanner", "obsSettingsBody",
                    "appAdvRestartBanner", "appAdvBody"):
            self.assertIn(f'id="{_id}"', self._tab(html), f"lost preserve-ID {_id}")

    def test_preserve_ids_rendered_by_js(self):
        # obs_* ids are built inside renderObsSettings's template literal,
        # which now lives in static/js/observability.js -- use the
        # concatenated frontend source, not the raw served HTML.
        html = frontend_source()
        for _id in ("netHostSelect", "netSettingsNotice",
                    "obs_enabled", "obs_bind", "obs_api_poll_s", "obsSettingsError",
                    "appadv_no_browser", "appAdvError"):
            self.assertIn(f'id="{_id}"', html, f"lost preserve-ID {_id}")

    def test_preserve_interpolated_ids(self):
        # OBS_LISTENERS / renderObsSettings / saveObsSettings moved to
        # static/js/observability.js.
        html = frontend_source()
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
        # loadObsSettings/saveObsSettings (and the /api/observability/config
        # call they make) moved to static/js/observability.js.
        html = frontend_source()
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
        # saveObsSettings() moved to static/js/observability.js.
        html = frontend_source()
        for hook in ("loadAppSettings()", "saveAppSettings()",
                     "saveCliBlacklistSetting()", "saveObsSettings()",
                     "saveAppAdvSettings()"):
            self.assertIn(hook, html)

    def test_rbac_preserved(self):
        # loadAppSettings()/etc. moved to static/js/settings.js.
        html = frontend_source()
        self.assertIn(
            "class=\"nav-item requires-admin\" data-tab=\"tab-settings\"",
            html)
        # The ping-monitor, observability, application, cloud-backup and SMTP
        # panels stay admin-gated in-body (5 gates: one per admin-only
        # concern).
        self.assertEqual(self._tab(html).count("requires-admin"), 5)
        self.assertIn('class="panel requires-admin"', self._tab(html))
        # Every loader is also role-gated server-side of the render.
        self.assertIn("if (currentRole !== 'admin') return;", html)

    def test_tab_uses_component_classes(self):
        html = _html()
        tab = self._tab(html)
        for cls in ('class="hero"', 'class="hero-card"'):
            self.assertIn(cls, tab)
        # Eight one-concern cards: ui variant, network exposure, command safety,
        # ping monitor, observability, application (general), cloud backup, SMTP.
        self.assertEqual(tab.count("class=\"panel"), 8)

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
        # APP_ADV_FIELDS/renderAppAdvSettings moved to static/js/settings.js.
        html = frontend_source()
        # The general card mixes three concerns; each field declares the
        # subsection it renders under. Presentation only -- saveAppAdvSettings()
        # still posts one combined payload to /api/settings/app.
        self.assertEqual(html.count("grp: 'appAdvGrpServer'"), 5)
        self.assertEqual(html.count("grp: 'appAdvGrpRetention'"), 5)
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
        # flowsSelectAll is emitted only by renderFlowsTable(), which moved to
        # static/js/observability.js.
        html = frontend_source()
        # I controlli di finestra/metrica/tenant sono passati all'header unico
        # del tab (prefisso traf*): erano triplicati, uno per pannello.
        for _id in ('flowsTableHead', 'flowsTableBody', 'anomTableBody',
                    'trafWindow', 'trafMetric', 'trafTenantBtn',
                    'trafTenantDropdown', 'trafTenantAll', 'trafTenantList',
                    'trafAutoRefresh', 'trafLastUpdate', 'flowsObsBanner',
                    'flowsAiNote', 'flowsSourceChips', 'flowsColsBtn',
                    'flowsColsDropdown', 'anomStatus', 'anomIpFilterChip',
                    'flowDetailPanel', 'flowDetailPanelBody'):
            self.assertIn(f'id="{_id}"', html)
        for hook in ('flowsTabShown', 'loadTopTalkers', 'loadAnomalies',
                     'toggleTrafTenantDropdown', 'toggleTrafTenantAll',
                     'toggleFlowsColsDropdown', 'analyzeFlowsWithAi',
                     'clearAnomIpFilter', 'closeFlowDetailPanel'):
            self.assertIn(hook, html)
        # Ids created only by JS (never literal in the static markup).
        for _id in ('flowsSelectAll',):
            self.assertIn(f"id=\\\"{_id}\\\"", html.replace('"', '\\"'))
        # RBAC: the two AI actions stay write-gated.
        idx = html.index('id="btnAnalyzeFlowsAi"')
        tag_end = html.index('>', idx)
        self.assertIn('requires-write', html[html.rindex('<button', 0, idx):tag_end])
        self.assertIn('data-action="detail-ai-flow"', html)
        # Anomaly transitions stay write-gated.
        self.assertIn('data-action="anom-transition"', html)

    def test_source_filter_chips_and_column_toggle_survive(self):
        # FLOWS_SOURCES/renderFlowsSourceChips/renderSyslogTable moved to
        # static/js/observability.js.
        html = frontend_source()
        # Source chips (incl. the syslog view) are data-driven; the array is
        # what actually determines the chips, so assert the array itself.
        self.assertIn("const FLOWS_SOURCES = ['all', 'netflow', 'ipfix', 'sflow', 'syslog'];", html)
        self.assertIn("function renderFlowsSourceChips()", html)
        self.assertIn('data-action="set-flows-source"', html)
        # Syslog view swaps thead + tbody renderers.
        self.assertIn("if (_flowsSource === 'syslog')", html)
        # Dual-target: main table (syslog view) or the all-sources section below the flows.
        self.assertIn("function renderSyslogTable(tbodyId = 'flowsTableBody')", html)
        # Column-visibility toggle + its persistence.
        self.assertIn("const FLOW_TOGGLE_COLS = [", html)
        self.assertIn('class="flows-col-cb"', html)
        self.assertIn("localStorage.setItem('sentinelnet_flows_hidden_cols'", html)

    def test_endpoint_contract_present(self):
        # loadTopTalkers/loadAnomalies/checkObsStatusBanner (and the
        # apiFetch calls they make) moved to static/js/observability.js.
        html = frontend_source()
        for ep in ('/api/observability/top?window=',
                   '/api/observability/syslog?window=',
                   '/api/observability/anomalies?status=',
                   # La transizione va sulla rotta degli incidenti: l'id di
                   # un'anomalia e' l'id del suo incidente, e l'alias sotto
                   # /observability e' deprecato.
                   '/api/incidents/${id}/status',
                   '/api/observability/health'):
            self.assertIn(ep, html)

    def test_english_relabel(self):
        html = _html()
        tab = self._tab(html)
        # EN default in the markup...
        self.assertIn('data-i18n="titleFlows">Traffic', tab)
        self.assertNotIn('Flussi Live', tab)
        # ...EN canonical in the en map, Italian retained in the it map.
        # i18n dict e stato spostato in static/js/i18n.js (Task 3).
        src = frontend_source()
        self.assertIn("titleFlows: 'Traffic',", src)
        # Il tab non e' piu' solo i flussi: tiene Panoramica, Flussi,
        # Ricerca e Anomalie, e il titolo lo dice.
        self.assertIn("titleFlows: 'Traffico',", src)
        self.assertIn('tabFlows: \'<i class="fa-solid fa-wave-square"></i> Live Flows\',', src)
        self.assertIn('tabFlows: \'<i class="fa-solid fa-wave-square"></i> Flussi Live\',', src)

    def test_no_hardcoded_italian_left_in_tab(self):
        # openFlowDetailPanel() (the `const hlTitle = ...` line) moved to
        # static/js/observability.js -- use the concatenated frontend source
        # for the whole-document checks below.
        src = frontend_source()
        tab = self._tab(_html())
        # Strings that previously shipped without a data-i18n key.
        self.assertNotIn('>Dettaglio flusso<', src)
        self.assertNotIn('title="Chiudi"', src)
        self.assertNotIn('title="Evidenzia nella topologia"', src)
        # ...now routed through keys / the file's existing `const L` pattern.
        self.assertIn('data-i18n="titleFlowDetail"', src)
        self.assertIn('data-i18n-title="titleClose"', src)
        self.assertIn("const hlTitle = escapeHtml(L.titleHighlightTopology", src)
        # Every remaining user-visible string in the tab body carries a key.
        self.assertNotIn('Anomalie correlate', tab)

    def test_component_classes_applied(self):
        tab = self._tab(_html())
        self.assertIn('<div class="hero" style="grid-template-columns:1fr;', tab)
        # Il tab ora tiene anche le viste Ricerca e Anomalie: ai pannelli di
        # prima (top talker, ripartizione protocolli, tabella flussi) si
        # aggiungono istogramma, query, faccette e registro della Ricerca.
        # Il pannello "Dettaglio Flussi" inline non c'e' piu': era la terza
        # copia della stessa ripartizione per protocollo.
        self.assertEqual(tab.count('<div class="panel"'), 8)
        self.assertEqual(tab.count('<div class="panel" style="margin-bottom:18px;"'), 5)
        # All tables wrapped: flows, syslog-in-all-sources, protocol breakdown,
        # top talkers, correlated anomalies.
        self.assertEqual(tab.count('class="table-wrap"'), 5)
        self.assertIn('class="filterbar"', tab)
        self.assertIn('id="anomIpFilterChip" class="chip"', tab)
        # Severity/status badges use the component status/chip classes.
        # sevBadge/statusBadge live inside loadAnomalies(), which moved to
        # static/js/observability.js.
        html = frontend_source()
        # Severity buckets mirror sevColor() in the syslog table: 0-3 bad,
        # 4 warn, 5+ neutral .chip. 5+ is "medio" (_SEVERITY_KIND in
        # observability/correlator.py), so it must NOT render as .status ok --
        # a medium anomaly badged green would read as healthy.
        self.assertIn('s <= 3 ? `<span class="status bad">${s}</span>`', html)
        self.assertIn('s <= 4 ? `<span class="status warn">${s}</span>`', html)
        self.assertIn(': `<span class="chip">${s}</span>`', html)
        self.assertNotIn('<span class="status ok">${s}</span>', html)
        self.assertIn('`<span class="status ok">${escapeHtml(st)}</span>`', html)
        # Flussi Live non e' piu' in preview: la voce di menu non porta badge.
        nav = html[html.index('data-tab="tab-flows"'):]
        self.assertNotIn('<span class="preview-badge">preview</span>', nav[:400])

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
        # jumpToAnomaliesForFlow() moved to static/js/observability.js.
        html = frontend_source()
        self.assertIn('id="anomSectionTitle"', html)
        self.assertIn("document.getElementById('anomSectionTitle')?.scrollIntoView(", html)
        self.assertNotIn("querySelector('#tab-flows h4')", html)

    def test_clientmap_tenant_filter_drives_grouped_and_rows_from_one_path(self):
        """Task 20 brief lists a 'known bug': the Client Map tenant filter is
        said to update the grouped results but not the row details.

        IT DOES NOT REPRODUCE -- the structure makes it impossible, and this
        test pins that structure so a future refactor cannot reintroduce it.

        Task 3 (endpoint tab merge) replaced the tenant checkbox multiselect
        with the single #locTenant select shared by all four panes: changing
        it runs locTenantChanged() -> LOC_LOADERS[_locView]() -> (on the
        Client Map pane) loadClientMapTab() -> populateArpGatewayFilter();
        arpClientSearch();

          arpClientSearch() -> for the selected tenant, ONE server-filtered GET
                             /api/arp/client-map?...&tenant=<t>, collected into a
                             single `byTenant` map keyed by tenant
                             -> renderArpResults(tenants, byTenant)
                             -> updateArpKpisFromResults(tenants, byTenant)
          renderArpResults() -> derives BOTH the per-tenant table headers and the
                                detail rows (rowHtml) from the SAME byTenant map,
                                in the SAME `box.innerHTML =` write.

        There is exactly one Client Map results container (#arpResults) and no
        separate row-details element, so grouping and rows cannot diverge.

        LIMIT: no test here executes JS, so this asserts the *source wiring*,
        not runtime behaviour. It proves the single-render-path property that
        makes the reported bug unrepresentable; it cannot prove the rendered
        DOM is correct. Runtime confirmation is the manual gate's job.
        """
        html = frontend_source()  # tenant + ARP client-map logic lives in client-map.js
        # One filter-application path: changing the tenant reconciles the
        # gateway list and then re-runs the single search.
        self.assertIn('function locTenantChanged()', html)
        changed = html[html.index('function locTenantChanged()'):
                        html.index('function loadMacTracker()')]
        self.assertIn('LOC_LOADERS[_locView]()', changed)
        loader = html[html.index('function loadClientMapTab()'):
                       html.index('function arpFilteredDevices()')]
        self.assertIn('populateArpGatewayFilter();', loader)
        self.assertIn('arpClientSearch();', loader)
        # The tenant is applied SERVER-side, once, into ONE byTenant map that
        # both the renderer and the KPI calc consume.
        search = html[html.index('async function arpClientSearch()'):
                      html.index('function arpSearchReset()')]
        self.assertIn("params.set('tenant', t)", search)
        self.assertEqual(search.count("apiFetch('/api/arp/client-map?"), 1)
        self.assertEqual(search.count('renderArpResults('), 1)
        self.assertIn('renderArpResults(tenants, byTenant)', search)
        self.assertIn('updateArpKpisFromResults(tenants, byTenant)', search)
        # The renderer derives grouping (per-tenant sections) AND rows from the
        # same `byTenant` argument.
        render = html[html.index('function renderArpResults(tenants, byTenant)'):
                      html.index('function renderMacResults(rows)')]
        self.assertIn('tenants.map(t => {', render)          # per-tenant grouping
        self.assertIn('const rows = byTenant[t] || [];', render)  # rows, same source
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
        qm = re.match(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', sub[i:])
        assert m or qm, f"expected an object key at offset {i}: {sub[i:i+40]!r}"
        if m:
            key = m.group(0)
            i += m.end()
        elif qm:
            key = qm.group(1) if qm.group(1) is not None else (qm.group(2) or "")
            i += qm.end()
        else:
            key = ""
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
        # updateTelnetWarn/updateTransportsSummary/setTransportsForm moved to
        # static/js/devices.js -- frontend_source() concatenates dashboard.html
        # + all static js/css.
        cls.js = frontend_source()

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
        css_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "static", "css", "dashboard.css")
        css = open(css_path, encoding="utf-8").read()
        m = re.search(
            r'\.form-group\s+input([^,{]*),\s*\.form-group\s+select\s*\{([^}]*)\}',
            css)
        self.assertIsNotNone(m, "could not find the .form-group input/select CSS rule")
        selector_suffix, body = m.group(1), m.group(2)
        self.assertIn('[type="checkbox"]', selector_suffix)
        self.assertIn('[type="radio"]', selector_suffix)
        self.assertIn('width: 100%', body)
        self.assertIn('padding: 8px 10px 8px 30px', body)

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
                      self.js)
        self.assertIn("function updateTelnetWarn()", self.js)
        self.assertIn("document.getElementById('trTelnetWarn').style.display", self.js)

    def test_summary_updates_on_checkbox_and_port_change(self):
        self.assertIn("function updateTransportsSummary()", self.js)
        # wired for every protocol's checkbox (change) and port (input)
        self.assertIn(
            "document.getElementById('tr' + _trCap(p) + 'Enabled').addEventListener('change', updateTransportsSummary)",
            self.js)
        self.assertIn(
            "document.getElementById('tr' + _trCap(p) + 'Port').addEventListener('input', updateTransportsSummary)",
            self.js)
        # setTransportsForm() must refresh the summary after populating the form
        start = self.js.index('function setTransportsForm(')
        end = self.js.index('function ', start + len('function setTransportsForm('))
        set_form = self.js[start:end]
        self.assertIn('updateTransportsSummary()', set_form)

    def test_auto_expand_on_non_default_transports(self):
        # setTransportsForm() must open <details> when the device's transports
        # deviate from the SSH:22-only default -- never hide non-default state.
        start = self.js.index('function setTransportsForm(')
        end = self.js.index('function ', start + len('function setTransportsForm('))
        set_form = self.js[start:end]
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
        css_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "static", "css", "dashboard.css")
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
        self.assertIn("toggleSidebar", frontend_source())
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
        m_btn = re.search(r'<button[^>]*id="sidebarToggle"[^>]*>', self.html)
        self.assertIsNotNone(m_btn)
        tag = m_btn.group(0) if m_btn else ""
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
        self.assertNotIn('318px', gtc.group(1))
        expanded = re.search(r'--sidebar-w:\s*(\d+)px', body)
        self.assertIsNotNone(expanded, "body must define the expanded --sidebar-w")
        self.assertEqual(int(expanded.group(1)), 318)
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
        self.assertIn('--sidebar-w:62px', block.replace(' ', ''))
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
        rule_val = self._rule('.nav-item .nav-left i')
        self.assertIsNotNone(rule_val)
        if rule_val:
            self.assertIn('width:16px', rule_val,
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
            # Il gate RBAC vive sulla voce di nav che apre il tab: direttamente
            # (data-tab, click delegato in core.js dalla CSP in poi) oppure,
            # per i tab accorpati, sulla voce del gruppo che lo dichiara in
            # data-tabs. I sotto-tab non portano gate: stanno gia' dentro una
            # regione gated (stessa regola di TestMcpTabRestyle, "il corpo del
            # tab non porta requires-admin").
            direct = re.search(
                r'<button class="nav-item([^"]*)"[^>]*data-tab="'
                + tab + r'"', self.html)
            grouped = re.search(
                r'<button class="nav-item([^"]*)"[^>]*data-tabs="[^"]*\b'
                + tab + r'\b', self.html)
            m = direct or grouped
            self.assertIsNotNone(
                m, f"nessuna voce di nav apre {tab} (ne' diretta ne' via data-tabs)")
            self.assertIn(gate, m.group(1), f"{tab} ha perso il gate {gate}")

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
        # the <aside> is parsed. Lo script ora vive in un file esterno
        # (CSP senza 'unsafe-inline'): la posizione del tag non cambia.
        tag = self.html.find('src="/static/js/boot-sidebar.js"')
        self.assertNotEqual(tag, -1, "no pre-paint restore of the collapsed state")
        self.assertLess(tag, self.html.find('<aside'),
                        "collapsed state must be restored before <aside> is parsed")
        with open(os.path.join("static", "js", "boot-sidebar.js"),
                  encoding="utf-8") as f:
            boot = f.read()
        self.assertIn("localStorage.getItem('sidebarCollapsed') === '1'", boot)
        self.assertIn("document.body.classList.add('sidebar-collapsed')", boot)

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
        self.assertIsNotNone(thumb)
        if thumb:
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


class TestCaRenderedListIndex(unittest.TestCase):
    """``data-ca-idx`` indicizza la lista RENDERIZZATA, non ``caData``.

    Bug reale: le viste VLAN/Routing/ACL/Interfacce filtrano via firewall e
    server, ma ``caOnToggle``/``caApplyFocus`` risolvevano il device con
    ``caData[idx]``. Con un FortiGate o un server prima in elenco, l'indice
    puntava a un altro apparato: la mappa route di uno switch disegnava le
    rotte del device precedente, e il deep-link "Config porta" apriva la
    scheda sbagliata.
    """

    def _source(self):
        return frontend_source()

    def test_the_rendered_list_is_captured_for_index_lookups(self):
        js = self._source()
        self.assertIn("caList = list;", js)

    def test_no_lookup_resolves_an_index_against_the_full_dataset(self):
        js = self._source()
        # L'indice viene dalla lista filtrata: cercarlo in caData e' il bug.
        self.assertNotIn("caData[idx]", js)

    def test_route_map_defines_its_own_selected_colours(self):
        """Senza 'highlight' vis.js seleziona con sfondo #D2E5FF quasi bianco,
        e l'etichetta bianca del nodo diventa illeggibile."""
        js = self._source()
        block = js[js.index("function caBuildRouteMap"):]
        block = block[:block.index("function caRenderAcls")]
        # Il selezionato tiene una superficie del sistema invece del default di
        # vis.js: cosi' il contrasto con l'etichetta regge in entrambe le rese.
        self.assertIn("highlight: { background: cssVar('--surface-3'", block)
        self.assertIn("highlight: { background: cssVar('--surface-2'", block)

    def test_toggle_and_focus_read_the_rendered_list(self):
        js = self._source()
        toggle = js[js.index("function caOnToggle"):]
        self.assertIn("caList[idx]", toggle[:400])
        focus = js[js.index("function caApplyFocus"):]
        self.assertIn("caList.findIndex", focus[:900])


class TestCaTriageButton(unittest.TestCase):
    """Triage per-apparato dalla scheda del Config Analyzer.

    Riusa l'endpoint e il controllo dell'inventario: la stessa azione non deve
    avere due bottoni diversi da imparare. Dopo il triage il backup su disco e'
    cambiato, quindi i dati a schermo sono vecchi e vanno ricaricati.
    """

    def _js(self):
        return frontend_source()

    def test_it_delegates_to_the_inventory_triage_and_reloads(self):
        js = self._js()
        fn = js[js.index("async function caTriageDevice"):]
        fn = fn[:fn.index("function destroyCaNetworks")]
        self.assertIn("triageSingleDevice(ip, btnEl)", fn)
        # Senza il refetch il bottone sembrerebbe non fare niente.
        self.assertIn("fetchConfigAnalyzer()", fn)
        self.assertIn("data-ca-ip", fn)

    def test_the_click_does_not_toggle_the_accordion(self):
        # Il bottone sta dentro <summary>: senza preventDefault il click
        # aprirebbe e chiuderebbe la scheda mentre parte il triage.
        js = self._js()
        fn = js[js.index("async function caTriageDevice"):]
        self.assertIn("ev.preventDefault()", fn[:400])
        self.assertIn("ev.stopPropagation()", fn[:400])

    def test_every_device_card_carries_the_button_and_its_ip(self):
        js = self._js()
        # Un data-ca-ip per ogni <details> di apparato: accordion per-vista,
        # envelope firewall/server, e le due schede di validazione.
        self.assertEqual(4, js.count('data-ca-ip="${escapeHtml(dev.ip)}"'))
        # Solo le interpolazioni: la definizione della funzione non e' un uso.
        self.assertEqual(4, js.count("${caTriageButton(dev, L)}"))

    def test_the_button_matches_the_inventory_control(self):
        js = self._js()
        btn = js[js.index("function caTriageButton"):]
        btn = btn[:btn.index("async function caTriageDevice")]
        self.assertIn("fa-bolt-lightning", btn)
        self.assertIn("var(--warning)", btn)
        self.assertIn("titleCaTriage", btn)

    def test_the_button_is_hidden_from_viewers(self):
        # Il triage e' operator-only lato API: 'requires-write' e' il gancio
        # gia' esistente (body.role-viewer lo nasconde in dashboard.css).
        js = self._js()
        btn = js[js.index("function caTriageButton"):]
        btn = btn[:btn.index("async function caTriageDevice")]
        self.assertIn("requires-write", btn)
        self.assertIn("body.role-viewer .requires-write", js)

    def test_the_age_of_the_data_sits_next_to_the_button(self):
        # E' l'eta' del dato che rende il bottone una decisione.
        js = self._js()
        btn = js[js.index("function caTriageButton"):]
        btn = btn[:btn.index("async function caTriageDevice")]
        self.assertIn("backupAgeLabel(dev.backup_ts)", btn)


class TestBackupAgeLabelShared(unittest.TestCase):
    """Una sola formula per l'eta' del backup, in core.js.

    La mappa Port-Channel e il Config Analyzer mostrano lo stesso fatto: due
    copie divergerebbero, ed e' gia' successo — quella locale di topology.js
    diceva "fa" anche in inglese.
    """

    def test_the_helper_lives_in_core_and_is_language_aware(self):
        js = frontend_source()
        fn = js[js.index("function backupAgeLabel"):]
        fn = fn[:fn.index("// --- RUOLI / PRIVILEGI ---")]
        self.assertIn("ago", fn)
        self.assertIn("fa`", fn)
        # Oltre una settimana il dato non descrive piu' la rete di adesso.
        self.assertIn("var(--warning)", fn)

    def test_both_call_sites_use_it_and_no_copy_survives(self):
        # assertTrue e non assertIn: su un fallimento assertIn stamperebbe
        # l'intero sorgente frontend concatenato (oltre 1 MB).
        js = frontend_source()
        self.assertTrue("backupAgeLabel(ts)" in js,
                        "topology.js non delega a backupAgeLabel")
        self.assertTrue("backupAgeLabel(dev.backup_ts)" in js,
                        "config-analyzer.js non usa backupAgeLabel")
        # La formula compare una volta sola.
        self.assertEqual(1, js.count("Math.round(h * 60)"))


class TestRedundancyUi(unittest.TestCase):
    def test_redundancy_ui_uses_existing_payload_and_never_creates_vip_node(self):
        source = frontend_source()
        # Il badge arriva su n.redundancy insieme al resto del nodo mappa: nessuna
        # chiamata dedicata per disegnarlo, nessun nodo sintetico per il VIP.
        self.assertIn("function nodeStack", source)
        self.assertIn("r.type === 'stack'", source)
        self.assertIn("/api/redundancy/groups", source)
        self.assertNotIn("vip-node", source)

    def test_stack_is_rendered_on_both_maps_and_device_table(self):
        source = frontend_source()
        # Etichetta costruita dai dati: "N × <vendor> <modello> in STACK".
        self.assertIn("in STACK", source)
        self.assertIn("function stackLine", source)
        # Fascia STACK nella card SVG della mappa classica.
        self.assertIn("STACK ×", source)
        # Riga espandibile con le unità nella tab Dispositivi.
        self.assertIn("function toggleStackRow", source)
        self.assertIn("stack-members", source)

    def test_topology_ui_has_one_ha_heartbeat_style(self):
        source = frontend_source()
        self.assertIn("redundancy_heartbeat", source)
        self.assertIn("dashes: true", source)

    def test_redundancy_tab_renders_member_serials_and_switch_stack_details(self):
        source = frontend_source()
        self.assertIn("function renderRedundancyCard", source)
        self.assertIn("m.serial", source)
        self.assertIn("Switch #", source)
        self.assertIn("fa-barcode", source)

    def test_the_diagnosis_report_is_rendered_in_exactly_one_place(self):
        # Viveva in una modale della Client Map. Due copie dello stesso referto
        # sarebbero due copie da tenere allineate: il pulsante di riga porta
        # alla tab, la modale non esiste piu'.
        source = frontend_source()
        self.assertIn('id="locPane-diagnosi"', source)
        self.assertIn("function renderDiagnosi", source)
        self.assertIn("diagnoseClientInTab(", source)
        self.assertNotIn("closeDiagnosisModal", source)
        self.assertNotIn("clientDiagnosisModal", source)

    def test_the_new_sections_reach_the_report(self):
        source = frontend_source()
        # Cronologia e catena trunk: le due sezioni nuove del referto.
        self.assertIn("function _diagTrunk", source)
        self.assertIn("chain_known", source)
        self.assertIn("fa-clock-rotate-left", source)
        # Freschezza: dice se il referto descrive la rete di adesso.
        self.assertIn("function _diagFreshness", source)

    def test_an_l2_only_position_explains_what_is_missing(self):
        # Senza ARP la posizione fisica c'e' lo stesso: se non si dice perche'
        # IP e gateway mancano, si legge come un guasto invece che come un
        # limite di visibilita'.
        source = frontend_source()
        self.assertIn("p.l2_only", source)
        self.assertIn("binding_reason", source)

    def test_a_multi_tenant_address_lets_the_user_choose(self):
        # Lo stesso indirizzo esiste in piu' sedi: sceglierne uno in silenzio
        # diagnostica la rete sbagliata senza dirlo.
        source = frontend_source()
        self.assertIn("function _diagTenantChoice", source)
        self.assertIn("tenants_available", source)
        self.assertIn("function diagnosiPickTenant", source)
        self.assertIn("body.tenant = _diagTenant", source)

    def test_port_bounce_requires_typing_the_port_name(self):
        # Una conferma che si puo' dare col mouse senza leggere non e' una
        # conferma: la porta che si sta per staccare va digitata.
        source = frontend_source()
        self.assertIn("/api/diagnose/port-bounce", source)
        self.assertIn("diagBounceConfirm", source)
        self.assertIn("typed.toLowerCase() !== String(_diagSwitch.port).toLowerCase()", source)

    def test_client_diagnosis_endpoints_are_reachable_from_the_ui(self):
        # Entrambe le rotte esistevano ma nessuna interfaccia le chiamava:
        # erano diagnosi raggiungibili solo via curl. Se questo test cade,
        # il pulsante è stato tolto e la rotta è di nuovo orfana.
        source = frontend_source()
        # FortiGate: pill nel pane Traffico + voce del registro FGT_DATASETS.
        self.assertIn('data-fgt-pill="clientDiagnosis"', source)
        self.assertIn("/diagnose-client`", source)
        self.assertIn("loadFgtDataset('clientDiagnosis')", source)
        # WLC: card nel referto della Client Map, lanciata a mano.
        self.assertIn("/api/wlc/${encodeURIComponent(ip)}/diagnose-client/", source)
        self.assertIn("function diagnoseWifi", source)
        self.assertIn('data-action="diagnose-wifi"', source)

    def test_query_views_do_not_fire_with_an_empty_form(self):
        # Aprire la pill carica la vista: senza il campo obbligatorio partiva
        # una richiesta con la domanda vuota, e il firewall rispondeva a
        # un'altra domanda.
        source = frontend_source()
        self.assertIn("if (spec.requires && !_fgtVal(spec.requires))", source)
        self.assertIn("requires: 'fgtDiagClient'", source)
        self.assertIn("requires: 'fgtLookupSrc'", source)


class TestIdentitiesActionsWired(unittest.TestCase):
    def test_identity_action_listener_binds_an_id_that_exists(self):
        # Edit/Delete/Assign in the "Identita' del Tenant" table all go through a
        # single delegated listener. It was bound to '#identitiesList', an id
        # never present in the template: optional chaining swallowed the null and
        # the buttons stayed mute.
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base, "static", "js", "core.js"), encoding="utf-8") as f:
            js = f.read()
        m = re.search(
            r"getElementById\('([A-Za-z0-9_-]+)'\)\??\.addEventListener\("
            r"(?:(?!getElementById).)*?edit-identity",
            js, re.S)
        self.assertIsNotNone(m, "identities delegated listener not found")
        self.assertIn('id="%s"' % m.group(1), _html())


class TestGlobalsAreNotReadOffWindow(unittest.TestCase):
    """core.js declares its globals with 'let': in a classic script those land
    in the global lexical scope, NOT as window properties. Reading them as
    window.globalDevices always returns undefined and the '|| []' fallback hides
    the failure — that was the empty device list in the 'Assegna identita''
    modal. Writing them onto window instead creates a second variable the normal
    readers never see."""

    def test_no_module_reads_or_writes_core_globals_through_window(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        js_dir = os.path.join(base, "static", "js")
        with open(os.path.join(js_dir, "core.js"), encoding="utf-8") as f:
            core = f.read()
        lexical = set(re.findall(r"^(?:let|const)\s+(\w+)", core, re.M))
        offenders = []
        for name in sorted(os.listdir(js_dir)):
            if not name.endswith(".js"):
                continue
            with open(os.path.join(js_dir, name), encoding="utf-8") as f:
                src = f.read()
            # Comments mention the identifiers for explanatory purposes.
            src = re.sub(r"//[^\n]*", "", src)
            for var in re.findall(r"window\.(\w+)", src):
                if var in lexical:
                    offenders.append("%s: window.%s" % (name, var))
        self.assertEqual(offenders, [], "core.js globals used via window: %s" % offenders)


class TestDelegatedListenersBindRealIds(unittest.TestCase):
    """A delegated listener bound with getElementById('x')?. to an id that does
    not exist raises nothing: optional chaining swallows the null and the buttons
    stay mute. Four modules were in that state after the frontend was split into
    modules. This checks the delegated containers: if the id disappears from the
    template, the test fails instead of the UI."""

    CONTAINERS = {
        "core.js": "identitiesTableBody",
        "site-agent.js": "agentControlBody",
        "fortigate-management.js": "fgtMgrTableBody",
        "audit_checklist.js": "auditSectionAccordion",
    }

    def test_containers_exist_in_template(self):
        html = _html()
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for mod, container in self.CONTAINERS.items():
            with self.subTest(module=mod):
                with open(os.path.join(base, "static", "js", mod), encoding="utf-8") as f:
                    js = f.read()
                self.assertIn("getElementById('%s')" % container, js)
                self.assertIn('id="%s"' % container, html)

    def test_audit_checklist_module_is_loaded_with_its_tab(self):
        # The Firewall Audit Checklist is a sub-tab of NetSec Audit: without this
        # entry the module was never injected and the sub-tab was inert
        # (loadAuditChecklistTab undefined).
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base, "static", "js", "core.js"), encoding="utf-8") as f:
            core = f.read()
        m = re.search(r"'tab-netsec-audit':\s*\[([^\]]*)\]", core)
        self.assertIsNotNone(m, "LAZY_TAB_SCRIPTS entry for tab-netsec-audit not found")
        self.assertIn("/static/js/audit_checklist.js", m.group(1))

    def test_audit_checklist_form_controls_are_wired(self):
        # The two forms and the workspace buttons were missing markup: the
        # template lost them while the module kept looking for them.
        html = _html()
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base, "static", "js", "audit_checklist.js"), encoding="utf-8") as f:
            js = f.read()
        for el in ("formNewAudit", "btnCancelNewAudit", "formTemplateItem",
                   "btnCancelTemplateItem", "btnViewAuditReport",
                   "btnCloseAuditWorkspace", "auditWorkspace", "newAuditModal",
                   "templateItemModal"):
            with self.subTest(element=el):
                self.assertIn('id="%s"' % el, html)
        for el in ("formNewAudit", "btnCancelNewAudit", "formTemplateItem",
                   "btnCancelTemplateItem", "btnViewAuditReport",
                   "btnCloseAuditWorkspace"):
            with self.subTest(listener=el):
                self.assertIn("getElementById('%s')" % el, js)


if __name__ == "__main__":
    unittest.main()
