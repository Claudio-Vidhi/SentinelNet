# -*- coding: utf-8 -*-
import os, tempfile
_TMP = tempfile.mkdtemp(prefix="sentinelnet_uirevamp_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP
import unittest
from fastapi.testclient import TestClient  # noqa: E402
import data_config  # noqa: E402
data_config.DATA_DIR = _TMP
import app_server  # noqa: E402


def _html():
    return TestClient(app_server.app).get("/").text


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


if __name__ == "__main__":
    unittest.main()
