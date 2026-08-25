# -*- coding: utf-8 -*-
"""Vista mappa "A livelli": piani dedotti dalla topologia e modificabili a mano."""

import os
import shutil
import subprocess
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestLayeredMapView(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = open(os.path.join(_REPO_ROOT, "static", "js", "topology.js"),
                       encoding="utf-8").read()
        cls.html = open(os.path.join(_REPO_ROOT, "templates", "dashboard.html"),
                        encoding="utf-8").read()

    def test_view_button_and_reset_exist_in_template(self):
        # Un listener legato a un id assente resta muto: entrambi gli id devono
        # esistere nel template.
        for element_id in ("mapViewLayeredBtn", "layeredResetBtn", "layeredResetWrap"):
            self.assertIn(f'id="{element_id}"', self.html)
            self.assertIn(f"getElementById('{element_id}')", self.src)

    def test_no_inline_handlers_added(self):
        head = self.html[self.html.index('id="mapViewLayeredBtn"') - 200:
                         self.html.index('id="layeredResetBtn"') + 400]
        self.assertNotIn("onclick=", head)

    def test_map_is_empty_until_a_tenant_is_chosen(self):
        # Aprire la tab disegnava d'ufficio TUTTI i tenant: il selettore parte
        # su un segnaposto senza valore e il renderer esce subito.
        select = self.html[self.html.index('id="interactiveGroupSelect"'):]
        select = select[:select.index("</select>")]
        self.assertIn('<option value="" data-i18n="optSelectSite"', select)
        self.assertLess(select.index('value=""'), select.index('value="all"'))
        self.assertIn("if (!selectedGroup) { showMapPlaceholder(); return; }", self.src)
        # ...e la tendina non torna su "all" quando viene ripopolata.
        core = open(os.path.join(_REPO_ROOT, "static", "js", "core.js"),
                    encoding="utf-8").read()
        block = core[core.index("const interSelect = document.getElementById('interactiveGroupSelect')"):]
        block = block[:block.index("\n        }")]
        self.assertNotIn("interSelect.value = 'all'", block)

    def test_long_lists_scroll_inside_their_section(self):
        # Con 14 vicini le sezioni sotto finivano fuori vista: ogni elenco
        # lungo scorre da solo e i titoli restano appesi in alto.
        css = open(os.path.join(_REPO_ROOT, "static", "css", "dashboard.css"),
                   encoding="utf-8").read()
        self.assertIn(".drawer-list-scroll", css)
        self.assertIn('id="drawerNeighborList" class="drawer-list drawer-list-scroll"', self.html)
        self.assertIn('id="drawerPortChannelList" class="drawer-list drawer-list-scroll"', self.html)
        title = css[css.index(".drawer-section-title {"):]
        self.assertIn("position: sticky", title[:title.index("}")])

    def test_portchannels_and_vlans_are_fetched_when_missing(self):
        # Le due sezioni dicevano "nessuno" solo perche' i dati non erano mai
        # stati chiesti: il report aggregati e l'analisi della config.
        self.assertIn("'/api/portchannels?group='", self.src)
        self.assertIn("'/api/config-analyzer/'", self.src)
        # La risposta di un nodo non deve finire nel pannello di un altro.
        self.assertIn("token === drawerFetchToken && currentSelectedNodeId === nodeId", self.src)

    def test_map_and_panel_are_reachable_from_the_keyboard(self):
        # Vis.js disegna su canvas: senza questi appigli un apparato si sceglie
        # solo col mouse e il pannello resta irraggiungibile.
        # assertTrue e non assertIn: su un fallimento assertIn stamperebbe
        # l'intero sorgente del modulo.
        self.assertIn('id="networkGraphContainer" tabindex="0"', self.html)
        self.assertTrue("'ArrowRight'" in self.src, "nessuna navigazione a frecce sulla mappa")
        self.assertTrue("ev.key !== 'Escape'" in self.src, "Esc non chiude il pannello")
        self.assertIn('role="dialog"', self.html)
        self.assertIn('id="drawerNodeHostname" class="drawer-title" tabindex="-1"', self.html)
        # Gli elenchi che scorrono devono poter ricevere il fuoco.
        for element_id in ("drawerNeighborList", "drawerPortChannelList"):
            block = self.html[self.html.index(f'id="{element_id}"'):]
            block = block[:block.index(">")]
            self.assertIn('tabindex="0"', block)

    def test_group_and_tier_changes_do_not_refetch_the_map(self):
        # Aprire un gruppo e' una scelta di disegno, non un dato nuovo: prima
        # ogni click rifaceva due chiamate al backend.
        self.assertTrue("function redrawInteractiveMap()" in self.src)
        for fn in ("toggleLayeredGroup", "collapseAllLayeredGroups", "resetLayeredLevels"):
            block = self.src[self.src.index(f"function {fn}("):]
            block = block[:block.index("\n    }")]
            self.assertIn("redrawInteractiveMap()", block, fn)
            self.assertNotIn("loadInteractiveMap()", block, fn)

    def test_map_area_follows_the_window_height(self):
        # 600px fissi lasciavano le ultime sezioni del pannello fuori dal
        # riquadro: l'unico modo di vederle era rimpicciolire la pagina.
        css = open(os.path.join(_REPO_ROOT, "static", "css", "dashboard.css"),
                   encoding="utf-8").read()
        block = css[css.index("#networkGraphContainer {"):]
        block = block[:block.index("}")]
        self.assertIn("calc(100vh", block)
        self.assertIn("min-height", block)
        # Il ridimensionamento manuale resta.
        self.assertIn("resize: vertical", block)

    def test_kpi_values_do_not_break_mid_word(self):
        # break-all spezzava "AIR-AP2802I-E-K9" e "1 min ago" a meta' parola.
        css = open(os.path.join(_REPO_ROOT, "static", "css", "dashboard.css"),
                   encoding="utf-8").read()
        block = css[css.index(".drawer-kpi strong {"):]
        block = block[:block.index("}")]
        self.assertNotIn("word-break: break-all", block)
        self.assertIn("overflow-wrap: anywhere", block)

    @unittest.skipUnless(shutil.which("node"), "node non disponibile")
    def test_vlans_of_a_leaf_come_from_the_switch_port(self):
        # Un access point non ha una config: le sue VLAN stanno sulla porta
        # dello switch che lo alimenta.
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_drawer_vlans.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)

    def test_portchannel_report_waits_for_a_tenant(self):
        # Il report Port-Channel apriva il tab elencando TUTTI i tenant:
        # nessuna sede preselezionata, nessuna chiamata al backend.
        select = self.html[self.html.index('id="topologyGroupSelect"'):]
        select = select[:select.index("</select>")]
        self.assertIn('<option value="" data-i18n="optSelectSite"', select)
        self.assertLess(select.index('value=""'), select.index('value="all"'))
        block = self.src[self.src.index("async function loadPortchannelReport("):]
        block = block[:block.index("try {")]
        self.assertIn("if (!selectedGroup) {", block)
        core = open(os.path.join(_REPO_ROOT, "static", "js", "core.js"),
                    encoding="utf-8").read()
        core_block = core[core.index("const topoSelect = document.getElementById('topologyGroupSelect')"):]
        core_block = core_block[:core_block.index("\n        }")]
        self.assertNotIn("topoSelect.value = 'all'", core_block)

    def test_drawer_fields_exist_and_are_filled(self):
        # Il pannello mostrava "—" quasi ovunque: i campi che il backend gia'
        # manda (sede, seriale, versione, VLAN mgmt, vicini) devono esserci
        # nel template E venire popolati, altrimenti restano riquadri vuoti.
        for element_id in ("drawerNodeSite", "drawerNodeSerial", "drawerNodeSoftware",
                           "drawerNodeMgmtVlan", "drawerStackInfo", "drawerNeighborList"):
            self.assertIn(f'id="{element_id}"', self.html)
            self.assertIn(f"getElementById('{element_id}')", self.src)
        # I vicini si leggono dalle adiacenze dell'ultima mappa caricata.
        self.assertIn("cachedTopologyLinks = data.links", self.src)

    @unittest.skipUnless(shutil.which("node"), "node non disponibile")
    def test_levels_come_from_topology_not_device_type(self):
        # Core, distribuzione e accesso sono tutti "switch": il piano deve
        # venire dai salti, altrimenti la vista torna piatta.
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_layered_levels.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


class TestWideContentFits(unittest.TestCase):
    """Tabelle larghe: scorrono nel loro contenitore, non oltre la finestra."""

    def test_main_can_shrink_below_its_content(self):
        # `main` e' una cella di griglia: con il `min-width: auto` di default
        # una tabella larga la faceva crescere oltre la finestra e
        # `body { overflow-x: hidden }` tagliava il contenuto a destra.
        css = open(os.path.join(_REPO_ROOT, "static", "css", "dashboard.css"),
                   encoding="utf-8").read()
        block = css[css.index("main { padding:"):]
        block = block[:block.index("\n\n")]
        self.assertIn("min-width: 0", block)
        self.assertIn("main .tab-content, main .panel, main .hero { min-width: 0; }", css)
        # Il contenitore delle tabelle deve poter scorrere in orizzontale.
        wrap = css[css.index(".table-container, .table-wrap {"):]
        self.assertIn("overflow-x: auto", wrap[:wrap.index("}")])


class TestLayeredGroups(unittest.TestCase):
    """Foglie dello stesso tipo sotto lo stesso padre: un riquadro solo."""

    @classmethod
    def setUpClass(cls):
        cls.src = open(os.path.join(_REPO_ROOT, "static", "js", "topology.js"),
                       encoding="utf-8").read()
        cls.html = open(os.path.join(_REPO_ROOT, "templates", "dashboard.html"),
                        encoding="utf-8").read()

    def test_collapse_button_is_bound(self):
        self.assertIn('id="layeredCollapseBtn"', self.html)
        self.assertIn("getElementById('layeredCollapseBtn')", self.src)

    def test_group_node_opens_instead_of_the_drawer(self):
        # Un riquadro "8 × Access Point" non ha un ispettore da mostrare: il
        # click deve aprirlo, non aprire il pannello laterale.
        self.assertIn("id.startsWith(GROUP_PREFIX)", self.src)
        self.assertIn("layeredGroupOfChild[p.nodes[0]]", self.src)

    @unittest.skipUnless(shutil.which("node"), "node non disponibile")
    def test_grouping_runs_for_real(self):
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_layered_groups.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


class TestMapNodeEnrichment(unittest.TestCase):
    """/api/network-map: dati d'identita' che l'app ha gia' altrove."""

    def _enrich(self, nodes, versions, ap_entries):
        from routers import topology
        from services import ap_store

        real_versions = topology.inventory_manager.get_detected_versions
        real_store = ap_store.read_all
        topology.inventory_manager.get_detected_versions = lambda: versions
        ap_store.read_all = lambda: ap_entries
        try:
            return topology.enrich_map_nodes({"nodes": nodes, "links": []})["nodes"]
        finally:
            topology.inventory_manager.get_detected_versions = real_versions
            ap_store.read_all = real_store

    def test_discovered_node_shows_the_announced_ip(self):
        # L'id sintetico "discovered_<hostname>" non e' un indirizzo: il
        # pannello mostrava "—" con l'IP gia' in mano al backend.
        nodes = [{"id": "discovered_switch-01", "label": "switch-01",
                  "status": "discovered", "reported_ip": "192.0.2.10"},
                 {"id": "192.0.2.1", "label": "switch-00", "status": "online"}]
        out = self._enrich(nodes, {}, {})
        self.assertEqual("192.0.2.10", out[0]["display_ip"])
        self.assertEqual("192.0.2.1", out[1]["display_ip"])

    def test_ap_serial_and_mac_come_from_the_controller(self):
        # Un access point non annuncia il proprio seriale: lo sa solo il WLC
        # che l'ha adottato, e quel dato e' gia' nello store degli AP.
        entry = {"serial": "FGL0000A0AA", "model": "<model>", "ip": "192.0.2.50",
                 "mac": "AA:BB:CC:DD:EE:FF", "wlc_ip": "192.0.2.5",
                 "tenant": "site-a", "seen_at": "2026-08-24T10:00:00Z"}
        nodes = [{"id": "discovered_ap-01", "label": "ap-01", "group": "site-a",
                  "status": "discovered", "reported_ip": ""}]
        out = self._enrich(nodes, {}, {"ap-01": entry, "ip:192.0.2.50": entry})
        self.assertEqual("FGL0000A0AA", out[0]["serial"])
        self.assertEqual("AA:BB:CC:DD:EE:FF", out[0]["mac"])
        # Senza IP annunciato vale quello che il controller conosce.
        self.assertEqual("192.0.2.50", out[0]["display_ip"])

    def test_controller_provenance_travels_with_the_node(self):
        # Uptime e VLAN mgmt restano vuoti per un AP, ma il controller sa a chi
        # si e' agganciato e quando l'ha visto: il pannello lo dice come dato
        # del WLC, non come dato dell'apparato.
        entry = {"serial": "FGL0000A0AA", "ip": "192.0.2.50", "mac": "",
                 "wlc_ip": "192.0.2.5", "tenant": "site-a",
                 "seen_at": "2026-08-24T10:00:00+00:00"}
        nodes = [{"id": "discovered_ap-01", "label": "ap-01", "group": "site-a",
                  "status": "discovered", "reported_ip": ""}]
        out = self._enrich(nodes, {}, {"ap-01": entry})
        self.assertEqual("192.0.2.5", out[0]["wlc_ip"])
        self.assertEqual("2026-08-24T10:00:00+00:00", out[0]["wlc_seen_at"])

    def test_scan_serial_wins_over_the_ap_store(self):
        # Il seriale letto dall'apparato stesso e' piu' affidabile di quello
        # riferito dal controller.
        entry = {"serial": "FROM-WLC", "ip": "", "mac": "", "tenant": "site-a"}
        nodes = [{"id": "192.0.2.20", "label": "switch-02", "group": "site-a",
                  "status": "online"}]
        out = self._enrich(nodes, {"192.0.2.20": {"serial": "FROM-DEVICE"}},
                           {"switch-02": entry})
        self.assertEqual("FROM-DEVICE", out[0]["serial"])

    def test_existing_serial_is_never_overwritten(self):
        nodes = [{"id": "192.0.2.30", "label": "switch-03", "status": "online",
                  "serial": "FROM-BACKUP"}]
        out = self._enrich(nodes, {"192.0.2.30": {"serial": "OTHER"}}, {})
        self.assertEqual("FROM-BACKUP", out[0]["serial"])


if __name__ == "__main__":
    unittest.main()
