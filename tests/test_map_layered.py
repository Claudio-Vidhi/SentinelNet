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
