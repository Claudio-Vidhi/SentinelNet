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


if __name__ == "__main__":
    unittest.main()
