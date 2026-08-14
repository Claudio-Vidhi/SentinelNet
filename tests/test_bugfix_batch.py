# -*- coding: utf-8 -*-
"""Tre difetti trovati sul campo: modello dai vicini, sidebar compressa, unifilare.

1. Il modello di un apparato non puo' arrivare dai suoi vicini. Un backup Cisco
   contiene i blocchi CDP/LLDP di telefoni, AP e altri switch: quelle sezioni
   descrivono ALTRI apparati e finivano in colonna al posto dello chassis.
2. Con la sidebar compressa la riga del marchio resta orizzontale e sborda dai
   62px della colonna: i pulsanti tema/compressione vengono tagliati.
3. Le bay dello schema unifilare portano tutte all'inventario senza filtro:
   cliccare un tenant deve aprire l'inventario gia' filtrato su quel tenant.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="sentinelnet_bugfix_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP

from core import core_engine  # noqa: E402
from tests.test_helpers_frontend import frontend_source  # noqa: E402


# Backup sintetico: nessun 'Model Number:' nel blocco di versione (piattaforme
# recenti non lo stampano), un telefono annunciato via LLDP che invece un
# 'Model:' ce l'ha, e lo chassis vero solo dentro SHOW INVENTORY.
BACKUP_NEIGHBOR_ONLY = """\
--- SHOW VERSION ---
Cisco IOS Software, Version 15.2(7)E3

--- SHOW LLDP NEIGHBORS DETAIL ---
------------------------------------------------
Local Intf: Gi1/0/12
System Name: SEP001122334455
    S/W revision: sip00-0.0-0000
    Serial number: XXXXXXXXXXX
    Manufacturer: Cisco Systems, Inc.
    Model: CP-0000
    Capabilities: NP, PD, IN
------------------------------------------------

--- SHOW INVENTORY ---
NAME: "1", DESCR: "WS-C2960X-48FPD-L"
PID: WS-C2960X-48FPD-L , VID: V01  , SN: XXXXXXXXXXX

NAME: "Gi1/0/49", DESCR: "SFP-10GBase-SR"
PID: SFP-10G-SR        , VID: V03  , SN: XXXXXXXXXXX
"""

# Stesso difetto con il modello proprio disponibile: il blocco del vicino viene
# PRIMA, quindi vince chi cerca su tutto il file.
BACKUP_NEIGHBOR_BEFORE_VERSION = """\
--- SHOW LLDP NEIGHBORS DETAIL ---
System Name: SEP001122334455
    Manufacturer: Cisco Systems, Inc.
    Model: CP-0000

--- SHOW VERSION ---
Model Number                         : WS-C2960X-48FPD-L
System Serial Number                 : XXXXXXXXXXX
"""

# Nessuna fonte propria: meglio nessun modello che il modello del telefono.
BACKUP_ONLY_NEIGHBORS = """\
--- SHOW CDP NEIGHBORS DETAIL ---
Device ID: SEP001122334455
Platform: Cisco IP Phone CP-0000,  Capabilities: Host Phone Two-port Mac Relay
    Model: CP-0000
"""


class TestModelNeverComesFromNeighbors(unittest.TestCase):

    def test_chassis_model_read_from_inventory_not_from_lldp_phone(self):
        self.assertEqual("WS-C2960X-48FPD-L",
                         core_engine.extract_model_from_backup(BACKUP_NEIGHBOR_ONLY))

    def test_neighbor_block_before_version_does_not_win(self):
        self.assertEqual("WS-C2960X-48FPD-L",
                         core_engine.extract_model_from_backup(
                             BACKUP_NEIGHBOR_BEFORE_VERSION))

    def test_no_own_model_returns_none_rather_than_a_neighbor_model(self):
        self.assertIsNone(core_engine.extract_model_from_backup(BACKUP_ONLY_NEIGHBORS))

    def test_existing_cisco_model_number_still_read(self):
        self.assertEqual("WS-C2960X-48FPD-L", core_engine.extract_model_from_backup(
            "--- SHOW VERSION ---\nModel Number : WS-C2960X-48FPD-L\n"))


class TestCollapsedSidebarDoesNotOverflow(unittest.TestCase):

    def setUp(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base, "static", "css", "dashboard.css"),
                  encoding="utf-8") as fh:
            self.css = fh.read()

    def _rule(self, selector):
        m = re.search(re.escape(selector) + r'\s*(?:,[^{]*)?\{([^}]*)\}', self.css)
        self.assertIsNotNone(m, f"regola mancante per {selector}")
        return m.group(1)

    def test_brand_row_stacks_when_collapsed(self):
        # La riga marchio + azioni non entra in 62px se resta in fila.
        merged = self.css[self.css.index("body.sidebar-collapsed"):]
        for sel in ("body.sidebar-collapsed .brand-row",
                    "body.sidebar-collapsed .aside-actions"):
            m = re.search(re.escape(sel) + r'[^{]*\{([^}]*)\}', merged)
            self.assertIsNotNone(m, f"regola mancante per {sel}")
            self.assertIn("column", m.group(1),
                          f"{sel} deve impilare i figli con la sidebar compressa")


class TestOnelineBayOpensFilteredInventory(unittest.TestCase):

    def setUp(self):
        self.src = frontend_source()

    def test_helper_selects_tenant_then_renders_inventory(self):
        # La funzione vive ora in static/js/home.js (blocco inline estratto
        # per la CSP senza 'unsafe-inline'): chiusura a colonna 0, non piu'
        # indentata di 4 spazi come nel vecchio blocco inline.
        m = re.search(r'function openInventoryForTenant\s*\([^)]*\)\s*\{(.*?)\n\}',
                      self.src, re.DOTALL)
        self.assertIsNotNone(m, "manca openInventoryForTenant()")
        body = m.group(1)
        self.assertIn("filterGroupSelect", body)
        self.assertIn("renderDeviceTable()", body)
        self.assertIn("switchTab('tab-devices')", body)

    def test_bay_button_passes_its_tenant(self):
        # La bay per tenant non deve piu' aprire l'inventario senza filtro.
        bay = re.search(r'class="oneline-bay" data-state="\$\{state\(b\)\}"\s*'
                        r'data-action="open-inventory-tenant"\s*'
                        r'data-tenant="\$\{escapeHtml\(name\)\}"', self.src)
        self.assertIsNotNone(bay, "bottone bay per tenant non trovato")
        self.assertIn("openInventoryForTenant", self.src)


class TestSortKeepsDetailRowsWithTheirParent(unittest.TestCase):
    """Le tabelle con riga di dettaglio espandibile (matrice audit) la
    perdevano al primo click su un'intestazione: l'ordinamento trattava la
    riga di dettaglio come una voce a se', e quella non ha la colonna su cui
    si ordina."""

    @unittest.skipUnless(shutil.which("node"), "node non disponibile")
    def test_sorter_groups_full_width_rows_with_the_row_above(self):
        # Il resto di questa suite verifica il frontend per sottostringhe, e su
        # questa regressione non basterebbe: la versione rotta conteneva tutte
        # le parole giuste e lasciava la tabella immobile. Qui la funzione viene
        # eseguita davvero, su un DOM finto.
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        harness = os.path.join(base, "tests", "js", "test_sort_table.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=base)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


class TestSortIndicatorIsDrawnByCss(unittest.TestCase):
    """La freccia di ordinamento deve essere disegnata dal CSS a partire dagli
    attributi dell'intestazione. Come nodo figlio non sopravviveva a
    applyLanguage(), che riscrive l'innerHTML di ogni [data-i18n]."""

    def setUp(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base, "static", "css", "dashboard.css"),
                  encoding="utf-8") as fh:
            self.css = fh.read()

    def test_neutral_ascending_and_descending_all_have_a_rule(self):
        for selector in ('th[data-sortable="1"]::after',
                         'th[data-sort-asc="true"]::after',
                         'th[data-sort-asc="false"]::after'):
            self.assertIn(selector, self.css, f"manca la regola per {selector}")

    def test_each_state_sets_its_own_glyph(self):
        glyphs = re.findall(r'th\[data-sort(?:able|-asc)="[^"]+"\]::after\s*\{[^}]*'
                            r'content:\s*[\'"]([^\'"]+)[\'"]', self.css)
        self.assertEqual(3, len(glyphs), f"attesi 3 glifi distinti, trovati {glyphs}")
        self.assertEqual(3, len(set(glyphs)), f"i tre stati non sono distinguibili: {glyphs}")


if __name__ == "__main__":
    unittest.main()
