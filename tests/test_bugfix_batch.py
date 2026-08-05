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
        m = re.search(r'function openInventoryForTenant\s*\([^)]*\)\s*\{(.*?)\n    \}',
                      self.src, re.DOTALL)
        self.assertIsNotNone(m, "manca openInventoryForTenant()")
        body = m.group(1)
        self.assertIn("filterGroupSelect", body)
        self.assertIn("renderDeviceTable()", body)
        self.assertIn("switchTab('tab-devices')", body)

    def test_bay_button_passes_its_tenant(self):
        # La bay per tenant non deve piu' aprire l'inventario senza filtro.
        bay = re.search(r'class="oneline-bay" data-state="\$\{state\(b\)\}"\s*'
                        r'onclick="([^"]+)"', self.src)
        self.assertIsNotNone(bay, "bottone bay per tenant non trovato")
        self.assertIn("openInventoryForTenant(", bay.group(1))


if __name__ == "__main__":
    unittest.main()
