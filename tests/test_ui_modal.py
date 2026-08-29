# -*- coding: utf-8 -*-
"""Gestore unico delle modali (static/js/ui-modal.js).

Gli script sono classici e senza bundler: un id sbagliato o una modale
riaperta a mano con style.display non fallisce da nessuna parte, lascia solo
un pulsante morto o una finestra senza trappola del focus. Questi controlli
sono l'unico posto in cui la cosa si vede.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JS_DIR = ROOT / "static" / "js"
DASHBOARD = ROOT / "templates" / "dashboard.html"

_OPEN_CALL = re.compile(r"""(?:open|close)Modal\(\s*['"]([A-Za-z0-9_-]+)['"]\s*\)""")
# Toggle diretto del display su un nodo che si chiama modale: la cosa che il
# gestore esiste per sostituire.
_RAW_TOGGLE = re.compile(
    r"""getElementById\(\s*['"][A-Za-z0-9_]*(?:[Mm]odal|[Bb]ackdrop)[A-Za-z0-9_]*['"]\s*\)"""
    r"""\.style\.display\s*=""")


def _modules():
    return [p for p in JS_DIR.glob("*.js") if p.name != "ui-modal.js"]


class TestModalManager(unittest.TestCase):

    def setUp(self):
        self.html = DASHBOARD.read_text(encoding="utf-8")

    def test_every_modal_id_exists_in_the_template(self):
        missing = []
        for path in _modules():
            for mid in set(_OPEN_CALL.findall(path.read_text(encoding="utf-8"))):
                if f'id="{mid}"' not in self.html:
                    missing.append(f"{path.name}: {mid}")
        self.assertEqual(missing, [], "id di modali inesistenti nel template")

    def test_no_module_toggles_a_modal_display_directly(self):
        offenders = [p.name for p in _modules()
                     if _RAW_TOGGLE.search(p.read_text(encoding="utf-8"))]
        self.assertEqual(offenders, [],
                         "usare openModal/closeModal: il toggle diretto salta "
                         "semantica dialog, trappola del focus e Esc")

    def test_manager_is_loaded_before_its_consumers(self):
        pos = self.html.find("/static/js/ui-modal.js")
        self.assertNotEqual(pos, -1, "ui-modal.js non e' incluso nel template")
        core = self.html.find("/static/js/core.js")
        self.assertLess(pos, core, "ui-modal.js deve precedere core.js")

    def test_manager_provides_dialog_semantics_and_focus_trap(self):
        src = (JS_DIR / "ui-modal.js").read_text(encoding="utf-8")
        for needle in ('role', 'aria-modal', 'Escape', 'Tab', 'focus('):
            self.assertIn(needle, src, f"manca {needle} nel gestore modali")


if __name__ == "__main__":
    unittest.main()
