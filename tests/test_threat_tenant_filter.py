# -*- coding: utf-8 -*-
"""Il filtro per sede della scheda Threat Intel deve avere effetto SUBITO.

Sintomo riportato: scelta "tutte le sedi", poi una sede specifica, e la lista
continuava a mostrare tutti gli apparati; solo un refresh della pagina la
correggeva.

Due cause distinte, stesso sintomo:

1. `startThreatScan` aveva un guardiano `_threatScanBusy` che, a scansione in
   corso, SCARTAVA la richiesta nuova. Quella richiesta e' proprio quella che
   riflette la scelta appena fatta: buttarla via lascia a schermo il risultato
   del filtro precedente.
2. `applyGlobalTenant` seminava il valore nella tendina della scheda senza mai
   ricaricarla, quindi la tendina diceva una sede e la lista sotto ne mostrava
   un'altra.

I test leggono la sorgente: sono controlli di struttura, non di rendering.
"""

import os
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(_ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


class LaScansioneNonScartaLaSceltaPiuRecente(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = _read("static", "js", "threat-intel.js")
        start = cls.js.index("async function startThreatScan")
        cls.fn = cls.js[start:cls.js.index("function extractReadableVersion")]

    def test_una_richiesta_arrivata_durante_la_scansione_viene_ricordata(self):
        # Il guardiano non puo' limitarsi a `return`: cosi' la selezione nuova
        # sparisce e a schermo resta il filtro vecchio.
        self.assertIn("_threatScanAgain = true", self.fn)

    def test_e_viene_rieseguita_alla_fine_del_giro_in_corso(self):
        tail = self.fn[self.fn.index("} finally {"):]
        self.assertIn("_threatScanAgain", tail)
        self.assertIn("startThreatScan()", tail)

    def test_il_flag_viene_azzerato_prima_di_ripartire(self):
        # Altrimenti ogni giro ne accoda un altro, per sempre.
        tail = self.fn[self.fn.index("} finally {"):]
        self.assertLess(tail.index("_threatScanAgain = false"),
                        tail.index("startThreatScan()"))

    def test_il_flag_e_dichiarato_fra_i_globali(self):
        # Una proprieta' di window non dichiarata fallisce check_frontend.py:
        # e' il comportamento voluto, non rumore da zittire.
        self.assertIn("_threatScanAgain", _read("types", "globals.d.ts"))


class IlSelettoreGlobaleRicaricaLaVistaAperta(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        core = _read("static", "js", "core.js")
        start = core.index("function applyGlobalTenant")
        cls.fn = core[start:start + 4000]

    def test_la_scheda_matcher_e_fra_quelle_riallineate(self):
        self.assertIn("'threatGroupSelect', 'tiViewMatcher'", self.fn)

    def test_la_visibilita_si_misura_con_offsetparent(self):
        # Un pannello con display:block dentro una scheda non attiva e'
        # comunque invisibile: style.display non lo sa.
        self.assertIn("offsetParent !== null", self.fn)
        self.assertNotIn("pane.style.display", self.fn)

    def test_il_valore_viene_seminato_anche_quando_non_si_ricarica(self):
        # Chi apre la scheda dopo deve trovarci la sede scelta.
        seed = self.fn.index("sel.value = val;")
        dispatch = self.fn.index("dispatchEvent")
        self.assertLess(seed, dispatch)


if __name__ == "__main__":
    unittest.main()
