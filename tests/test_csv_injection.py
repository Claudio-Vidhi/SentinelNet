# -*- coding: utf-8 -*-
"""Iniezione di formule nei CSV esportati.

Un CSV correttamente quotato e' comunque pericoloso: Excel e LibreOffice
valutano come formula qualunque cella che inizi per ``= + - @`` (e per TAB o
CR, che i fogli di calcolo normalizzano). I valori esportati arrivano dagli
APPARATI — hostname, versione, banner — quindi chi controlla un apparato
scrive nel foglio di chi esporta l'inventario.

La neutralizzazione e' un apostrofo in testa: il foglio mostra il testo e non
lo esegue. La quotatura CSV NON basta e non c'entra: sono due problemi
diversi, e i tre export li confondevano.
"""

import os
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_csvinj_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

# I payload classici: formula, comando DDE, e i due che passano inosservati
# perche' non "sembrano" formule.
PAYLOADS = [
    "=1+1",
    "+1+1",
    "-1+1",
    "@SUM(A1:A9)",
    '=cmd|\' /c calc\'!A1',
    "\t=1+1",
    "\r=1+1",
]


class TestExportDispositiviServer(unittest.TestCase):
    """/api/export/devices: Hostname, Vendor e Version arrivano dall'apparato."""

    def _export(self, hostname):
        from fastapi.testclient import TestClient
        from unittest.mock import patch
        import app_server
        from routers.deps import get_current_user

        devices = [{"IP": "192.0.2.10", "Hostname": hostname,
                    "Vendor": "cisco", "Group": "sede-a"}]
        # Depends() cattura la funzione al momento della decorazione: patchare
        # il nome nel modulo arriva tardi, l'override e' l'unico aggancio.
        app_server.app.dependency_overrides[get_current_user] = \
            lambda: {"sub": "tester", "role": "admin"}
        try:
            with patch("services.inventory_manager.get_all_devices",
                       return_value=devices), \
                 patch("services.inventory_manager.get_detected_versions",
                       return_value={"192.0.2.10": {"version": "1.0",
                                                    "status": "ok"}}), \
                 patch("routers.inventory.log_audit"):
                client = TestClient(app_server.app)
                res = client.get("/api/export/devices",
                                 headers={"X-Requested-With": "x"})
        finally:
            app_server.app.dependency_overrides.pop(get_current_user, None)
        return res

    def test_a_formula_hostname_is_neutralised(self):
        for payload in PAYLOADS:
            with self.subTest(payload=payload):
                res = self._export(payload)
                self.assertEqual(res.status_code, 200)
                # Il CSV va PARSATO, non spezzato per righe: un CR dentro una
                # cella quotata e' legittimo e spezzarlo a mano fa leggere un
                # frammento come se fosse una cella nuova.
                import csv as _csv
                import io as _io
                rows = list(_csv.reader(_io.StringIO(res.text)))
                for row in rows[1:]:
                    for cell in row:
                        self.assertFalse(
                            cell[:1] in ("=", "+", "-", "@", "\t", "\r"),
                            f"cella eseguibile in Excel: {cell!r}")

    def test_an_innocent_value_is_left_alone(self):
        # Neutralizzare tutto renderebbe illeggibile l'export normale.
        res = self._export("switch-01")
        self.assertIn("switch-01", res.text)
        self.assertNotIn("'switch-01", res.text)


class TestExportFrontend(unittest.TestCase):
    """Verifica grep-style: non c'e' un runner JS.

    I due export lato client (inventario endpoint e categorie) costruivano
    ciascuno il proprio escaper, e nessuno dei due guardava il primo
    carattere. La correzione e' UNA funzione condivisa in core.js: tre copie
    della stessa regola sono tre occasioni di sbagliarla."""

    @classmethod
    def setUpClass(cls):
        from tests.test_helpers_frontend import frontend_source
        cls.src = frontend_source()

    def test_core_defines_the_shared_helper(self):
        self.assertIn("function csvCell(", self.src)

    def test_the_helper_neutralises_every_dangerous_leader(self):
        # La finestra attorno alla definizione: la regola deve stare li',
        # non sparsa nei chiamanti.
        i = self.src.index("function csvCell(")
        body = self.src[i:i + 700]
        for ch in ("=", "+", "-", "@"):
            self.assertIn(ch, body,
                          f"csvCell non nomina il carattere {ch!r}")
        self.assertIn("'", body, "manca l'apostrofo di neutralizzazione")

    def test_the_client_export_uses_it(self):
        # Per file, non sul sorgente concatenato: cosi' si sa QUALE export ha
        # smesso di usarla. E si cerca il nome, non 'csvCell(' -- passarla a
        # .map() come riferimento e' uso legittimo quanto chiamarla.
        # topology.js no longer builds CSV in the browser: classification is
        # now exported by the server (see /api/export/classification).
        import os
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for rel in ("static/js/endpoint-inventory.js",):
            with self.subTest(file=rel):
                with open(os.path.join(base, rel), encoding="utf-8") as f:
                    body = f.read()
                self.assertIn("csvCell", body, f"{rel} non usa csvCell")
                # Nessun escaper locale sopravvissuto: erano loro il bug, e
                # una copia rimasta indietro e' il modo in cui torna.
                self.assertNotIn("const cell = v =>", body)
                self.assertNotIn("const esc = (v) =>", body)


if __name__ == "__main__":
    unittest.main()
