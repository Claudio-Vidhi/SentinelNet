# -*- coding: utf-8 -*-
"""Anche le tendine di APPARATI seguono il tenant scelto in alto.

test_global_tenant_sync.py sorveglia i select di tenant. Questi sono un'altra
cosa: elenchi di apparati che non hanno mai avuto un filtro per tenant e
mostravano l'intera flotta anche con un cliente selezionato.

Il backend limita gia' allo scope dei permessi dell'utente, ma un operatore che
vede piu' tenant li vedeva tutti insieme: "in scope" non vuol dire "del cliente
che sto guardando".
"""
import os
import re
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class TestPickersFollowTheGlobalTenant(unittest.TestCase):
    """Ogni tendina che elenca apparati deve leggere lo scope globale."""

    # (file, funzione che popola la tendina)
    _PICKERS = [
        ("static/js/routes-view.js", "loadRtDeviceList"),
        ("static/js/observability.js", "loadTrafPolDeviceList"),
        ("static/js/fortigate-management.js", "renderFgtTargetSelect"),
    ]

    def _body(self, src, name):
        i = src.index(name)
        depth, start, out = 0, src.index("{", i), []
        for ch in src[start:]:
            out.append(ch)
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
        return "".join(out)

    def test_every_device_picker_reads_the_global_tenant(self):
        for path, fn in self._PICKERS:
            with self.subTest(picker=fn):
                body = self._body(_read(*path.split("/")), fn)
                self.assertIn("globalSelectedTenant", body,
                              f"{fn} non guarda il tenant globale: elenca gli "
                              "apparati di tutti i clienti")

    def test_a_tenant_change_rebuilds_them(self):
        # Filtrare al primo caricamento non basta: senza il listener la tendina
        # resta quella del cliente precedente finche' non si riapre la vista.
        for path, _ in self._PICKERS:
            with self.subTest(module=path):
                self.assertIn("globalTenantChanged", _read(*path.split("/")))


class TestFortigateTargetsCarryTheirTenant(unittest.TestCase):
    """Senza il campo `group` la tendina non ha NIENTE su cui filtrare.

    Lo store dei token e' indicizzato per IP e non ha mai saputo di che sede
    fosse un apparato: il tenant va preso dall'inventario, lato server.
    """

    def test_the_endpoint_joins_the_inventory(self):
        src = _read("routers", "fortigate.py")
        block = src[src.index('@router.get("/api/fortigate/targets")'):]
        block = block[:block.index("@router.post")]
        self.assertIn("devices_in_scope", block)
        self.assertIn('"group"', block)

    def test_a_target_with_no_inventory_match_stays_visible(self):
        # Nasconderlo lo renderebbe irraggiungibile: e' configurato, esiste, e
        # l'unico posto da cui lo si raggiunge e' quella tendina.
        src = _read("static", "js", "fortigate-management.js")
        self.assertTrue(
            re.search(r"!t\.group\s*\|\|\s*t\.group\s*===\s*tenant", src),
            "un target senza tenant in inventario deve restare elencato")


if __name__ == "__main__":
    unittest.main()
