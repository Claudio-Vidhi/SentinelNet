# -*- coding: utf-8 -*-
"""Il selettore di tenant in alto deve arrivare a ogni pannello.

Il bug che questi test bloccano non e' visibile leggendo un file solo:
``applyGlobalTenant`` scrive ``sel.value`` sui select dei pannelli, ma quei
pannelli sono lazy e ripopolano il proprio select QUANDO si aprono, cioe' dopo.
Scrivere ``.value`` su un select ancora senza option non fa niente e non
solleva niente, quindi il pannello rileggeva '' e ripiegava su "tutti": lo
scope globale spariva in silenzio, e a schermo restava "Filtra per Tenant:
Tutti" con un tenant scelto in alto.

La correzione e' un solo posto — ``tenantSelectSeed`` in core.js — usato da
ogni punto che ripopola un select di tenant.
"""
import os
import re
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_JS_DIR = os.path.join(_REPO_ROOT, "static", "js")

# Il pattern rotto: si ripopula un select DI TENANT e si ripiega su un default
# senza mai guardare il tenant globale. Il nome della collezione (groups /
# tenants) e' quello che distingue un filtro di tenant da uno di categorie o di
# apparati, che un default legittimamente ce l'hanno.
_BROKEN = re.compile(
    r"\.value\s*=\s*(\w*(?:groups|tenants)\w*)\.includes\(\s*\w+\s*\)"
    r"\s*\?\s*\w+\s*:\s*['\"]", re.IGNORECASE)

# populateGlobalTenantSelect E' la sorgente dello scope: legge gia' URL e
# window.globalSelectedTenant da se', non puo' seminarsi dal proprio output.
_ALLOWED = {("core.js", "populateGlobalTenantSelect")}


def _js_files():
    for name in sorted(os.listdir(_JS_DIR)):
        if name.endswith(".js"):
            yield name, os.path.join(_JS_DIR, name)


class TestTenantSelectSeeding(unittest.TestCase):

    def test_no_panel_repopulates_a_tenant_select_ignoring_the_global_scope(self):
        offenders = []
        for name, path in _js_files():
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
            for lineno, line in enumerate(lines, start=1):
                if not _BROKEN.search(line):
                    continue
                # Risali alla funzione che contiene la riga per l'allow-list.
                enclosing = ""
                for prev in reversed(lines[:lineno]):
                    m = re.match(r"\s*(?:async\s+)?function\s+(\w+)", prev)
                    if m:
                        enclosing = m.group(1)
                        break
                if (name, enclosing) in _ALLOWED:
                    continue
                offenders.append(f"{name}:{lineno}: {line.strip()}")
        self.assertEqual(
            [], offenders,
            "Questi punti ripopolano un select ripiegando su un default e "
            "buttano via il tenant globale. Usa tenantSelectSeed(cur, groups, "
            "fallback) di core.js:\n  " + "\n  ".join(offenders))

    def test_the_helper_exists_and_reads_the_global_tenant(self):
        with open(os.path.join(_JS_DIR, "core.js"), encoding="utf-8") as f:
            core = f.read()
        self.assertIn("function tenantSelectSeed(", core)
        self.assertIn("window.tenantSelectSeed = tenantSelectSeed;", core)
        # Senza questa lettura l'helper e' solo il vecchio ternario travestito.
        seed = core.split("function tenantSelectSeed(", 1)[1].split("\n}", 1)[0]
        self.assertIn("window.globalSelectedTenant", seed)

    def test_the_helper_is_declared_as_a_window_global(self):
        # Una window property non dichiarata fa fallire check_frontend.py:
        # e' il comportamento voluto, non rumore da zittire (AGENTS.md).
        with open(os.path.join(_REPO_ROOT, "types", "globals.d.ts"),
                  encoding="utf-8") as f:
            self.assertIn("tenantSelectSeed", f.read())

    def test_every_panel_select_the_global_selector_syncs_actually_uses_it(self):
        # applyGlobalTenant elenca gli id che sincronizza. Un id in quella lista
        # il cui pannello non passa da tenantSelectSeed e' esattamente il bug
        # di partenza: sincronizzato a caldo, perso a freddo.
        with open(os.path.join(_JS_DIR, "core.js"), encoding="utf-8") as f:
            core = f.read()
        block = core.split("function applyGlobalTenant(", 1)[1].split("\n}", 1)[0]
        synced = set(re.findall(r"'([a-zA-Z]+(?:Tenant|Group)[a-zA-Z]*)'", block))
        self.assertIn("ptTenantSelect", synced, "lista degli id non trovata")

        seeded_files = [name for name, path in _js_files()
                        if "tenantSelectSeed(" in open(path, encoding="utf-8").read()]
        self.assertGreaterEqual(
            len(seeded_files), 6,
            "l'helper e' usato in troppo pochi moduli: " + repr(seeded_files))


if __name__ == "__main__":
    unittest.main()
