# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Le tab concedibili a un utente non-admin.

La lista in settings.js era mantenuta a mano ed era divergente: sei tab
spedite (WLC, Interfacce, HA, Policy Test, Rotte, Config Drift) non erano
concedibili a nessuno, e una spunta offriva tab-groups, che e' requires-admin
e resta nascosta comunque. Il difetto vero non erano le sei voci mancanti: era
che ogni tab nuova richiedeva di ricordarsi di aggiungerla.

La derivazione dalla barra di navigazione e' verificata contro il template
dall'harness node; qui restano le due guardie che non richiedono node.
"""

import os
import shutil
import subprocess
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts) -> str:
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class TestAssignableTabsAreDerived(unittest.TestCase):

    def test_the_list_is_not_hand_maintained_any_more(self):
        src = _read("static", "js", "settings.js")
        self.assertNotIn("const ASSIGNABLE_TABS = [", src)
        self.assertIn("function assignableTabs(rowRole)", src)

    def test_the_editor_uses_the_derivation(self):
        src = _read("static", "js", "settings.js")
        self.assertIn("assignableTabs(u.role).map(", src)

    def test_every_non_admin_nav_tab_is_reachable(self):
        """Le due meta': ogni pannello non-admin del template e' concedibile, e
        ogni id offerto esiste nel template. L'harness node esegue la funzione
        vera contro il markup vero."""
        node = shutil.which("node")
        if not node:
            self.skipTest("node non disponibile")
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_assignable_tabs.mjs")
        proc = subprocess.run([node, harness], capture_output=True, text=True,
                              cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


if __name__ == "__main__":
    unittest.main()
