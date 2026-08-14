# -*- coding: utf-8 -*-
"""La matrice risultati si filtra per stato audit come per severita' e
categoria: con centinaia di regole l'operatore vuole vedere solo le FAIL.

Gli stati sono le costanti di services/netsec_audit/model.py; cio' che non
e' PASS/FAIL/WARN si legge N/D (UNKNOWN), come nel badge della tabella.
"""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class TestStatusFilter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "netsec-audit.js")
        cls.i18n = _read("static", "js", "i18n.js")

    def test_the_select_exists_with_every_status_and_rerenders(self):
        idx = self.html.index('id="auditStatusFilter"')
        tag = self.html[self.html.rindex("<select", 0, idx):
                        self.html.index("</select>", idx)]
        self.assertIn('onchange="renderAuditRulesTable()"', tag)
        for value in ("all", "PASS", "FAIL", "WARN", "UNKNOWN"):
            self.assertIn(f'value="{value}"', tag)

    def test_the_render_applies_the_status_filter(self):
        body = self.js[self.js.index("function renderAuditRulesTable"):]
        body = body[:body.index("function toggleAuditDetail")]
        self.assertIn("auditStatusFilter", body)
        self.assertIn("'UNKNOWN'", body)

    def test_the_i18n_key_exists_in_both_langs(self):
        self.assertEqual(2, self.i18n.count("nsaFilterStatusAll:"))


if __name__ == "__main__":
    unittest.main()
