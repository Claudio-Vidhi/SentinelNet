# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The FortiGate advisor lives in its own sub-tab of the Security audit tab."""

import os
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts) -> str:
    with open(os.path.join(_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class TestAdvisorSubtab(unittest.TestCase):

    def setUp(self):
        self.html = _read("templates", "dashboard.html")

    def test_button_is_in_the_subtab_nav(self):
        nav = self.html.index('id="netsecSubtabNav"')
        nav_end = self.html.index("</div>", nav)
        btn = self.html.index('id="subtabBtnAuditAdvisor"')
        self.assertTrue(nav < btn < nav_end)
        self.assertIn('data-subtab="advisor"', self.html[btn:nav_end])
        self.assertIn('id="auditAdvisorCount"', self.html[btn:nav_end])

    def test_panel_lives_in_the_advisor_pane_not_in_scan(self):
        scan = self.html.index('id="netsecSubtabScan"')
        scan_end = self.html.index("<!-- End #netsecSubtabScan -->")
        pane = self.html.index('id="netsecSubtabAdvisor"')
        panel = self.html.index('id="auditAdvisorPanel"')
        self.assertLess(pane, panel)
        self.assertFalse(scan < panel < scan_end)
        self.assertIn('id="auditAdvisorEmpty"', self.html[pane:])

    def test_js_switches_to_the_advisor_pane(self):
        self.assertIn("netsecSubtabAdvisor", _read("static", "js", "netsec-audit.js"))

    def test_keys_in_both_languages(self):
        src = _read("static", "js", "i18n.js")
        for line in (
            'nsaSubtabAdvisor: "Advisor FortiGate"',
            'nsaSubtabAdvisor: "FortiGate Advisor"',
            'nsaAdvEmpty: "Esegui la scansione di un FortiGate nella sotto-tab Scansione per vedere qui i consigli."',
            'nsaAdvEmpty: "Scan a FortiGate in the Scan sub-tab to see its recommendations here."',
        ):
            self.assertIn(line, src)


if __name__ == "__main__":
    unittest.main()
