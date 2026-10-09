# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The decommission controls exist in the template and are bound in
devices.js: a getElementById on a missing id leaves a button silently dead."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
JS = (ROOT / "static" / "js" / "devices.js").read_text(encoding="utf-8")
HIST = (ROOT / "static" / "js" / "device-history.js").read_text(encoding="utf-8")

BOUND = ("btnSelDecommission", "btnSelReactivate", "btnSelDelete",
         "btnInvBulkConfirm", "btnInvBulkCancel", "btnCloseInvBulk")


class TestDecommissionUi(unittest.TestCase):
    def test_controls_exist_and_are_bound(self):
        for el in BOUND + ("invBulkModal", "invBulkTitle", "invBulkText", "invBulkList",
                           "invKpiDecommissioned"):
            with self.subTest(el=el):
                self.assertIn(f'id="{el}"', HTML)
        for el in BOUND:
            with self.subTest(el=el):
                self.assertIn(f"getElementById('{el}')", JS)

    def test_status_tab_and_endpoints(self):
        self.assertIn('data-inv-status="decommissioned"', HTML)
        self.assertIn("'/api/devices/decommissioned'", JS)
        self.assertIn("`/api/devices/${action}`", JS)

    def test_selection_is_keyed_by_tenant_and_ip(self):
        self.assertNotIn("selectedDeviceIps", JS)
        self.assertIn("data-key=", JS)

    def test_hidden_bar_buttons_stay_hidden(self):
        # .btn sets display, which beats the [hidden] attribute's UA style:
        # without this rule «Riattiva» showed on the active tabs.
        css = (ROOT / "static" / "css" / "dashboard.css").read_text(encoding="utf-8")
        self.assertIn(".inv-selection .btn[hidden] { display: none; }", css)

    def test_history_knows_the_new_kinds(self):
        for kind in ("decommissioned", "reactivated"):
            with self.subTest(kind=kind):
                self.assertIn(kind, HIST)


if __name__ == "__main__":
    unittest.main()
