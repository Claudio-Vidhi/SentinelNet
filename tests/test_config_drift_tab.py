# -*- coding: utf-8 -*-
"""The Config Drift tab must be wired, translated and lazily loaded."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class TheTabIsWired(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
        self.core = (ROOT / "static/js/core.js").read_text(encoding="utf-8")
        self.i18n = (ROOT / "static/js/i18n.js").read_text(encoding="utf-8")

    def test_the_nav_button_and_panel_exist(self):
        self.assertIn('data-tab="tab-config-drift"', self.html)
        self.assertIn('id="tab-config-drift"', self.html)

    def test_the_module_is_lazily_loaded_for_its_tab(self):
        self.assertIn("'tab-config-drift': ['/static/js/config-drift.js']", self.core)

    def test_the_controls_it_binds_exist_in_the_template(self):
        for element_id in ("driftTenantSelect", "driftDeviceList",
                           "driftBaselineText", "btnDriftSaveBaseline",
                           "btnDriftSeedBaseline"):
            self.assertIn(f'id="{element_id}"', self.html, element_id)

    def test_no_inline_handler_was_introduced(self):
        panel = self.html.split('id="tab-config-drift"', 1)[1]
        self.assertNotIn("onclick=", panel.split("</div>")[0])

    def test_every_key_is_in_both_languages(self):
        it_block, en_block = self.i18n.split("    en: {", 1)
        for key in ("tabConfigDrift", "driftSubHistory", "driftSubBaseline",
                    "thDriftDevice", "thDriftLastChange", "thDriftLastSeen",
                    "driftNoVersions", "driftBaselineHint"):
            self.assertIn(f"{key}:", it_block, f"{key} missing from it")
            self.assertIn(f"{key}:", en_block, f"{key} missing from en")


if __name__ == "__main__":
    unittest.main()
