# -*- coding: utf-8 -*-
"""The Config Drift tab must be wired, translated and lazily loaded."""
import pathlib
import re
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

    def test_switchtab_dispatches_to_the_tab(self):
        """A control existing is not enough: switchTab must actually call the
        module's loader once the lazy script has loaded, or the tab opens
        empty on its first click (the click that triggered the lazy load has
        already finished dispatching before any listener the module adds
        itself could catch it)."""
        body = self.core[self.core.index("async function switchTab("):]
        body = body[:body.index("\n}")]
        calls = dict(re.findall(
            r"tabId === '(tab-[a-z0-9-]+)'[^\n]*?\b([a-zA-Z_][A-Za-z0-9_]*)\s*\(\)",
            body))
        self.assertIn("tab-config-drift", calls,
                       "switchTab never dispatches to tab-config-drift")
        func = calls["tab-config-drift"]

        drift_js = (ROOT / "static/js/config-drift.js").read_text(encoding="utf-8")
        self.assertIn(f"function {func}(", drift_js,
                       f"switchTab calls {func}() but config-drift.js never defines it")
        self.assertIn(f"window.{func} = {func};", drift_js,
                       f"{func} is defined but never exported on window, so switchTab's "
                       "bare call throws a ReferenceError")

    def test_every_key_is_in_both_languages(self):
        it_block, en_block = self.i18n.split("    en: {", 1)
        for key in ("tabConfigDrift", "driftSubHistory", "driftSubBaseline",
                    "thDriftDevice", "thDriftLastChange", "thDriftLastSeen",
                    "driftNoVersions", "driftBaselineHint"):
            self.assertIn(f"{key}:", it_block, f"{key} missing from it")
            self.assertIn(f"{key}:", en_block, f"{key} missing from en")


if __name__ == "__main__":
    unittest.main()
