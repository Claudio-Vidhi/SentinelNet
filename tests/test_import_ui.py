# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""CSV import inside the "Add devices" wizard: what the old Import page offered
(template, column help, probe ids, "move to location", per-location import)
is still there, bound, and translated."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read(*parts):
    return ROOT.joinpath(*parts).read_text(encoding="utf-8")


HTML = _read("templates", "dashboard.html")
ADW = _read("static", "js", "add-devices.js")
DEVICES = _read("static", "js", "devices.js")
I18N = _read("static", "js", "i18n.js")


class TestImportUi(unittest.TestCase):
    def test_the_import_page_is_gone(self):
        self.assertNotIn('id="tab-import"', HTML)
        self.assertNotIn("openImportFor", DEVICES)

    def test_template_and_help_live_in_the_csv_step(self):
        step = HTML[HTML.index('data-adw-for="csv"'):]
        step = step[:step.index('data-adw-for="scan"')]
        for el_id in ("btnDownloadCsvTemplate", "importProbeIds", "importProbeIdsList"):
            with self.subTest(id=el_id):
                self.assertIn(f'id="{el_id}"', step)
        self.assertIn("#btnDownloadCsvTemplate", ADW)
        self.assertIn("'/api/probes'", ADW)

    def test_preview_decisions_reach_both_calls(self):
        self.assertIn("decisions: adw.csvDecisions", ADW)
        self.assertIn("{ ...adw.csvDecisions }", ADW)
        self.assertIn("data-adw-move", ADW)
        self.assertIn("r.action.kind === 'move'", ADW)

    def test_location_row_opens_the_wizard_on_csv(self):
        self.assertIn('data-action="loc-import"', DEVICES)
        self.assertIn("canOpenTab('tab-import')", DEVICES)
        self.assertIn("window.openAddDevices({ src: 'csv', group: btn.dataset.org, location: btn.dataset.loc })", DEVICES)

    def test_every_key_in_both_dictionaries(self):
        keys = {"adwCsvHelp", "btnDownloadCsvTemplate", "importFlexNote", "importTenantVsProbeBody",
                "importProbeIdsNote", "importProbeIdsAvailable", "importActionMove", "importPwdChanged",
                "locImportDevices"}
        for key in sorted(keys):
            with self.subTest(key=key):
                self.assertEqual(len(re.findall(rf"^\s+{key}:", I18N, re.M)), 2)


if __name__ == "__main__":
    unittest.main()
