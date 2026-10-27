# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The classification export UI is wired, and the old browser-side CSV is gone."""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class ClassificationExportUi(unittest.TestCase):
    def test_the_modal_exists_in_the_template(self):
        self.assertIn('id="classificationExportModal"', _read("templates/dashboard.html"))

    def test_the_button_binds_to_an_id_that_exists(self):
        self.assertIn('id="btnExportClassification"', _read("templates/dashboard.html"))
        self.assertIn("btnExportClassification", _read("static/js/topology.js"))

    def test_the_browser_side_csv_builder_is_gone(self):
        """Two exports for one table is how they drift apart."""
        self.assertNotIn("exportCategoriesCsv", _read("static/js/topology.js"))

    def test_no_inline_handlers_were_introduced(self):
        self.assertNotIn("onclick=", _read("templates/dashboard.html"))

    def test_both_languages_carry_every_new_key(self):
        js = _read("static/js/i18n.js")
        for key in ("titleClassificationExport", "descClassificationExport",
                    "btnExportClassification", "lblClsCategory",
                    "lblClsNeighbourCategory", "lblExportPreview", "btnPresetDefault",
                    "btnPresetHardware", "lblClsScenario", "clsScenarioSwAp",
                    "clsScenarioApSw", "clsScenarioSerials", "clsScenarioSimple",
                    "clsScenarioFull", "lblClsSentExport", "lblClsSentWithNeighbours",
                    "lblClsSentTenant", "optClsAllDevices", "optClsNoNeighbour",
                    "optClsAnyNeighbour", "lblClsSkipWithout", "lblClsTenant",
                    "lblExportDevicesCount", "btnClsExportRows"):
            self.assertEqual(2, len(re.findall(r"\b%s\s*:" % key, js)),
                             f"{key} must appear in both the it and en blocks")

    def test_preview_elements_exist_in_template(self):
        html = _read("templates/dashboard.html")
        self.assertIn('id="clsExportPreviewContainer"', html)
        for el in ("clsCategorySelect", "clsNeighbourSelect", "clsTenantSelect",
                   "clsOnlyMatchingNeighbours", "clsColumnList", "clsScenarioList"):
            self.assertIn(f'id="{el}"', html)
        self.assertIn('id="deviceExportPreviewContainer"', html)

    def test_every_scenario_button_has_a_definition(self):
        """A chip without an entry in CLS_SCENARIOS is a dead button."""
        html = _read("templates/dashboard.html")
        js = _read("static/js/topology.js")
        chips = re.findall(r'data-scenario="([^"]+)"', html)
        self.assertEqual(5, len(chips))
        for name in chips:
            self.assertRegex(js, r"'%s'\s*:\s*\{" % re.escape(name))


if __name__ == "__main__":
    unittest.main()
