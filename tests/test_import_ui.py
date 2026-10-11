# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Importa tab UI: destination selects, preview table and the Organizations
link exist, are bound, and every new string is in both dictionaries."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read(*parts):
    return ROOT.joinpath(*parts).read_text(encoding="utf-8")


HTML = _read("templates", "dashboard.html")
DEVICES = _read("static", "js", "devices.js")
I18N = _read("static", "js", "i18n.js")
GLOBALS = _read("types", "globals.d.ts")

IDS = ("importOrgSelect", "importLocationSelect", "importDestChips", "importColumns",
       "importFilterTabs", "importPreviewBody", "importSummary", "btnUploadCsv")


class TestImportUi(unittest.TestCase):
    def test_ids_exist_and_are_bound(self):
        for el_id in IDS:
            with self.subTest(id=el_id):
                self.assertIn(f'id="{el_id}"', HTML)
                self.assertIn(el_id, DEVICES)

    def test_open_import_for_is_exposed(self):
        self.assertIn("window.openImportFor =", DEVICES)
        self.assertIn("openImportFor", GLOBALS)
        self.assertIn('data-action="loc-import"', DEVICES)

    def test_every_key_in_both_dictionaries(self):
        keys = set(re.findall(r"tr\('((?:import[A-Za-z_]*|btnImportDevices|locImportDevices))'", DEVICES))
        self.assertTrue(keys)
        keys |= {"importDestTitle", "importPickDestination", "importResult"}
        for key in sorted(keys):
            with self.subTest(key=key):
                self.assertEqual(len(re.findall(rf"^\s+{key}:", I18N, re.M)), 2)

    def test_accessibility(self):
        self.assertRegex(HTML, r'id="importFilterTabs"[^>]*role="tablist"')
        for sel in ("importOrgSelect", "importLocationSelect"):
            self.assertIn(f'<label for="{sel}"', HTML)


if __name__ == "__main__":
    unittest.main()
