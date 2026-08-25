# -*- coding: utf-8 -*-
"""Sezione UI del mirror offsite: id presenti e agganciati, stringhe in
entrambe le lingue, nessun handler inline, modulo caricato sul suo tab."""
import os
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    return open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8").read()


class TestCloudBackupUi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.src = _read("static", "js", "cloud-backup.js")
        cls.i18n = _read("static", "js", "i18n.js")
        cls.core = _read("static", "js", "core.js")

    def test_every_bound_id_exists_in_the_template(self):
        for element_id in ("cbEnabled", "cbHost", "cbPort", "cbUsername", "cbAuth",
                           "cbKeyPath", "cbSecret", "cbRemoteRoot", "cbFingerprint", "cbEncrypt",
                           "cbRunAfterBackup", "cbBtnSave", "cbBtnTest", "cbBtnRun",
                           "cbStatusBox"):
            self.assertIn(f'id="{element_id}"', self.html, element_id)
            self.assertIn(f"getElementById('{element_id}')", self.src, element_id)

    def test_no_inline_handlers_in_the_section(self):
        start = self.html.index('id="cloudBackupPanel"')
        section = self.html[start:start + 8000]
        self.assertNotIn("onclick=", section)
        self.assertNotIn("onsubmit=", section)

    def test_strings_exist_in_both_languages(self):
        for key in ("cbTitle", "cbLblHost", "cbLblEncrypt", "cbEncryptWarning",
                    "cbBtnTest", "cbStale", "cbPending", "cbLblFingerprint",
                    "cbFingerprintHelp", "cbPinHint"):
            self.assertGreaterEqual(self.i18n.count(f"{key}:"), 2, key)

    def test_module_is_lazy_loaded_on_the_settings_tab(self):
        block = self.core[self.core.index("LAZY_TAB_SCRIPTS"):]
        block = block[:block.index("};")]
        self.assertIn("cloud-backup.js", block)

    def test_global_is_declared(self):
        self.assertIn("loadCloudBackup", _read("types", "globals.d.ts"))

    def test_settings_tab_calls_loadCloudBackup_on_open(self):
        self.assertIn("loadCloudBackup()", _read("static", "js", "settings.js"))


if __name__ == "__main__":
    unittest.main()
