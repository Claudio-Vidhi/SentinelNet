# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Probe wizard wiring: every id the JS binds exists in the template, the old
modals are gone, and the save sends the confirmed fingerprint only when the
operator ticked it."""
import os
import re
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class ProbeWizardUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "settings.js")

    def test_old_modals_are_gone(self):
        for old in ("createProbeModal", "editProbeModal", "probeEnrollModal", "newProbeMode", "jumpLimitsTitle"):
            self.assertNotIn(old, self.html, old)
            self.assertNotIn(old, self.js, old)

    def test_every_bound_id_exists(self):
        ids = set(re.findall(r"swEl\('([A-Za-z]+)'\)", self.js))
        ids |= {"probeWizard", "probeWizardForm", "probeEnrollConfig", "probeEnrollCommands", "btnNewProbe"}
        missing = sorted(i for i in ids if f'id="{i}"' not in self.html)
        self.assertEqual(missing, [])

    def test_wizard_is_created_on_the_panel(self):
        self.assertIn("createWizard('probeWizard'", self.js)
        self.assertIn('id="probeWizard"', self.html)
        self.assertIn("getElementById('probeWizard')?.addEventListener", self.js)
        self.assertIn("getElementById('btnNewProbe')?.addEventListener", self.js)

    def test_fingerprint_is_sent_only_when_confirmed(self):
        self.assertIn("body.confirmed_fingerprint = sw.test.fingerprint", self.js)
        self.assertIn("swEl('swFpConfirm').checked", self.js)

    def test_test_result_is_announced(self):
        start = self.html.index('id="swTestResult"')
        tag = self.html[self.html.rindex("<", 0, start):self.html.index(">", start)]
        self.assertIn('aria-live="polite"', tag)

    def test_after_the_token_only_the_enrollment_step_remains(self):
        # Back from Enrollment to Summary would offer Save again and create the
        # probe a second time: once a token is issued every other step skips.
        start = self.js.index("createWizard('probeWizard'")
        steps = self.js[start:self.js.index("onFinish:", start)]
        self.assertEqual(4, steps.count("!!sw.token"), steps)

    def test_the_next_button_label_belongs_to_the_wizard(self):
        # data-i18n would reset it to "Next" on a language switch, even on the
        # step whose label is Save.
        start = self.html.index("data-wizard-next")
        tag = self.html[self.html.rindex("<", 0, start):self.html.index(">", start)]
        self.assertNotIn("data-i18n=", tag)

    def test_resuming_an_edit_draft_keeps_edit_mode(self):
        # "+ New identity" during an edit comes back through "Nuova sede".
        self.assertIn("editable: !!sw.editing", self.js)

    def test_unverified_badge(self):
        self.assertIn("chipNotVerified", self.js)
        self.assertIn("bastion_verified_ts", self.js)


if __name__ == "__main__":
    unittest.main()
