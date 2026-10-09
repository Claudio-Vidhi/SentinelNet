# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Verifica della procedura guidata (tutorial) e onboarding utente."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = ROOT / "templates" / "dashboard.html"
TUTORIALS_JS = ROOT / "static" / "js" / "tutorials.js"
I18N_JS = ROOT / "static" / "js" / "i18n.js"
GLOBALS_D_TS = ROOT / "types" / "globals.d.ts"


class TestTutorialsAndOnboarding(unittest.TestCase):

    def setUp(self):
        self.html = DASHBOARD.read_text(encoding="utf-8")
        self.js = TUTORIALS_JS.read_text(encoding="utf-8")
        self.i18n = I18N_JS.read_text(encoding="utf-8")
        self.globals = GLOBALS_D_TS.read_text(encoding="utf-8")

    def test_markup_elements_exist_in_template(self):
        self.assertIn('id="modalTutorialsHub"', self.html)
        self.assertIn('id="tutorialSvgMask"', self.html)
        self.assertIn('id="tutorialCutout"', self.html)
        self.assertIn('id="tutorialCard"', self.html)
        self.assertIn('id="onboardingWelcomeCard"', self.html)
        self.assertIn('id="btnOpenTutorials"', self.html)

    def test_tutorials_script_included_in_template(self):
        self.assertIn('<script src="/static/js/tutorials.js"></script>', self.html)

    def test_globals_declared_in_types(self):
        for name in (
            "startTutorial",
            "openTutorialsHub",
            "closeTutorialsHub",
            "initTutorialsOnboarding",
            "resetTutorialsOnboarding",
        ):
            self.assertIn(f"declare var {name}: any;", self.globals)
            self.assertIn(f"{name}: any;", self.globals)

    def test_tutorial_keys_exist_in_i18n(self):
        keys = re.findall(r"(?:titleKey|descKey|badgeKey|textKey):\s*['\"]([A-Za-z0-9_]+)['\"]", self.js)
        self.assertTrue(keys, "Nessuna chiave i18n trovata in tutorials.js")

        it_part, en_part = self.i18n.split("    en: {", 1)
        for key in set(keys):
            self.assertIn(f"{key}:", it_part, f"Chiave {key} mancante nel dizionario italiano")
            self.assertIn(f"{key}:", en_part, f"Chiave {key} mancante nel dizionario inglese")

    def test_every_step_target_exists(self):
        # A step whose #id left the template highlights nothing: the tour
        # silently shows a card over the whole page (two inventory steps did).
        targets = re.findall(r"target:\s*'#([A-Za-z0-9_-]+)", self.js)
        self.assertTrue(targets)
        for t in set(targets):
            with self.subTest(target=t):
                self.assertTrue(f'id="{t}"' in self.html, f"#{t} not in dashboard.html")

    def test_probe_and_history_tours_exist(self):
        for tour in ("probes:", "device_history:"):
            with self.subTest(tour=tour):
                self.assertIn(tour, self.js)
        self.assertIn("tab: 'tab-probes'", self.js)
        self.assertIn("tab: 'tab-device-history'", self.js)


if __name__ == "__main__":
    unittest.main()
