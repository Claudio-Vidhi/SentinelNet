# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""ui-wizard.js: the step panel shared by the site, device and provisioning
flows. The node harness runs the real file against a fake DOM."""
import os
import shutil
import subprocess
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class UiWizard(unittest.TestCase):
    def test_harness(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node non disponibile")
        proc = subprocess.run([node, os.path.join(_REPO_ROOT, "tests", "js", "test_ui_wizard.mjs")],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)

    def test_loaded_after_the_modal_manager_and_before_core(self):
        html = _read("templates", "dashboard.html")
        modal = html.find("/static/js/ui-modal.js")
        wizard = html.find("/static/js/ui-wizard.js")
        core = html.find("/static/js/core.js")
        self.assertTrue(0 < modal < wizard < core, "order must be ui-modal, ui-wizard, core")

    def test_exposure_is_declared(self):
        self.assertIn("window.createWizard = createWizard", _read("static", "js", "ui-wizard.js"))
        # A top-level function re-exposed on window: only the Window half is
        # declared, a `declare var` would duplicate the identifier.
        self.assertIn("createWizard: any;", _read("types", "globals.d.ts"))


if __name__ == "__main__":
    unittest.main()
