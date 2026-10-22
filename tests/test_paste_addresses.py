# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Pasted addresses in the CSV import: the node harness runs the real parser."""

import os
import shutil
import subprocess
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestPasteAddresses(unittest.TestCase):
    def test_parser(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node non disponibile")
        proc = subprocess.run([node, os.path.join(_REPO_ROOT, "tests", "js", "test_paste_addresses.mjs")],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)

    def test_paste_box_is_wired(self):
        with open(os.path.join(_REPO_ROOT, "templates", "dashboard.html"), encoding="utf-8") as f:
            html = f.read()
        self.assertIn('<label for="importPasteBox"', html)
        self.assertIn('id="importPasteBox"', html)


if __name__ == "__main__":
    unittest.main()
