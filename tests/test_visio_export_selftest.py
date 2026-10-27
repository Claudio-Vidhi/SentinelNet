# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Runs the self-test of services/visio_export.py (valid package, glued
cables with their formulas, one page per site), so the suite covers it."""

import os
import subprocess
import sys
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestVisioExportSelfTest(unittest.TestCase):

    def test_selftest(self):
        proc = subprocess.run([sys.executable, os.path.join("services", "visio_export.py")],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)
        self.assertIn("OK (pages)", proc.stdout)


if __name__ == "__main__":
    unittest.main()
