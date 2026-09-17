# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Python wrapper for tests/js/test_endpoint_inventory_ui.mjs, so the suite runs it."""

import os
import shutil
import subprocess
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestEndpointInventoryUi(unittest.TestCase):

    @unittest.skipUnless(shutil.which("node"), "node non disponibile")
    def test_harness(self):
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_endpoint_inventory_ui.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


if __name__ == "__main__":
    unittest.main()
