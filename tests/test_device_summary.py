# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Device PDF summary (static/js/device-summary-pdf.js): the node harness runs
the real zoneMatrix/deviceSummaryHtml against synthetic FortiOS and IOS data."""
import os
import shutil
import subprocess
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestDeviceSummary(unittest.TestCase):
    def test_harness(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_device_summary.mjs")
        proc = subprocess.run([node, harness], capture_output=True, text=True,
                              cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


if __name__ == "__main__":
    unittest.main()
