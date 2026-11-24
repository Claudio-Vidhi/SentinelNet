# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Search box on top of device dropdowns (static/js/ui-select-search.js)."""

import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


class TestSelectSearch(unittest.TestCase):

    def test_matcher_runs_for_real(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node non disponibile")
        harness = os.path.join(_ROOT, "tests", "js", "test_select_search.mjs")
        proc = subprocess.run([node, harness], capture_output=True, text=True, cwd=_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)

    def test_dashboard_loads_the_script(self):
        html = (_ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn('<script src="/static/js/ui-select-search.js"></script>', html)

    def test_device_selects_are_marked(self):
        sources = [_ROOT / "templates" / "dashboard.html", *(_ROOT / "static" / "js").glob("*.js")]
        n = sum(len(re.findall(r"<select[^>]*\bdata-device-search\b", p.read_text(encoding="utf-8")))
                for p in sources)
        self.assertGreaterEqual(n, 8)


if __name__ == "__main__":
    unittest.main()
