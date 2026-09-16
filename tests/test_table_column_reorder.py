# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Python wrapper for the column-reorder node harness (see AGENTS.md pattern:
tests/js/*.mjs eval the real static/js/core.js against a stub DOM; a grep on
strings would not catch a permutation bug that leaves the right words in the
source while moving the wrong cell)."""

import os
import shutil
import subprocess
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestTableColumnReorder(unittest.TestCase):

    @unittest.skipUnless(shutil.which("node"), "node non disponibile")
    def test_reorder_logic_runs_against_a_stub_dom(self):
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_table_column_reorder.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                               capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


if __name__ == "__main__":
    unittest.main()
