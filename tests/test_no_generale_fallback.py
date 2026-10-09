# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""«Generale» fallback removal ratchet (spec 2026-10-09 organizations-locations).
Every device row belongs to an organization; no organization is special.
A line that must keep it (the migration's empty-Group rule only) carries
'check-generale: ok'."""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "check-generale: ok"
SCANNED = re.compile(r"\.(py|js|mjs|html)$")
QUOTED = re.compile(r"""['"]Generale['"]""")


def offending(text: str):
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        if MARK in line:
            continue
        bad = QUOTED.findall(line)
        if bad:
            hits.append((n, bad))
    return hits


def _tracked():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout.splitlines()
    return [p for p in out if not p.startswith(("docs/", "tests/", "tests_data/"))]


class TestNoGeneraleFallback(unittest.TestCase):
    def _offenders(self):
        found = {}
        for rel in _tracked():
            if not SCANNED.search(rel):
                continue
            path = ROOT / rel
            if not path.is_file():
                continue
            hits = offending(path.read_text(encoding="utf-8", errors="replace"))
            if hits:
                found[rel] = hits
        return found

    def test_no_generale_fallback_in_codebase(self):
        offenders = self._offenders()
        self.assertEqual(offenders, {}, "remove Generale fallback, or mark with " + MARK)


if __name__ == "__main__":
    unittest.main()
