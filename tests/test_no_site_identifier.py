# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
""""site" meant *probe* and is gone: one name per concept (spec
2026-10-09-site-to-probe-rename-design.md). A new site_... is a red test.

A line that must keep the spelling (the CSV alias for old exports, the test
asserting old headers are refused, the migration's old names) carries the
marker below; adding one is a reviewable diff, the same rule as
check_no_private_data.

"site" for a tenant is the same confusion, so no tracked file may spell it;
there is no pending list."""
import functools
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "check-site-name: ok"
SCANNED = re.compile(r"\.(py|js|mjs|html|ts|sql|ps1|sh|spec|service)$")
TOKEN = re.compile(r"[A-Za-z0-9_-]*[Ss][Ii][Tt][Ee][A-Za-z0-9_-]*")
QUOTED = re.compile(r"""['"]sites?['"]|/sites?\b""", re.I)
# Words that merely contain the letters; each was reviewed.
WORDS = ("site-to-site", "prerequisite", "prerequisites", "opposite", "offsite", "onsite",
         "composite", "website", "requisite", "parasite", "visited", "on-site",
         "samesite", "sitemap", "statusitem", "cross-site")


_COMPOUNDS = [w for w in WORDS if "-" in w]
_PARTS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")


def _bad(token: str) -> bool:
    """Words are stripped only as a whole token or a hyphen-delimited part,
    never inside camelCase: SiteStatusItem is bad, SameSite is not."""
    low = token.lower()
    if low in ("site", "sites") or low in WORDS:
        return False
    for w in _COMPOUNDS:
        token = re.sub(r"(?<![A-Za-z0-9])" + re.escape(w) + r"(?![A-Za-z0-9])",
                       " ", token, flags=re.I)
    return any("site" in p and p not in WORDS
               for p in map(str.lower, _PARTS.findall(token)))


def offending(text: str):
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        if MARK in line:
            continue
        bad = [t for t in TOKEN.findall(line) if _bad(t)] + QUOTED.findall(line)
        if bad:
            hits.append((n, bad))
    return hits


def _tracked():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout.splitlines()
    return [p for p in out if not p.startswith("docs/")]


@functools.cache
def _offenders():
    found = {}
    for rel in _tracked():
        if rel == "tests/test_no_site_identifier.py":
            continue
        if _bad(Path(rel).name):
            found[rel] = [(0, ["<file name>"])]
            continue
        if not SCANNED.search(rel):
            continue
        hits = offending((ROOT / rel).read_text(encoding="utf-8", errors="replace"))
        if hits:
            found[rel] = hits
    return found


class TestNoSiteIdentifier(unittest.TestCase):
    def test_no_new_offenders(self):
        new = {p: h[:3] for p, h in _offenders().items()}
        self.assertEqual(new, {}, "rename to probe/tenant, or mark the line with " + MARK)

    def test_bad_token_rules(self):
        for t in ("site_id", "SiteStatusItem", "onSiteWizardClose", "allSites",
                  "site-a", "SITE_ID", "getWebsiteSite"):
            self.assertTrue(_bad(t), t)
        for t in ("is_prerequisite", "samesite", "SameSite", "fa-sitemap",
                  "site-to-site", "website", "visited", "cross-site", "site",
                  "sites", "isOpposite", "getWebsiteUrl"):
            self.assertFalse(_bad(t), t)

    def test_quoted_rules(self):
        for line in ("x['site']", 'y["Sites"]', "fetch('/api/site/1')", "/sites"):
            self.assertTrue(QUOTED.search(line), line)
        self.assertFalse(QUOTED.search("website"))


if __name__ == "__main__":
    unittest.main()
