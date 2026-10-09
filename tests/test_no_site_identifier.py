# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
""""site" meant *probe* and is gone: one name per concept (spec
2026-10-09-site-to-probe-rename-design.md). A new site_... is a red test.

A line that must keep the spelling (the CSV alias for old exports, the test
asserting old headers are refused, the migration's old names) carries the
marker below; adding one is a reviewable diff, the same rule as
check_no_private_data.

PENDING lists files not renamed yet. It only shrinks: a listed file that no
longer offends fails too, so the list cannot go stale."""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "check-site-name: ok"
SCANNED = re.compile(r"\.(py|js|mjs|html|ts|sql|ps1|sh|spec|service)$")
TOKEN = re.compile(r"[A-Za-z0-9_-]*[Ss][Ii][Tt][Ee][A-Za-z0-9_-]*")
QUOTED = re.compile(r"""['"]Sites?['"]|/sites\b""")
# Words that merely contain the letters; each was reviewed.
WORDS = ("site-to-site", "prerequisite", "opposite", "offsite", "onsite",
         "composite", "website", "requisite", "parasite", "visited", "on-site",
         "samesite", "sitemap", "statusitem")

PENDING = frozenset({
    "routers/auth.py",
    "routers/deps.py",
    "static/js/core.js",
    "static/js/devices.js",
    "static/js/i18n.js",
    "static/js/topology.js",
    "templates/dashboard.html",
    "tests/js/test_layered_groups.mjs",
    "tests/js/test_layered_levels.mjs",
    "tests/js/test_map_layout.mjs",
    "tests/test_bugfix_batch.py",
    "tests/test_category_tenant_scope.py",
    "tests/test_classification_assist.py",
    "tests/test_classify_device_type.py",
    "tests/test_client_diagnosis.py",
    "tests/test_cloud_backup_api.py",
    "tests/test_cloud_backup_payload.py",
    "tests/test_cloud_backup_restore_script.py",
    "tests/test_cloud_backup_state.py",
    "tests/test_cloud_backup_sync.py",
    "tests/test_cloud_backup_transport.py",
    "tests/test_cloud_backup_verify.py",
    "tests/test_config_analyzer_panos.py",
    "tests/test_config_analyzer_scoping.py",
    "tests/test_device_meta_store.py",
    "tests/test_firewall_traffic.py",
    "tests/test_flow_siem.py",
    "tests/test_map_layered.py",
    "tests/test_route_table.py",
    "tests/test_scan_verify.py",
    "tests/test_settings_restart.py",
    "tests/test_ui_revamp.py",
})


def _bad(token: str) -> bool:
    t = token.lower()
    for w in WORDS:
        t = t.replace(w, "")
    return "site" in t and t not in ("site", "sites")


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


class TestNoSiteIdentifier(unittest.TestCase):
    def _offenders(self):
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

    def test_no_new_offenders(self):
        new = {p: h[:3] for p, h in self._offenders().items() if p not in PENDING}
        self.assertEqual(new, {}, "rename to probe, or mark the line with " + MARK)

    def test_pending_only_shrinks(self):
        stale = sorted(PENDING - set(self._offenders()))
        self.assertEqual(stale, [], "remove these from PENDING: they are clean")


if __name__ == "__main__":
    unittest.main()
