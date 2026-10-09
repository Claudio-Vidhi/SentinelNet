# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""«Generale» fallback removal ratchet (spec 2026-10-09 organizations-locations).
Every device row belongs to an organization; no organization is special.
A line that must keep it (the migration's empty-Group rule only) carries
'check-generale: ok'.

PENDING lists files not cleaned up yet. It only shrinks: a listed file that no
longer offends fails too, so the list cannot go stale."""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "check-generale: ok"
SCANNED = re.compile(r"\.(py|js|mjs|html)$")
QUOTED = re.compile(r"""['"]Generale['"]""")

PENDING = frozenset({
    "routers/agent.py",
    "routers/ai.py",
    "routers/analyzer.py",
    "routers/arp.py",
    "routers/backup.py",
    "routers/catalog.py",
    "routers/commands.py",
    "routers/cve.py",
    "routers/deps.py",
    "routers/firewall_traffic.py",
    "routers/fortigate.py",
    "routers/interface_errors.py",
    "routers/inventory.py",
    "routers/mac.py",
    "routers/manual_config.py",
    "routers/probes.py",
    "routers/provisioner.py",
    "routers/route_table.py",
    "routers/settings.py",
    "routers/triage.py",
    "static/js/ai.js",
    "static/js/client-map.js",
    "static/js/devices.js",
    "static/js/i18n.js",
    "static/js/netsec-audit.js",
    "static/js/policy-test.js",
    "static/js/probe-agent.js",
    "static/js/provisioning.js",
    "static/js/topology.js",
    "static/js/wlc.js",
    "templates/dashboard.html",
})


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

    def test_no_new_offenders(self):
        offenders = self._offenders()
        new = {p: h[:3] for p, h in offenders.items() if p not in PENDING}
        self.assertEqual(new, {}, "remove Generale fallback, or mark with " + MARK)

    def test_pending_only_shrinks(self):
        stale = sorted(PENDING - set(self._offenders()))
        self.assertEqual(stale, [], "remove these from PENDING: they are clean")


if __name__ == "__main__":
    unittest.main()
