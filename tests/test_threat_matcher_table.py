# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Threat Intel matcher: one ranked table, live NVD checks on request only."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class TheMatcherIsATable(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = (ROOT / "static/js/threat-intel.js").read_text(encoding="utf-8")
        cls.html = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")

    def test_analyze_all_button_is_bound(self):
        self.assertIn('id="btnThreatAnalyzeAll"', self.html)
        self.assertIn("getElementById('btnThreatAnalyzeAll')?.addEventListener('click', analyzeAllThreats)", self.js)

    def test_analyze_all_queries_nvd_one_device_at_a_time(self):
        # Parallel queries hit the NVD rate limit and turn rows into errors.
        body = self.js[self.js.index("async function analyzeAllThreats"):]
        body = body[:body.index("\n    }\n")]
        self.assertIn("await runManagedVulnCheck", body)
        self.assertNotIn("Promise.all", body)

    def test_rows_are_ranked_by_stored_counts(self):
        self.assertIn("/api/cve/summary?tenant=", self.js)
        self.assertIn("tiGroups.sort(", self.js)
        self.assertIn("function tiRank", self.js)

    def test_live_result_opens_its_detail_row(self):
        # runEuvdQuery writes into results-<id>: that element must live in the
        # detail row runManagedVulnCheck un-hides. The firmware row is keyed by
        # its first device's IP, which is the data-ip its button sends.
        self.assertIn('id="ti-detail-${sid}"', self.js)
        self.assertIn('<div id="results-${sid}"', self.js)
        self.assertIn("g.id = g.rep.IP.replace(/\./g, '-')", self.js)
        self.assertIn('data-ip="${escapeHtml(g.rep.IP)}"', self.js)
        fn = self.js[self.js.index("async function runManagedVulnCheck"):]
        self.assertIn("`ti-detail-${safeIpId}`", fn[:400])


    def test_one_row_per_firmware(self):
        # Same vendor + model + version share one NVD answer: one row, not one per device.
        self.assertIn("[(d.Vendor || '').toLowerCase(), model, version].join('|')", self.js)
        self.assertIn('<tbody class="ti-group"', self.js)

    def test_analyze_all_also_refreshes_the_archive_from_cache(self):
        start = self.js.index("async function analyzeAllThreats")
        body = self.js[start:self.js.index("document.getElementById('securityTriageContainer')", start)]
        self.assertIn("/refresh?fresh=false", body)
        self.assertIn("tiRenderStored(", body)


if __name__ == "__main__":
    unittest.main()
