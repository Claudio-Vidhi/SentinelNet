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
        self.assertIn("onlineDevices.sort(", self.js)

    def test_live_result_opens_its_detail_row(self):
        # runEuvdQuery writes into results-<id>: that element must live in the
        # detail row runManagedVulnCheck un-hides.
        self.assertIn('id="ti-detail-${safeIpId}"', self.js)
        self.assertIn('<div id="results-${safeIpId}"', self.js)
        fn = self.js[self.js.index("async function runManagedVulnCheck"):]
        self.assertIn("`ti-detail-${safeIpId}`", fn[:400])


if __name__ == "__main__":
    unittest.main()
