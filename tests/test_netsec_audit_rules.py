# -*- coding: utf-8 -*-
"""Test del modello di stato e delle singole regole del motore di audit."""

import unittest

from services.netsec_audit.model import (
    FAIL, PASS, UNKNOWN, WARN, Evidence, RuleOutcome, score_rules)


class TestScoring(unittest.TestCase):
    def _rules(self, *statuses):
        return [{"status": s} for s in statuses]

    def test_unknown_is_excluded_from_the_denominator(self):
        """Una sezione assente non deve ne' gonfiare ne' deprimere il punteggio."""
        score, summary = score_rules(self._rules(PASS, PASS, FAIL, UNKNOWN))
        self.assertEqual(score, 67)          # 2 su 3, non 2 su 4
        self.assertEqual(summary["unknown"], 1)
        self.assertEqual(summary["total"], 4)

    def test_all_unknown_yields_no_score(self):
        score, summary = score_rules(self._rules(UNKNOWN, UNKNOWN))
        self.assertIsNone(score)
        self.assertEqual(summary["unknown"], 2)

    def test_warn_counts_against_the_score(self):
        score, _ = score_rules(self._rules(PASS, WARN))
        self.assertEqual(score, 50)

    def test_empty_rule_list(self):
        score, summary = score_rules([])
        self.assertIsNone(score)
        self.assertEqual(summary["total"], 0)


class TestRuleOutcome(unittest.TestCase):
    def test_evidence_defaults_to_empty(self):
        o = RuleOutcome(PASS, "tutto a posto")
        self.assertEqual(list(o.evidence), [])

    def test_evidence_carries_line_and_context(self):
        e = Evidence(42, "set allowaccess telnet", "system interface / port1")
        o = RuleOutcome(FAIL, "telnet abilitato", [e])
        self.assertEqual(o.evidence[0].line, 42)
        self.assertEqual(o.evidence[0].context, "system interface / port1")


if __name__ == "__main__":
    unittest.main()
