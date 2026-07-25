# -*- coding: utf-8 -*-
"""Test del modello di stato e delle singole regole del motore di audit."""

import os
import unittest

from services.netsec_audit.model import (
    FAIL, PASS, UNKNOWN, WARN, Evidence, RuleOutcome, score_rules)
from services.netsec_audit import rules
from services.netsec_audit.parser import parse_with_lines

_FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def _load(name):
    with open(os.path.join(_FIX, name), encoding="utf-8") as fh:
        return parse_with_lines(fh.read())


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


class _RuleBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bad = _load("fortigate_violations.conf")
        cls.good = _load("fortigate_clean.conf")
        cls.partial = _load("fortigate_partial.conf")

    def assertEvidenceLine(self, outcome, needle):
        """L'evidenza deve citare una riga che contiene davvero la direttiva."""
        self.assertTrue(outcome.evidence, "nessuna evidenza allegata")
        joined = " | ".join(e.text for e in outcome.evidence)
        self.assertIn(needle, joined)
        for e in outcome.evidence:
            self.assertGreater(e.line, 0)


class TestHardeningRules(_RuleBase):
    def test_management_protocols_fails_on_telnet(self):
        o = rules.check_management_protocols(self.bad)
        self.assertEqual(o.status, FAIL)
        self.assertEvidenceLine(o, "telnet")
        self.assertIn("port1", " ".join(e.context for e in o.evidence))

    def test_management_protocols_passes_when_clean(self):
        self.assertEqual(
            rules.check_management_protocols(self.good).status, PASS)

    def test_management_protocols_unknown_without_interfaces(self):
        self.assertEqual(
            rules.check_management_protocols(self.partial).status, UNKNOWN)

    def test_management_protocols_ignores_telnet_outside_allowaccess(self):
        """Le parole 'telnet'/'http' fuori da 'allowaccess' non devono generare
        un falso FAIL: il vecchio motore a substring cercava questi termini
        nell'intero testo (commenti compresi) e ci cascava."""
        cfg = parse_with_lines(
            '# telnet era abilitato prima di questo audit, ora disattivato\n'
            'config system interface\n'
            '    edit "port1"\n'
            '        set role wan\n'
            '        set allowaccess ping https\n'
            '        set comment "fallback raggiungibile su http://10.0.0.1/status"\n'
            '    next\n'
            'end\n'
            'config firewall service custom\n'
            '    edit "TELNET-LEGACY-BLOCK"\n'
            '        set tcp-portrange 23\n'
            '    next\n'
            'end\n')
        self.assertEqual(
            rules.check_management_protocols(cfg).status, PASS)

    def test_management_protocols_evidence_points_at_the_allowaccess_line(self):
        """L'evidenza deve citare esattamente la riga 'allowaccess', non una
        riga qualunque del blocco 'edit'."""
        text = (
            'config system interface\n'            # riga 1
            '    edit "port1"\n'                    # riga 2
            '        set role wan\n'                 # riga 3
            '        set allowaccess ping telnet\n'  # riga 4
            '    next\n'                             # riga 5
            'end\n')                                 # riga 6
        o = rules.check_management_protocols(parse_with_lines(text))
        self.assertEqual(o.status, FAIL)
        self.assertEqual(len(o.evidence), 1)
        self.assertEqual(o.evidence[0].line, 4)
        self.assertIn("telnet", o.evidence[0].text)

    def test_tls_fails_on_deprecated_version(self):
        o = rules.check_tls_version(self.bad)
        self.assertEqual(o.status, FAIL)
        self.assertEvidenceLine(o, "TLSv1-1")

    def test_tls_passes_on_12(self):
        self.assertEqual(rules.check_tls_version(self.good).status, PASS)

    def test_tls_warns_when_unset_but_global_present(self):
        cfg = parse_with_lines("config system global\n set admintimeout 5\nend\n")
        self.assertEqual(rules.check_tls_version(cfg).status, WARN)

    def test_tls_unknown_without_global_block(self):
        self.assertEqual(rules.check_tls_version(parse_with_lines("")).status,
                         UNKNOWN)

    def test_tls_ignores_weak_version_mentioned_outside_the_setting(self):
        """'sslv3'/'tlsv1.1' citate in un commento o in un campo 'comment' non
        devono generare un falso FAIL: la regola legge solo la direttiva
        'ssl-min-proto-version', non l'intero testo della configurazione."""
        cfg = parse_with_lines(
            '# ricordo: sslv3 e tlsv1.1 sono bandite dalla policy aziendale\n'
            'config system global\n'
            '    set ssl-min-proto-version TLSv1-2\n'
            'end\n'
            'config system admin\n'
            '    edit "admin"\n'
            '        set comment "non usare sslv3"\n'
            '    next\n'
            'end\n')
        self.assertEqual(rules.check_tls_version(cfg).status, PASS)

    def test_idle_timeout_fails_on_zero(self):
        o = rules.check_idle_timeout(self.bad)
        self.assertEqual(o.status, FAIL)
        self.assertEvidenceLine(o, "admintimeout 0")

    def test_idle_timeout_fails_when_too_long(self):
        cfg = parse_with_lines(
            "config system global\n set admintimeout 480\nend\n")
        self.assertEqual(rules.check_idle_timeout(cfg).status, FAIL)

    def test_idle_timeout_passes_at_ten(self):
        self.assertEqual(rules.check_idle_timeout(self.good).status, PASS)

    def test_idle_timeout_unknown_without_global(self):
        self.assertEqual(
            rules.check_idle_timeout(parse_with_lines("")).status, UNKNOWN)

    def test_strong_crypto_warns_when_disabled(self):
        o = rules.check_strong_crypto(self.bad)
        self.assertEqual(o.status, WARN)
        self.assertEvidenceLine(o, "strong-crypto")

    def test_strong_crypto_passes_when_enabled(self):
        self.assertEqual(rules.check_strong_crypto(self.good).status, PASS)


if __name__ == "__main__":
    unittest.main()
