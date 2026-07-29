# -*- coding: utf-8 -*-
"""Test del parser e delle regole Cisco IOS XE del motore di audit.

Il parser IOS ha due comportamenti che nessuna regola puo' compensare se
sbagliati, quindi sono verificati per primi: il corpo di un banner e il dump
esadecimale di un certificato NON sono configurazione, e leggerli come tale
produce verdetti inventati (un 'transport input telnet' dentro un certificato
farebbe fallire una linea vty che non esiste).
"""

import os
import unittest

from services import netsec_audit
from services.netsec_audit import ios_parser, ios_rules
from services.netsec_audit.model import FAIL, PASS, UNKNOWN, WARN

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return fh.read()


class TestIosParser(unittest.TestCase):
    def setUp(self):
        self.cfg = ios_parser.parse_ios(_fixture("ios_clean.conf"))

    def test_banner_body_is_not_configuration(self):
        for text in ("accesso riservato", "ogni attivita'"):
            self.assertFalse(
                [l for l in self.cfg.lines if text in l.lower],
                "il corpo del banner e' finito fra le righe di configurazione")

    def test_banner_header_is_kept(self):
        self.assertTrue(ios_parser.find(self.cfg, "banner login"))
        self.assertTrue(ios_parser.find(self.cfg, "banner motd"))

    def test_certificate_dump_is_skipped(self):
        """Il dump contiene di proposito 'no cdp run' e 'transport input
        telnet': se il parser li leggesse, due regole cambierebbero verdetto."""
        self.assertFalse([l for l in self.cfg.lines if "30820330" in l.lower])
        self.assertEqual(
            1, len([l for l in self.cfg.lines if l.lower == "no cdp run"]))
        self.assertFalse([l for l in self.cfg.lines
                          if l.lower == "transport input telnet"])

    def test_blocks_carry_their_children(self):
        vtys = ios_parser.blocks_matching(self.cfg, "line vty")
        self.assertEqual(2, len(vtys))
        for _, kids in vtys:
            self.assertIsNotNone(ios_parser.child(kids, "transport input"))
            self.assertIsNotNone(ios_parser.child(kids, "access-class"))

    def test_children_are_not_global_commands(self):
        """'exec-timeout' vive dentro una linea, non al livello globale."""
        self.assertFalse(ios_parser.find_top(self.cfg, "exec-timeout"))
        self.assertTrue(ios_parser.find(self.cfg, "exec-timeout"))

    def test_line_numbers_point_at_the_real_line(self):
        rec = ios_parser.first_top(self.cfg, "ip ssh version")
        self.assertIsNotNone(rec)
        raw = _fixture("ios_clean.conf").splitlines()[rec.line - 1]
        self.assertEqual("ip ssh version 2", raw.strip())

    def test_comments_and_blank_lines_are_dropped(self):
        self.assertFalse([l for l in self.cfg.lines if l.text.startswith("!")])

    def test_unterminated_banner_does_not_swallow_the_file(self):
        text = "banner motd ^C\nriga di banner\n" \
               + "riempitivo\n" * 150 + "hostname switch-01\n"
        cfg = ios_parser.parse_ios(text)
        self.assertTrue(ios_parser.find_top(cfg, "hostname"))

    def test_empty_input_is_empty_not_an_error(self):
        for value in (None, "", "   \n\n"):
            self.assertTrue(ios_parser.is_empty(ios_parser.parse_ios(value)))


class TestIosRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clean = ios_parser.parse_ios(_fixture("ios_clean.conf"))
        cls.bad = ios_parser.parse_ios(_fixture("ios_violations.conf"))

    def test_clean_config_passes_every_rule(self):
        failures = [(name, fn(self.clean).status, fn(self.clean).detail)
                    for name, fn in _all_rules()
                    if fn(self.clean).status != PASS]
        self.assertEqual([], failures)

    def test_violations_are_detected(self):
        statuses = {name: fn(self.bad).status for name, fn in _all_rules()}
        for name in ("check_ios_vty_transport_ssh", "check_ios_enable_secret",
                     "check_ios_snmp_default_community",
                     "check_ios_snmp_readwrite", "check_ios_ssh_version",
                     "check_ios_cdp", "check_ios_logging_host",
                     "check_ios_ntp_servers", "check_ios_banner_motd",
                     "check_ios_source_route"):
            self.assertEqual(FAIL, statuses[name], name)

    def test_every_non_pass_outcome_cites_evidence(self):
        for name, fn in _all_rules():
            out = fn(self.bad)
            if out.status in (FAIL, WARN):
                self.assertTrue(out.evidence, "%s senza evidenza" % name)

    def test_unknown_outcomes_carry_no_evidence(self):
        empty = ios_parser.parse_ios("")
        for name, fn in _all_rules():
            out = fn(empty)
            self.assertEqual(UNKNOWN, out.status, name)
            self.assertEqual((), tuple(out.evidence), name)

    def test_absent_aux_port_is_not_a_violation(self):
        """Molti apparati non hanno una porta ausiliaria: assenza != violazione."""
        cfg = ios_parser.parse_ios("hostname switch-01\nline vty 0 4\n"
                                   " transport input ssh\n")
        self.assertEqual(UNKNOWN, ios_rules.check_ios_aux_no_exec(cfg).status)

    def test_missing_no_service_is_warn_not_fail(self):
        """IOS non stampa i default: senza 'show running-config all' non si puo'
        affermare che il servizio sia attivo, solo che non e' spento."""
        cfg = ios_parser.parse_ios("hostname switch-01\n")
        self.assertEqual(WARN, ios_rules.check_ios_cdp(cfg).status)

    def test_login_method_none_fails(self):
        cfg = ios_parser.parse_ios(
            "aaa new-model\naaa authentication login default none\n")
        out = ios_rules.check_ios_aaa_authentication_login(cfg)
        self.assertEqual(FAIL, out.status)


class TestIosBenchmarkIntegration(unittest.TestCase):
    def test_vendor_detection(self):
        self.assertEqual(netsec_audit.IOS,
                         netsec_audit.detect_vendor(_fixture("ios_clean.conf")))
        self.assertEqual(
            netsec_audit.FORTIOS,
            netsec_audit.detect_vendor(_fixture("fortigate_clean.conf")))
        self.assertIsNone(netsec_audit.detect_vendor(""))
        self.assertIsNone(netsec_audit.detect_vendor("solo testo qualunque"))

    def test_ios_config_is_evaluated_with_ios_rules(self):
        res = netsec_audit.run_netsec_audit(
            config_text=_fixture("ios_clean.conf"), benchmark="cis")
        self.assertEqual(netsec_audit.IOS, res["vendor"])
        self.assertEqual(100, res["score"])
        self.assertTrue(res["rules"])
        for r in res["rules"]:
            self.assertEqual(netsec_audit.IOS, r["vendor"])

    def test_ios_violations_score_low_and_cite_lines(self):
        res = netsec_audit.run_netsec_audit(
            config_text=_fixture("ios_violations.conf"), benchmark="cis")
        self.assertLess(res["score"], 20)
        for r in res["rules"]:
            if r["status"] == FAIL:
                self.assertTrue(r["evidence"], r["id"])

    def test_fortios_rules_are_not_run_on_an_ios_config(self):
        """Valutare una running-config Cisco col parser FortiOS produrrebbe
        soltanto UNKNOWN: un risultato che sembra un esito senza esserlo."""
        res = netsec_audit.run_netsec_audit(
            config_text=_fixture("ios_clean.conf"), benchmark="cis")
        self.assertFalse([r for r in res["rules"]
                          if r["vendor"] == netsec_audit.FORTIOS])

    def test_every_rule_declares_its_metadata(self):
        for key, entries in netsec_audit.BENCHMARKS.items():
            for tmpl in entries:
                for field in ("vendor", "ref", "level", "automated", "audit",
                              "remediation", "check"):
                    self.assertIn(field, tmpl, "%s / %s" % (key, tmpl["id"]))
                self.assertIn(tmpl["vendor"],
                              (netsec_audit.FORTIOS, netsec_audit.IOS))
                self.assertIn(tmpl["level"], (1, 2))
                self.assertTrue((tmpl["check"].__doc__ or "").strip(),
                                "%s senza docstring" % tmpl["id"])

    def test_rule_ids_are_unique_per_benchmark(self):
        for key, entries in netsec_audit.BENCHMARKS.items():
            ids = [t["id"] for t in entries]
            self.assertEqual(len(ids), len(set(ids)), key)


def _all_rules():
    return sorted((n, getattr(ios_rules, n)) for n in dir(ios_rules)
                  if n.startswith("check_ios_"))


if __name__ == "__main__":
    unittest.main()
