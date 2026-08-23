# -*- coding: utf-8 -*-
"""A tenant baseline: which lines must be there, which must not.

Deliberately not an audit — no score, no grade, no severity. One answer per
pattern: present, or missing.
"""
import unittest

from services.config_drift import baseline

CONFIG = (
    "hostname switch-01\n"
    "ip dhcp snooping\n"
    "ip http server\n"
    "login block-for 120 attempts 5 within 60\n"
)

BASELINE = (
    "+ ip dhcp snooping\n"
    "+ service password-encryption\n"
    "- ip http server\n"
    "- transport input telnet\n"
)


class BaselineMatching(unittest.TestCase):
    def test_a_missing_required_line_is_a_deviation(self):
        problems = baseline.evaluate("cisco", CONFIG, BASELINE)
        missing = [p for p in problems if p["problem"] == "missing"]
        self.assertEqual(["service password-encryption"],
                         [p["pattern"] for p in missing])

    def test_a_present_forbidden_line_is_a_deviation(self):
        problems = baseline.evaluate("cisco", CONFIG, BASELINE)
        present = [p for p in problems if p["problem"] == "present"]
        self.assertEqual(["ip http server"], [p["pattern"] for p in present])

    def test_a_compliant_config_has_no_deviations(self):
        config = "ip dhcp snooping\nservice password-encryption\n"
        self.assertEqual([], baseline.evaluate("cisco", config, BASELINE))

    def test_a_regex_pattern_is_honoured(self):
        self.assertEqual([], baseline.evaluate(
            "cisco", "banner motd ^C Reserved ^C\n", "+ /banner motd/\n"))

    def test_a_malformed_regex_is_not_a_crash(self):
        problems = baseline.evaluate("cisco", CONFIG, "+ /[unclosed/\n")
        self.assertEqual("missing", problems[0]["problem"])

    def test_blank_lines_and_comments_are_ignored(self):
        self.assertEqual(1, len(baseline.parse("\n# a comment\n+ ip dhcp snooping\n")))

    def test_a_line_without_a_marker_is_ignored(self):
        self.assertEqual([], baseline.parse("ip dhcp snooping\n"))

    def test_an_empty_baseline_reports_nothing(self):
        self.assertEqual([], baseline.evaluate("cisco", CONFIG, ""))


class SeedingProposesRulesWithoutSecrets(unittest.TestCase):
    def test_security_lines_are_proposed_as_required(self):
        seeded = baseline.seed_from_config("cisco", CONFIG)
        self.assertIn("+ ip dhcp snooping", seeded)

    def test_device_identity_is_not_proposed(self):
        """hostname and addresses differ per device by design: a baseline
        containing them would fail on the second switch."""
        self.assertNotIn("hostname", baseline.seed_from_config("cisco", CONFIG))

    def test_a_seeded_rule_carries_no_secret(self):
        """Seeded rules are proposed from a real device config, so they would
        otherwise carry that device's live credentials into a stored baseline."""
        seeded = baseline.seed_from_config(
            "cisco",
            "snmp-server group G v3 priv\n"
            "snmp-server user monitor G v3 auth sha AuthPhrase priv aes 128 PrivPhrase\n")
        self.assertNotIn("AuthPhrase", seeded)
        self.assertNotIn("PrivPhrase", seeded)


if __name__ == "__main__":
    unittest.main()
