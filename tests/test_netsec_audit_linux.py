# -*- coding: utf-8 -*-
"""Test del parser e delle regole Linux del motore di audit.

Due comportamenti valgono piu' di ogni singola regola, quindi vengono per
primi: un artefatto Linux NON deve essere scambiato per una configurazione
FortiOS (il fallback storico del motore), e l'assenza di una direttiva deve
significare cose diverse a seconda del file — su sshd vale il default
compilato, su sysctl.conf non vale niente perche' il valore puo' stare in
«sysctl.d/». Sbagliare l'una o l'altra produce verdetti inventati.
"""

import os
import unittest

from services import netsec_audit
from services.netsec_audit import linux_parser, linux_rules
from services.netsec_audit.benchmarks import FORTIOS, IOS, LINUX
from services.netsec_audit.model import FAIL, PASS, UNKNOWN, WARN

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return fh.read()


def _parse(name):
    return linux_parser.parse_linux(_fixture(name))


class TestLinuxParser(unittest.TestCase):
    def setUp(self):
        self.cfg = _parse("linux_clean.conf")

    def test_the_artifact_is_split_per_file(self):
        for path in ("/etc/ssh/sshd_config", "/etc/login.defs",
                     "/etc/sysctl.conf", "/etc/fstab", "/etc/hosts"):
            self.assertTrue(linux_parser.has_file(self.cfg, path), path)

    def test_a_directive_belongs_only_to_its_own_file(self):
        """Una riga di /etc/hosts non deve poter rispondere a una regola su
        sshd_config: e' l'unica cosa che il parser deve garantire."""
        hosts = linux_parser.file_lines(self.cfg, "/etc/hosts")
        self.assertTrue(hosts)
        self.assertFalse(linux_parser.directives(hosts, "permitrootlogin"))

    def test_commented_directives_are_not_configuration(self):
        cfg = _parse("linux_violations.conf")
        sshd = linux_parser.file_lines(cfg, "/etc/ssh/sshd_config")
        self.assertIsNone(linux_parser.first_directive(sshd, "banner"))

    def test_line_numbers_point_at_the_real_line(self):
        sshd = linux_parser.file_lines(self.cfg, "/etc/ssh/sshd_config")
        rec = linux_parser.first_directive(sshd, "maxauthtries")
        self.assertIsNotNone(rec)
        raw = _fixture("linux_clean.conf").splitlines()[rec.line - 1]
        self.assertEqual("MaxAuthTries 4", raw.strip())

    def test_the_last_assignment_wins_where_it_should(self):
        cfg = linux_parser.parse_linux(
            "--- /etc/login.defs ---\nPASS_MAX_DAYS 99999\nPASS_MAX_DAYS 90\n")
        line = linux_parser.last_directive(
            linux_parser.file_lines(cfg, "/etc/login.defs"), "pass_max_days")
        self.assertEqual("PASS_MAX_DAYS 90", line.text)

    def test_fstab_options_are_read_from_the_right_column(self):
        fstab = linux_parser.file_lines(self.cfg, "/etc/fstab")
        entry = linux_parser.fstab_entry(fstab, "/tmp")
        self.assertIsNotNone(entry)
        self.assertIn("noexec", linux_parser.fstab_options(entry))
        self.assertNotIn("noexec",
                         linux_parser.fstab_options(
                             linux_parser.fstab_entry(fstab, "/var")))

    def test_empty_input_is_empty_not_an_error(self):
        for value in (None, "", "   \n\n"):
            self.assertTrue(linux_parser.is_empty(
                linux_parser.parse_linux(value)))

    def test_garbage_does_not_raise(self):
        cfg = linux_parser.parse_linux("--- ---\n\x00\x01 spazzatura\n--- /x ---")
        self.assertIsInstance(cfg.files, dict)


class TestVendorDetection(unittest.TestCase):
    def test_a_linux_artifact_is_not_mistaken_for_fortios(self):
        """Il motore ripiega su FortiOS quando non riconosce il testo: senza
        marcatori Linux un backup di server verrebbe valutato con le regole
        sbagliate e uscirebbe tutto UNKNOWN, che sembra un esito ma non lo e'."""
        self.assertEqual(LINUX,
                         netsec_audit.detect_vendor(_fixture("linux_clean.conf")))
        self.assertEqual(LINUX,
                         netsec_audit.detect_vendor(_fixture("linux_violations.conf")))

    def test_the_other_two_platforms_still_win_on_their_own_text(self):
        self.assertEqual(IOS, netsec_audit.detect_vendor(_fixture("ios_clean.conf")))
        self.assertEqual(FORTIOS,
                         netsec_audit.detect_vendor(_fixture("fortigate_clean.conf")))

    def test_unattributable_text_stays_none(self):
        self.assertIsNone(netsec_audit.detect_vendor("ciao\nmondo\n"))
        self.assertIsNone(netsec_audit.detect_vendor(""))


class TestCleanConfiguration(unittest.TestCase):
    def setUp(self):
        self.cfg = _parse("linux_clean.conf")

    def test_every_rule_passes(self):
        failed = []
        for tmpl in netsec_audit.BENCHMARKS["cis"]:
            if tmpl["vendor"] != LINUX:
                continue
            outcome = tmpl["check"](self.cfg)
            if outcome.status != PASS:
                failed.append((tmpl["id"], outcome.status, outcome.message))
        self.assertEqual([], failed)


class TestViolations(unittest.TestCase):
    def setUp(self):
        self.cfg = _parse("linux_violations.conf")

    def _status(self, check):
        return check(self.cfg).status

    def test_ssh_violations_are_failures(self):
        for check in (linux_rules.check_linux_sshd_permit_root_login,
                      linux_rules.check_linux_sshd_permit_empty_passwords,
                      linux_rules.check_linux_sshd_hostbased_auth,
                      linux_rules.check_linux_sshd_ignore_rhosts,
                      linux_rules.check_linux_sshd_disable_forwarding,
                      linux_rules.check_linux_sshd_max_auth_tries,
                      linux_rules.check_linux_sshd_login_grace_time,
                      linux_rules.check_linux_sshd_client_alive,
                      linux_rules.check_linux_sshd_log_level,
                      linux_rules.check_linux_sshd_banner):
            self.assertEqual(FAIL, self._status(check), check.__name__)

    def test_password_policy_violations_are_failures(self):
        for check in (linux_rules.check_linux_pass_max_days,
                      linux_rules.check_linux_pass_min_days,
                      linux_rules.check_linux_pass_warn_age,
                      linux_rules.check_linux_encrypt_method):
            self.assertEqual(FAIL, self._status(check), check.__name__)

    def test_network_parameter_violations_are_failures(self):
        for check in (linux_rules.check_linux_ip_forward,
                      linux_rules.check_linux_accept_redirects,
                      linux_rules.check_linux_send_redirects,
                      linux_rules.check_linux_source_route,
                      linux_rules.check_linux_tcp_syncookies,
                      linux_rules.check_linux_log_martians):
            self.assertEqual(FAIL, self._status(check), check.__name__)

    def test_a_failure_cites_the_exact_line(self):
        outcome = linux_rules.check_linux_sshd_permit_root_login(self.cfg)
        self.assertEqual(1, len(outcome.evidence))
        self.assertEqual("PermitRootLogin yes", outcome.evidence[0].text)
        raw = _fixture("linux_violations.conf").splitlines()
        self.assertEqual("PermitRootLogin yes",
                         raw[outcome.evidence[0].line - 1].strip())

    def test_mount_options_report_which_ones_are_missing(self):
        outcome = linux_rules.check_linux_tmp_mount_options(self.cfg)
        self.assertEqual(FAIL, outcome.status)
        self.assertEqual("nodev, nosuid, noexec", outcome.params["missing"])


class TestAbsenceMeansDifferentThingsPerFile(unittest.TestCase):
    """Il cuore delle regole Linux: cosa vuol dire che una riga non c'e'."""

    def _cfg(self, text):
        return linux_parser.parse_linux(text)

    def test_sshd_absent_directive_falls_back_to_the_compiled_default(self):
        # Nessun Include: quello che non e' scritto vale il default di OpenSSH.
        cfg = self._cfg("--- /etc/ssh/sshd_config ---\nPort 22\n")
        # Default 'prohibit-password' -> non conforme.
        self.assertEqual(
            FAIL, linux_rules.check_linux_sshd_permit_root_login(cfg).status)
        # Default 'no' -> conforme, senza che nessuno l'abbia scritto.
        self.assertEqual(
            PASS, linux_rules.check_linux_sshd_permit_empty_passwords(cfg).status)
        # Default 'INFO' -> conforme.
        self.assertEqual(
            PASS, linux_rules.check_linux_sshd_log_level(cfg).status)

    def test_sshd_with_include_is_not_assessable_from_the_file_alone(self):
        cfg = self._cfg("--- /etc/ssh/sshd_config ---\n"
                        "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
        outcome = linux_rules.check_linux_sshd_permit_root_login(cfg)
        self.assertEqual(UNKNOWN, outcome.status)

    def test_the_effective_config_wins_over_the_file(self):
        """`sshd -T` e' cio' che il demone applica davvero: quando il triage
        privilegiato lo raccoglie, la direttiva Include non e' piu' un dubbio."""
        cfg = self._cfg("--- /etc/ssh/sshd_config ---\n"
                        "Include /etc/ssh/sshd_config.d/*.conf\n"
                        "PermitRootLogin yes\n"
                        "--- SSHD EFFECTIVE CONFIG ---\n"
                        "permitrootlogin no\nmaxauthtries 4\n")
        self.assertEqual(
            PASS, linux_rules.check_linux_sshd_permit_root_login(cfg).status)
        self.assertEqual(
            PASS, linux_rules.check_linux_sshd_max_auth_tries(cfg).status)

    def test_sysctl_absent_parameter_is_not_a_verdict(self):
        # Puo' stare in /etc/sysctl.d/ o essere impostato a runtime: nessuna
        # delle due cose e' nel backup.
        cfg = self._cfg("--- /etc/sysctl.conf ---\nkernel.pid_max = 65536\n")
        self.assertEqual(UNKNOWN,
                         linux_rules.check_linux_ip_forward(cfg).status)

    def test_login_defs_absent_directive_is_a_missing_policy(self):
        cfg = self._cfg("--- /etc/login.defs ---\nUMASK 027\n")
        self.assertEqual(FAIL,
                         linux_rules.check_linux_pass_max_days(cfg).status)

    def test_a_mount_point_without_an_fstab_entry_is_not_a_verdict(self):
        cfg = self._cfg("--- /etc/fstab ---\n/dev/sda1 / ext4 defaults 0 1\n")
        self.assertEqual(
            UNKNOWN, linux_rules.check_linux_tmp_mount_options(cfg).status)

    def test_a_section_missing_from_the_artifact_is_unknown(self):
        # Backup parziale, non host non conforme.
        cfg = self._cfg("--- /etc/hosts ---\n127.0.0.1 localhost\n")
        for check in (linux_rules.check_linux_sshd_permit_root_login,
                      linux_rules.check_linux_pass_max_days,
                      linux_rules.check_linux_ip_forward,
                      linux_rules.check_linux_tmp_mount_options):
            self.assertEqual(UNKNOWN, check(cfg).status, check.__name__)

    def test_an_unreadable_numeric_value_warns_instead_of_guessing(self):
        cfg = self._cfg("--- /etc/ssh/sshd_config ---\nMaxAuthTries molte\n")
        self.assertEqual(
            WARN, linux_rules.check_linux_sshd_max_auth_tries(cfg).status)


class TestReportShape(unittest.TestCase):
    def test_only_linux_rules_are_evaluated(self):
        res = netsec_audit.run_netsec_audit(
            config_text=_fixture("linux_violations.conf"), device_name="web-01")
        self.assertEqual(LINUX, res["vendor"])
        self.assertEqual({LINUX}, {r["vendor"] for r in res["rules"]})
        self.assertTrue(res["rules"])
        self.assertTrue(all(r["id"].startswith("AUD-LNX-") for r in res["rules"]))

    def test_a_clean_host_scores_a_hundred(self):
        res = netsec_audit.run_netsec_audit(
            config_text=_fixture("linux_clean.conf"))
        self.assertEqual(100, res["score"])
        self.assertEqual(0, res["summary"]["failed"])

    def test_every_rule_cites_its_benchmark_recommendation(self):
        res = netsec_audit.run_netsec_audit(
            config_text=_fixture("linux_clean.conf"))
        self.assertTrue(all(r["ref"] for r in res["rules"]))


if __name__ == "__main__":
    unittest.main()
