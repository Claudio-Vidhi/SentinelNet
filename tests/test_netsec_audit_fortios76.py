# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""FortiOS 7.6 hardening checks and their benchmark."""

import unittest

from services import netsec_audit
from services.netsec_audit import rules
from services.netsec_audit.benchmarks import fortios_76
from services.netsec_audit.model import FAIL, PASS, UNKNOWN, WARN
from services.netsec_audit.parser import parse_with_lines


def _cfg(text):
    return parse_with_lines(text)


GLOBAL_WEAK = """config system global
    set hostname "fw-01"
end
"""

GLOBAL_STRONG = """config system global
    set dh-params 8192
    set private-data-encryption enable
    set admin-host "fw-01.example.net"
end
"""


class TestChecks(unittest.TestCase):
    def test_dh_params(self):
        self.assertEqual(WARN, rules.check_dh_params(_cfg(GLOBAL_WEAK)).status)
        self.assertEqual(PASS, rules.check_dh_params(_cfg(GLOBAL_STRONG)).status)
        weak = _cfg("config system global\n    set dh-params 2048\nend\n")
        self.assertEqual(WARN, rules.check_dh_params(weak).status)
        self.assertEqual(UNKNOWN, rules.check_dh_params(_cfg("")).status)

    def test_private_data_encryption_absent_is_fail(self):
        """Factory default is disable: absence is the violation."""
        self.assertEqual(FAIL, rules.check_private_data_encryption(
            _cfg(GLOBAL_WEAK)).status)
        self.assertEqual(PASS, rules.check_private_data_encryption(
            _cfg(GLOBAL_STRONG)).status)

    def test_admin_host(self):
        self.assertEqual(WARN, rules.check_admin_host(_cfg(GLOBAL_WEAK)).status)
        self.assertEqual(PASS, rules.check_admin_host(_cfg(GLOBAL_STRONG)).status)
        off = _cfg("config system global\n    set admin-https-redirect disable\nend\n")
        self.assertEqual(PASS, rules.check_admin_host(off).status)

    def test_legacy_password_hash_never_quotes_the_hash(self):
        cfg = _cfg("""config system admin
    edit "ops"
        set password ENC SH2AAAAhashvalue
    next
    edit "net"
        set password ENC PB2BBBBhashvalue
    next
end
""")
        out = rules.check_admin_password_hash(cfg)
        self.assertEqual(WARN, out.status)
        self.assertEqual(1, len(out.evidence))
        self.assertEqual("", out.evidence[0].text)
        self.assertIn("ops", out.evidence[0].context)

    def test_sslvpn_tunnel_mode(self):
        listening = """config vpn ssl settings
    set source-interface "wan1"
end
config vpn ssl web portal
    edit "full-access"
        set tunnel-mode enable
    next
    edit "web-access"
        set web-mode enable
    next
end
"""
        out = rules.check_sslvpn_tunnel_mode(_cfg(listening))
        self.assertEqual(WARN, out.status)
        self.assertEqual(1, len(out.evidence))
        idle = "config vpn ssl settings\n    set servercert \"x\"\nend\n"
        self.assertEqual(PASS, rules.check_sslvpn_tunnel_mode(_cfg(idle)).status)
        self.assertEqual(UNKNOWN, rules.check_sslvpn_tunnel_mode(_cfg(GLOBAL_WEAK)).status)

    def test_dos_policy(self):
        self.assertEqual(WARN, rules.check_dos_policy(_cfg(GLOBAL_WEAK)).status)
        cfg = _cfg("config firewall DoS-policy\n    edit 1\n"
                   "        set interface \"wan1\"\n    next\nend\n")
        self.assertEqual(PASS, rules.check_dos_policy(cfg).status)


POLICIES = """config firewall policy
    edit 1
        set name "lan-out"
        set srcintf "any"
        set dstintf "wan1"
        set action accept
    next
    edit 2
        set name "lan-out"
        set srcintf "port2"
        set dstintf "wan1"
        set action accept
    next
    edit 3
        set srcintf "wan1"
        set dstintf "port2"
        set match-vip disable
    next
end
"""


class TestBestPracticeChecks(unittest.TestCase):
    def test_admin_access_on_wan(self):
        cfg = _cfg("""config system interface
    edit "wan1"
        set role wan
        set allowaccess ping https
    next
    edit "port2"
        set allowaccess ping https ssh
    next
end
""")
        out = rules.check_admin_access_on_wan(cfg)
        self.assertEqual(FAIL, out.status)
        self.assertEqual(1, len(out.evidence))
        self.assertIn("wan1", out.evidence[0].context)

    def test_admin_mfa_skips_remote_admins(self):
        cfg = _cfg("""config system admin
    edit "ops"
        set accprofile "super_admin"
    next
    edit "tok"
        set two-factor fortitoken
    next
    edit "ldap-admins"
        set remote-auth enable
    next
end
""")
        out = rules.check_admin_mfa(cfg)
        self.assertEqual(WARN, out.status)
        self.assertEqual(["system admin / ops"],
                         [e.context for e in out.evidence])

    def test_auth_server_encryption(self):
        cfg = _cfg("""config user ldap
    edit "dc"
        set server "192.0.2.10"
    next
    edit "dc-tls"
        set secure ldaps
    next
end
config user radius
    edit "nps"
        set transport-protocol udp
    next
end
""")
        out = rules.check_auth_server_encryption(cfg)
        self.assertEqual(WARN, out.status)
        self.assertEqual(2, len(out.evidence))
        self.assertEqual(UNKNOWN,
                         rules.check_auth_server_encryption(_cfg(GLOBAL_WEAK)).status)

    def test_ntp_auth(self):
        cfg = _cfg("""config system ntp
    set type custom
    config ntpserver
        edit 1
            set server "192.0.2.1"
        next
        edit 2
            set server "192.0.2.2"
            set authentication enable
        next
    end
end
""")
        out = rules.check_ntp_auth(cfg)
        self.assertEqual(WARN, out.status)
        self.assertEqual(1, len(out.evidence))
        fg = _cfg("config system ntp\n    set ntpsync enable\nend\n")
        self.assertEqual(UNKNOWN, rules.check_ntp_auth(fg).status)

    def test_ospf_auth(self):
        none = _cfg("""config router ospf
    set router-id 192.0.2.1
    config area
        edit 0.0.0.0
        next
    end
end
""")
        self.assertEqual(WARN, rules.check_ospf_auth(none).status)
        md5 = _cfg("""config router ospf
    config area
        edit 0.0.0.0
            set authentication message-digest
        next
    end
end
""")
        self.assertEqual(PASS, rules.check_ospf_auth(md5).status)
        unused = _cfg("config router ospf\n    set router-id 0.0.0.0\nend\n")
        self.assertEqual(UNKNOWN, rules.check_ospf_auth(unused).status)

    def test_remote_logging_counts_fortianalyzer(self):
        self.assertEqual(FAIL, rules.check_remote_logging(_cfg(GLOBAL_WEAK)).status)
        faz = _cfg("config log fortianalyzer setting\n    set status enable\nend\n")
        self.assertEqual(PASS, rules.check_remote_logging(faz).status)

    def test_factory_certificates(self):
        self.assertEqual(WARN,
                         rules.check_factory_certificates(_cfg(GLOBAL_WEAK)).status)
        own = _cfg("config system global\n"
                   "    set admin-server-cert \"fw-01-le\"\nend\n")
        self.assertEqual(PASS, rules.check_factory_certificates(own).status)

    def test_policy_checks(self):
        cfg = _cfg(POLICIES)
        any_out = rules.check_policy_any_interface(cfg)
        self.assertEqual(WARN, any_out.status)
        self.assertEqual(1, len(any_out.evidence))
        names = rules.check_policy_names(cfg)
        self.assertEqual(WARN, names.status)
        # policy 2 duplicates the name, policy 3 has none
        self.assertEqual(2, len(names.evidence))
        vip = rules.check_deny_match_vip(cfg)
        self.assertEqual(WARN, vip.status)
        self.assertIn("3", vip.evidence[0].context)


class TestBenchmark(unittest.TestCase):
    def test_every_rule_cites_a_page_of_the_guide(self):
        ids = [r["id"] for r in fortios_76.RULES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(r["ref"].startswith("p.") for r in fortios_76.RULES))

    def test_runs_on_fortigate_config_in_both_languages(self):
        for lang in ("it", "en"):
            res = netsec_audit.run_netsec_audit(
                config_text=GLOBAL_WEAK + "config system admin\nend\n",
                benchmark="fortios-76", lang=lang)
            self.assertEqual("fortios-76", res["benchmark"])
            self.assertEqual(len(fortios_76.RULES), len(res["rules"]))
            self.assertTrue(all(r["id"].startswith("AUD-F76-") for r in res["rules"]))

    def test_not_a_cis_benchmark(self):
        """"cis" keeps resolving to CIS FortiGate, not to the vendor guide."""
        self.assertEqual("vendor", netsec_audit.BENCHMARK_GROUPS["fortios-76"])
        res = netsec_audit.run_netsec_audit(config_text=GLOBAL_WEAK,
                                            benchmark="cis")
        self.assertEqual("cis-fortigate", res["benchmark"])


if __name__ == "__main__":
    unittest.main()
