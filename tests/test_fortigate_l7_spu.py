# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for FortiGate hardware profiling, L7/SPU audit checks, and scan target selection."""

import unittest
from unittest import mock

from routers import deps
from services import fortigate_hw_profiles as hw
from services import netsec_audit
from services.netsec_audit import rules
from services.netsec_audit.benchmarks import fortios_l7_spu
from services.netsec_audit.model import FAIL, PASS, UNKNOWN, WARN
from services.netsec_audit.parser import parse_with_lines


def _cfg(text: str):
    return parse_with_lines(text)


class TestFortiGateHWProfiles(unittest.TestCase):
    def test_parse_config_header(self):
        cfg_text = "#config-version=FGT60F-7.4.5-FW-build2702-241015:opmode=0:vdom=0\nconfig system global\nend\n"
        self.assertEqual(("FGT60F", "7.4.5"), hw.parse_config_header(cfg_text))
        vm_text = "#config-version=FGVM64-7.6.0-FW-build3401:opmode=0\n"
        self.assertEqual(("FGVM64", "7.6.0"), hw.parse_config_header(vm_text))
        self.assertEqual(("", ""), hw.parse_config_header("#config-version=FGT\n"))
        self.assertEqual(("", ""), hw.parse_config_header(None))

    def test_parse_version_tuple(self):
        self.assertEqual((7, 4, 5), hw.parse_version_tuple("7.4.5"))
        self.assertEqual((7, 4, 4), hw.parse_version_tuple("v7.4.4,build2662"))
        self.assertEqual((7, 6, 0), hw.parse_version_tuple("7.6"))
        self.assertIsNone(hw.parse_version_tuple(""))
        self.assertIsNone(hw.parse_version_tuple("unknown"))

    def test_resolve_profile_families_and_proxy_boundary(self):
        p60f_old = hw.resolve_profile("FGT60F", "7.4.3")
        self.assertEqual("entry_2gb", p60f_old.family)
        self.assertEqual("soc4", p60f_old.npu)
        self.assertEqual("soc", p60f_old.cp)
        self.assertEqual("2gb", p60f_old.ram_tier)
        self.assertFalse(p60f_old.is_vm)
        self.assertFalse(p60f_old.proxy_removed_2gb)
        self.assertEqual("np6", p60f_old.sniffer_syntax)

        p60f_new = hw.resolve_profile("FGT60F", "7.4.4")
        self.assertTrue(p60f_new.proxy_removed_2gb)

        p60e = hw.resolve_profile("FGT60E", "7.4.5")
        self.assertEqual(("entry_2gb", "soc3", "2gb"), (p60e.family, p60e.npu, p60e.ram_tier))
        self.assertTrue(p60e.proxy_removed_2gb)

        p100f = hw.resolve_profile("FGT100F", "7.6.0")
        self.assertEqual(("soc4_4gb", "soc4", "4gb", False), (p100f.family, p100f.npu, p100f.ram_tier, p100f.proxy_removed_2gb))

        p90g = hw.resolve_profile("FGT90G", "7.4.5")
        self.assertEqual(("sp5", "sp5", "soc", "8gb+", "np7"), (p90g.family, p90g.npu, p90g.cp, p90g.ram_tier, p90g.sniffer_syntax))

        p200f = hw.resolve_profile("FGT200F", "7.4.5")
        self.assertEqual(("np6xlite", "np6xlite", "cp9", "8gb+", "np6"), (p200f.family, p200f.npu, p200f.cp, p200f.ram_tier, p200f.sniffer_syntax))

        p400f = hw.resolve_profile("FGT400F", "7.6.0")
        self.assertEqual(("np7", "np7", "cp9", "8gb+", "np7"), (p400f.family, p400f.npu, p400f.cp, p400f.ram_tier, p400f.sniffer_syntax))

        p100e = hw.resolve_profile("FGT100E", "7.2.8")
        self.assertEqual(("np6", "np6lite", "cp9"), (p100e.family, p100e.npu, p100e.cp))

        p300e = hw.resolve_profile("FGT300E", "7.2.8")
        self.assertEqual(("np6", "np6", "cp9"), (p300e.family, p300e.npu, p300e.cp))

        pvm = hw.resolve_profile("FGVM64", "7.6.0")
        self.assertEqual(("vm", "none", "none", "unknown", True, "none"), (pvm.family, pvm.npu, pvm.cp, pvm.ram_tier, pvm.is_vm, pvm.sniffer_syntax))

        pgen = hw.resolve_profile("unknown", "7.4.5")
        self.assertEqual(("generic", "unknown", "unknown", "unknown", False, "generic"), (pgen.family, pgen.npu, pgen.cp, pgen.ram_tier, pgen.is_vm, pgen.sniffer_syntax))

        p_serial = hw.resolve_profile(serial="FGT60FTK21000001", version="7.4.5")
        self.assertEqual(("entry_2gb", "FGT60F"), (p_serial.family, p_serial.model))

    def test_detect_from_config_and_dict_localization(self):
        text = "#config-version=FGT60F-7.4.5-FW-build2702:opmode=0\nconfig system global\nend\n"
        prof = hw.detect_from_config(text)
        self.assertEqual("FGT60F", prof.model)
        d_it = hw.profile_to_dict(prof, "it")
        d_en = hw.profile_to_dict(prof, "en")
        self.assertEqual(2, len(d_it["notes"]))
        self.assertEqual(2, len(d_en["notes"]))
        self.assertNotEqual(d_it["notes"], d_en["notes"])

    def test_parser_captures_header_without_creating_records(self):
        cfg = _cfg("#config-version=FGT400F-7.4.5-FW-build2702\nconfig system global\n    set hostname \"fw-01\"\nend\n")
        self.assertEqual(("FGT400F", "7.4.5"), cfg.header)
        self.assertTrue(all(not r.raw.strip().startswith("#") for r in cfg.records))


class TestL7AndSPUChecks(unittest.TestCase):
    def test_inbound_vip_l7_profiles(self):
        self.assertEqual(UNKNOWN, rules.check_inbound_vip_l7_profiles(_cfg("config firewall policy\nend\n")).status)

        missing_ips = _cfg("""config system interface
    edit "wan1"
        set role wan
    next
end
config firewall vip
    edit "VIP_Web_443"
        set extip 203.0.113.10
        set mappedip "10.10.20.50"
    next
end
config firewall policy
    edit 10
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "VIP_Web_443"
        set action accept
        set service "HTTPS"
    next
end
""")
        out = rules.check_inbound_vip_l7_profiles(missing_ips)
        self.assertEqual(WARN, out.status)
        self.assertEqual(1, len(out.evidence))

        covered = _cfg("""config system interface
    edit "wan1"
        set role wan
    next
end
config firewall vip
    edit "VIP_Web_443"
        set extip 203.0.113.10
        set mappedip "10.10.20.50"
    next
end
config firewall policy
    edit 10
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "VIP_Web_443"
        set action accept
        set utm-status enable
        set ips-sensor "IPS_WebServer_Linux"
    next
end
""")
        self.assertEqual(PASS, rules.check_inbound_vip_l7_profiles(covered).status)

    def test_dos_policy_wan_coverage(self):
        self.assertEqual(UNKNOWN, rules.check_dos_policy_wan_coverage(_cfg("config system global\nend\n")).status)

        lan_only = _cfg("""config system interface
    edit "wan1"
        set role wan
    next
    edit "lan"
        set role lan
    next
end
config firewall DoS-policy
    edit 1
        set interface "lan"
    next
end
""")
        self.assertEqual(WARN, rules.check_dos_policy_wan_coverage(lan_only).status)

        wan_ok = _cfg("""config system interface
    edit "wan1"
        set role wan
    next
end
config firewall DoS-policy
    edit 1
        set interface "wan1"
    next
end
""")
        self.assertEqual(PASS, rules.check_dos_policy_wan_coverage(wan_ok).status)

    def test_ssl_inspection_profile(self):
        self.assertEqual(UNKNOWN, rules.check_ssl_inspection_profile(_cfg("config system global\nend\n")).status)

        weak = _cfg("""config firewall ssl-ssh-profile
    edit "SSL_Protect_WebServer"
        config https
            set status deep-inspection
            set min-allowed-ssl-version tls-1.1
        end
        set server-cert-mode replace
        set server-cert "Fortinet_Factory"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
        set utm-status enable
        set ips-sensor "IPS_Client"
    next
end
""")
        out = rules.check_ssl_inspection_profile(weak)
        self.assertEqual(WARN, out.status)
        self.assertEqual(3, len(out.evidence))

        strong = _cfg("""config firewall ssl-ssh-profile
    edit "SSL_Protect_WebServer"
        config https
            set status deep-inspection
            set min-allowed-ssl-version tls-1.2
        end
        set server-cert-mode replace
        set server-cert "Cert_WebServer_Prod"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
        set utm-status enable
        set ips-sensor "IPS_Client"
        set ssl-ssh-profile "SSL_Protect_WebServer"
    next
end
""")
        self.assertEqual(PASS, rules.check_ssl_inspection_profile(strong).status)

    def test_ips_sensor_optimization(self):
        self.assertEqual(UNKNOWN, rules.check_ips_sensor_optimization(_cfg("config system global\nend\n")).status)

        suboptimal = _cfg("""#config-version=FGT60F-7.4.5-FW-build2702
config system interface
    edit "wan1"
        set role wan
    next
end
config firewall vip
    edit "VIP_Web"
        set extip 203.0.113.10
        set mappedip "10.10.20.50"
    next
end
config ips sensor
    edit "IPS_Debug"
        config entries
            edit 1
                set log-packet enable
            next
        end
    next
end
config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "dmz"
        set dstaddr "VIP_Web"
        set action accept
        set ips-sensor "default"
    next
    edit 2
        set srcintf "lan"
        set dstintf "wan1"
        set dstaddr "all"
        set action accept
        set ips-sensor "high_security"
    next
end
""")
        out = rules.check_ips_sensor_optimization(suboptimal)
        self.assertEqual(WARN, out.status)
        self.assertEqual(3, len(out.evidence))

        clean = _cfg("""#config-version=FGT400F-7.4.5-FW-build2702
config system interface
    edit "wan1"
        set role wan
    next
end
config firewall vip
    edit "VIP_Web"
        set extip 203.0.113.10
        set mappedip "10.10.20.50"
    next
end
config ips sensor
    edit "IPS_WebServer_Linux"
        config entries
            edit 1
                set location server
                set os Linux
            next
        end
    next
end
config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "dmz"
        set dstaddr "VIP_Web"
        set action accept
        set ips-sensor "IPS_WebServer_Linux"
    next
end
""")
        self.assertEqual(PASS, rules.check_ips_sensor_optimization(clean).status)

    def test_policy_asic_offload_and_vm_skip(self):
        vm_cfg = _cfg("""#config-version=FGVM64-7.6.0-FW
config firewall policy
    edit 1
        set action accept
        set auto-asic-offload disable
    next
end
""")
        self.assertEqual(UNKNOWN, rules.check_policy_asic_offload(vm_cfg).status)

        hw_disabled = _cfg("""#config-version=FGT400F-7.4.5-FW
config firewall policy
    edit 1
        set action accept
        set auto-asic-offload disable
    next
end
""")
        out = rules.check_policy_asic_offload(hw_disabled)
        self.assertEqual(WARN, out.status)
        self.assertEqual(1, len(out.evidence))

        hw_ok = _cfg("""#config-version=FGT400F-7.4.5-FW
config firewall policy
    edit 1
        set action accept
        set auto-asic-offload enable
    next
end
""")
        self.assertEqual(PASS, rules.check_policy_asic_offload(hw_ok).status)

    def test_policy_inspection_mode_2gb_fail_vs_warn(self):
        proxy_2gb_new = _cfg("""#config-version=FGT60F-7.4.5-FW
config firewall policy
    edit 1
        set action accept
        set inspection-mode proxy
    next
end
""")
        self.assertEqual(FAIL, rules.check_policy_inspection_mode(proxy_2gb_new).status)

        proxy_2gb_old = _cfg("""#config-version=FGT60F-7.4.3-FW
config firewall policy
    edit 1
        set action accept
        set inspection-mode proxy
    next
end
""")
        self.assertEqual(WARN, rules.check_policy_inspection_mode(proxy_2gb_old).status)

        proxy_400f = _cfg("""#config-version=FGT400F-7.4.5-FW
config firewall policy
    edit 1
        set action accept
        set inspection-mode proxy
    next
end
""")
        self.assertEqual(WARN, rules.check_policy_inspection_mode(proxy_400f).status)

        flow_ok = _cfg("""#config-version=FGT60F-7.4.5-FW
config firewall policy
    edit 1
        set action accept
        set inspection-mode flow
    next
end
""")
        self.assertEqual(PASS, rules.check_policy_inspection_mode(flow_ok).status)

    def test_policy_bypass_scope(self):
        broad = _cfg("""config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "Backup_Host"
        set service "VEEAM_TCP"
        set action accept
        set auto-asic-offload enable
    next
end
""")
        self.assertEqual(WARN, rules.check_policy_bypass_scope(broad).status)

        narrow = _cfg("""config firewall policy
    edit 1
        set srcaddr "ESXi_Host_32"
        set dstaddr "Backup_Host_32"
        set service "VEEAM_TCP"
        set action accept
        set auto-asic-offload enable
    next
    edit 2
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
        set auto-asic-offload enable
        set ips-sensor "IPS_Client"
    next
end
""")
        self.assertEqual(PASS, rules.check_policy_bypass_scope(narrow).status)

    def test_policy_bypass_scope_default_offload(self):
        # A plain `show` backup omits auto-asic-offload (default enable).
        implicit = _cfg("""config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
""")
        self.assertEqual(WARN, rules.check_policy_bypass_scope(implicit).status)

        not_offloaded = _cfg("""config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set auto-asic-offload disable
    next
end
""")
        self.assertEqual(PASS, rules.check_policy_bypass_scope(not_offloaded).status)

    def test_sip_session_helper(self):
        self.assertEqual(UNKNOWN, rules.check_sip_session_helper(_cfg("config system global\nend\n")).status)
        with_sip = _cfg("""config system session-helper
    edit 13
        set name sip
        set protocol 17
        set port 5060
    next
end
""")
        self.assertEqual(WARN, rules.check_sip_session_helper(with_sip).status)

        without_sip = _cfg("""config system session-helper
    edit 1
        set name pptp
        set protocol 6
        set port 1723
    next
end
""")
        self.assertEqual(PASS, rules.check_sip_session_helper(without_sip).status)

    def test_end_to_end_benchmark_and_hardware_profile_payload(self):
        cfg_text = """#config-version=FGT60F-7.4.5-FW-build2702
config system interface
    edit "wan1"
        set role wan
    next
end
config firewall vip
    edit "VIP_Web_443"
        set extip 203.0.113.10
        set mappedip "10.10.20.50"
    next
end
config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "VIP_Web_443"
        set service "HTTPS"
        set action accept
        set inspection-mode proxy
        set auto-asic-offload disable
    next
end
"""
        for lang in ("it", "en"):
            res = netsec_audit.run_netsec_audit(
                config_text=cfg_text, benchmark="fortios-l7-spu", lang=lang,
            )
            self.assertEqual("fortios-l7-spu", res["benchmark"])
            self.assertEqual(len(fortios_l7_spu.RULES), len(res["rules"]))
            self.assertIsNotNone(res["hardware_profile"])
            self.assertEqual("FGT60F", res["hardware_profile"]["model"])
            self.assertTrue(res["hardware_profile"]["proxy_removed_2gb"])
            for r in res["rules"]:
                self.assertTrue(r["detail"])
                self.assertNotIn("{count}", r["detail"])

        ios_res = netsec_audit.run_netsec_audit(
            config_text="hostname switch-01\nno ip http server\n",
            benchmark="cis",
        )
        self.assertIsNone(ios_res["hardware_profile"])


class TestSelectScanTargets(unittest.TestCase):
    DEVICES = [
        {"IP": "192.0.2.10", "Group": "TenantA", "Hostname": "sw-a1"},
        {"IP": "192.0.2.20", "Group": "TenantA", "Hostname": "sw-a2"},
        {"IP": "198.51.100.10", "Group": "TenantB", "Hostname": "sw-b1"},
        {"IP": "203.0.113.10", "Group": "", "Hostname": "sw-unassigned"},
    ]

    def _select(self, scope, **kw):
        with mock.patch.object(deps.inventory_manager, "get_all_devices", return_value=self.DEVICES), \
                mock.patch.object(deps, "user_group_scope", return_value=scope):
            return [d["IP"] for d in deps.select_scan_targets({"sub": "u"}, **kw)]

    def test_unscoped_all_and_group_filter(self):
        self.assertEqual(["192.0.2.10", "192.0.2.20", "198.51.100.10", "203.0.113.10"], self._select(None, group="all"))
        self.assertEqual(["198.51.100.10"], self._select(None, group="TenantB"))

    def test_scoped_user_and_ip_filters(self):
        self.assertEqual(["192.0.2.10", "192.0.2.20"], self._select({"TenantA"}, group="all"))
        self.assertEqual([], self._select({"TenantA"}, group="TenantB"))
        self.assertEqual(["192.0.2.20"], self._select({"TenantA"}, ip="192.0.2.20"))
        self.assertEqual(["192.0.2.10", "192.0.2.20"], self._select({"TenantA"}, ip="192.0.2.10", ips=["192.0.2.20"]))
        self.assertEqual([], self._select({"TenantA"}, ip="198.51.100.10"))


if __name__ == "__main__":
    unittest.main()
