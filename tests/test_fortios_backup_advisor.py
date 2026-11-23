# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The live FortiGate advisor run on a config backup (Security Audit tab).

Synthetic backup only: RFC 5737 / private addresses, invented names.
"""

import unittest
from unittest import mock

from services import fortigate_service as fgs
from services.netsec_audit.fortios_advisor import backup_advisor, parse_tree

# A normal backup: default-valued settings (status enable, inspection-mode
# flow, auto-asic-offload enable, utm-status disable) are not written.
BACKUP = """#config-version=FGT60F-7.4.5-FW-build2702:opmode=0:vdom=0:user=admin
config system global
    set hostname "switch-01"
end
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.0
        set role wan
    next
    edit "internal"
        set ip 192.168.10.1 255.255.255.0
        set role lan
    next
end
config firewall vip
    edit "VIP_Web"
        set extip 203.0.113.10
        set mappedip "192.168.10.10"
    next
end
config firewall ssl-ssh-profile
    edit "certificate-inspection"
        config https
            set ports 443
            set status certificate-inspection
        end
    next
end
config antivirus profile
    edit "AV_Block"
        config http
            set av-scan block
        end
        config ftp
            set av-scan block
        end
    next
end
config ips sensor
    edit "default"
        config entries
            edit 1
                set severity medium high critical
            next
        end
    next
end
config firewall policy
    edit 1
        set name "vip-in"
        set srcintf "wan1"
        set dstintf "internal"
        set action accept
        set srcaddr "all"
        set dstaddr "VIP_Web"
        set schedule "always"
        set service "HTTPS"
    next
    edit 2
        set name "lan-out"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "LAN_Net"
        set dstaddr "all"
        set schedule "always"
        set service "HTTPS"
        set utm-status enable
        set ssl-ssh-profile "certificate-inspection"
        set application-list "default"
        set webfilter-profile "default"
        set dnsfilter-profile "default"
    next
    edit 3
        set name "proxy-rule"
        set srcintf "internal"
        set dstintf "internal"
        set action accept
        set srcaddr "Host_A"
        set dstaddr "Host_B"
        set schedule "always"
        set service "SSH"
        set inspection-mode proxy
        set auto-asic-offload disable
    next
    edit 4
        set name "vip-generic-ips"
        set srcintf "wan1"
        set dstintf "internal"
        set action accept
        set srcaddr "all"
        set dstaddr "VIP_Web"
        set schedule "always"
        set service "HTTPS"
        set utm-status enable
        set ssl-ssh-profile "certificate-inspection"
        set ips-sensor "default"
    next
end
"""


def _ids(data):
    return {r["id"] for r in data["recommendations"]}


class TestParseTree(unittest.TestCase):
    def test_config_dict_edit_list_values(self):
        tree = parse_tree(BACKUP)
        ssl = tree["firewall ssl-ssh-profile"][0]
        self.assertEqual(ssl["_key"], "certificate-inspection")
        self.assertEqual(ssl["https"], {"ports": "443", "status": "certificate-inspection"})
        entry = tree["ips sensor"][0]["entries"][0]
        self.assertEqual(entry["_key"], "1")
        self.assertEqual(entry["severity"], ["medium", "high", "critical"])
        pols = tree["firewall policy"]
        self.assertEqual([p["_key"] for p in pols], ["1", "2", "3", "4"])
        self.assertEqual(pols[0]["dstaddr"], "VIP_Web")
        self.assertEqual(tree["system global"], {"hostname": "switch-01"})

    def test_nested_filters_list(self):
        tree = parse_tree(
            'config webfilter profile\n    edit "WF"\n        config ftgd-wf\n'
            '            config filters\n                edit 1\n'
            '                    set category 26\n                    set action block\n'
            '                next\n            end\n        end\n    next\nend\n')
        wf = tree["webfilter profile"][0]
        self.assertEqual(wf["ftgd-wf"]["filters"], [{"_key": "1", "category": "26", "action": "block"}])

    def test_malformed_is_tolerated(self):
        tree = parse_tree("end\nnext\nconfig a\n    edit 1\n        set x\n")
        self.assertEqual(tree["a"], [{"_key": "1", "x": []}])


class TestBackupAdvisor(unittest.TestCase):
    def setUp(self):
        self.data = backup_advisor(BACKUP, lang="en")
        self.ids = _ids(self.data)
        self.by_id = {r["id"]: r for r in self.data["recommendations"]}

    def test_vip_without_ips(self):
        self.assertIn("ADV-VIP-L7-1", self.ids)
        self.assertEqual(self.by_id["ADV-VIP-L7-1"]["severity"], "HIGH")

    def test_proxy_and_offload(self):
        # FGT60F on 7.4.5: 2GB unit, proxy mode removed.
        self.assertEqual(self.by_id["ADV-PROXY-3"]["severity"], "CRITICAL")
        self.assertIn("ADV-OFFLOAD-3", self.ids)
        # Absent inspection-mode / auto-asic-offload read as FortiOS defaults.
        self.assertNotIn("ADV-PROXY-1", self.ids)
        self.assertNotIn("ADV-OFFLOAD-1", self.ids)

    def test_internet_policy_reuses_blocking_av(self):
        rec = self.by_id["ADV-AV-2"]
        self.assertEqual(rec["reuses"], ["AV_Block"])
        self.assertIn('set av-profile "AV_Block"', rec["cli"])
        self.assertNotIn("ADV-SSL-2", self.ids)

    def test_generic_ips_sensor_on_vip(self):
        self.assertIn("ADV-IPS-4", self.ids)
        self.assertNotIn("ADV-VIP-L7-4", self.ids)

    def test_no_live_only_checks(self):
        self.assertFalse(any(i.startswith("ADV-ORDER") for i in self.ids))
        self.assertNotIn("ADV-PROFILES-UNAVAIL", self.ids)
        self.assertEqual(self.data["source"]["live_only"], ["ADV-ORDER"])
        self.assertEqual(self.data["source"]["kind"], "backup")
        self.assertEqual(self.data["errors"], {})

    def test_hardware_profile_from_header(self):
        self.assertEqual(self.data["hardware_profile"]["ram_tier"], "2gb")
        self.assertEqual(self.data["summary"]["policies_analyzed"], 4)

    def test_full_config_detection(self):
        self.assertFalse(self.data["source"]["full_config"])
        full = BACKUP.replace('        set name "vip-in"\n',
                              '        set name "vip-in"\n        set status enable\n')
        self.assertTrue(backup_advisor(full)["source"]["full_config"])
        # A disabled policy is written in both formats: not a marker.
        disabled = BACKUP.replace('        set name "vip-in"\n',
                                  '        set name "vip-in"\n        set status disable\n')
        self.assertFalse(backup_advisor(disabled)["source"]["full_config"])
        # No policies: a whole system global is the marker.
        many = "".join(f"    set key{i} value\n" for i in range(90))
        self.assertTrue(backup_advisor(f"config system global\n{many}end\n")["source"]["full_config"])
        self.assertFalse(backup_advisor("config system global\n    set hostname x\nend\n")
                         ["source"]["full_config"])

    def test_single_vdom_has_no_vdom_fields(self):
        self.assertEqual(self.data["source"]["vdoms"], [])
        self.assertFalse(any("vdom" in r for r in self.data["recommendations"]))


# Multi-VDOM layout: VDOM declarations, config global (interfaces carry their
# VDOM), then the per-VDOM sections in a second config vdom.
MULTI = """#config-version=FGT100F-7.4.5-FW-build2702:opmode=0:vdom=1:user=admin
config vdom
edit root
next
edit vd-b
next
end
config global
config system global
    set hostname "switch-01"
end
config system interface
    edit "wan1"
        set vdom "root"
        set role wan
    next
    edit "internal"
        set vdom "root"
        set role lan
    next
    edit "port5"
        set vdom "vd-b"
        set role wan
    next
    edit "port6"
        set vdom "vd-b"
        set role lan
    next
end
end
config vdom
edit root
config firewall policy
    edit 1
        set name "lan-out"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
    next
    edit 2
        set name "to-port5"
        set srcintf "internal"
        set dstintf "port5"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
    next
end
next
edit vd-b
config firewall vip
    edit "VIP_B"
        set extip 198.51.100.10
        set mappedip "10.0.20.10"
    next
end
config firewall policy
    edit 1
        set name "vip-in"
        set srcintf "port5"
        set dstintf "port6"
        set action accept
        set srcaddr "all"
        set dstaddr "VIP_B"
        set service "HTTPS"
    next
end
next
end
"""


class TestMultiVdom(unittest.TestCase):
    def setUp(self):
        self.data = backup_advisor(MULTI, lang="en")
        self.recs = self.data["recommendations"]
        self.by_id = {r["id"]: r for r in self.recs}

    def test_parse_tree_merges_vdom_blocks(self):
        vdoms = parse_tree(MULTI)["vdom"]
        self.assertEqual([v["_key"] for v in vdoms], ["root", "vd-b"])
        self.assertEqual([p["_key"] for p in vdoms[0]["firewall policy"]], ["1", "2"])
        self.assertIn("firewall vip", vdoms[1])

    def test_recs_from_both_vdoms_with_unique_ids(self):
        self.assertEqual(self.by_id["root:ADV-AV-1"]["vdom"], "root")
        self.assertEqual(self.by_id["vd-b:ADV-VIP-L7-1"]["vdom"], "vd-b")
        self.assertEqual(len(self.by_id), len(self.recs))
        self.assertEqual(self.data["source"]["vdoms"], ["root", "vd-b"])
        self.assertEqual(self.data["summary"]["policies_analyzed"], 3)
        self.assertEqual(self.data["summary"]["total"], len(self.recs))

    def test_wan_is_per_vdom(self):
        # port5 is WAN in vd-b only: policy 2 of root is not internet-bound.
        self.assertIn("root:ADV-BYPASS-2", self.by_id)
        self.assertNotIn("root:ADV-AV-2", self.by_id)

    def test_cli_wrapped_in_vdom(self):
        cli = self.by_id["vd-b:ADV-VIP-L7-1"]["cli"]
        self.assertTrue(cli.startswith("config vdom\n    edit vd-b\n        config "))
        self.assertTrue(cli.endswith("\n    next\nend"))
        self.assertIn("\n            edit 1\n", cli)

    def test_full_config_looks_at_all_vdoms(self):
        self.assertFalse(self.data["source"]["full_config"])
        full = MULTI.replace('        set name "vip-in"\n',
                             '        set name "vip-in"\n        set status enable\n')
        self.assertTrue(backup_advisor(full)["source"]["full_config"])


class TestRestParity(unittest.TestCase):
    """The same data through the REST fetch and the backup path: same ids."""

    def test_same_recommendation_ids(self):
        def pol(pid, name, src, dst, svc, srcintf, dstintf, **kw):
            row = {"policyid": pid, "name": name, "action": "accept", "status": "enable",
                   "srcintf": [{"name": srcintf}], "dstintf": [{"name": dstintf}],
                   "srcaddr": [{"name": src}], "dstaddr": [{"name": dst}],
                   "service": [{"name": svc}], "inspection-mode": "flow",
                   "auto-asic-offload": "enable", "utm-status": "disable",
                   "ssl-ssh-profile": "", "ips-sensor": "", "av-profile": "",
                   "application-list": "", "webfilter-profile": "", "dnsfilter-profile": ""}
            row.update(kw)
            return row

        policies = [
            pol(1, "vip-in", "all", "VIP_Web", "HTTPS", "wan1", "internal"),
            pol(2, "lan-out", "LAN_Net", "all", "HTTPS", "internal", "wan1",
                **{"utm-status": "enable", "ssl-ssh-profile": "certificate-inspection",
                   "application-list": "default", "webfilter-profile": "default",
                   "dnsfilter-profile": "default"}),
            pol(3, "proxy-rule", "Host_A", "Host_B", "SSH", "internal", "internal",
                **{"inspection-mode": "proxy", "auto-asic-offload": "disable"}),
            pol(4, "vip-generic-ips", "all", "VIP_Web", "HTTPS", "wan1", "internal",
                **{"utm-status": "enable", "ssl-ssh-profile": "certificate-inspection",
                   "ips-sensor": "default"}),
        ]
        cmdb = {
            "cmdb/ips/sensor": [{"name": "default", "entries": [
                {"id": 1, "severity": "medium high critical", "location": "all"}]}],
            "cmdb/firewall/ssl-ssh-profile": [{"name": "certificate-inspection",
                                              "server-cert-mode": "re-sign",
                                              "https": {"status": "certificate-inspection"}}],
            "cmdb/antivirus/profile": [{"name": "AV_Block", "http": {"av-scan": "block"},
                                        "ftp": {"av-scan": "block"}}],
            "cmdb/application/list": [],
            "cmdb/webfilter/profile": [],
            "cmdb/dnsfilter/profile": [],
            "cmdb/system/interface": [{"name": "wan1", "role": "wan"},
                                      {"name": "internal", "role": "lan"}],
        }

        def fake_cmdb(_ip, path, **_kw):
            return {"results": cmdb.get(path, [])}

        with mock.patch.object(fgs, "api_get_cmdb", side_effect=fake_cmdb), \
             mock.patch.object(fgs, "get_system_status",
                               return_value={"data": {"model": "FGT60F", "version": "7.4.5"}}), \
             mock.patch.object(fgs, "get_policies_with_stats", return_value={"data": policies}), \
             mock.patch.object(fgs, "get_vips", return_value={"data": [{"name": "VIP_Web"}]}), \
             mock.patch.object(fgs, "get_security_profiles", return_value={"data": {}, "errors": {}}):
            live = fgs.get_firewall_advisor({"IP": "192.0.2.1"}, lang="en")["data"]

        backup = backup_advisor(BACKUP, lang="en")
        self.assertEqual(live["errors"], {})
        self.assertEqual(_ids(live), _ids(backup))
        self.assertEqual([r["id"] for r in live["recommendations"]],
                         [r["id"] for r in backup["recommendations"]])


if __name__ == "__main__":
    unittest.main()
