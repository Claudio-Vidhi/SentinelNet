# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Change What-If & Safe Rollback simulator tests (unit + FastAPI endpoint)."""

import os
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app_server
from security import user_manager
from services.policy_test.fortios import parse_fortios_config
from services.policy_test.ios import parse_ios_config
from services.policy_test.junos import parse_junos_config
from services.policy_test.panos import parse_panos_config
from services.whatif_simulator import simulate_whatif

PASS = "PasswordSicura1!"

FORTI_CFG = """config system interface
    edit "port1"
        set ip 10.20.0.1 255.255.255.0
    next
    edit "port2"
        set ip 172.16.10.1 255.255.255.252
    next
end
config router static
    edit 1
        set dst 192.0.2.0 255.255.255.0
        set gateway 172.16.10.2
        set device "port2"
    next
end
config firewall policy
    edit 10
        set name "Allow-Modbus"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""

IOS_CFG = """hostname sw-core
ip access-list extended CELL-IN
 10 permit tcp 10.20.0.0 0.0.0.255 host 192.0.2.10 eq 502
 20 deny ip any any
!
interface Vlan10
 ip address 10.20.0.1 255.255.255.0
 ip access-group CELL-IN in
!
interface Vlan20
 ip address 192.0.2.254 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 172.16.10.2
"""


class TestWhatIfSimulator(unittest.TestCase):
    def test_disable_broad_rule_fortios_breaks_flow_resolves_finding_and_emits_rollback(self):
        env = parse_fortios_config(FORTI_CFG)
        res = simulate_whatif(
            env, "fortios",
            {"action": "disable_rule", "rule_id": "10"},
            flows=[{"src_ip": "10.20.0.5", "dst_ip": "192.0.2.10", "proto": "tcp", "dport": 502, "ingress_intf": "port1"}],
        )
        self.assertEqual(res["risk"], "HIGH")
        self.assertEqual(res["summary"]["broken"], 1)
        # Disabling an any-any rule resolves the static any_any finding
        self.assertEqual(res["summary"]["resolved_findings"], 1)
        self.assertIn("set status disable", res["rollback"]["cli_apply"])
        self.assertIn("set status enable", res["rollback"]["cli_rollback"])

    def test_add_rule_and_remove_route_ios_and_panos_junos(self):
        ios_env = parse_ios_config(IOS_CFG)
        added = simulate_whatif(
            ios_env, "ios",
            {
                "action": "add_rule", "acl": "CELL-IN", "rule_id": "5",
                "rule_action": "permit", "src_cidr": "10.30.0.0/24",
                "dst_cidr": "192.0.2.10/32", "proto": "tcp", "dport": 443,
            },
            flows=[{"src_ip": "10.30.0.9", "dst_ip": "192.0.2.10", "proto": "tcp", "dport": 443, "ingress_intf": "Vlan10"}],
        )
        self.assertEqual(added["summary"]["newly_allowed"], 1)
        self.assertIn("no 5", added["rollback"]["cli_rollback"])

        route_rm = simulate_whatif(
            ios_env, "ios",
            {"action": "remove_route", "prefix": "0.0.0.0/0"},
            flows=[{"src_ip": "10.20.0.5", "dst_ip": "192.0.2.10", "proto": "tcp", "dport": 502, "ingress_intf": "Vlan10"}],
        )
        self.assertIn("ip route 0.0.0.0 0.0.0.0 172.16.10.2", route_rm["rollback"]["cli_rollback"])

        pan_env = parse_panos_config(
            "set network interface ethernet ethernet1/1 layer3 ip 203.0.113.10/24\n"
            "set network interface ethernet ethernet1/2 layer3 ip 172.16.10.1/30\n"
            "set zone u network layer3 ethernet1/1\n"
            "set zone o network layer3 ethernet1/2\n"
            "set rulebase security rules R1 from u\n"
            "set rulebase security rules R1 to o\n"
            "set rulebase security rules R1 source any\n"
            "set rulebase security rules R1 destination any\n"
            "set rulebase security rules R1 service any\n"
            "set rulebase security rules R1 action allow\n"
        )
        pan_res = simulate_whatif(pan_env, "panos", {"action": "disable_rule", "rule_id": "R1"})
        self.assertEqual(pan_res["rollback"]["cli_rollback"], 'set rulebase security rules "R1" disabled no')

        jun_env = parse_junos_config(
            "set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.20/24\n"
            "set routing-options static route 192.0.2.0/24 next-hop 172.16.20.2\n"
        )
        jun_res = simulate_whatif(jun_env, "junos", {"action": "add_route", "prefix": "198.51.100.0/24", "next_hop": "172.16.20.2"})
        self.assertEqual(jun_res["rollback"]["cli_rollback"], "rollback 1")


class TestWhatIfApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for u, role, grps in (("adm_wi", "admin", None), ("op_a_wi", "operator", ["site-a"])):
            try:
                user_manager.create_user(u, PASS, role=role, groups=grps)
            except Exception:
                pass

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200
        return c

    def test_whatif_endpoint_auth_and_tenant_boundary(self):
        dev_a = {"IP": "192.0.2.40", "Hostname": "fw-a", "Vendor": "fortinet", "Group": "site-a"}
        dev_b = {"IP": "198.51.100.40", "Hostname": "fw-b", "Vendor": "fortinet", "Group": "site-b"}

        with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False, encoding="utf-8") as tf:
            tf.write(FORTI_CFG)
            cfg_path = tf.name

        try:
            with mock.patch("services.inventory_manager.get_all_devices", return_value=[dev_a, dev_b]), \
                 mock.patch("ai.config_analyzer._find_freshest_backup", return_value=(cfg_path, "site-a")):
                # Operator in site-a can simulate site-a device
                r_ok = self._client("op_a_wi").post(
                    "/api/policy-test/192.0.2.40/what-if",
                    json={
                        "change": {"action": "disable_rule", "rule_id": "10"},
                        "flows": [{"src_ip": "10.20.0.5", "dst_ip": "192.0.2.10", "proto": "tcp", "dport": 502, "ingress_intf": "port1"}],
                    },
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )
                self.assertEqual(r_ok.status_code, 200, r_ok.text)
                self.assertEqual(r_ok.json()["risk"], "HIGH")

                # Operator in site-a gets 403/404 for site-b device
                r_denied = self._client("op_a_wi").post(
                    "/api/policy-test/198.51.100.40/what-if",
                    json={"change": {"action": "disable_rule", "rule_id": "10"}},
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )
                self.assertIn(r_denied.status_code, (403, 404))
        finally:
            try:
                os.unlink(cfg_path)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
