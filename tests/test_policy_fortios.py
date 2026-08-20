# -*- coding: utf-8 -*-
"""Unit tests for FortiOS policy and routing validation (services.policy_test.fortios)."""

import unittest
from services.policy_test.engine import evaluate
from services.policy_test.fortios import parse_fortios_config
from services.policy_test.model import Flow


class TestPolicyFortiOS(unittest.TestCase):

    SAMPLE_CONFIG = """
config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
        set status up
    next
    edit "port2"
        set ip 198.51.100.1 255.255.255.0
        set status up
    next
end

config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 198.51.100.254
        set device "port2"
    next
end

config firewall address
    edit "INTERNAL_HOST"
        set subnet 192.0.2.50 255.255.255.255
    next
    edit "DMZ_NET"
        set subnet 192.0.2.0 255.255.255.0
    next
    edit "BRANCH_NET"
        set subnet 198.51.100.128 255.255.255.128
    next
end

config firewall addrgrp
    edit "LOCAL_NETWORKS"
        set member "DMZ_NET" "BRANCH_NET"
    next
    edit "NESTED_GROUP"
        set member "LOCAL_NETWORKS" "INTERNAL_HOST"
    next
end

config firewall service custom
    edit "CUSTOM_APP_8443"
        set protocol TCP/UDP/SCTP
        set tcp-portrange 8443
    next
end

config firewall policy
    edit 1
        set name "Disabled Rule"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set status disable
        set service "ALL"
    next
    edit 10
        set name "Allow Web Out"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "NESTED_GROUP"
        set dstaddr "all"
        set action accept
        set service "HTTPS" "HTTP"
        set nat enable
    next
    edit 20
        set name "Allow Custom App"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "INTERNAL_HOST"
        set dstaddr "all"
        set action accept
        set service "CUSTOM_APP_8443"
    next
    edit 30
        set name "Broken Policy"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "UNDEFINED_ADDRESS"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""

    def setUp(self):
        self.env = parse_fortios_config(self.SAMPLE_CONFIG)

    def test_nested_addrgrp_resolution(self):
        self.assertIn("NESTED_GROUP", self.env.addresses)
        cubes = self.env.addresses["NESTED_GROUP"]
        # Should contain DMZ_NET (192.0.2.0/24), BRANCH_NET (198.51.100.128/25), INTERNAL_HOST (192.0.2.50)
        self.assertEqual(len(cubes), 3)

    def test_builtin_and_custom_service_resolution(self):
        self.assertIn("CUSTOM_APP_8443", self.env.services)
        svc = self.env.services["CUSTOM_APP_8443"]
        self.assertEqual(svc["dst_ports"], [(8443, 8443)])

    def test_policy_chain_evaluation_permit_and_nat(self):
        # Flow matching policy 10 (HTTPS with NAT)
        flow = Flow(src_ip="192.0.2.50", dst_ip="203.0.113.5", proto="tcp", dport=443)
        trace = evaluate(self.env, flow)

        self.assertEqual(trace.verdict, "PERMIT")
        self.assertTrue(trace.nat_applied)
        # Check skipped disabled policy 1, route lookup, and policy 10 match
        kinds = [s.kind for s in trace.steps]
        self.assertIn("route", kinds)
        self.assertIn("skipped_policy", kinds)
        self.assertIn("policy", kinds)

        pol_step = next(s for s in trace.steps if s.kind == "policy")
        self.assertEqual(pol_step.rule_id, "10")
        self.assertEqual(pol_step.action, "permit")

    def test_disabled_policy_is_skipped_and_reported(self):
        flow = Flow(src_ip="192.0.2.50", dst_ip="203.0.113.5", proto="tcp", dport=443)
        trace = evaluate(self.env, flow)
        skip_step = next((s for s in trace.steps if s.kind == "skipped_policy"), None)
        self.assertIsNotNone(skip_step)
        self.assertEqual(skip_step.rule_id, "1")

    def test_unresolved_object_produces_unknown(self):
        # Flow that misses policy 10 & 20 and hits policy 30 (which has undefined address)
        # Policy 20 requires src=192.0.2.50 & port=8443. Here port=9000 -> misses 10 & 20.
        flow = Flow(src_ip="10.0.0.1", dst_ip="203.0.113.5", proto="tcp", dport=9000)
        # But policy 30 has srcaddr="UNDEFINED_ADDRESS" which is opaque / unknown
        # Policy 30 rule has fields.opaque=True, so it matches nothing in normal match,
        # but let's check policy 30 unresolved status:
        p30 = next(p for p in self.env.policies if p.id == "30")
        self.assertEqual(p30.action, "unknown")
        self.assertTrue(p30.fields.opaque)
        self.assertTrue(any("UNDEFINED_ADDRESS" in u for u in p30.unresolved))


if __name__ == "__main__":
    unittest.main()
