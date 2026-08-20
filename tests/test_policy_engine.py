# -*- coding: utf-8 -*-
"""Unit tests for services.policy_test.engine."""

import unittest
from services.policy_test.engine import evaluate_ios
from services.policy_test.ios import parse_ios_config
from services.policy_test.model import Flow


class TestPolicyEngineIOS(unittest.TestCase):

    CONFIG = """
hostname switch-01
!
object-group network DMZ_SERVERS
 host 192.0.2.10
 host 192.0.2.11
!
object-group service WEB_SERVICES
 tcp eq www
 tcp eq 443
!
ip access-list extended GUEST_IN
 10 remark Drop access to DMZ
 20 deny ip any object-group DMZ_SERVERS
 30 permit ip 192.0.2.0 0.0.0.255 any
!
ip access-list extended WAN_OUT
 10 permit tcp any any eq 443
 20 permit tcp any any eq 80
!
interface GigabitEthernet0/1
 description Ingress LAN
 ip address 192.0.2.1 255.255.255.0
 ip access-group GUEST_IN in
!
interface GigabitEthernet0/2
 description Egress WAN
 ip address 198.51.100.1 255.255.255.0
 ip access-group WAN_OUT out
!
ip route 0.0.0.0 0.0.0.0 198.51.100.254
!
"""

    def setUp(self):
        self.env = parse_ios_config(self.CONFIG)

    def test_permitted_flow_full_chain(self):
        flow = Flow(src_ip="192.0.2.50", dst_ip="203.0.113.10", proto="tcp", dport=443)
        trace = evaluate_ios(self.env, flow)

        self.assertEqual(trace.verdict, "PERMIT")
        self.assertEqual(len(trace.steps), 3)

        # Step 1: Ingress ACL
        self.assertEqual(trace.steps[0].kind, "acl_in")
        self.assertEqual(trace.steps[0].acl, "GUEST_IN")
        self.assertEqual(trace.steps[0].action, "permit")
        self.assertEqual(trace.steps[0].matched, "seq 30")

        # Step 2: Route lookup
        self.assertEqual(trace.steps[1].kind, "route")
        self.assertEqual(trace.steps[1].egress, "GigabitEthernet0/2")
        self.assertEqual(trace.steps[1].prefix, "0.0.0.0/0")

        # Step 3: Egress ACL
        self.assertEqual(trace.steps[2].kind, "acl_out")
        self.assertEqual(trace.steps[2].acl, "WAN_OUT")
        self.assertEqual(trace.steps[2].action, "permit")
        self.assertEqual(trace.steps[2].matched, "seq 10")

    def test_denied_at_ingress_acl(self):
        # Destined to DMZ server 192.0.2.10
        flow = Flow(src_ip="192.0.2.50", dst_ip="192.0.2.10", proto="tcp", dport=443)
        trace = evaluate_ios(self.env, flow)

        self.assertEqual(trace.verdict, "DENY")
        self.assertEqual(len(trace.steps), 1)
        self.assertEqual(trace.steps[0].kind, "acl_in")
        self.assertEqual(trace.steps[0].action, "deny")
        self.assertEqual(trace.steps[0].matched, "seq 20")

    def test_denied_at_egress_acl(self):
        # Allowed through GUEST_IN, but port 22 is blocked by WAN_OUT (implicit deny)
        flow = Flow(src_ip="192.0.2.50", dst_ip="203.0.113.10", proto="tcp", dport=22)
        trace = evaluate_ios(self.env, flow)

        self.assertEqual(trace.verdict, "DENY")
        self.assertEqual(len(trace.steps), 3)
        self.assertEqual(trace.steps[0].action, "permit")
        self.assertEqual(trace.steps[1].kind, "route")
        self.assertEqual(trace.steps[2].kind, "acl_out")
        self.assertEqual(trace.steps[2].action, "deny")
        self.assertEqual(trace.steps[2].matched, "implicit deny")
        self.assertTrue(trace.implicit_deny)

    def test_no_static_route_returns_unknown(self):
        # Switch with no default route
        config_no_route = """
interface GigabitEthernet0/1
 ip address 192.0.2.1 255.255.255.0
!
"""
        env = parse_ios_config(config_no_route)
        flow = Flow(src_ip="192.0.2.50", dst_ip="203.0.113.10", proto="tcp", dport=443)
        trace = evaluate_ios(env, flow)

        self.assertEqual(trace.verdict, "UNKNOWN")
        self.assertEqual(trace.steps[-1].kind, "route")
        self.assertEqual(trace.steps[-1].matched, "no_static_route")


if __name__ == "__main__":
    unittest.main()
