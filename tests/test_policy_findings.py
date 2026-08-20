# -*- coding: utf-8 -*-
"""Unit tests for services.policy_test.findings."""

import unittest
from services.policy_test.findings import (
    analyze_policy_findings, find_routing_defects, find_ruleset_defects,
)
from services.policy_test.model import (
    Cube, FieldSet, PortSet, Route, RouteTable, Rule, RuleSet,
)


class TestPolicyFindings(unittest.TestCase):

    def test_shadowed_rule_detection(self):
        rule_broad = Rule(
            id="10",
            action="deny",
            fields=FieldSet(
                src_ips=[Cube.from_cidr("192.0.2.0", 24)],
                dst_ips=[Cube.any()],
            ),
        )
        rule_narrow = Rule(
            id="20",
            action="permit",
            fields=FieldSet(
                src_ips=[Cube.from_ip("192.0.2.50")],
                dst_ips=[Cube.any()],
            ),
        )

        rs = RuleSet(name="TEST_ACL", rules=[rule_broad, rule_narrow])
        findings = find_ruleset_defects(rs)

        shadowed = [f for f in findings if f.key == "shadowed"]
        self.assertEqual(len(shadowed), 1)
        self.assertEqual(shadowed[0].rule_id, "20")
        self.assertEqual(shadowed[0].params["shadowed_by"], "10")

    def test_unreachable_rule_after_any_any(self):
        rule_any = Rule(
            id="10",
            action="deny",
            fields=FieldSet(
                src_ips=[Cube.any()],
                dst_ips=[Cube.any()],
                src_ports=None,
                dst_ports=None,
                protos=None,
            ),
        )
        rule_next = Rule(
            id="20",
            action="permit",
            fields=FieldSet(
                src_ips=[Cube.from_ip("192.0.2.1")],
                dst_ips=[Cube.any()],
            ),
        )

        rs = RuleSet(name="TEST_ACL", rules=[rule_any, rule_next])
        findings = find_ruleset_defects(rs)

        unreach = [f for f in findings if f.key == "unreachable"]
        self.assertEqual(len(unreach), 1)
        self.assertEqual(unreach[0].rule_id, "20")

    def test_any_any_permit_detection(self):
        rule_permit_all = Rule(
            id="99",
            action="permit",
            fields=FieldSet(
                src_ips=[Cube.any()],
                dst_ips=[Cube.any()],
            ),
        )
        rs = RuleSet(name="OPEN_ACL", rules=[rule_permit_all])
        findings = find_ruleset_defects(rs)

        any_any = [f for f in findings if f.key == "any_any"]
        self.assertEqual(len(any_any), 1)
        self.assertEqual(any_any[0].rule_id, "99")

    def test_route_to_nowhere(self):
        rt = RouteTable(routes=[
            # Connected subnet 192.0.2.0/24 on Gi0/1
            Route(prefix="192.0.2.0/24", prefix_cube=Cube.from_cidr("192.0.2.0", 24), interface="Gi0/1", source="connected"),
            # Valid static route (next hop 192.0.2.254 is in 192.0.2.0/24)
            Route(prefix="10.0.0.0/8", prefix_cube=Cube.from_cidr("10.0.0.0", 8), next_hop="192.0.2.254", interface="Gi0/1", source="static"),
            # Route to nowhere: next hop 203.0.113.50 is in no connected subnet
            Route(prefix="172.16.0.0/16", prefix_cube=Cube.from_cidr("172.16.0.0", 16), next_hop="203.0.113.50", interface="", source="static"),
        ])

        findings = find_routing_defects(rt)
        nowhere = [f for f in findings if f.key == "route_to_nowhere"]
        self.assertEqual(len(nowhere), 1)
        self.assertEqual(nowhere[0].params["prefix"], "172.16.0.0/16")
        self.assertEqual(nowhere[0].params["next_hop"], "203.0.113.50")


if __name__ == "__main__":
    unittest.main()
