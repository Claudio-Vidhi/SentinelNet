# -*- coding: utf-8 -*-
"""Unit tests for services.policy_test.examples."""

import unittest
from services.policy_test.examples import generate_rule_example
from services.policy_test.model import Cube, FieldSet, Flow, PortSet, Rule


class TestPolicyExamples(unittest.TestCase):

    def test_example_inside_cube_and_near_miss_port(self):
        rule = Rule(
            id="10",
            action="permit",
            fields=FieldSet(
                src_ips=[Cube.from_cidr("192.0.2.0", 24)],
                dst_ips=[Cube.from_ip("198.51.100.10")],
                dst_ports=PortSet.from_op("eq", 443),
                protos={6},
            ),
            raw_text="10 permit tcp 192.0.2.0 0.0.0.255 host 198.51.100.10 eq 443",
        )

        example = generate_rule_example(rule)
        # Matching flow matches the rule
        self.assertTrue(rule.fields.matches(example.matching_flow))
        self.assertEqual(example.matching_flow.dport, 443)
        self.assertEqual(example.matching_flow.dst_ip, "198.51.100.10")

        # Near-miss flow fails the rule
        self.assertIsNotNone(example.near_miss_flow)
        self.assertFalse(rule.fields.matches(example.near_miss_flow))
        self.assertNotEqual(example.near_miss_flow.dport, 443)
        self.assertIn("Destination port", example.near_miss_reason)

    def test_near_miss_destination_ip(self):
        rule = Rule(
            id="20",
            action="permit",
            fields=FieldSet(
                src_ips=[Cube.any()],
                dst_ips=[Cube.from_cidr("198.51.100.0", 24)],
                dst_ports=None,
                protos={6},
            ),
            raw_text="20 permit tcp any 198.51.100.0 0.0.0.255",
        )

        example = generate_rule_example(rule)
        self.assertTrue(rule.fields.matches(example.matching_flow))

        # Near-miss mutates destination IP outside 198.51.100.0/24
        self.assertIsNotNone(example.near_miss_flow)
        self.assertFalse(rule.fields.matches(example.near_miss_flow))
        self.assertIn("Destination IP", example.near_miss_reason)

    def test_hint_address_preference(self):
        rule = Rule(
            id="30",
            action="permit",
            fields=FieldSet(
                src_ips=[Cube.from_cidr("192.0.2.0", 24)],
                dst_ips=[Cube.any()],
            ),
        )
        hints = ["10.0.0.1", "192.0.2.77", "172.16.0.1"]
        example = generate_rule_example(rule, hint_addresses=hints)

        # Prefers 192.0.2.77 because it matches the source subnet cube
        self.assertEqual(example.matching_flow.src_ip, "192.0.2.77")


if __name__ == "__main__":
    unittest.main()
