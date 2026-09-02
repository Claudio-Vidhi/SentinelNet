# -*- coding: utf-8 -*-
"""Unit tests for services.policy_test.ios (Cisco IOS parser and environment)."""

import unittest
from services.policy_test.ios import (
    parse_ace_line, parse_ios_config, parse_object_groups,
)
from services.policy_test.model import Flow


class TestIOSAceParser(unittest.TestCase):

    def test_standard_numbered_acl(self):
        rule = parse_ace_line("access-list 10 permit 192.0.2.50")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.action, "permit")
        self.assertTrue(rule.fields.matches(Flow(src_ip="192.0.2.50", dst_ip="198.51.100.1")))
        self.assertFalse(rule.fields.matches(Flow(src_ip="192.0.2.51", dst_ip="198.51.100.1")))

    def test_standard_wildcard_acl(self):
        rule = parse_ace_line("access-list 10 permit 192.0.2.0 0.0.0.255")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.action, "permit")
        self.assertTrue(rule.fields.matches(Flow(src_ip="192.0.2.100", dst_ip="198.51.100.1")))
        # Fuori dalla 192.0.2.0/24 dell'ACL: e' il caso negativo, e deve
        # restare un indirizzo DIVERSO da quello della riga sopra.
        self.assertFalse(rule.fields.matches(Flow(src_ip="198.51.100.100", dst_ip="198.51.100.1")))

    def test_extended_named_acl_ports_and_proto(self):
        rule = parse_ace_line("10 permit tcp 192.0.2.0 0.0.0.255 host 198.51.100.10 eq 443")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.id, "10")
        self.assertEqual(rule.action, "permit")
        # Matches flow
        self.assertTrue(rule.fields.matches(Flow(src_ip="192.0.2.50", dst_ip="198.51.100.10", proto="tcp", dport=443)))
        # Non-matching dport
        self.assertFalse(rule.fields.matches(Flow(src_ip="192.0.2.50", dst_ip="198.51.100.10", proto="tcp", dport=80)))
        # Non-matching proto
        self.assertFalse(rule.fields.matches(Flow(src_ip="192.0.2.50", dst_ip="198.51.100.10", proto="udp", dport=443)))

    def test_established_and_log_suffixes(self):
        rule = parse_ace_line("20 permit tcp any any established log")
        self.assertIsNotNone(rule)
        self.assertTrue(rule.fields.established)
        # Flow with established=True
        self.assertTrue(rule.fields.matches(Flow(src_ip="192.0.2.1", dst_ip="198.51.100.1", proto="tcp", established=True)))
        # Flow without established
        self.assertFalse(rule.fields.matches(Flow(src_ip="192.0.2.1", dst_ip="198.51.100.1", proto="tcp", established=False)))

    def test_remarks_are_skipped(self):
        rule1 = parse_ace_line("remark Allow web traffic")
        self.assertIsNone(rule1)
        rule2 = parse_ace_line("access-list 100 remark Internal network")
        # In IOS 'access-list 100 remark ...' is a remark
        self.assertIsNone(rule2)

    def test_neq_and_range_port_operators(self):
        rule_range = parse_ace_line("permit tcp any any range 8000 8080")
        self.assertIsNotNone(rule_range)
        self.assertTrue(rule_range.fields.matches(Flow(src_ip="1.1.1.1", dst_ip="203.0.113.2", proto="tcp", dport=8000)))
        self.assertTrue(rule_range.fields.matches(Flow(src_ip="1.1.1.1", dst_ip="203.0.113.2", proto="tcp", dport=8050)))
        self.assertTrue(rule_range.fields.matches(Flow(src_ip="1.1.1.1", dst_ip="203.0.113.2", proto="tcp", dport=8080)))
        self.assertFalse(rule_range.fields.matches(Flow(src_ip="1.1.1.1", dst_ip="203.0.113.2", proto="tcp", dport=8081)))

        rule_neq = parse_ace_line("permit tcp any any neq 22")
        self.assertIsNotNone(rule_neq)
        self.assertFalse(rule_neq.fields.matches(Flow(src_ip="1.1.1.1", dst_ip="203.0.113.2", proto="tcp", dport=22)))
        self.assertTrue(rule_neq.fields.matches(Flow(src_ip="1.1.1.1", dst_ip="203.0.113.2", proto="tcp", dport=80)))

    def test_opaque_fallback_on_unparseable_ace(self):
        rule = parse_ace_line("permit ip strange syntax cannot parse ???")
        self.assertIsNotNone(rule)
        # Marked opaque, matches nothing
        self.assertTrue(rule.fields.opaque)
        self.assertFalse(rule.fields.matches(Flow(src_ip="192.0.2.1", dst_ip="198.51.100.1")))


class TestIOSConfigParsing(unittest.TestCase):

    SAMPLE_CONFIG = """
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
interface GigabitEthernet0/1
 description Ingress LAN
 ip address 192.0.2.1 255.255.255.0
 ip access-group GUEST_IN in
!
interface GigabitEthernet0/2
 description Egress WAN
 ip address 198.51.100.1 255.255.255.0
!
interface GigabitEthernet0/3
 description Down link
 shutdown
 ip address 203.0.113.1 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 198.51.100.254
ip route 10.0.0.0 255.0.0.0 198.51.100.200 5
!
router ospf 1
 network 192.0.2.0 0.0.0.255 area 0
!
"""

    def test_full_ios_parse(self):
        env = parse_ios_config(self.SAMPLE_CONFIG)

        # Object groups
        self.assertIn("DMZ_SERVERS", env.object_groups)
        self.assertEqual(len(env.object_groups["DMZ_SERVERS"].cubes), 2)

        # ACLs
        self.assertIn("GUEST_IN", env.acls)
        guest_acl = env.acls["GUEST_IN"]
        self.assertEqual(len(guest_acl.rules), 2)  # seq 20 and seq 30 (remark skipped)

        # Interfaces
        self.assertIn("GigabitEthernet0/1", env.interfaces)
        intf1 = env.interfaces["GigabitEthernet0/1"]
        self.assertEqual(intf1["ip"], "192.0.2.1")
        self.assertEqual(intf1["acl_in"], "GUEST_IN")

        # Routes
        # Connected: Gi0/1 (192.0.2.0/24), Gi0/2 (198.51.100.0/24), Gi0/3 is shutdown (not in routes)
        # Static: 0.0.0.0/0 via 198.51.100.254 (egress resolved to Gi0/2), 10.0.0.0/8 via 198.51.100.200 (Gi0/2)
        rt = env.route_table
        self.assertTrue(rt.dynamic_routing_present)
        self.assertIn("ospf", rt.protocols)

        # Lookup destination in 10.0.0.0/8
        r_10 = rt.lookup("10.1.2.3")
        self.assertIsNotNone(r_10)
        self.assertEqual(r_10.prefix, "10.0.0.0/8")
        self.assertEqual(r_10.interface, "GigabitEthernet0/2")

        # Lookup destination on Internet -> default route
        r_def = rt.lookup("8.8.8.8")
        self.assertIsNotNone(r_def)
        self.assertEqual(r_def.prefix, "0.0.0.0/0")
        self.assertEqual(r_def.interface, "GigabitEthernet0/2")


if __name__ == "__main__":
    unittest.main()
