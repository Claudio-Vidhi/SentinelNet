# -*- coding: utf-8 -*-
"""Regression tests for the Policy & Route Validation defects found in review.

Every test here failed before its fix and none was caught by the original
suite, which asserted the parsers against their own assumptions. The theme is
one defect repeated in six places: an ambiguity the parser could not resolve
was turned into "allow", confidently. Example addresses are RFC 5737.
"""

import unittest

from services.policy_test import engine, examples, findings, fortios, ios
from services.policy_test.model import Cube, FieldSet, Flow


FGT_PLUMBING = """config router static
edit 1
set dst 0.0.0.0 0.0.0.0
set gateway 198.51.100.1
set device "port2"
next
end
config system interface
edit "port1"
set ip 192.0.2.1 255.255.255.0
next
edit "port2"
set ip 198.51.100.2 255.255.255.0
next
end
"""

IOS_ODD_WILDCARD = """hostname switch-01
ip access-list extended ODD
 10 permit ip 192.0.2.0 0.0.255.0 any
 20 deny ip any any
!
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
 ip access-group ODD in
!
ip route 0.0.0.0 0.0.0.0 192.0.2.254
"""


class FqdnAddressDoesNotFailOpen(unittest.TestCase):
    """An address object that cannot be resolved offline must not become ANY."""

    def test_policy_scoped_to_fqdn_does_not_permit_arbitrary_destination(self):
        env = fortios.parse_fortios_config("""#config-version=FGT
config firewall address
edit "corp-net"
set subnet 192.0.2.0 255.255.255.0
next
edit "vendor-portal"
set type fqdn
set fqdn "portal.example.com"
next
end
config firewall policy
edit 1
set name "to-vendor-portal-only"
set srcintf "port1"
set dstintf "port2"
set srcaddr "corp-net"
set dstaddr "vendor-portal"
set service "HTTPS"
set action accept
set status enable
next
end
""" + FGT_PLUMBING)
        trace = engine.evaluate(env, Flow(
            src_ip="192.0.2.50", dst_ip="203.0.113.99",
            proto="tcp", dport=443, ingress_intf="port1"))
        # Was PERMIT: the empty cube list fell back to Cube.any().
        self.assertEqual(trace.verdict, "UNKNOWN")
        self.assertTrue(any("vendor-portal" in u for u in trace.unresolved))

    def test_unresolved_reason_is_not_repeated(self):
        env = fortios.parse_fortios_config("""#config-version=FGT
config firewall address
edit "vendor-portal"
set type fqdn
set fqdn "portal.example.com"
next
end
config firewall policy
edit 1
set srcintf "port1"
set dstintf "port2"
set srcaddr "all"
set dstaddr "vendor-portal"
set service "ALL"
set action accept
set status enable
next
end
""" + FGT_PLUMBING)
        trace = engine.evaluate(env, Flow(
            src_ip="192.0.2.50", dst_ip="203.0.113.99",
            proto="tcp", dport=443, ingress_intf="port1"))
        self.assertEqual(len(trace.unresolved), len(set(trace.unresolved)))


class UnresolvableRuleStopsTheWalk(unittest.TestCase):
    """An undecidable rule must not be skipped to reach a later decidable one."""

    def test_isdb_deny_is_not_bypassed_by_the_next_permit(self):
        env = fortios.parse_fortios_config("""#config-version=FGT
config firewall address
edit "corp-net"
set subnet 192.0.2.0 255.255.255.0
next
end
config firewall policy
edit 1
set name "block-known-bad"
set srcintf "port1"
set dstintf "port2"
set srcaddr "corp-net"
set internet-service enable
set internet-service-name "Malicious-Server"
set action deny
set status enable
next
edit 2
set name "allow-all-out"
set srcintf "port1"
set dstintf "port2"
set srcaddr "corp-net"
set dstaddr "all"
set service "ALL"
set action accept
set status enable
next
end
""" + FGT_PLUMBING)
        trace = engine.evaluate(env, Flow(
            src_ip="192.0.2.50", dst_ip="203.0.113.99",
            proto="tcp", dport=443, ingress_intf="port1"))
        # Was PERMIT via policy 2, with the deny silently stepped over.
        self.assertEqual(trace.verdict, "UNKNOWN")
        self.assertIn("policy 1",
                      [s.matched for s in trace.steps if s.kind == "policy"])

    def test_undecidable_rule_excluded_by_a_parsed_dimension_is_still_skipped(self):
        """An unresolvable policy on another interface pair must not block."""
        env = fortios.parse_fortios_config("""#config-version=FGT
config firewall address
edit "corp-net"
set subnet 192.0.2.0 255.255.255.0
next
end
config firewall policy
edit 1
set name "other-segment-isdb"
set srcintf "port9"
set dstintf "port2"
set srcaddr "all"
set internet-service enable
set action deny
set status enable
next
edit 2
set name "allow-all-out"
set srcintf "port1"
set dstintf "port2"
set srcaddr "corp-net"
set dstaddr "all"
set service "ALL"
set action accept
set status enable
next
end
""" + FGT_PLUMBING)
        trace = engine.evaluate(env, Flow(
            src_ip="192.0.2.50", dst_ip="203.0.113.99",
            proto="tcp", dport=443, ingress_intf="port1"))
        self.assertEqual(trace.verdict, "PERMIT")


class UnparseableAceIsReported(unittest.TestCase):
    """An ACE the parser cannot read must not yield a confident verdict."""

    IOS_OBJECT_GROUP = """hostname switch-01
object-group service SVC
 tcp eq 443
!
ip access-list extended EDGE_IN
 10 permit object-group SVC object-group SRC any
 20 deny ip any any
!
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
 ip access-group EDGE_IN in
!
interface Vlan20
 ip address 198.51.100.1 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 198.51.100.254
"""

    def test_object_group_ace_yields_unknown_not_a_confident_deny(self):
        env = ios.parse_ios_config(self.IOS_OBJECT_GROUP)
        trace = engine.evaluate(env, Flow(
            src_ip="192.0.2.77", dst_ip="203.0.113.5",
            proto="tcp", dport=22, ingress_intf="Vlan10"))
        # Was a confident DENY attributed to seq 20, with seq 10 dropped.
        self.assertEqual(trace.verdict, "UNKNOWN")
        self.assertTrue(trace.unresolved)

    def test_unparseable_ace_raises_a_finding(self):
        env = ios.parse_ios_config(self.IOS_OBJECT_GROUP)
        keys = [f.key for f in findings.analyze_policy_findings(env)]
        self.assertIn("unresolved_object", keys)

    def test_opaque_rule_yields_no_example_flow(self):
        env = ios.parse_ios_config(self.IOS_OBJECT_GROUP)
        rules = [r for acl in env.acls.values() for r in acl.rules]
        opaque = [r for r in rules if r.fields.opaque]
        self.assertTrue(opaque)
        example = examples.generate_rule_example(opaque[0])
        self.assertIsNone(example.matching_flow)


class InterfaceNameHandling(unittest.TestCase):
    """Interface names are free text from the operator: case must not decide."""

    def test_all_spellings_of_a_real_interface_agree(self):
        env = ios.parse_ios_config(IOS_ODD_WILDCARD)
        verdicts = {
            spelling: engine.evaluate(env, Flow(
                src_ip="203.0.113.5", dst_ip="198.51.100.9",
                proto="ip", ingress_intf=spelling)).verdict
            for spelling in ("Vlan10", "vlan10", "VLAN10")
        }
        # 'vlan10' used to miss the dict, skip the inbound ACL and PERMIT.
        self.assertEqual(set(verdicts.values()), {"DENY"}, verdicts)

    def test_interface_that_does_not_exist_is_unknown_not_permit(self):
        env = ios.parse_ios_config(IOS_ODD_WILDCARD)
        trace = engine.evaluate(env, Flow(
            src_ip="203.0.113.5", dst_ip="198.51.100.9",
            proto="ip", ingress_intf="Vlan99"))
        self.assertEqual(trace.verdict, "UNKNOWN")


class FortiOSPortRangeSyntax(unittest.TestCase):
    """'dst:src' is not a range. Reading it as one widened services enormously."""

    def test_dst_src_separator_keeps_only_the_destination_half(self):
        self.assertEqual(fortios.parse_port_ranges("80:8080"), [(80, 80)])

    def test_source_range_after_colon_does_not_empty_the_service(self):
        # Returning [] here made the caller treat the service as ANY port.
        self.assertEqual(fortios.parse_port_ranges("443:1024-65535"), [(443, 443)])

    def test_plain_forms_are_unchanged(self):
        self.assertEqual(fortios.parse_port_ranges("443"), [(443, 443)])
        self.assertEqual(fortios.parse_port_ranges("8000-8080"), [(8000, 8080)])
        self.assertEqual(fortios.parse_port_ranges("80 443"), [(80, 80), (443, 443)])


class AnyAnyRespectsInterfaceScope(unittest.TestCase):
    """A policy scoped to an interface pair is not wide open."""

    THREE_SCOPED_POLICIES = """#config-version=FGT
config firewall address
edit "corp-net"
set subnet 192.0.2.0 255.255.255.0
next
end
config firewall policy
edit 1
set name "lan-to-wan-general"
set srcintf "port1"
set dstintf "port2"
set srcaddr "all"
set dstaddr "all"
set service "ALL"
set action accept
set status enable
next
edit 2
set name "dmz-web-in"
set srcintf "port3"
set dstintf "port4"
set srcaddr "all"
set dstaddr "corp-net"
set service "HTTPS"
set action accept
set status enable
next
edit 3
set name "guest-block"
set srcintf "port5"
set dstintf "port2"
set srcaddr "corp-net"
set dstaddr "all"
set service "ALL"
set action deny
set status enable
next
end
"""

    def test_interface_scoped_policies_raise_nothing(self):
        env = fortios.parse_fortios_config(self.THREE_SCOPED_POLICIES)
        # Was: any_any on 1, then unreachable on 2 and 3. All three false.
        self.assertEqual(findings.analyze_policy_findings(env), [])

    def test_a_genuinely_wide_open_policy_is_still_caught(self):
        env = fortios.parse_fortios_config("""#config-version=FGT
config firewall policy
edit 9
set name "wide-open"
set srcintf "any"
set dstintf "any"
set srcaddr "all"
set dstaddr "all"
set service "ALL"
set action accept
set status enable
next
end
""")
        self.assertIn("any_any",
                      [f.key for f in findings.analyze_policy_findings(env)])

    def test_is_any_any_is_false_when_an_interface_is_named(self):
        scoped = FieldSet(ingress_intfs={"port1"}, egress_intfs={"port2"})
        self.assertFalse(scoped.is_any_any())
        self.assertTrue(FieldSet().is_any_any())


class StaticRouteDistance(unittest.TestCase):
    """Only a bare number is the administrative distance."""

    ROUTES = """hostname switch-01
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
!
ip route 198.51.100.0 255.255.255.0 192.0.2.254 tag 250
ip route 203.0.113.0 255.255.255.0 192.0.2.254 track 7
ip route 192.0.2.128 255.255.255.128 192.0.2.254 200 name BACKUP
ip route 198.18.0.0 255.255.0.0 192.0.2.254
"""

    def _distances(self):
        env = ios.parse_ios_config(self.ROUTES)
        return {r.prefix: r.distance for r in env.route_table.routes
                if r.source == "static"}

    def test_tag_value_is_not_the_distance(self):
        self.assertEqual(self._distances()["198.51.100.0/24"], 1)

    def test_track_value_is_not_the_distance(self):
        self.assertEqual(self._distances()["203.0.113.0/24"], 1)

    def test_a_real_distance_is_still_read(self):
        self.assertEqual(self._distances()["192.0.2.128/25"], 200)

    def test_default_distance_without_options(self):
        self.assertEqual(self._distances()["198.18.0.0/16"], 1)


class GeneratedExamplesMatchTheirRule(unittest.TestCase):
    """A 'matching' example that does not match is worse than none."""

    def _rule_10(self):
        env = ios.parse_ios_config(IOS_ODD_WILDCARD)
        rules = [r for acl in env.acls.values() for r in acl.rules]
        return next(r for r in rules if r.id == "10")

    def test_non_contiguous_wildcard_example_lands_inside_the_cube(self):
        rule = self._rule_10()
        example = examples.generate_rule_example(rule)
        # 'permit ip 192.0.2.0 0.0.255.0' keeps the LAST octet significant, so
        # value + 1 produced 192.0.0.1 — outside the rule it illustrates.
        self.assertIsNotNone(example.matching_flow)
        assert example.matching_flow is not None
        self.assertTrue(rule.fields.matches(example.matching_flow))

    def test_near_miss_really_misses(self):
        rule = self._rule_10()
        example = examples.generate_rule_example(rule)
        self.assertIsNotNone(example.near_miss_flow)
        assert example.near_miss_flow is not None
        self.assertFalse(rule.fields.matches(example.near_miss_flow))

    def test_scatter_stays_inside_an_odd_mask(self):
        cube = Cube.from_wildcard("192.0.2.0", "0.0.255.0")
        for n in range(1, 8):
            self.assertTrue(
                cube.contains_ip(examples._scatter_into_free_bits(cube, n)))


if __name__ == "__main__":
    unittest.main()
