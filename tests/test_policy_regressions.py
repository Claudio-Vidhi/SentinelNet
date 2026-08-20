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


# An ACL whose two ICMP rules can never catch the same packet. Reported as
# shadowed for as long as the parser threw the message name away. Shape taken
# from a real config; addresses are RFC 5737.
IOS_ICMP_TYPES = """hostname switch-01
ip access-list extended ACL-PING
 10 permit icmp 192.0.2.0 0.0.0.255 any echo-reply
 20 permit icmp 192.0.2.0 0.0.0.255 host 192.0.2.254 echo
 30 deny   ip any any
!
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
 ip access-group ACL-PING in
"""


class IcmpMessageTypeIsADimension(unittest.TestCase):
    """An echo request is not an echo reply, however alike the addresses look.

    Cisco matches ICMP on the message type. Dropping the trailing 'echo' /
    'echo-reply' token widened both ACEs to bare 'icmp', at which point the
    first trivially contained the second and the shadow detector fired on a
    pair of rules that share no packet at all.
    """

    def _rules(self):
        env = ios.parse_ios_config(IOS_ICMP_TYPES)
        return {r.id: r for r in env.acls["ACL-PING"].rules}

    def test_message_name_reaches_the_field_set(self):
        rules = self._rules()
        self.assertEqual(rules["10"].fields.icmp_types, {0})
        self.assertEqual(rules["20"].fields.icmp_types, {8})

    def test_a_reply_rule_does_not_contain_a_request_rule(self):
        rules = self._rules()
        self.assertFalse(rules["10"].fields.contains(rules["20"].fields))

    def test_the_two_rules_share_no_packet(self):
        rules = self._rules()
        self.assertFalse(rules["10"].fields.intersects(rules["20"].fields))

    def test_no_shadowed_finding_is_reported(self):
        env = ios.parse_ios_config(IOS_ICMP_TYPES)
        self.assertEqual(
            [f.params["rule_id"] for f in findings.analyze_policy_findings(env)
             if f.key == "shadowed"],
            [])

    def test_an_echo_packet_is_caught_by_the_echo_rule(self):
        env = ios.parse_ios_config(IOS_ICMP_TYPES)
        trace = engine.evaluate(env, Flow(
            src_ip="192.0.2.10", dst_ip="192.0.2.254", proto="icmp",
            ingress_intf="Vlan10", icmp_type=8))
        caught = next((s.rule_id for s in trace.steps if s.kind == "acl_in"), None)
        self.assertEqual(caught, "20")
        self.assertEqual(trace.verdict, "PERMIT")

    def test_a_reply_packet_is_caught_by_the_reply_rule(self):
        env = ios.parse_ios_config(IOS_ICMP_TYPES)
        trace = engine.evaluate(env, Flow(
            src_ip="192.0.2.10", dst_ip="192.0.2.254", proto="icmp",
            ingress_intf="Vlan10", icmp_type=0))
        caught = next((s.rule_id for s in trace.steps if s.kind == "acl_in"), None)
        self.assertEqual(caught, "10")

    def test_two_rules_differing_only_in_message_type_are_not_redundant(self):
        """The ACL-FOTOVOLTAICO shape: identical but for echo vs echo-reply."""
        env = ios.parse_ios_config("""hostname switch-01
ip access-list extended ACL-BOTH
 20 permit icmp 192.0.2.0 0.0.0.255 any echo
 30 permit icmp 192.0.2.0 0.0.0.255 any echo-reply
!
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
 ip access-group ACL-BOTH in
""")
        self.assertEqual(
            [f.key for f in findings.analyze_policy_findings(env)
             if f.key == "shadowed"],
            [])

    def test_the_near_miss_flips_the_message_type(self):
        rules = self._rules()
        example = examples.generate_rule_example(rules["20"])
        assert example.matching_flow is not None
        assert example.near_miss_flow is not None
        self.assertEqual(example.matching_flow.icmp_type, 8)
        self.assertEqual(example.near_miss_flow.icmp_type, 0)
        self.assertTrue(rules["20"].fields.matches(example.matching_flow))
        self.assertFalse(rules["20"].fields.matches(example.near_miss_flow))


def _acl_q(body: str):
    """An ACL-Q holding the given ACE lines, bound inbound on Vlan10."""
    return ios.parse_ios_config(
        HEAD_ACL_Q + body + TAIL_ACL_Q)


HEAD_ACL_Q = """hostname switch-01
ip access-list extended ACL-Q
"""

TAIL_ACL_Q = """!
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
 ip access-group ACL-Q in
"""


class UnmodelledQualifiersStopClaimingCoverage(unittest.TestCase):
    """Same defect class as the ICMP message type: a dropped keyword widens.

    Every trailing keyword on an ACE narrows it on the device. One this model
    cannot evaluate must therefore stop the rule from asserting that it covers
    a neighbour, and stop the trace from answering with confidence.
    """

    def test_log_is_inert_and_leaves_the_rule_certain(self):
        env = _acl_q(" 10 permit tcp 192.0.2.0 0.0.0.255 any eq 443 log\n")
        rule = env.acls["ACL-Q"].rules[0]
        self.assertEqual(rule.fields.narrowing_quals, ())
        self.assertEqual(rule.unresolved, [])

    def test_dscp_is_recorded_not_dropped(self):
        env = _acl_q(" 10 permit ip 192.0.2.0 0.0.0.255 any dscp af21\n")
        rule = env.acls["ACL-Q"].rules[0]
        self.assertIn("dscp", rule.fields.narrowing_quals)
        self.assertTrue(rule.unresolved)

    def test_a_qualified_rule_does_not_shadow_a_plain_one(self):
        env = _acl_q(
            " 10 permit ip 192.0.2.0 0.0.0.255 any dscp af21\n"
            " 20 permit ip 192.0.2.0 0.0.0.255 host 192.0.2.9\n")
        self.assertEqual(
            [f.key for f in findings.analyze_policy_findings(env)
             if f.key == "shadowed"],
            [])

    def test_a_plain_rule_still_shadows_a_qualified_one(self):
        """A rule narrower than modelled is still covered by a wide one."""
        env = _acl_q(
            " 10 permit ip 192.0.2.0 0.0.0.255 any\n"
            " 20 permit ip 192.0.2.0 0.0.0.255 host 192.0.2.9 dscp af21\n")
        shadowed = [f.params["rule_id"]
                    for f in findings.analyze_policy_findings(env)
                    if f.key == "shadowed"]
        self.assertEqual(shadowed, ["20"])

    def test_matching_a_qualified_rule_yields_unknown(self):
        env = _acl_q(" 10 permit ip 192.0.2.0 0.0.0.255 any fragments\n")
        trace = engine.evaluate(env, Flow(
            src_ip="192.0.2.10", dst_ip="198.51.100.5", proto="tcp",
            ingress_intf="Vlan10"))
        self.assertEqual(trace.verdict, "UNKNOWN")

    def test_tcp_flag_qualifier_is_not_silently_ignored(self):
        env = _acl_q(" 10 permit tcp 192.0.2.0 0.0.0.255 any eq 22 syn\n")
        self.assertIn("syn", env.acls["ACL-Q"].rules[0].fields.narrowing_quals)

    def test_a_qualified_rule_gets_no_witness(self):
        env = _acl_q(
            " 10 permit ip 192.0.2.0 0.0.0.255 any\n"
            " 20 permit ip 192.0.2.0 0.0.0.255 host 192.0.2.9 dscp af21\n")
        for f in findings.analyze_policy_findings(env):
            if f.key == "shadowed":
                self.assertIsNone(f.witness)



FORTIOS_ICMP = """#config-version=FGT
config firewall address
edit "corp-net"
set subnet 192.0.2.0 255.255.255.0
next
end
config firewall service custom
edit "PING-REQ"
set protocol ICMP
set icmptype 8
next
edit "PING-REPLY"
set protocol ICMP
set icmptype 0
next
end
config firewall policy
edit 1
set name "allow-ping-reply"
set srcintf "port1"
set dstintf "port2"
set srcaddr "corp-net"
set dstaddr "all"
set service "PING-REPLY"
set action accept
next
edit 2
set name "allow-ping-request"
set srcintf "port1"
set dstintf "port2"
set srcaddr "corp-net"
set dstaddr "all"
set service "PING-REQ"
set action accept
next
end
"""


class FortiOsIcmpServicesAreDistinct(unittest.TestCase):
    """'set icmptype' is the FortiOS spelling of the Cisco echo keyword."""

    def _env(self):
        return fortios.parse_fortios_config(FORTIOS_ICMP)

    def test_the_message_type_reaches_the_policy(self):
        env = self._env()
        by_id = {p.id: p for p in env.policies}
        self.assertEqual(by_id["1"].fields.icmp_types, {0})
        self.assertEqual(by_id["2"].fields.icmp_types, {8})

    def test_two_icmp_policies_are_not_shadowed(self):
        env = self._env()
        self.assertEqual(
            [f.key for f in findings.analyze_policy_findings(env)
             if f.key == "shadowed"],
            [])

    def test_the_factory_ping_service_is_echo_request_only(self):
        from services.policy_test.builtins import lookup_builtin_service
        self.assertEqual(lookup_builtin_service("PING")["icmp_types"], {8})


class FortiOsConditionsAreNotDiscarded(unittest.TestCase):
    """A policy condition the model cannot evaluate must be visible."""

    def _policy(self, extra: str):
        cfg = FORTIOS_ICMP.replace('set service "PING-REPLY"\n',
                                   'set service "PING-REPLY"\n' + extra)
        env = fortios.parse_fortios_config(cfg)
        return {p.id: p for p in env.policies}["1"]

    def test_a_schedule_other_than_always_is_recorded(self):
        p = self._policy('set schedule "work-hours"\n')
        self.assertIn("schedule work-hours", p.fields.narrowing_quals)
        self.assertTrue(p.unresolved)

    def test_schedule_always_is_inert(self):
        p = self._policy('set schedule "always"\n')
        self.assertEqual(p.fields.narrowing_quals, ())

    def test_a_negated_source_makes_the_policy_undecidable(self):
        p = self._policy("set srcaddr-negate enable\n")
        self.assertTrue(any("srcaddr-negate" in u for u in p.unresolved))
        self.assertTrue(p.fields.opaque)

    def test_identity_conditions_are_recorded(self):
        p = self._policy('set groups "domain-admins"\n')
        self.assertIn("groups", p.fields.narrowing_quals)

    def test_the_ipsec_action_is_not_read_as_a_deny(self):
        cfg = FORTIOS_ICMP.replace("set action accept", "set action ipsec", 1)
        env = fortios.parse_fortios_config(cfg)
        p = {x.id: x for x in env.policies}["1"]
        self.assertEqual(p.action, "unknown")
        self.assertTrue(any("ipsec" in u for u in p.unresolved))

if __name__ == "__main__":
    unittest.main()
