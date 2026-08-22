# -*- coding: utf-8 -*-
"""The shadowed-rule check must reach every surface that shows rules.

One engine, several readers. These tests pin the wiring, not the matching
logic (that lives in test_policy_regressions.py): each surface must actually
carry the findings, and the CIS score must stay out of it. RFC 5737 addresses
and placeholder hostnames only.
"""

import unittest

from ai import config_analyzer
from services.netsec_audit import run_netsec_audit


IOS_SHADOWED = """hostname switch-01
ip access-list extended EDGE_IN
 10 permit ip 192.0.2.0 0.0.0.255 any
 20 deny   ip 192.0.2.64 0.0.0.63 any
 30 permit tcp any any eq 443
!
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
 ip access-group EDGE_IN in
!
ip route 0.0.0.0 0.0.0.0 192.0.2.254
"""

IOS_CLEAN = """hostname switch-01
ip access-list extended EDGE_IN
 10 permit tcp 192.0.2.0 0.0.0.255 any eq 443
 20 deny ip any any
!
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
 ip access-group EDGE_IN in
"""

FORTIOS_SHADOWED = """#config-version=FGT
config firewall address
edit "corp-net"
set subnet 192.0.2.0 255.255.255.0
next
end
config firewall policy
edit 1
set name "allow-corp-any"
set srcintf "port1"
set dstintf "port2"
set srcaddr "corp-net"
set dstaddr "all"
set service "ALL"
set action accept
set status enable
next
edit 2
set name "block-corp-web"
set srcintf "port1"
set dstintf "port2"
set srcaddr "corp-net"
set dstaddr "all"
set service "HTTPS"
set action deny
set status enable
next
end
"""


class ConfigAnalyzerCarriesPolicyFindings(unittest.TestCase):
    """The validation view is the ACL-problems view; defects belong in it."""

    def test_ios_validation_reports_the_shadowed_ace(self):
        validation = config_analyzer.analyze_config(IOS_SHADOWED)["validation"]
        self.assertIn("policy_findings", validation)
        shadowed = [f for f in validation["policy_findings"]
                    if f["key"] == "shadowed"]
        self.assertEqual(len(shadowed), 1)
        self.assertEqual(shadowed[0]["params"]["rule_id"], "20")
        self.assertEqual(shadowed[0]["params"]["shadowed_by"], "10")
        self.assertEqual(shadowed[0]["acl_name"], "EDGE_IN")

    def test_fortios_validation_reports_the_shadowed_policy(self):
        validation = config_analyzer.analyze_fortios_config(
            FORTIOS_SHADOWED)["validation"]
        self.assertIn("policy_findings", validation)
        keys = [f["key"] for f in validation["policy_findings"]]
        self.assertIn("shadowed", keys)

    def test_existing_validation_keys_are_untouched(self):
        """The new key is additive; nothing that existed may disappear."""
        validation = config_analyzer.analyze_config(IOS_SHADOWED)["validation"]
        for key in ("unused_acls", "missing_acls", "unused_vlans",
                    "undefined_vlans", "route_acl_refs"):
            self.assertIn(key, validation)

    def test_a_clean_config_reports_no_shadowing(self):
        validation = config_analyzer.analyze_config(IOS_CLEAN)["validation"]
        self.assertEqual(
            [f for f in validation["policy_findings"] if f["key"] == "shadowed"],
            [])

    def test_unparseable_config_yields_no_findings_not_an_exception(self):
        validation = config_analyzer.analyze_config("\x00 not a config at all")
        self.assertEqual(validation["validation"]["policy_findings"], [])


class NetsecAuditKeepsDefectsOutOfTheScore(unittest.TestCase):
    """'ACE 20 shadowed by ACE 10' is a real defect and not a CIS control."""

    def test_defects_are_reported(self):
        result = run_netsec_audit(IOS_SHADOWED, device_name="switch-01", lang="en")
        self.assertIn("shadowed", [d["key"] for d in result["policy_defects"]])

    def test_defects_do_not_enter_the_benchmark_summary(self):
        result = run_netsec_audit(IOS_SHADOWED, device_name="switch-01", lang="en")
        summary = result["summary"]
        counted = (summary["passed"] + summary["failed"]
                   + summary["warned"] + summary["unknown"])
        # Every counted outcome came from a benchmark rule; the defects list is
        # carried alongside and adds nothing to the denominator.
        self.assertEqual(summary["total"], len(result["rules"]))
        self.assertEqual(counted, summary["total"])

    def test_score_is_identical_with_and_without_a_shadowed_rule(self):
        with_defect = run_netsec_audit(IOS_SHADOWED, device_name="switch-01",
                                       lang="en")
        without = run_netsec_audit(IOS_CLEAN, device_name="switch-01", lang="en")
        self.assertTrue(with_defect["policy_defects"])
        self.assertEqual(with_defect["score"], without["score"])

    def test_empty_config_does_not_raise(self):
        result = run_netsec_audit("", device_name="-", lang="en")
        self.assertEqual(result["policy_defects"], [])




class FindingsCarryTheirOwnProof(unittest.TestCase):
    """A finding must be checkable, not merely asserted.

    Each containment finding ships a witness: a packet the reported rule was
    written to catch. Tracing it has to land on the rule the finding blames,
    which is the claim made testable by the same engine that answers the
    tracer.
    """

    def _env(self):
        from services.policy_test import ios
        return ios.parse_ios_config(IOS_SHADOWED)

    def test_shadowed_finding_ships_a_witness(self):
        from services.policy_test import findings as pt
        shadowed = [f for f in pt.analyze_policy_findings(self._env())
                    if f.key == "shadowed"]
        self.assertEqual(len(shadowed), 1)
        self.assertIsNotNone(shadowed[0].witness)
        self.assertEqual(shadowed[0].expected_rule_id, "10")

    def test_the_witness_actually_matches_the_reported_rule(self):
        """Otherwise it proves nothing about that rule."""
        from services.policy_test import findings as pt
        from services.policy_test.model import Flow
        env = self._env()
        finding = next(f for f in pt.analyze_policy_findings(env)
                       if f.key == "shadowed")
        rule = next(r for acl in env.acls.values() for r in acl.rules
                    if r.id == finding.params["rule_id"])
        assert finding.witness is not None
        self.assertTrue(rule.fields.matches(Flow(**finding.witness)))

    def test_tracing_the_witness_lands_on_the_blamed_rule(self):
        from services.policy_test import engine, findings as pt
        from services.policy_test.model import Flow
        env = self._env()
        finding = next(f for f in pt.analyze_policy_findings(env)
                       if f.key == "shadowed")
        assert finding.witness is not None
        flow = dict(finding.witness)
        flow["ingress_intf"] = flow.get("ingress_intf") or "Vlan10"
        trace = engine.evaluate(env, Flow(**flow))
        caught_by = next((s.rule_id for s in trace.steps
                          if s.kind == "acl_in" and s.rule_id), None)
        self.assertEqual(caught_by, finding.expected_rule_id)

    def test_a_clean_acl_produces_no_finding_to_prove(self):
        from services.policy_test import ios, findings as pt
        env = ios.parse_ios_config(IOS_CLEAN)
        self.assertEqual(
            [f for f in pt.analyze_policy_findings(env) if f.key == "shadowed"],
            [])

    def test_unparseable_rule_gets_no_witness(self):
        """Unknown coverage: no packet can be claimed to exercise it."""
        from services.policy_test import ios, findings as pt
        env = ios.parse_ios_config("""hostname switch-01
ip access-list extended EDGE_IN
 10 permit object-group SVC object-group SRC any
 20 deny ip any any
!
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
 ip access-group EDGE_IN in
""")
        for f in pt.analyze_policy_findings(env):
            if f.key == "unresolved_object":
                self.assertIsNone(f.witness)


class NumberedAclDeclarationTest(unittest.TestCase):
    """A numbered ACL must still say whether it is standard or extended."""

    def test_numbered_kinds_render_the_declaration(self):
        from routers.policy_test import _acl_declaration
        self.assertEqual(
            _acl_declaration("101", "numbered-extended"), "access-list 101 (extended)"
        )
        self.assertEqual(
            _acl_declaration("10", "numbered-standard"), "access-list 10 (standard)"
        )


if __name__ == "__main__":
    unittest.main()
