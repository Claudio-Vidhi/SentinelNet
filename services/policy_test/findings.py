# -*- coding: utf-8 -*-
"""Static policy and route findings detector.

Detects configuration defects purely from the model:
- shadowed: ACE or policy fully covered by a single earlier rule
- unreachable: rule following an any-any rule
- any_any: permit rule matching any source, destination and service
- route_to_nowhere: static route whose next hop does not match any connected subnet
- unresolved_object: rule referencing undefined address or service objects

Pure module with zero I/O.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Union

from services.policy_test.ios import IOSPolicyEnvironment
from services.policy_test.model import (
    Finding, RouteTable, Rule, RuleSet, ip_to_int,
)


def find_ruleset_defects(ruleset: RuleSet) -> List[Finding]:
    """Analyze a single RuleSet for shadowed, unreachable, any_any, and unresolved rules."""
    findings: List[Finding] = []
    rules = [r for r in ruleset.rules if not r.disabled]

    # Track covering any-any rule if seen
    covering_any_any: Optional[Rule] = None

    for idx, rule in enumerate(rules):
        # 1. Unresolved objects
        if rule.unresolved:
            findings.append(Finding(
                key="unresolved_object",
                severity="medium",
                rule_id=rule.id,
                acl_name=ruleset.name,
                params={"rule_id": rule.id, "objects": list(rule.unresolved), "acl": ruleset.name},
                message_key="finding.unresolved_object",
            ))

        # 2. Unreachable check (follows a preceding any-any rule)
        if covering_any_any is not None:
            findings.append(Finding(
                key="unreachable",
                severity="high" if rule.action == "permit" else "medium",
                rule_id=rule.id,
                acl_name=ruleset.name,
                params={"rule_id": rule.id, "blocked_by": covering_any_any.id, "acl": ruleset.name},
                message_key="finding.unreachable",
            ))
            continue  # Already unreachable, skip single-rule shadow check

        # 3. Any-any permit check
        if rule.action == "permit" and rule.fields.is_any_any():
            findings.append(Finding(
                key="any_any",
                severity="high",
                rule_id=rule.id,
                acl_name=ruleset.name,
                params={"rule_id": rule.id, "acl": ruleset.name},
                message_key="finding.any_any",
            ))

        # 4. Shadow check against all earlier rules
        if not rule.fields.opaque:
            for prev in rules[:idx]:
                if not prev.fields.opaque and prev.fields.contains(rule.fields):
                    findings.append(Finding(
                        key="shadowed",
                        severity="high" if prev.action != rule.action else "low",
                        rule_id=rule.id,
                        acl_name=ruleset.name,
                        params={
                            "rule_id": rule.id,
                            "shadowed_by": prev.id,
                            "acl": ruleset.name,
                            "prev_action": prev.action,
                            "curr_action": rule.action,
                        },
                        message_key="finding.shadowed",
                    ))
                    break  # Report only first covering rule

        # Update covering any-any tracker
        if not rule.fields.opaque and rule.fields.is_any_any():
            covering_any_any = rule

    return findings


def find_routing_defects(route_table: RouteTable) -> List[Finding]:
    """Check for static routes to nowhere (next hop not in any connected subnet)."""
    findings: List[Finding] = []
    connected = route_table.connected_subnets()

    for r in route_table.routes:
        if r.source == "static" and r.next_hop and not r.interface:
            # Check if next hop is contained in any connected subnet
            try:
                nh_int = ip_to_int(r.next_hop)
                has_connected = any(c.prefix_cube.contains_ip(nh_int) for c in connected)
                if not has_connected:
                    findings.append(Finding(
                        key="route_to_nowhere",
                        severity="high",
                        params={"prefix": r.prefix, "next_hop": r.next_hop},
                        message_key="finding.route_to_nowhere",
                    ))
            except Exception:
                findings.append(Finding(
                    key="route_to_nowhere",
                    severity="high",
                    params={"prefix": r.prefix, "next_hop": r.next_hop},
                    message_key="finding.route_to_nowhere",
                ))

    return findings


def analyze_policy_findings(env: Any) -> List[Finding]:
    """Collect all static findings from an IOS or FortiOS environment."""
    findings: List[Finding] = []

    # RuleSet findings
    if isinstance(env, IOSPolicyEnvironment):
        for acl in env.acls.values():
            findings.extend(find_ruleset_defects(acl))
        findings.extend(find_routing_defects(env.route_table))
    elif hasattr(env, "policies") and hasattr(env, "route_table"):
        # FortiOS environment
        rs = RuleSet(name="firewall_policy", kind="firewall_policy", rules=env.policies)
        findings.extend(find_ruleset_defects(rs))
        findings.extend(find_routing_defects(env.route_table))

    return findings
