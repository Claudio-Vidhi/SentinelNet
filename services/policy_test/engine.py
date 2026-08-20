# -*- coding: utf-8 -*-
"""Policy and Route Evaluation Engine.

Executes the on-device packet path chain:
- Cisco IOS: Ingress ACL -> Route Lookup (connected + static) -> Egress ACL.
- FortiOS: Route Lookup (egress) -> Firewall Policy List evaluation.

Pure engine with zero I/O. Propagates UNKNOWN when objects are unresolved or
routes are absent on dynamic routing boxes.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple, Union

from services.policy_test.ios import IOSPolicyEnvironment
from services.policy_test.model import (
    Flow, Route, RouteTable, Rule, RuleSet, Step, Trace, ip_to_int,
)


def _first_match(rules: List[Rule], flow: Flow) -> Optional[Rule]:
    """First rule that matches the flow, or the first undecidable one covering it.

    A rule whose objects could not be resolved offline is not a rule that
    matches nothing: it is a rule whose coverage is unknown. Walking past it
    to reach a later, fully parsed rule produces a confident verdict computed
    over a policy set the parser could not read — an unresolvable *deny* got
    silently bypassed so the next permit could answer PERMIT.

    So an undecidable rule stops the walk as soon as it *could* cover the
    flow. It is still skipped when a dimension that WAS parsed excludes the
    flow outright, which keeps the common case decidable.
    """
    for rule in rules:
        if _rule_stops_walk(rule, flow):
            return rule
    return None


def _find_interface(interfaces: Dict[str, Dict[str, Any]],
                    name: Optional[str]) -> Optional[Dict[str, Any]]:
    """Interface entry for ``name``, matched case-insensitively.

    IOS accepts 'Vlan10', 'vlan10' and 'VLAN10' for the same interface, and
    the tracer takes this name as free text from the operator. An exact dict
    lookup meant a lowercase spelling found no interface, so the inbound ACL
    was skipped and a denied flow came back PERMIT — with a step list that
    still looked complete.
    """
    if not name:
        return None
    entry = interfaces.get(name)
    if entry is not None:
        return entry
    lowered = name.lower()
    for iface_name, info in interfaces.items():
        if iface_name.lower() == lowered:
            return info
    return None


def _rule_stops_walk(rule: Rule, flow: Flow) -> bool:
    """True when evaluation must stop at this rule.

    Either it definitely matches, or it is undecidable and could cover the
    flow. See ``_first_match`` for why undecidable has to stop the walk.
    """
    if rule.fields.opaque or rule.unresolved:
        return rule.fields.may_match(flow)
    return rule.fields.matches(flow)


def _derive_ingress_intf(src_ip: str, route_table: RouteTable) -> Optional[str]:
    """Derive ingress interface from source IP matching connected subnets."""
    try:
        ip_val = ip_to_int(src_ip)
    except Exception:
        return None

    for r in route_table.connected_subnets():
        if r.prefix_cube.contains_ip(ip_val):
            return r.interface
    return None


def evaluate_ios(env: IOSPolicyEnvironment, flow: Flow) -> Trace:
    """Evaluate a Flow through a Cisco IOS policy and routing environment."""
    steps: List[Step] = []
    unresolved: List[str] = list(env.unresolved)
    dynamic_present = env.route_table.dynamic_routing_present

    # 1. Determine Ingress Interface
    ingress = flow.ingress_intf
    if not ingress:
        ingress = _derive_ingress_intf(flow.src_ip, env.route_table)

    evaluated_flow = Flow(
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        proto=flow.proto,
        sport=flow.sport,
        dport=flow.dport,
        ingress_intf=ingress,
        egress_intf=flow.egress_intf,
        tcp_flags=flow.tcp_flags,
        established=flow.established,
    )

    # 2. Ingress ACL evaluation
    iface_info = _find_interface(env.interfaces, ingress)
    if iface_info is not None:
        acl_in_name = iface_info.get("acl_in")
        if acl_in_name and acl_in_name in env.acls:
            acl = env.acls[acl_in_name]
            matched_rule: Optional[Rule] = _first_match(acl.rules, evaluated_flow)

            if matched_rule is not None:
                if matched_rule.unresolved or matched_rule.fields.opaque:
                    steps.append(Step(
                        kind="acl_in",
                        acl=acl_in_name,
                        matched=f"seq {matched_rule.id}" if matched_rule.id else "rule",
                        action="unknown",
                        rule_id=matched_rule.id,
                        raw_text=matched_rule.raw_text,
                        note="unresolved or opaque ACE",
                    ))
                    return Trace(
                        verdict="UNKNOWN",
                        steps=steps,
                        implicit_deny=False,
                        dynamic_routing_present=dynamic_present,
                        unresolved=unresolved + matched_rule.unresolved,
                        flow=evaluated_flow.to_dict(),
                    )
                elif matched_rule.action == "deny":
                    steps.append(Step(
                        kind="acl_in",
                        acl=acl_in_name,
                        matched=f"seq {matched_rule.id}" if matched_rule.id else "rule",
                        action="deny",
                        rule_id=matched_rule.id,
                        raw_text=matched_rule.raw_text,
                    ))
                    return Trace(
                        verdict="DENY",
                        steps=steps,
                        implicit_deny=False,
                        dynamic_routing_present=dynamic_present,
                        unresolved=unresolved,
                        flow=evaluated_flow.to_dict(),
                    )
                else:
                    # Permit
                    steps.append(Step(
                        kind="acl_in",
                        acl=acl_in_name,
                        matched=f"seq {matched_rule.id}" if matched_rule.id else "rule",
                        action="permit",
                        rule_id=matched_rule.id,
                        raw_text=matched_rule.raw_text,
                    ))
            else:
                # Implicit deny at end of ACL
                steps.append(Step(
                    kind="acl_in",
                    acl=acl_in_name,
                    matched="implicit deny",
                    action="deny",
                    note="implicit deny at end of ACL",
                ))
                return Trace(
                    verdict="DENY",
                    steps=steps,
                    implicit_deny=True,
                    dynamic_routing_present=dynamic_present,
                    unresolved=unresolved,
                    flow=evaluated_flow.to_dict(),
                )
        else:
            steps.append(Step(
                kind="acl_in",
                acl=None,
                matched=None,
                action="permit",
                note=f"no inbound ACL bound on {ingress}",
            ))
    elif ingress:
        # The operator named an interface this device does not have. Reporting
        # "no inbound ACL" would be a permit derived from a typo: the ACL that
        # governs the real ingress was never consulted.
        steps.append(Step(
            kind="acl_in",
            acl=None,
            matched=None,
            action="unknown",
            note=f"interface {ingress} does not exist on this device",
        ))
        return Trace(
            verdict="UNKNOWN",
            steps=steps,
            implicit_deny=False,
            dynamic_routing_present=dynamic_present,
            unresolved=unresolved + [
                f"ingress interface '{ingress}' is not configured on this device"],
            flow=evaluated_flow.to_dict(),
        )
    else:
        steps.append(Step(
            kind="acl_in",
            acl=None,
            matched=None,
            action="permit",
            note="ingress interface unknown; inbound ACL skipped",
        ))

    # 3. Route Lookup
    route = env.route_table.lookup(flow.dst_ip)
    if route is None:
        steps.append(Step(
            kind="route",
            matched="no_static_route",
            action="unknown",
            note="no connected or static route found for destination",
        ))
        return Trace(
            verdict="UNKNOWN",
            steps=steps,
            implicit_deny=False,
            dynamic_routing_present=dynamic_present,
            unresolved=unresolved,
            flow=evaluated_flow.to_dict(),
        )

    egress = route.interface
    evaluated_flow.egress_intf = egress
    steps.append(Step(
        kind="route",
        prefix=route.prefix,
        next_hop=route.next_hop,
        egress=egress,
        source=route.source,
        action="permit",
    ))

    # 4. Egress ACL evaluation
    out_iface_info = _find_interface(env.interfaces, egress)
    if out_iface_info is not None:
        acl_out_name = out_iface_info.get("acl_out")
        if acl_out_name and acl_out_name in env.acls:
            acl = env.acls[acl_out_name]
            matched_rule = _first_match(acl.rules, evaluated_flow)

            if matched_rule is not None:
                if matched_rule.unresolved or matched_rule.fields.opaque:
                    steps.append(Step(
                        kind="acl_out",
                        acl=acl_out_name,
                        matched=f"seq {matched_rule.id}" if matched_rule.id else "rule",
                        action="unknown",
                        rule_id=matched_rule.id,
                        raw_text=matched_rule.raw_text,
                        note="unresolved or opaque ACE",
                    ))
                    return Trace(
                        verdict="UNKNOWN",
                        steps=steps,
                        implicit_deny=False,
                        dynamic_routing_present=dynamic_present,
                        unresolved=unresolved + matched_rule.unresolved,
                        flow=evaluated_flow.to_dict(),
                    )
                elif matched_rule.action == "deny":
                    steps.append(Step(
                        kind="acl_out",
                        acl=acl_out_name,
                        matched=f"seq {matched_rule.id}" if matched_rule.id else "rule",
                        action="deny",
                        rule_id=matched_rule.id,
                        raw_text=matched_rule.raw_text,
                    ))
                    return Trace(
                        verdict="DENY",
                        steps=steps,
                        implicit_deny=False,
                        dynamic_routing_present=dynamic_present,
                        unresolved=unresolved,
                        flow=evaluated_flow.to_dict(),
                    )
                else:
                    steps.append(Step(
                        kind="acl_out",
                        acl=acl_out_name,
                        matched=f"seq {matched_rule.id}" if matched_rule.id else "rule",
                        action="permit",
                        rule_id=matched_rule.id,
                        raw_text=matched_rule.raw_text,
                    ))
            else:
                steps.append(Step(
                    kind="acl_out",
                    acl=acl_out_name,
                    matched="implicit deny",
                    action="deny",
                    note="implicit deny at end of ACL",
                ))
                return Trace(
                    verdict="DENY",
                    steps=steps,
                    implicit_deny=True,
                    dynamic_routing_present=dynamic_present,
                    unresolved=unresolved,
                    flow=evaluated_flow.to_dict(),
                )
        else:
            steps.append(Step(
                kind="acl_out",
                acl=None,
                matched=None,
                action="permit",
                note="no ACL bound outbound",
            ))
    else:
        steps.append(Step(
            kind="acl_out",
            acl=None,
            matched=None,
            action="permit",
            note="no ACL bound outbound",
        ))

    return Trace(
        verdict="PERMIT",
        steps=steps,
        implicit_deny=False,
        dynamic_routing_present=dynamic_present,
        unresolved=unresolved,
        flow=evaluated_flow.to_dict(),
    )


def evaluate_fortios_chain(
    policies: List[Rule],
    route_table: RouteTable,
    flow: Flow,
    unresolved_objects: Optional[List[str]] = None,
) -> Trace:
    """Evaluate a Flow through FortiOS routing and security policies."""
    steps: List[Step] = []
    unresolved = list(unresolved_objects or [])
    dynamic_present = route_table.dynamic_routing_present
    nat_applied = False

    # 1. Route Lookup to determine egress interface
    route = route_table.lookup(flow.dst_ip)
    if route is None:
        steps.append(Step(
            kind="route",
            matched="no_static_route",
            action="unknown",
            note="no connected or static route found for destination",
        ))
        return Trace(
            verdict="UNKNOWN",
            steps=steps,
            implicit_deny=False,
            dynamic_routing_present=dynamic_present,
            unresolved=unresolved,
            flow=flow.to_dict(),
        )

    egress = route.interface
    ingress = flow.ingress_intf or _derive_ingress_intf(flow.src_ip, route_table)

    evaluated_flow = Flow(
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        proto=flow.proto,
        sport=flow.sport,
        dport=flow.dport,
        ingress_intf=ingress,
        egress_intf=egress,
        tcp_flags=flow.tcp_flags,
        established=flow.established,
    )

    steps.append(Step(
        kind="route",
        prefix=route.prefix,
        next_hop=route.next_hop,
        egress=egress,
        source=route.source,
        action="permit",
    ))

    # 2. Sequential policy evaluation
    matched_policy: Optional[Rule] = None

    for policy in policies:
        if policy.disabled:
            steps.append(Step(
                kind="skipped_policy",
                acl=policy.name or f"policy {policy.id}",
                matched=f"policy {policy.id}",
                action="skip",
                rule_id=policy.id,
                note="status disable",
            ))
            continue

        if _rule_stops_walk(policy, evaluated_flow):
            matched_policy = policy
            break

    if matched_policy is not None:
        if matched_policy.nat_enabled:
            nat_applied = True

        if matched_policy.unresolved or matched_policy.fields.opaque:
            steps.append(Step(
                kind="policy",
                acl=matched_policy.name or f"policy {matched_policy.id}",
                matched=f"policy {matched_policy.id}",
                action="unknown",
                rule_id=matched_policy.id,
                raw_text=matched_policy.raw_text,
                note=", ".join(matched_policy.unresolved) if matched_policy.unresolved else "unresolved object",
            ))
            return Trace(
                verdict="UNKNOWN",
                steps=steps,
                implicit_deny=False,
                dynamic_routing_present=dynamic_present,
                unresolved=unresolved + matched_policy.unresolved,
                nat_applied=nat_applied,
                flow=evaluated_flow.to_dict(),
            )
        elif matched_policy.action in ("deny", "drop"):
            steps.append(Step(
                kind="policy",
                acl=matched_policy.name or f"policy {matched_policy.id}",
                matched=f"policy {matched_policy.id}",
                action="deny",
                rule_id=matched_policy.id,
                raw_text=matched_policy.raw_text,
            ))
            return Trace(
                verdict="DENY",
                steps=steps,
                implicit_deny=False,
                dynamic_routing_present=dynamic_present,
                unresolved=unresolved,
                nat_applied=nat_applied,
                flow=evaluated_flow.to_dict(),
            )
        else:
            steps.append(Step(
                kind="policy",
                acl=matched_policy.name or f"policy {matched_policy.id}",
                matched=f"policy {matched_policy.id}",
                action="permit",
                rule_id=matched_policy.id,
                raw_text=matched_policy.raw_text,
            ))
            return Trace(
                verdict="PERMIT",
                steps=steps,
                implicit_deny=False,
                dynamic_routing_present=dynamic_present,
                unresolved=unresolved,
                nat_applied=nat_applied,
                flow=evaluated_flow.to_dict(),
            )

    # 3. Implicit deny (Policy 0)
    steps.append(Step(
        kind="policy",
        acl="default",
        matched="implicit deny",
        action="deny",
        note="implicit deny (policy 0)",
    ))
    return Trace(
        verdict="DENY",
        steps=steps,
        implicit_deny=True,
        dynamic_routing_present=dynamic_present,
        unresolved=unresolved,
        nat_applied=False,
        flow=evaluated_flow.to_dict(),
    )


def evaluate(env: Any, flow: Flow) -> Trace:
    """Generic entry point: dispatches to evaluate_ios or evaluate_fortios."""
    if hasattr(env, "policies") and hasattr(env, "route_table"):
        return evaluate_fortios_chain(env.policies, env.route_table, flow, getattr(env, "unresolved", []))
    if isinstance(env, IOSPolicyEnvironment):
        return evaluate_ios(env, flow)
    raise ValueError(f"Unknown policy environment type: {type(env)}")
