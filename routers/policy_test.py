# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router Policy Test: reachability tracing, rule example generator, and static findings.

Endpoints for offline policy and route validation against stored device backups.
Tenant-scoped via assert_device_allowed.
"""

import os
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Depends, HTTPException
from routers.deps import require_tab
from pydantic import BaseModel, Field

from ai import config_analyzer
from routers.deps import assert_device_allowed, get_current_user
from services.policy_test.engine import evaluate
from services.policy_test.examples import generate_ruleset_examples
from services.policy_test.findings import analyze_policy_findings
from services.policy_test.fortios import parse_fortios_config
from services.policy_test.ios import parse_ios_config
from services.policy_test.model import Flow

router = APIRouter(dependencies=[Depends(require_tab("tab-policy-test"))], tags=["PolicyTest"])


class FlowRequest(BaseModel):
    src_ip: str
    dst_ip: str
    proto: str = "tcp"
    sport: Optional[int] = Field(None, ge=1, le=65535)
    dport: Optional[int] = Field(None, ge=1, le=65535)
    ingress_intf: Optional[str] = None
    egress_intf: Optional[str] = None
    tcp_flags: Optional[str] = None
    established: bool = False
    icmp_type: Optional[int] = Field(None, ge=0, le=255)


def _load_device_backup_detail(ip: str, current_user) -> Tuple[str, str, Optional[float]]:
    """Load backup text, detected config type, and mtime timestamp for device IP.

    Returns (content, config_type, backup_ts). Raises HTTP 404/403/500 as appropriate.
    """
    device = assert_device_allowed(current_user, ip)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Dispositivo {ip} non trovato.")

    path, _tenant = config_analyzer._find_freshest_backup(ip, device.get("Group"))
    if not path:
        raise HTTPException(status_code=404, detail=f"Nessun backup trovato per {ip}.")

    try:
        backup_ts: Optional[float] = os.path.getmtime(path)
    except OSError:
        backup_ts = None

    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            raw_content = fh.read()
    except OSError:
        raise HTTPException(status_code=500, detail=f"Impossibile leggere il backup di {ip}.")

    content = "\n".join(config_analyzer.running_config(raw_content))
    config_type = config_analyzer.detect_config_type(content, device)
    return content, config_type, backup_ts


def _load_device_backup(ip: str, current_user) -> Tuple[str, str]:
    """Load backup text and detect config type for device IP.

    Returns (content, config_type). Raises HTTP 404/403/500 as appropriate.
    """
    content, config_type, _backup_ts = _load_device_backup_detail(ip, current_user)
    return content, config_type


# Vendors whose config this feature knows how to evaluate. Anything else has
# to be refused: routing every unknown type to the IOS parser produced an
# empty environment, so /findings answered [] and the UI painted a green
# "no defects" panel for a device that was never analysed at all.
_SUPPORTED_CONFIG_TYPES = {"ios", "fortios", "panos", "junos", "nxos", "ot_switch"}


def _parse_environment(content: str, config_type: str) -> Any:
    """Parse policy environment based on vendor. 422 on an unsupported one."""
    if config_type == "fortios":
        return parse_fortios_config(content)
    if config_type == "panos":
        from services.policy_test.panos import parse_panos_config
        return parse_panos_config(content)
    if config_type == "junos":
        from services.policy_test.junos import parse_junos_config
        return parse_junos_config(content)
    if config_type in ("ios", "nxos", "ot_switch"):
        return parse_ios_config(content)
    raise HTTPException(
        status_code=422,
        detail=f"Validazione policy non supportata per configurazioni '{config_type}'. "
               f"Vendor supportati: {', '.join(sorted(_SUPPORTED_CONFIG_TYPES))}.",
    )


@router.post("/api/policy-test/{ip}/trace")
def policy_trace(ip: str, flow_req: FlowRequest, current_user = Depends(get_current_user)):
    """Evaluate a Flow through the device policy and route chain."""
    content, config_type = _load_device_backup(ip, current_user)
    env = _parse_environment(content, config_type)

    flow = Flow(
        src_ip=flow_req.src_ip,
        dst_ip=flow_req.dst_ip,
        proto=flow_req.proto,
        sport=flow_req.sport,
        dport=flow_req.dport,
        ingress_intf=flow_req.ingress_intf,
        egress_intf=flow_req.egress_intf,
        tcp_flags=flow_req.tcp_flags,
        established=flow_req.established,
        icmp_type=flow_req.icmp_type,
    )

    trace = evaluate(env, flow)
    return trace.to_dict()


def _acl_declaration(name: str, kind: str) -> str:
    """The configuration line that declares this rule set.

    The name alone does not say what the rules can express: a standard ACL
    matches source addresses only, an extended one carries protocol, ports and
    destination. Showing the declaration the device actually holds —
    'ip access-list extended ACL-NAME' — tells the reader which of the two they
    are looking at, in the syntax they would type.
    """
    if kind == "firewall_policy":
        return "config firewall policy"
    if kind == "named-ext":
        return f"ip access-list extended {name}"
    if kind == "named-std":
        return f"ip access-list standard {name}"
    # Numbered ACLs are declared per line, not by a block header; the number
    # and its range are what identify the kind.
    if kind.startswith("numbered-"):
        return f"access-list {name} ({kind.split('-', 1)[1]})"
    return name


def _acl_bindings(env: Any, acl_name: str) -> List[Dict[str, str]]:
    """Interfaces where an ACL is applied, and in which direction.

    An ACL name on its own does not tell an operator what the rules govern.
    'EDGE_IN on Vlan10 inbound' does.
    """
    out: List[Dict[str, str]] = []
    for iface_name, info in (getattr(env, "interfaces", {}) or {}).items():
        for key, direction in (("acl_in", "in"), ("acl_out", "out")):
            if info.get(key) == acl_name:
                out.append({"interface": iface_name, "direction": direction})
    return out


@router.get("/api/policy-test/{ip}/examples")
def policy_examples(ip: str, current_user = Depends(get_current_user)):
    """Generate representative matching and near-miss flows, grouped by rule set.

    Grouped, not flat: a device carries several ACLs and their sequence
    numbers restart in each one. Flattening them lost the ACL name, so two
    different 'rule 10's reached the UI indistinguishable and no reader could
    tell what either one governed.
    """
    content, config_type = _load_device_backup(ip, current_user)
    env = _parse_environment(content, config_type)

    groups: List[Dict[str, Any]] = []
    if hasattr(env, "policies"):
        is_panos = hasattr(env, "nat_rules")
        is_junos = hasattr(env, "applications") and not is_panos
        grp_name = "security rulebase" if is_panos else ("security policies" if is_junos else "firewall policy")
        decl = ("rulebase security rules" if is_panos
                else ("security policies from-zone -> to-zone" if is_junos
                      else _acl_declaration("firewall policy", "firewall_policy")))
        zone_bindings = [
            {"interface": f"{z} ({', '.join(ifs)})", "direction": "zone"}
            for z, ifs in (getattr(env, "zones", {}) or {}).items() if ifs
        ]
        groups.append({
            "name": grp_name,
            "kind": "firewall_policy",
            "declaration": decl,
            "bindings": zone_bindings,
            "default_action": "deny",
            "examples": [e.to_dict() for e in generate_ruleset_examples(env.policies)],
        })
    else:
        for acl_name, ruleset in env.acls.items():
            groups.append({
                "name": acl_name,
                "kind": ruleset.kind,
                "declaration": _acl_declaration(acl_name, ruleset.kind),
                "bindings": _acl_bindings(env, acl_name),
                "default_action": ruleset.default_action,
                "examples": [e.to_dict()
                             for e in generate_ruleset_examples(ruleset.rules)],
            })
    return groups


@router.get("/api/policy-test/{ip}/findings")
def policy_findings(ip: str, current_user = Depends(get_current_user)):
    """Analyze device configuration for static policy and routing findings."""
    content, config_type = _load_device_backup(ip, current_user)
    env = _parse_environment(content, config_type)
    findings = analyze_policy_findings(env, config_text=content, vendor=config_type)
    return [f.to_dict() for f in findings]


@router.get("/api/policy-test/{ip}/metadata")
def policy_metadata(ip: str, current_user = Depends(get_current_user)):
    """Return parsed interfaces, ACLs, rule summaries, static routes, and backup metadata."""
    content, config_type, backup_ts = _load_device_backup_detail(ip, current_user)
    env = _parse_environment(content, config_type)

    raw_ifaces = getattr(env, "interfaces", None) or {}
    iface_to_zone = getattr(env, "iface_to_zone", None) or {}
    interfaces: List[Dict[str, Any]] = []
    for name in sorted(raw_ifaces.keys()):
        info = raw_ifaces.get(name) or {}
        if not isinstance(info, dict):
            continue
        interfaces.append({
            "name": str(name),
            "ip": str(info.get("ip") or ""),
            "mask": str(info.get("mask") or ""),
            "acl_in": str(info.get("acl_in") or ""),
            "acl_out": str(info.get("acl_out") or ""),
            "zone": str(iface_to_zone.get(name, "")),
        })

    zones = sorted(str(z) for z in (getattr(env, "zones", None) or {}).keys())

    acls: List[Dict[str, Any]] = []
    rules: List[Dict[str, Any]] = []
    if hasattr(env, "policies"):
        policies = list(getattr(env, "policies", None) or [])
        acls.append({
            "name": "firewall_policy",
            "kind": "firewall_policy",
            "rule_count": len(policies),
            "bindings": [],
        })
        for r in policies[:500]:
            rules.append({
                "acl": "firewall_policy",
                "id": str(r.id),
                "name": str(r.name or ""),
                "action": str(r.action),
                "disabled": bool(r.disabled),
                "raw_text": str(r.raw_text or ""),
            })
    else:
        acls_map = getattr(env, "acls", None) or {}
        for acl_name, ruleset in acls_map.items():
            acls.append({
                "name": str(acl_name),
                "kind": str(ruleset.kind),
                "rule_count": len(ruleset.rules),
                "bindings": _acl_bindings(env, str(acl_name)),
            })
            for r in ruleset.rules:
                if len(rules) >= 500:
                    break
                rules.append({
                    "acl": str(acl_name),
                    "id": str(r.id),
                    "name": str(r.name or ""),
                    "action": str(r.action),
                    "disabled": bool(r.disabled),
                    "raw_text": str(r.raw_text or ""),
                })

    rt = getattr(env, "route_table", None)
    rt_routes = getattr(rt, "routes", None) or []
    static_routes: List[Dict[str, Any]] = []
    for route in rt_routes:
        if getattr(route, "source", "") != "static":
            continue
        static_routes.append({
            "prefix": str(route.prefix),
            "next_hop": str(route.next_hop or ""),
            "interface": str(route.interface or ""),
            "distance": int(route.distance),
            "vrf": str(route.vrf or ""),
        })
        if len(static_routes) >= 200:
            break

    return {
        "device_ip": ip,
        "config_type": config_type,
        "backup_ts": backup_ts,
        "dynamic_routing_present": bool(getattr(rt, "dynamic_routing_present", False)),
        "protocols": [str(p) for p in (getattr(rt, "protocols", None) or [])],
        "interfaces": interfaces,
        "zones": zones,
        "acls": acls,
        "rules": rules,
        "static_routes": static_routes,
    }


class ProofRequest(BaseModel):
    """A finding's witness packet plus the rule the finding says will catch it."""
    witness: FlowRequest
    expected_rule_id: str


@router.post("/api/policy-test/{ip}/prove")
def policy_prove(ip: str, req: ProofRequest, current_user = Depends(get_current_user)):
    """Run a finding's witness packet and report whether the claim holds.

    A finding asserts that a rule cannot fire. This turns the assertion into
    something checkable: the witness is a packet that rule was written to
    catch, so tracing it must land on the rule the finding blames instead.
    The verdict is computed by the same engine that answers the tracer, not by
    a second code path that could agree with the detector by construction.

    ``proven`` false is a real answer, not an error: it means the detector and
    the evaluator disagree about this configuration, and that is worth seeing.
    """
    content, config_type = _load_device_backup(ip, current_user)
    env = _parse_environment(content, config_type)

    flow = Flow(**req.witness.model_dump())
    trace = evaluate(env, flow)

    # The rule that actually caught the packet, from the ACL/policy step.
    actual = next((s.rule_id for s in trace.steps
                   if s.kind in ("acl_in", "acl_out", "policy") and s.rule_id), None)
    return {
        "proven": actual == req.expected_rule_id,
        "expected_rule_id": req.expected_rule_id,
        "actual_rule_id": actual,
        "trace": trace.to_dict(),
    }


class WhatIfChange(BaseModel):
    action: str = Field(..., min_length=1, max_length=40)
    rule_id: Optional[str] = None
    acl: Optional[str] = None
    name: Optional[str] = None
    rule_action: str = "permit"
    src_cidr: Optional[str] = None
    dst_cidr: Optional[str] = None
    proto: str = "tcp"
    dport: Optional[int] = Field(None, ge=1, le=65535)
    src_intf: Optional[str] = None
    dst_intf: Optional[str] = None
    position: str = "top"
    prefix: Optional[str] = None
    next_hop: Optional[str] = None
    interface: Optional[str] = None
    distance: int = Field(1, ge=1, le=255)


class WhatIfRequest(BaseModel):
    change: WhatIfChange
    flows: List[FlowRequest] = Field(default_factory=list)


@router.post("/api/policy-test/{ip}/what-if")
def policy_whatif(ip: str, req: WhatIfRequest, current_user = Depends(get_current_user)):
    """Simulate a rule or route change offline and compute verdict diffs and rollback plan."""
    from services.whatif_simulator import simulate_whatif

    content, config_type = _load_device_backup(ip, current_user)
    env = _parse_environment(content, config_type)
    try:
        return simulate_whatif(
            env,
            config_type,
            req.change.model_dump(),
            flows=[f.model_dump() for f in req.flows],
            device_ip=ip,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

