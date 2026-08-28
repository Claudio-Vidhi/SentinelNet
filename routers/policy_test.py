# -*- coding: utf-8 -*-
"""Router Policy Test: reachability tracing, rule example generator, and static findings.

Endpoints for offline policy and route validation against stored device backups.
Tenant-scoped via assert_device_allowed.
"""

from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ai import config_analyzer
from routers.deps import assert_device_allowed, get_current_user
from services.policy_test.engine import evaluate
from services.policy_test.examples import generate_ruleset_examples
from services.policy_test.findings import analyze_policy_findings
from services.policy_test.fortios import parse_fortios_config
from services.policy_test.ios import parse_ios_config
from services.policy_test.model import Flow

router = APIRouter(tags=["PolicyTest"])


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


def _load_device_backup(ip: str, current_user) -> Tuple[str, str]:
    """Load backup text and detect config type for device IP.

    Returns (content, config_type). Raises HTTP 404/403/500 as appropriate.
    """
    device = assert_device_allowed(current_user, ip)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Dispositivo {ip} non trovato.")

    path, _tenant = config_analyzer._find_freshest_backup(ip)
    if not path:
        raise HTTPException(status_code=404, detail=f"Nessun backup trovato per {ip}.")

    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            raw_content = fh.read()
    except OSError:
        raise HTTPException(status_code=500, detail=f"Impossibile leggere il backup di {ip}.")

    content = "\n".join(config_analyzer.running_config(raw_content))
    config_type = config_analyzer.detect_config_type(content, device)
    return content, config_type


# Vendors whose config this feature knows how to evaluate. Anything else has
# to be refused: routing every unknown type to the IOS parser produced an
# empty environment, so /findings answered [] and the UI painted a green
# "no defects" panel for a device that was never analysed at all.
_SUPPORTED_CONFIG_TYPES = {"ios", "fortios"}


def _parse_environment(content: str, config_type: str) -> Any:
    """Parse policy environment based on vendor. 422 on an unsupported one."""
    if config_type == "fortios":
        return parse_fortios_config(content)
    if config_type == "ios":
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
        # FortiOS: a single ordered policy list, evaluated top-down.
        groups.append({
            "name": "firewall policy",
            "kind": "firewall_policy",
            "declaration": _acl_declaration("firewall policy", "firewall_policy"),
            "bindings": [],
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
    findings = analyze_policy_findings(env)
    return [f.to_dict() for f in findings]


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
