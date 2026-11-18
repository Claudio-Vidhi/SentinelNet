# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Change What-If & Safe Rollback Simulator.

Clones a parsed policy/routing environment (FortiOS, PAN-OS, Junos, IOS/NX-OS/OT),
applies a hypothetical rule or route change offline, evaluates all critical/observed/
synthetic flows before vs after, computes static finding deltas, and produces
vendor-specific Apply CLI/API + Safe Rollback snippets before touching the device.
"""

from __future__ import annotations

import copy
import ipaddress
import sqlite3
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from core import db
from services.policy_test.engine import evaluate
from services.policy_test.examples import generate_ruleset_examples
from services.policy_test.findings import analyze_policy_findings
from services.policy_test.model import (
    Cube, FieldSet, Flow, PortSet, Route, Rule, int_to_ip, proto_from_name,
)


def _cidr_to_cube(spec: Optional[str]) -> List[Cube]:
    s = (spec or "").strip()
    if not s or s.lower() in ("any", "all", "0.0.0.0/0"):
        return [Cube.any()]
    if "/" not in s:
        s = f"{s}/32"
    net = ipaddress.ip_network(s, strict=False)
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError(f"Unsupported IP network: {spec}")
    return [Cube.from_cidr(str(net.network_address), net.prefixlen)]


def _representative_ip(cidr: Optional[str]) -> Optional[str]:
    s = (cidr or "").strip()
    if not s or s.lower() in ("any", "all"):
        return None
    if "/" not in s:
        s = f"{s}/32"
    try:
        net = ipaddress.ip_network(s, strict=False)
        if not isinstance(net, ipaddress.IPv4Network):
            return None
        if net.prefixlen >= 31:
            return str(net.network_address)
        return int_to_ip(int(net.network_address) + 1)
    except ValueError:
        return None


def _build_candidate_rule(change: Dict[str, Any], default_id: str) -> Rule:
    rid = str(change.get("rule_id") or default_id)
    action = str(change.get("rule_action") or "permit").strip().lower()
    if action in ("accept", "allow"):
        action = "permit"
    elif action in ("drop", "reject"):
        action = "deny"

    src_cubes = _cidr_to_cube(change.get("src_cidr"))
    dst_cubes = _cidr_to_cube(change.get("dst_cidr"))

    proto_raw = str(change.get("proto") or "ip").strip().lower()
    pnum = proto_from_name(proto_raw)
    protos: Optional[Set[int]] = {pnum} if pnum is not None else None

    dport_raw = change.get("dport")
    dst_ports: Optional[PortSet] = None
    if dport_raw is not None and str(dport_raw).strip() != "":
        port_i = int(dport_raw)
        if 1 <= port_i <= 65535:
            dst_ports = PortSet.from_list([(port_i, port_i)])
            if protos is None:
                protos = {6}

    src_intf = (change.get("src_intf") or "").strip()
    dst_intf = (change.get("dst_intf") or "").strip()

    fields = FieldSet(
        src_ips=src_cubes,
        dst_ips=dst_cubes,
        dst_ports=dst_ports,
        protos=protos,
        ingress_intfs={src_intf} if src_intf else None,
        egress_intfs={dst_intf} if dst_intf else None,
    )
    raw = (
        f"[WHAT-IF] {action} {proto_raw} "
        f"{change.get('src_cidr') or 'any'} -> {change.get('dst_cidr') or 'any'}"
        + (f":{dport_raw}" if dport_raw else "")
    )
    return Rule(
        id=rid,
        name=str(change.get("name") or f"whatif-{rid}"),
        action=action,
        fields=fields,
        disabled=False,
        raw_text=raw,
    )


def _apply_change(
    env: Any,
    config_type: str,
    change: Dict[str, Any],
) -> Tuple[Optional[Rule], Optional[Route], str]:
    """Mutate a cloned environment in-place and return (original_rule, original_route, summary)."""
    action = str(change.get("action") or "").strip().lower()
    rule_id = str(change.get("rule_id") or "").strip()
    acl_name = str(change.get("acl") or "").strip()

    if action in ("disable_rule", "delete_rule"):
        if not rule_id:
            raise ValueError("rule_id is required for disable_rule/delete_rule")
        if hasattr(env, "policies"):
            for idx, r in enumerate(env.policies):
                if str(r.id) == rule_id or (r.name and r.name == rule_id):
                    orig = copy.deepcopy(r)
                    if action == "disable_rule":
                        r.disabled = True
                    else:
                        del env.policies[idx]
                    return orig, None, f"{action} {rule_id}"
            raise ValueError(f"Rule '{rule_id}' not found in security policies")
        if hasattr(env, "acls"):
            target_acls = [acl_name] if acl_name and acl_name in env.acls else list(env.acls.keys())
            for aname in target_acls:
                rs = env.acls[aname]
                for idx, r in enumerate(rs.rules):
                    if str(r.id) == rule_id or f"{aname}:{r.id}" == rule_id:
                        orig = copy.deepcopy(r)
                        del rs.rules[idx]
                        return orig, None, f"{action} {aname} seq {r.id}"
            raise ValueError(f"Rule '{rule_id}' not found in ACLs")
        raise ValueError(f"Unsupported environment for {action}")

    if action == "add_rule":
        pos = str(change.get("position") or "top").strip().lower()
        new_rule = _build_candidate_rule(change, "999")
        if hasattr(env, "policies"):
            if pos == "bottom":
                env.policies.append(new_rule)
            else:
                env.policies.insert(0, new_rule)
            return None, None, f"add_rule {new_rule.id} ({pos})"
        if hasattr(env, "acls"):
            target_acl = acl_name or next(iter(env.acls.keys()), "")
            if not target_acl or target_acl not in env.acls:
                raise ValueError("Target ACL not found on device; specify 'acl'")
            rules = env.acls[target_acl].rules
            if pos == "bottom":
                rules.append(new_rule)
            else:
                rules.insert(0, new_rule)
            return None, None, f"add_rule {target_acl} seq {new_rule.id} ({pos})"
        raise ValueError("Environment has neither policies nor ACLs")

    if action == "tighten_rule":
        if not rule_id:
            raise ValueError("rule_id is required for tighten_rule")
        if hasattr(env, "policies"):
            for r in env.policies:
                if str(r.id) == rule_id or (r.name and r.name == rule_id):
                    orig = copy.deepcopy(r)
                    if change.get("src_cidr"):
                        r.fields.src_ips = _cidr_to_cube(change.get("src_cidr"))
                    if change.get("dst_cidr"):
                        r.fields.dst_ips = _cidr_to_cube(change.get("dst_cidr"))
                    if change.get("proto"):
                        pn = proto_from_name(change.get("proto"))
                        r.fields.protos = {pn} if pn is not None else None
                    if change.get("dport") is not None and str(change.get("dport")).strip() != "":
                        dp = int(change["dport"])
                        r.fields.dst_ports = PortSet.from_list([(dp, dp)])
                    return orig, None, f"tighten_rule {rule_id}"
            raise ValueError(f"Rule '{rule_id}' not found")
        if hasattr(env, "acls"):
            target_acls = [acl_name] if acl_name and acl_name in env.acls else list(env.acls.keys())
            for aname in target_acls:
                for r in env.acls[aname].rules:
                    if str(r.id) == rule_id or f"{aname}:{r.id}" == rule_id:
                        orig = copy.deepcopy(r)
                        if change.get("src_cidr"):
                            r.fields.src_ips = _cidr_to_cube(change.get("src_cidr"))
                        if change.get("dst_cidr"):
                            r.fields.dst_ips = _cidr_to_cube(change.get("dst_cidr"))
                        if change.get("dport") is not None and str(change.get("dport")).strip() != "":
                            dp = int(change["dport"])
                            r.fields.dst_ports = PortSet.from_list([(dp, dp)])
                        return orig, None, f"tighten_rule {aname} seq {r.id}"
            raise ValueError(f"Rule '{rule_id}' not found in ACLs")
        raise ValueError("Unsupported environment for tighten_rule")

    if action == "add_route":
        prefix = str(change.get("prefix") or "").strip()
        if not prefix:
            raise ValueError("prefix is required for add_route")
        net = ipaddress.ip_network(prefix, strict=False)
        if not isinstance(net, ipaddress.IPv4Network):
            raise ValueError(f"Invalid IPv4 prefix: {prefix}")
        new_route = Route(
            prefix=str(net),
            prefix_cube=Cube.from_cidr(str(net.network_address), net.prefixlen),
            next_hop=(change.get("next_hop") or "").strip() or None,
            interface=str(change.get("interface") or "").strip(),
            source="static",
            distance=int(change.get("distance") or 1),
        )
        env.route_table.routes.append(new_route)
        return None, None, f"add_route {net} -> {new_route.next_hop or new_route.interface}"

    if action == "remove_route":
        prefix = str(change.get("prefix") or "").strip()
        if not prefix:
            raise ValueError("prefix is required for remove_route")
        norm_prefix = str(ipaddress.ip_network(prefix, strict=False))
        for idx, r in enumerate(env.route_table.routes):
            if r.prefix == prefix or r.prefix == norm_prefix:
                if r.source == "connected":
                    continue
                orig_r = copy.deepcopy(r)
                del env.route_table.routes[idx]
                return None, orig_r, f"remove_route {r.prefix}"
        raise ValueError(f"Static route '{prefix}' not found")

    raise ValueError(
        f"Unsupported what-if action '{action}'. "
        "Supported: disable_rule, delete_rule, add_rule, tighten_rule, add_route, remove_route."
    )


def _load_device_events_flows(device_ip: str, limit: int = 20) -> List[Flow]:
    try:
        conn = db.get_observability_connection()
    except Exception:
        return []
    try:
        try:
            since = int(time.time()) - 30 * 86400
            rows = conn.execute(
                "SELECT src_ip, dst_ip, dst_port, protocol FROM events "
                "WHERE device_ip = ? AND ts >= ? AND src_ip IS NOT NULL AND src_ip != '' "
                "AND dst_ip IS NOT NULL AND dst_ip != '' "
                "ORDER BY ts DESC LIMIT ?",
                (device_ip, since, limit),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        out: List[Flow] = []
        for r in rows:
            out.append(Flow(
                src_ip=str(r["src_ip"]),
                dst_ip=str(r["dst_ip"]),
                proto=str(r["protocol"] or "tcp").lower(),
                dport=int(r["dst_port"]) if r["dst_port"] else None,
            ))
        return out
    finally:
        conn.close()


def _collect_test_flows(
    env: Any,
    change: Dict[str, Any],
    custom_flows: Optional[List[Dict[str, Any]]] = None,
    device_ip: Optional[str] = None,
) -> List[Tuple[Flow, str]]:
    """Build labeled list of flows (Flow, origin_label) to test before & after."""
    candidates: List[Tuple[Flow, str]] = []

    # 1. Caller-supplied custom flows
    for cf in custom_flows or []:
        if not cf.get("src_ip") or not cf.get("dst_ip"):
            continue
        candidates.append((
            Flow(
                src_ip=str(cf["src_ip"]).strip(),
                dst_ip=str(cf["dst_ip"]).strip(),
                proto=str(cf.get("proto") or "tcp").lower(),
                sport=int(cf["sport"]) if cf.get("sport") else None,
                dport=int(cf["dport"]) if cf.get("dport") else None,
                ingress_intf=(cf.get("ingress_intf") or "").strip() or None,
                egress_intf=(cf.get("egress_intf") or "").strip() or None,
                established=bool(cf.get("established", False)),
                icmp_type=int(cf["icmp_type"]) if cf.get("icmp_type") is not None else None,
            ),
            "custom",
        ))

    # 2. Flow derived directly from the candidate change itself
    ch_src = _representative_ip(change.get("src_cidr"))
    ch_dst = _representative_ip(change.get("dst_cidr")) or _representative_ip(change.get("prefix"))
    if ch_dst:
        if not ch_src:
            # Pick a source inside any connected subnet
            for c in env.route_table.connected_subnets():
                if not c.prefix_cube.is_any():
                    ch_src = _representative_ip(c.prefix)
                    if ch_src:
                        break
        if ch_src:
            candidates.append((
                Flow(
                    src_ip=ch_src,
                    dst_ip=ch_dst,
                    proto=str(change.get("proto") or "tcp").lower(),
                    dport=int(change["dport"]) if change.get("dport") else None,
                    ingress_intf=(change.get("src_intf") or "").strip() or None,
                ),
                "candidate_change",
            ))

    # 3. Observed flows from observability.db (if device_ip provided)
    if device_ip:
        for ev_flow in _load_device_events_flows(device_ip):
            candidates.append((ev_flow, "observed"))

    # 4. Synthetic examples generated from the device's actual ruleset
    rules: List[Rule] = []
    if hasattr(env, "policies"):
        rules.extend(env.policies)
    elif hasattr(env, "acls"):
        for acl_name, rs in env.acls.items():
            iface_in = next(
                (iname for iname, info in (env.interfaces or {}).items() if info.get("acl_in") == acl_name),
                None,
            )
            for ex in generate_ruleset_examples(rs.rules):
                if ex.matching_flow is not None:
                    f = copy.copy(ex.matching_flow)
                    if iface_in and not f.ingress_intf:
                        f.ingress_intf = iface_in
                    candidates.append((f, f"rule:{acl_name}:{ex.rule_id}"))
    if rules:
        for ex in generate_ruleset_examples(rules):
            if ex.matching_flow is not None:
                candidates.append((ex.matching_flow, f"rule:{ex.rule_id}"))

    # Deduplicate up to 60 flows while preserving origin priority
    seen: Set[Tuple[str, str, str, Optional[int], Optional[str]]] = set()
    out: List[Tuple[Flow, str]] = []
    for flow, origin in candidates:
        key = (flow.src_ip, flow.dst_ip, (flow.proto or "tcp").lower(), flow.dport, flow.ingress_intf)
        if key in seen:
            continue
        seen.add(key)
        out.append((flow, origin))
        if len(out) >= 60:
            break
    return out


def _trace_summary(trace: Any) -> Dict[str, Any]:
    rule_step = next(
        (s for s in trace.steps if s.kind in ("policy", "acl_in", "acl_out")),
        None,
    )
    route_step = next((s for s in trace.steps if s.kind == "route"), None)
    return {
        "verdict": trace.verdict,
        "rule_id": rule_step.rule_id if rule_step else None,
        "acl": rule_step.acl if rule_step else None,
        "matched": rule_step.matched if rule_step else None,
        "implicit_deny": trace.implicit_deny,
        "route_prefix": route_step.prefix if route_step else None,
        "next_hop": route_step.next_hop if route_step else None,
        "egress_intf": route_step.egress if route_step else None,
    }


def _build_apply_and_rollback(
    config_type: str,
    change: Dict[str, Any],
    orig_rule: Optional[Rule],
    orig_route: Optional[Route],
) -> Dict[str, str]:
    v = (config_type or "fortios").lower()
    action = str(change.get("action") or "").lower()
    rid = str(change.get("rule_id") or (orig_rule.id if orig_rule else "999"))
    acl = str(change.get("acl") or "ACL")

    if action in ("disable_rule", "delete_rule"):
        if v == "fortios":
            if action == "disable_rule":
                apply_cli = f"config firewall policy\n    edit {rid}\n        set status disable\n    next\nend"
                rb_cli = f"config firewall policy\n    edit {rid}\n        set status enable\n    next\nend"
                api = f'PATCH /api/v2/cmdb/firewall/policy/{rid}  {{"status": "disable"}}'
            else:
                apply_cli = f"config firewall policy\n    delete {rid}\nend"
                rb_cli = (
                    f"config firewall policy\n    edit {rid}\n"
                    f"        # restore rule {orig_rule.name if orig_rule else rid}\n"
                    f"        set action {'accept' if not orig_rule or orig_rule.action == 'permit' else 'deny'}\n"
                    f"    next\nend"
                )
                api = f"DELETE /api/v2/cmdb/firewall/policy/{rid}"
            return {"cli_apply": apply_cli, "cli_rollback": rb_cli, "api_dry_run": api}
        if v == "panos":
            rname = orig_rule.name if orig_rule and orig_rule.name else rid
            if action == "disable_rule":
                return {
                    "cli_apply": f'set rulebase security rules "{rname}" disabled yes',
                    "cli_rollback": f'set rulebase security rules "{rname}" disabled no',
                    "api_dry_run": f'POST /api/?type=config&action=set security/rules/entry[@name="{rname}"] disabled=yes',
                }
            return {
                "cli_apply": f'delete rulebase security rules "{rname}"',
                "cli_rollback": f'load config partial from backup  # restore "{rname}"',
                "api_dry_run": f'POST /api/?type=config&action=delete security/rules/entry[@name="{rname}"]',
            }
        if v == "junos":
            rname = orig_rule.name if orig_rule and orig_rule.name else rid
            return {
                "cli_apply": f"deactivate security policies policy {rname}" if action == "disable_rule" else f"delete security policies policy {rname}",
                "cli_rollback": "rollback 1  # and commit check",
                "api_dry_run": f"NETCONF <edit-config> candidate + <validate> on {rname}",
            }
        raw = orig_rule.raw_text.strip() if orig_rule and orig_rule.raw_text else f"seq {rid}"
        return {
            "cli_apply": f"ip access-list extended {acl}\n no {raw}",
            "cli_rollback": f"ip access-list extended {acl}\n {raw}",
            "api_dry_run": f"RESTCONF DELETE ACL {acl} rule {rid}",
        }

    if action == "add_rule":
        r_act = "accept" if str(change.get("rule_action") or "permit").lower() in ("permit", "accept") else "deny"
        src = change.get("src_cidr") or "all"
        dst = change.get("dst_cidr") or "all"
        proto = str(change.get("proto") or "tcp").lower()
        dport = change.get("dport")
        if v == "fortios":
            apply_cli = (
                "config firewall policy\n"
                f"    edit {rid}\n"
                f"        set srcintf {change.get('src_intf') or 'any'}\n"
                f"        set dstintf {change.get('dst_intf') or 'any'}\n"
                f"        set srcaddr {src}\n"
                f"        set dstaddr {dst}\n"
                f"        set action {r_act}\n"
                f"        set service {('TCP_' + str(dport)) if dport else 'ALL'}\n"
                "    next\nend"
            )
            rb_cli = f"config firewall policy\n    delete {rid}\nend"
            api = f'POST /api/v2/cmdb/firewall/policy  {{"policyid": {rid}, "action": "{r_act}"}}'
            return {"cli_apply": apply_cli, "cli_rollback": rb_cli, "api_dry_run": api}
        if v == "panos":
            pan_act = "allow" if r_act == "accept" else "deny"
            return {
                "cli_apply": f'set rulebase security rules "{rid}" source {src} destination {dst} action {pan_act}',
                "cli_rollback": f'delete rulebase security rules "{rid}"',
                "api_dry_run": f'POST /api/?type=config&action=set rule "{rid}" action={pan_act}',
            }
        ios_act = "permit" if r_act == "accept" else "deny"
        port_kw = f" eq {dport}" if dport else ""
        return {
            "cli_apply": f"ip access-list extended {acl}\n {rid} {ios_act} {proto} {src} {dst}{port_kw}",
            "cli_rollback": f"ip access-list extended {acl}\n no {rid}",
            "api_dry_run": f"RESTCONF PATCH ACL {acl} add seq {rid}",
        }

    if action == "tighten_rule":
        src = change.get("src_cidr") or "unchanged"
        dst = change.get("dst_cidr") or "unchanged"
        dport = change.get("dport")
        if v == "fortios":
            return {
                "cli_apply": f"config firewall policy\n    edit {rid}\n        set srcaddr {src}\n        set dstaddr {dst}\n    next\nend",
                "cli_rollback": f"config firewall policy\n    edit {rid}\n        # restore previous objects from backup\n    next\nend",
                "api_dry_run": f'PATCH /api/v2/cmdb/firewall/policy/{rid}  {{"srcaddr": "{src}", "dstaddr": "{dst}"}}',
            }
        return {
            "cli_apply": f"update rule {rid}: src={src} dst={dst}" + (f" dport={dport}" if dport else ""),
            "cli_rollback": f"restore rule {rid} from golden backup",
            "api_dry_run": f"DRY-RUN PATCH rule {rid}",
        }

    if action in ("add_route", "remove_route"):
        prefix = str(change.get("prefix") or (orig_route.prefix if orig_route else ""))
        nh = str(change.get("next_hop") or (orig_route.next_hop if orig_route else "") or "")
        intf = str(change.get("interface") or (orig_route.interface if orig_route else "") or "")
        net = ipaddress.ip_network(prefix, strict=False)
        if v == "fortios":
            add_cmd = (
                "config router static\n    edit 0\n"
                f"        set dst {net.network_address} {net.netmask}\n"
                + (f"        set gateway {nh}\n" if nh else "")
                + (f'        set device "{intf}"\n' if intf else "")
                + "    next\nend"
            )
            del_cmd = f"config router static\n    # delete route for {net.network_address}/{net.prefixlen}\nend"
            return {
                "cli_apply": add_cmd if action == "add_route" else del_cmd,
                "cli_rollback": del_cmd if action == "add_route" else add_cmd,
                "api_dry_run": f"{'POST' if action == 'add_route' else 'DELETE'} /api/v2/cmdb/router/static ({net})",
            }
        if v == "junos":
            set_cmd = f"set routing-options static route {net} next-hop {nh or intf}"
            del_cmd = f"delete routing-options static route {net}"
            return {
                "cli_apply": set_cmd if action == "add_route" else del_cmd,
                "cli_rollback": "rollback 1",
                "api_dry_run": f"NETCONF <edit-config> static route {net}",
            }
        ios_cmd = f"ip route {net.network_address} {net.netmask} {nh or intf}".strip()
        return {
            "cli_apply": ios_cmd if action == "add_route" else f"no {ios_cmd}",
            "cli_rollback": f"no {ios_cmd}" if action == "add_route" else ios_cmd,
            "api_dry_run": f"RESTCONF PATCH static-routes {net}",
        }

    return {"cli_apply": "", "cli_rollback": "", "api_dry_run": ""}


def _finding_sig(f: Any) -> Tuple[str, str, str, str]:
    d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
    p = d.get("params") or {}
    return (
        str(d.get("key") or ""),
        str(d.get("acl_name") or ""),
        str(d.get("rule_id") or p.get("prefix") or p.get("rule_id") or ""),
        str(p.get("shadowed_by") or p.get("blocked_by") or p.get("next_hop") or ""),
    )


def simulate_whatif(
    env: Any,
    config_type: str,
    change: Dict[str, Any],
    flows: Optional[List[Dict[str, Any]]] = None,
    device_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Run before/after offline policy & routing simulation with rollback plan."""
    after_env = copy.deepcopy(env)
    orig_rule, orig_route, change_summary = _apply_change(after_env, config_type, change)

    test_flows = _collect_test_flows(env, change, custom_flows=flows, device_ip=device_ip)

    diff_rows: List[Dict[str, Any]] = []
    counts = {"broken": 0, "newly_allowed": 0, "rerouted_or_changed": 0, "unchanged": 0}

    for flow, origin in test_flows:
        t_before = evaluate(env, flow)
        t_after = evaluate(after_env, flow)
        b = _trace_summary(t_before)
        a = _trace_summary(t_after)

        if b["verdict"] == "PERMIT" and a["verdict"] != "PERMIT":
            transition = "broken"
        elif b["verdict"] != "PERMIT" and a["verdict"] == "PERMIT":
            transition = "newly_allowed"
        elif (
            b["verdict"] != a["verdict"]
            or b["rule_id"] != a["rule_id"]
            or b["egress_intf"] != a["egress_intf"]
            or b["next_hop"] != a["next_hop"]
        ):
            transition = "rerouted_or_changed"
        else:
            transition = "unchanged"

        counts[transition] += 1
        diff_rows.append({
            "flow": flow.to_dict(),
            "origin": origin,
            "transition": transition,
            "before": b,
            "after": a,
        })

    # Put verdict-changing flows first so critical regressions sit at top
    order = {"broken": 0, "newly_allowed": 1, "rerouted_or_changed": 2, "unchanged": 3}
    diff_rows.sort(key=lambda r: (order.get(r["transition"], 9), r["origin"]))

    # Static findings before vs after
    f_before = analyze_policy_findings(env)
    f_after = analyze_policy_findings(after_env)
    b_map = {_finding_sig(f): f.to_dict() for f in f_before}
    a_map = {_finding_sig(f): f.to_dict() for f in f_after}
    resolved_findings = [v for k, v in b_map.items() if k not in a_map]
    new_findings = [v for k, v in a_map.items() if k not in b_map]

    snippets = _build_apply_and_rollback(config_type, change, orig_rule, orig_route)
    risk = (
        "HIGH" if (counts["broken"] > 0 or len(new_findings) > 0)
        else ("MEDIUM" if (counts["newly_allowed"] > 0 or counts["rerouted_or_changed"] > 0) else "LOW")
    )

    return {
        "config_type": config_type,
        "change_summary": change_summary,
        "risk": risk,
        "summary": {
            "flows_tested": len(diff_rows),
            "broken": counts["broken"],
            "newly_allowed": counts["newly_allowed"],
            "rerouted_or_changed": counts["rerouted_or_changed"],
            "unchanged": counts["unchanged"],
            "resolved_findings": len(resolved_findings),
            "new_findings": len(new_findings),
        },
        "flows": diff_rows,
        "findings_diff": {
            "resolved": resolved_findings,
            "introduced": new_findings,
        },
        "rollback": snippets,
    }
