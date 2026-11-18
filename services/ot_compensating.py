# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""OT compensating controls: is a vulnerable OT asset shielded by its gateway?

Unit = (asset, CVE). For every OT asset (Purdue L0-L2) with a CVE snapshot and
every KEV or CVSS >= 7 CVE on it, the flows from untrusted sources to the
CVE's attack surface are evaluated offline, on the backups of the gateways
that have an interface in the asset's subnet, with the policy_test engine.

A false "mitigated" is worse than a false "exposed": auditors rely on it. Any
doubt (no gateway, unreadable backup, undecidable rule, IPS entry that cannot
be tied to the CVE) ends in NOT_EVALUATED or EXPOSED, never in MITIGATED_*.
"""

import functools
import ipaddress
import os
import re

from services import cve_intel, ot_vuln_intel, purdue_model
from services.policy_test.engine import _derive_ingress_intf, evaluate
from services.policy_test.model import Flow, Step, Trace, int_to_ip, mask_to_prefix_len

CLASSES = ("NOT_EVALUATED", "SERVICE_DISABLED", "EXPOSED",
           "MITIGATED_BY_IPS", "MITIGATED_BY_FIREWALL")

# Service names as cve_intel.cve_services() writes them in the snapshot.
# 'http' covers HTTPS too, as in cve_intel._service_signal.
_SERVICE_PORTS = {
    "http": (("tcp", 80), ("tcp", 443)),
    "ssh": (("tcp", 22),),
    "telnet": (("tcp", 23),),
    "snmp": (("udp", 161),),
}
_MGMT_PORTS = (("tcp", 22), ("tcp", 23), ("tcp", 80), ("tcp", 443), ("udp", 161))
# Modbus, S7, EtherNet/IP, OPC UA, IEC 104, DNP3, BACnet, EtherNet/IP I/O.
_OT_PORTS = (("tcp", 502), ("tcp", 102), ("tcp", 44818), ("tcp", 4840),
             ("tcp", 2404), ("tcp", 20000), ("udp", 47808), ("udp", 2222))

_FIREWALL_TYPES = ("fortios", "panos", "junos")
_CISCO_TYPES = ("ios", "nxos")
_TRUSTED_LEVELS = purdue_model.OT_LEVELS | {"L3"}
_JUMP_LEVELS = ("L3", "L3.5")
_IPS_BLOCKING = ("block", "reset")

# Internet stand-ins (RFC 5737). The first one not inside a trusted zone of
# the tenant is used: a tenant may well number a zone out of 203.0.113.0/24.
_INTERNET_REPS = ("203.0.113.1", "198.51.100.1", "192.0.2.1")
_GENERIC_PRIVATE = "10.255.255.1"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def _first_host(net) -> str:
    return str(net.network_address + 1) if net.num_addresses > 2 else str(net.network_address)


def _cube_ip(cube) -> str:
    """An address the cube matches, preferring a host over the network address."""
    plen = mask_to_prefix_len(cube.mask)
    return int_to_ip(cube.value + 1 if plen is not None and plen <= 30 else cube.value)


def _in_net(ip, net) -> bool:
    addr = purdue_model._ip_obj(ip)
    return addr is not None and addr.version == net.version and addr in net


def _rules(env) -> list:
    if hasattr(env, "policies"):
        return list(env.policies)
    return [r for acl in env.acls.values() for r in acl.rules]


@functools.lru_cache(maxsize=64)
def _ios_routes(path: str, mtime: float) -> bool:
    """Whether a Cisco IOS backup routes IP. Catalyst/IE switches default to
    no routing and print ``ip routing`` once enabled; routers route by
    default and print only ``no ip routing``. A config with ``switchport``
    lines is a switch platform. ``mtime`` is only the cache key."""
    with open(path, encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    if re.search(r"^no ip routing\b", text, re.M):
        return False
    if re.search(r"^ip routing\b", text, re.M):
        return True
    return not re.search(r"^\s*switchport\b", text, re.M)


def _load_gateway_candidates(tenant: str, devices: list) -> list:
    """Firewalls and Cisco L3 devices of the tenant with their parsed backup.

    Each item: {"device", "config_type", "env" (None when unreadable), "reason"}.
    """
    from ai import config_analyzer
    from services.path_trace import _parse_hop_backup

    out = []
    for d in devices:
        cfg = config_analyzer.detect_config_type("", d)
        vendor = (d.get("Vendor") or "").lower()
        if not (cfg in _FIREWALL_TYPES or (cfg in _CISCO_TYPES and vendor.startswith("cisco"))):
            continue
        path, _t = config_analyzer._find_freshest_backup(d.get("IP"), tenant)
        if not path:
            out.append({"device": d, "config_type": cfg, "env": None, "reason": "gateway_no_backup"})
            continue
        # An L2 switch with only a management SVI in the OT VLAN routes
        # nothing: taking it for the gateway reported every asset behind a
        # real firewall as exposed through its ACL-less SVI.
        try:
            # The backup may vanish after _find_freshest_backup picked it.
            mtime = os.path.getmtime(path)
            if cfg == "ios" and not _ios_routes(path, mtime):
                continue
            cfg, env = _parse_hop_backup(path, mtime, d.get("Vendor") or "")
        except Exception:
            env = None
        out.append({"device": d, "config_type": cfg, "env": env,
                    "reason": "" if env is not None else "gateway_unsupported"})
    return out


def _evaluate_flow(env, src: str, dst: str, proto: str, port: int):
    # The ingress is the interface the source is routed through: deriving it
    # from connected subnets only leaves every remote source ingress-less,
    # which skips inbound ACLs and zone-scoped policies.
    route = env.route_table.lookup(src)
    ingress = route.interface if route is not None and route.interface else None
    # Junos and PAN-OS statics carry only the next hop: the ingress is the
    # connected interface that reaches it, as evaluate() does for egress.
    if ingress is None and route is not None and route.next_hop:
        ingress = _derive_ingress_intf(route.next_hop, env.route_table)
    flow = Flow(src_ip=src, dst_ip=dst, proto=proto, dport=port, ingress_intf=ingress)
    if ingress is None and (
            any(r.fields.ingress_intfs and not r.disabled for r in _rules(env))
            or any(i.get("acl_in") for i in getattr(env, "interfaces", {}).values())):
        # Without an ingress, zone-scoped policies match any source and
        # inbound ACLs are skipped: a deny scoped to another zone would read
        # as a mitigation.
        return Trace(verdict="UNKNOWN", flow=flow.to_dict(), steps=[Step(
            kind="note", action="unknown",
            note=f"ingress interface of {src} unknown (no route with interface)")])
    return evaluate(env, flow)


def _matched_rules(env, trace) -> list:
    """(step, Rule) of the ACL/policy steps that decided the flow."""
    out = []
    for s in trace.steps:
        if s.kind not in ("acl_in", "acl_out", "policy") or not s.rule_id:
            continue
        if s.kind == "policy":
            pool = env.policies
        else:
            acl = env.acls.get(s.acl or "")
            pool = acl.rules if acl is not None else []
        # IOS ACEs without a sequence number all share the id 'ext': the
        # raw line is what tells them apart.
        rule = next((r for r in pool if r.id == s.rule_id and r.raw_text == s.raw_text), None)
        out.append((s, rule))
    return out


def _ips_check(env, policy_id: str, cve_id: str):
    """(evidence | None, sensor_present) for the FortiOS policy that accepted the flow.

    Entries are walked in order, as FortiOS does: an earlier entry with no
    CVE list (a generic or OT signature filter) that does not block may catch
    the signature first, so it stops the walk as unverified.
    """
    pol = getattr(env, "policy_ips", {}).get(policy_id) or {}
    sensor = pol.get("ips_sensor") or ""
    if not pol.get("utm_status") or not sensor:
        return None, False
    for entry in getattr(env, "ips_sensors", {}).get(sensor, []):
        if entry["status"] == "disable":
            continue
        if cve_id.upper() in entry["cve"]:
            if entry["action"] in _IPS_BLOCKING and not entry["filtered"]:
                return {"kind": "ips", "policy_id": policy_id, "sensor": sensor,
                        "entry": entry["id"], "action": entry["action"]}, True
            return None, True
        if not entry["cve"] and entry["action"] not in _IPS_BLOCKING:
            return None, True
    return None, True


def classify_tenant(tenant: str, devices: list) -> dict:
    from services import segment_manager

    devices = [d for d in devices if (d.get("Group") or "") == tenant]
    segments = segment_manager.list_segments(tenant).get("segments") or []
    segs = purdue_model._index_segments(segments)
    dev_by_ip = {str(d.get("IP") or ""): d for d in devices if d.get("IP")}

    def zone(ip: str) -> str:
        return purdue_model.resolve_ip_zone(ip, devices, segments, segs, dev_by_ip)["level"]

    def in_ot_segment(ip: str) -> bool:
        addr = purdue_model._ip_obj(ip)
        for s in segs:
            if s["purdue_level"] not in purdue_model.OT_LEVELS or ip in s["excluded"]:
                continue
            if ip in s["members"] or (addr is not None and any(
                    addr.version == n.version and addr in n for n in s["subnets"])):
                return True
        return False

    candidates = None  # loaded lazily: a tenant with no OT CVE needs no backup parsing
    rows: list = []
    assets = 0
    for device in devices:
        ip = str(device.get("IP") or "")
        snapshot = cve_intel.load(device)
        if not snapshot or not (zone(ip) in purdue_model.OT_LEVELS or in_ot_segment(ip)):
            continue
        services = cve_intel.device_services(device)
        cves = {}
        for r in cve_intel.score_rows(snapshot, services, device=device):
            if r["id"] and r["id"] not in cves and (r["kev"] or (r["cvss"] or 0) >= 7):
                cves[r["id"]] = r
        if not cves:
            continue
        assets += 1
        if candidates is None:
            candidates = _load_gateway_candidates(tenant, devices)
        rows.extend(_classify_asset(tenant, device, ip, cves, services, candidates, segs, zone))

    rows.sort(key=lambda r: (_SEVERITY_ORDER[r["severity"]], r["device"], r["cve_id"]))
    summary = {c: 0 for c in CLASSES}
    for r in rows:
        summary[r["class"]] += 1
    return {"rows": rows, "summary": summary, "assets_evaluated": assets}


def _classify_asset(tenant, device, ip, cves, services, candidates, segs, zone) -> list:
    patch_planned = bool(ot_vuln_intel.asset_patch_posture(device)["maintenance_window"])
    base = {"device": device.get("Hostname") or ip, "ip": ip, "tenant": tenant,
            "patch_planned": patch_planned}

    def row(cve, cls, **extra) -> dict:
        kev = bool(cve["kev"])
        if cls == "EXPOSED":
            sev = "critical" if kev else "high"
        else:
            sev = "medium" if cls == "NOT_EVALUATED" else "info"
        out = dict(base, cve_id=cve["id"], cvss=cve["cvss"], kev=kev, **{"class": cls},
                   severity=sev, gateways=[], ports=[], exposure=None, evidence=[],
                   reason="", ips_present_unverified=False)
        out.update(extra)
        return out

    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return [row(c, "NOT_EVALUATED", reason="asset_unresolvable") for c in cves.values()]

    gws, local_nets = [], []
    for c in candidates:
        if c["env"] is None or str(c["device"].get("IP") or "") == ip:
            continue
        nets = [ipaddress.IPv4Network(r.prefix, strict=False)
                for r in c["env"].route_table.connected_subnets()
                if r.prefix_cube.contains_ip(int(addr))]
        if nets:
            gws.append(c)
            local_nets.extend(nets)
    asset_nets = local_nets + [n for s in segs for n in s["subnets"]
                               if n.version == 4 and addr in n]
    # A firewall whose backup is missing or unreadable cannot be ruled out as
    # a gateway: its inventory address inside the asset's subnet says it is one.
    unreadable = next((c for c in candidates if c["env"] is None and any(
        _in_net(c["device"].get("IP"), n) for n in asset_nets)), None)
    gw_list = [{"ip": c["device"].get("IP", ""), "config_type": c["config_type"]} for c in gws]
    if unreadable is not None:
        return [row(c, "NOT_EVALUATED", gateways=gw_list,
                    reason=f"{unreadable['reason']}:{unreadable['device'].get('IP', '')}")
                for c in cves.values()]
    if not gws:
        return [row(c, "NOT_EVALUATED", reason="no_gateway") for c in cves.values()]

    sources = _untrusted_sources(gws, local_nets, segs, zone)
    flow_cache: dict = {}

    def flows(ports) -> list:
        out = []
        for gw in gws:
            for src, label in sources.items():
                for proto, port in ports:
                    key = (gw["device"].get("IP"), src, proto, port)
                    if key not in flow_cache:
                        flow_cache[key] = _flow_result(gw, src, label, ip, proto, port, zone)
                    out.append(flow_cache[key])
        return out

    out = []
    for cve in cves.values():
        names = cve["services"]
        if names and all(cve_intel._service_signal([n], services) == "disabled" for n in names):
            out.append(row(cve, "SERVICE_DISABLED",
                           evidence=[{"kind": "service_disabled", "services": names}]))
            continue
        # ponytail: a service name with no port mapping falls back to the
        # full management + OT surface instead of being skipped.
        if names and all(n in _SERVICE_PORTS for n in names):
            ports = list(dict.fromkeys(p for n in names for p in _SERVICE_PORTS[n]))
        else:
            ports = list(_MGMT_PORTS + _OT_PORTS)
        extra = {"gateways": gw_list, "ports": [f"{p}/{n}" for p, n in ports]}
        # ponytail: only flows THROUGH the subnet's gateways are checked. A
        # path that bypasses them (dual-homed host, second NIC, flat L2
        # extension) is out of scope here — the dual-homed detector covers it.
        results = flows(ports)
        exposing = [r for r in results if r["verdict"] == "PERMIT" and not r["jump_host"]]
        unknown = [r for r in results if r["verdict"] == "UNKNOWN"]
        if exposing:
            ips_hits, uncovered, present = [], None, False
            for r in exposing:
                hit, has_sensor = (None, False)
                if r["config_type"] == "fortios" and r["rule_id"]:
                    hit, has_sensor = _ips_check(r["env"], r["rule_id"], cve["id"])
                if hit is not None:
                    ips_hits.append(dict(hit, gateway=r["gateway"]))
                else:
                    present = present or has_sensor
                    uncovered = uncovered or r
            if uncovered is not None:
                out.append(row(cve, "EXPOSED", exposure=_public(uncovered),
                               ips_present_unverified=present, **extra))
            elif unknown:
                out.append(row(cve, "NOT_EVALUATED", reason="undecidable_policy",
                               evidence=[_public(r) for r in unknown[:5]], **extra))
            else:
                out.append(row(cve, "MITIGATED_BY_IPS", evidence=_distinct(ips_hits), **extra))
        elif unknown:
            out.append(row(cve, "NOT_EVALUATED", reason="undecidable_policy",
                           evidence=[_public(r) for r in unknown[:5]], **extra))
        else:
            ev = [{"kind": "jump_host" if r["jump_host"] else "deny", "gateway": r["gateway"],
                   "rule_id": r["rule_id"], "rule_name": r["rule_name"]} for r in results]
            out.append(row(cve, "MITIGATED_BY_FIREWALL", evidence=_distinct(ev), **extra))
    return out


def _distinct(items: list) -> list:
    seen, out = set(), []
    for it in items:
        key = tuple(sorted(it.items()))
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


def _public(r: dict) -> dict:
    return {k: r[k] for k in ("src", "src_level", "proto", "port", "gateway",
                              "rule_id", "rule_name", "rule_text", "verdict")}


def _untrusted_sources(gws, local_nets, segs, zone) -> dict:
    """{representative ip: zone label} of the untrusted sources to test.

    Representatives, not ranges: a permit narrower than a whole zone would be
    missed by one sample, so every permit rule's source contributes its own
    witness address too (that is also what lets the jump-host exception see
    the /32 it is about).
    """
    out: dict = {}

    def add(ip: str, label: str = "") -> None:
        addr = purdue_model._ip_obj(ip)
        if ip in out or addr is None or addr.version != 4:
            return
        # Same subnet as the asset: the traffic never crosses the gateway.
        if any(addr in n for n in local_nets):
            return
        level = zone(ip)
        if level in _TRUSTED_LEVELS:
            return
        out[ip] = label or ("internet" if level == "external" else level or "unclassified")

    internet = next((ip for ip in _INTERNET_REPS if zone(ip) not in _TRUSTED_LEVELS), None)
    if internet:
        add(internet, "internet")
    for s in segs:
        if s["purdue_level"] in ("L4", "L3.5"):
            for n in s["subnets"]:
                if n.version == 4:
                    add(_first_host(n), s["purdue_level"])
    for gw in gws:
        for r in gw["env"].route_table.connected_subnets():
            if purdue_model.resolve_target_zone(
                    r.prefix, [], [], segs, {})["level"] in ("", "external"):
                add(_first_host(ipaddress.IPv4Network(r.prefix, strict=False)))
    if "unclassified" not in out.values():
        add(_GENERIC_PRIVATE, "unclassified")
    for gw in gws:
        for rule in _rules(gw["env"]):
            if rule.disabled or rule.action == "deny":
                continue
            for cube in rule.fields.src_ips:
                if not cube.is_any():
                    add(_cube_ip(cube))
    return out


def _flow_result(gw, src, label, dst, proto, port, zone) -> dict:
    env = gw["env"]
    trace = _evaluate_flow(env, src, dst, proto, port)
    verdict = trace.verdict.lower()
    matched = _matched_rules(env, trace)
    step, rule = next(((s, r) for s, r in matched if s.action == verdict), (None, None))
    # Several permit steps (IOS inbound + outbound ACL) intersect: one of
    # them restricted to the jump host is enough to restrict the flow.
    jump_host = trace.verdict == "PERMIT" and any(
        s.action == "permit" and r is not None and len(r.fields.src_ips) == 1
        and r.fields.src_ips[0].is_exact()
        and zone(int_to_ip(r.fields.src_ips[0].value)) in _JUMP_LEVELS
        for s, r in matched)
    if step is not None:
        rule_id = step.rule_id or ""
        rule_name = (rule.name if rule is not None and rule.name else "") or (step.acl or "")
    elif trace.verdict == "PERMIT":
        rule_id, rule_name = "", "no ACL/policy bound"
    else:
        last = next((s for s in reversed(trace.steps) if s.action == verdict), None)
        rule_id = ""
        rule_name = (f"{last.acl or ''} {last.matched or last.note or ''}".strip()
                     if last is not None else "")
    return {"verdict": trace.verdict, "jump_host": jump_host, "env": env,
            "config_type": gw["config_type"], "gateway": gw["device"].get("IP", ""),
            "src": src, "src_level": label, "proto": proto, "port": port,
            "rule_id": rule_id, "rule_name": rule_name,
            "rule_text": (step.raw_text or "") if step is not None else ""}
