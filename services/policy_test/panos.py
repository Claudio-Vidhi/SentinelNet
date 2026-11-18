# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Palo Alto PAN-OS policy, NAT, zone, address, service and route parser.

Supports both PAN-OS CLI ``set ...`` format and XML ``<config>`` exports.
Pure module with zero I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import shlex
from typing import Any, Dict, List, Optional, Set, Tuple

from drivers.paloalto_panos import parse_panos_xml_config
from services.policy_test.model import (
    Cube, FieldSet, PortSet, Route, RouteTable, Rule,
    int_to_ip, ip_to_int, proto_from_name,
)


@dataclass
class PanOSPolicyEnvironment:
    """Extracted PAN-OS security policy, zone, NAT, object and routing environment."""
    policies: List[Rule] = field(default_factory=list)
    route_table: RouteTable = field(default_factory=RouteTable)
    interfaces: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    zones: Dict[str, List[str]] = field(default_factory=dict)
    iface_to_zone: Dict[str, str] = field(default_factory=dict)
    addresses: Dict[str, List[Cube]] = field(default_factory=dict)
    address_groups: Dict[str, List[str]] = field(default_factory=dict)
    services: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    service_groups: Dict[str, List[str]] = field(default_factory=dict)
    nat_rules: List[Dict[str, Any]] = field(default_factory=list)
    vips: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    unresolved: List[str] = field(default_factory=list)
    hostname: str = ""


_PANOS_BUILTIN_SERVICES: Dict[str, Tuple[Optional[int], Optional[PortSet]]] = {
    "any": (None, None),
    "application-default": (None, None),
    "service-http": (6, PortSet.from_list([(80, 80)])),
    "service-https": (6, PortSet.from_list([(443, 443)])),
    "http": (6, PortSet.from_list([(80, 80)])),
    "https": (6, PortSet.from_list([(443, 443)])),
    "ssh": (6, PortSet.from_list([(22, 22)])),
    "dns": (17, PortSet.from_list([(53, 53)])),
    "modbus": (6, PortSet.from_list([(502, 502)])),
    "s7comm": (6, PortSet.from_list([(102, 102)])),
    "opc-ua": (6, PortSet.from_list([(4840, 4840)])),
}


def _addr_cubes(spec: str) -> List[Cube]:
    s = (spec or "").strip()
    if not s:
        return []
    if "-" in s and s.count(".") >= 6:
        lo_s, hi_s = s.split("-", 1)
        try:
            lo = ip_to_int(lo_s.strip())
            hi = ip_to_int(hi_s.strip())
            if lo <= hi:
                return [
                    Cube.from_cidr(str(net.network_address), net.prefixlen)
                    for net in ipaddress.summarize_address_range(
                        ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi)
                    )
                ]
        except Exception:
            return []
    try:
        net = ipaddress.ip_network(s, strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            return [Cube.from_cidr(str(net.network_address), net.prefixlen)]
    except ValueError:
        return []
    return []


def _parse_ports(spec: str) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for part in str(spec or "").replace(",", " ").split():
        p = part.strip()
        if not p:
            continue
        if "-" in p:
            a, b = p.split("-", 1)
            if a.isdigit() and b.isdigit():
                out.append((min(int(a), int(b)), max(int(a), int(b))))
        elif p.isdigit():
            v = int(p)
            out.append((v, v))
    return out


def _resolve_addr_list(
    names: List[str],
    addresses: Dict[str, List[Cube]],
    groups: Dict[str, List[str]],
    unresolved: List[str],
    seen: Optional[Set[str]] = None,
) -> List[Cube]:
    seen = seen or set()
    if not names or any(n.lower() == "any" for n in names):
        return [Cube.any()]
    cubes: List[Cube] = []
    for n in names:
        if n in seen:
            continue
        direct = _addr_cubes(n)
        if direct:
            cubes.extend(direct)
            continue
        if n in addresses:
            cubes.extend(addresses[n])
            continue
        if n in groups:
            seen_next = seen | {n}
            cubes.extend(_resolve_addr_list(groups[n], addresses, groups, unresolved, seen_next))
            continue
        if n not in unresolved:
            unresolved.append(n)
    return cubes or [Cube.any()]


def _parse_set_cli(content: str) -> Dict[str, Any]:
    """Parse PAN-OS `set ...` lines into normalized intermediate structures."""
    hostname = ""
    addresses: Dict[str, str] = {}
    address_groups: Dict[str, List[str]] = {}
    services: Dict[str, Dict[str, str]] = {}
    service_groups: Dict[str, List[str]] = {}
    zones: Dict[str, List[str]] = {}
    interfaces: Dict[str, Dict[str, Any]] = {}
    rules_by_name: Dict[str, Dict[str, Any]] = {}
    rule_order: List[str] = []
    nat_by_name: Dict[str, Dict[str, Any]] = {}
    static_routes: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for raw in (content or "").splitlines():
        s = raw.strip()
        if not s or s.startswith("#") or not s.lower().startswith("set "):
            continue
        try:
            raw_toks = shlex.split(s)
        except ValueError:
            raw_toks = s.split()
        toks = [t for t in raw_toks if t not in ("[", "]")]
        if len(toks) < 3:
            continue

        # set deviceconfig system hostname FW-PA-01
        if len(toks) >= 5 and toks[1] == "deviceconfig" and toks[2] == "system" and toks[3] == "hostname":
            hostname = toks[4]
            continue

        # set address <name> ip-netmask|ip-range|fqdn <val>
        if toks[1] == "address" and len(toks) >= 5 and toks[3] in ("ip-netmask", "ip-range", "fqdn"):
            addresses[toks[2]] = toks[4]
            continue

        # set address-group <name> static [ m1 m2 ]
        if toks[1] == "address-group" and len(toks) >= 5 and toks[3] == "static":
            address_groups.setdefault(toks[2], []).extend(toks[4:])
            continue

        # set service <name> protocol tcp|udp port <spec>
        if toks[1] == "service" and len(toks) >= 7 and toks[3] == "protocol" and toks[5] == "port":
            services[toks[2]] = {"proto": toks[4].lower(), "port": toks[6]}
            continue

        # set service-group <name> members [ s1 s2 ]
        if toks[1] == "service-group" and len(toks) >= 5 and toks[3] == "members":
            service_groups.setdefault(toks[2], []).extend(toks[4:])
            continue

        # set zone <z> network layer3|layer2 [ if1 if2 ]
        if toks[1] == "zone" and len(toks) >= 6 and toks[3] == "network":
            zname = toks[2]
            ifaces = toks[5:]
            zones.setdefault(zname, []).extend(ifaces)
            for ifn in ifaces:
                interfaces.setdefault(ifn, {})["zone"] = zname
            continue

        # set network interface ethernet <if> layer3 [units <unit>] ip <ip/cidr>
        if toks[1] == "network" and toks[2] == "interface":
            if "ip" in toks:
                ip_idx = toks.index("ip")
                if ip_idx + 1 < len(toks):
                    ip_cidr = toks[ip_idx + 1]
                    if "units" in toks:
                        u_idx = toks.index("units")
                        ifname = toks[u_idx + 1] if u_idx + 1 < len(toks) else toks[4]
                    elif len(toks) >= 5:
                        ifname = toks[4]
                    else:
                        ifname = ""
                    if ifname:
                        interfaces.setdefault(ifname, {})["ip_cidr"] = ip_cidr
            continue

        # set network virtual-router <vr> routing-table ip static-route <name> destination|nexthop|interface|metric ...
        if toks[1] == "network" and toks[2] == "virtual-router" and "static-route" in toks:
            vr = toks[3]
            vrf = "" if vr in ("default", "") else vr
            sr_idx = toks.index("static-route")
            if sr_idx + 2 < len(toks):
                sr_name = toks[sr_idx + 1]
                key = (vrf, sr_name)
                sr = static_routes.setdefault(key, {"name": sr_name, "vrf": vrf, "metric": 10})
                i = sr_idx + 2
                while i < len(toks):
                    attr = toks[i]
                    if attr == "destination" and i + 1 < len(toks):
                        sr["prefix"] = toks[i + 1]
                        i += 2
                    elif attr == "nexthop" and i + 2 < len(toks) and toks[i + 1] == "ip-address":
                        sr["next_hop"] = toks[i + 2]
                        i += 3
                    elif attr == "interface" and i + 1 < len(toks):
                        sr["interface"] = toks[i + 1]
                        i += 2
                    elif attr == "metric" and i + 1 < len(toks) and toks[i + 1].isdigit():
                        sr["metric"] = int(toks[i + 1])
                        i += 2
                    else:
                        i += 1
            continue

        # set rulebase security rules <name> <field> <val...>
        if toks[1] == "rulebase" and toks[2] == "security" and len(toks) >= 6 and toks[3] == "rules":
            rname = toks[4]
            if rname not in rules_by_name:
                rule_order.append(rname)
                rules_by_name[rname] = {
                    "name": rname, "disabled": False, "action": "permit",
                    "from": [], "to": [], "source": [], "destination": [],
                    "service": [], "application": [], "raw_lines": [],
                }
            r = rules_by_name[rname]
            r["raw_lines"].append(s)
            fld = toks[5]
            vals = toks[6:]
            if fld == "action" and vals:
                r["action"] = "permit" if vals[0].lower() == "allow" else "deny"
            elif fld == "disabled" and vals:
                r["disabled"] = vals[0].lower() == "yes"
            elif fld in ("from", "to", "source", "destination", "service", "application"):
                r[fld].extend(vals)
            continue

        # set rulebase nat rules <name> ...
        if toks[1] == "rulebase" and toks[2] == "nat" and len(toks) >= 6 and toks[3] == "rules":
            nname = toks[4]
            nr = nat_by_name.setdefault(nname, {
                "name": nname, "disabled": False, "from": [], "to": [],
                "source": [], "destination": [], "dnat": "", "snat": "",
            })
            fld = toks[5]
            vals = toks[6:]
            if fld == "disabled" and vals:
                nr["disabled"] = vals[0].lower() == "yes"
            elif fld in ("from", "to", "source", "destination"):
                nr[fld].extend(vals)
            elif fld == "destination-translation" and "translated-address" in vals:
                idx = vals.index("translated-address")
                if idx + 1 < len(vals):
                    nr["dnat"] = vals[idx + 1]
            elif fld == "source-translation":
                if "translated-address" in vals:
                    idx = vals.index("translated-address")
                    if idx + 1 < len(vals):
                        nr["snat"] = vals[idx + 1]
                elif "interface" in vals:
                    idx = vals.index("interface")
                    if idx + 1 < len(vals):
                        nr["snat"] = vals[idx + 1]
            continue

    return {
        "hostname": hostname,
        "addresses": addresses,
        "address_groups": address_groups,
        "services": services,
        "service_groups": service_groups,
        "zones": zones,
        "interfaces": interfaces,
        "security_rules": [rules_by_name[n] for n in rule_order],
        "nat_rules": list(nat_by_name.values()),
        "static_routes": list(static_routes.values()),
    }


def parse_panos_config(content: str) -> PanOSPolicyEnvironment:
    """Parse PAN-OS config (XML `<config>` or CLI `set ...`) into PanOSPolicyEnvironment."""
    text = (content or "").strip()
    if text.startswith("<"):
        raw = parse_panos_xml_config(text)
    else:
        raw = _parse_set_cli(text)

    env = PanOSPolicyEnvironment(
        hostname=raw.get("hostname") or "",
        zones=raw.get("zones") or {},
        interfaces=raw.get("interfaces") or {},
        address_groups=raw.get("address_groups") or {},
        services=raw.get("services") or {},
        service_groups=raw.get("service_groups") or {},
        nat_rules=raw.get("nat_rules") or [],
    )
    for zname, ifaces in env.zones.items():
        for ifn in ifaces:
            env.iface_to_zone[ifn.lower()] = zname

    # Resolve address objects
    for name, val in (raw.get("addresses") or {}).items():
        cubes = _addr_cubes(val)
        if cubes:
            env.addresses[name] = cubes

    # Route table (connected + static)
    routes: List[Route] = []
    for ifname, info in env.interfaces.items():
        ip_cidr = info.get("ip_cidr") or ""
        if not ip_cidr:
            continue
        try:
            net = ipaddress.ip_network(ip_cidr, strict=False)
            info["ip"] = str(ipaddress.ip_interface(ip_cidr).ip)
            info["network"] = str(net)
            if isinstance(net, ipaddress.IPv4Network):
                routes.append(Route(
                    prefix=str(net),
                    prefix_cube=Cube.from_cidr(str(net.network_address), net.prefixlen),
                    interface=ifname,
                    source="connected",
                    distance=0,
                ))
        except ValueError:
            pass
    for sr in raw.get("static_routes") or []:
        pfx = sr.get("prefix")
        if pfx:
            try:
                net = ipaddress.ip_network(pfx, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    routes.append(Route(
                        prefix=str(net),
                        prefix_cube=Cube.from_cidr(str(net.network_address), net.prefixlen),
                        next_hop=sr.get("next_hop") or None,
                        interface=sr.get("interface") or "",
                        source="static",
                        distance=int(sr.get("metric") or 10),
                        vrf=sr.get("vrf") or "",
                    ))
            except ValueError:
                pass
    env.route_table = RouteTable(routes=routes)

    # NAT rules -> VIP dictionary (for DNAT in path_trace)
    for nr in env.nat_rules:
        if nr.get("disabled") or not nr.get("dnat"):
            continue
        dsts = nr.get("destination") or []
        ext_spec = dsts[0] if dsts and dsts[0] != "any" else ""
        if ext_spec in env.addresses and env.addresses[ext_spec]:
            c = env.addresses[ext_spec][0]
            if c.is_exact():
                ext_spec = int_to_ip(c.value)
        elif "/" in ext_spec and ext_spec.endswith("/32"):
            ext_spec = ext_spec.split("/", 1)[0]
        mapped = nr["dnat"]
        if mapped in env.addresses and env.addresses[mapped]:
            c = env.addresses[mapped][0]
            if c.is_exact():
                mapped = int_to_ip(c.value)
        elif "/" in mapped and mapped.endswith("/32"):
            mapped = mapped.split("/", 1)[0]
        if ext_spec and mapped:
            env.vips[nr["name"]] = {"name": nr["name"], "extip": ext_spec, "mappedip": mapped, "extintf": "any"}

    # Build security rules
    for sr in raw.get("security_rules") or []:
        r_unres: List[str] = []
        src_cubes = _resolve_addr_list(sr.get("source") or [], env.addresses, env.address_groups, r_unres)
        dst_cubes = _resolve_addr_list(sr.get("destination") or [], env.addresses, env.address_groups, r_unres)

        proto_vals: Set[int] = set()
        dport_ivs: List[Tuple[int, int]] = []
        svc_any = False
        svc_names = sr.get("service") or ["application-default"]
        for sn in svc_names:
            low = sn.lower()
            if low in ("any", "application-default"):
                svc_any = True
                break
            if low in _PANOS_BUILTIN_SERVICES:
                p, ps = _PANOS_BUILTIN_SERVICES[low]
                if p is not None:
                    proto_vals.add(p)
                if ps is not None:
                    dport_ivs.extend(ps.intervals)
                continue
            sv_items = env.service_groups.get(sn) or [sn]
            for item in sv_items:
                if item in env.services:
                    sp = proto_from_name(env.services[item]["proto"])
                    if sp is not None:
                        proto_vals.add(sp)
                    dport_ivs.extend(_parse_ports(env.services[item]["port"]))
                elif item.lower() in _PANOS_BUILTIN_SERVICES:
                    p, ps = _PANOS_BUILTIN_SERVICES[item.lower()]
                    if p is not None:
                        proto_vals.add(p)
                    if ps is not None:
                        dport_ivs.extend(ps.intervals)
                elif item not in r_unres:
                    r_unres.append(item)

        protos_set: Optional[Set[int]] = None if (svc_any or not proto_vals) else proto_vals
        dport_set: Optional[PortSet] = PortSet.from_list(dport_ivs) if (dport_ivs and not svc_any) else None

        in_zones = set(sr.get("from") or [])
        out_zones = set(sr.get("to") or [])
        in_set = None if (not in_zones or any(z.lower() == "any" for z in in_zones)) else in_zones
        out_set = None if (not out_zones or any(z.lower() == "any" for z in out_zones)) else out_zones

        nquals: List[str] = []
        apps = [a for a in (sr.get("application") or []) if a.lower() != "any"]
        if apps:
            nquals.append(f"app:{','.join(apps)}")

        fs = FieldSet(
            src_ips=[Cube.any()] if r_unres else src_cubes,
            dst_ips=[Cube.any()] if r_unres else dst_cubes,
            dst_ports=None if r_unres else dport_set,
            protos=None if r_unres else protos_set,
            ingress_intfs=in_set,
            egress_intfs=out_set,
            opaque=bool(r_unres),
            narrowing_quals=tuple(nquals),
        )
        raw_text = "\n".join(sr.get("raw_lines") or [f"security rule {sr['name']} action {sr['action']}"])
        env.policies.append(Rule(
            id=sr["name"],
            name=sr["name"],
            action="unknown" if r_unres else sr["action"],
            fields=fs,
            disabled=bool(sr.get("disabled")),
            raw_text=raw_text,
            unresolved=r_unres,
        ))
        for u in r_unres:
            if u not in env.unresolved:
                env.unresolved.append(u)

    return env
