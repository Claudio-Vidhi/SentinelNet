# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Juniper Junos OS (`show configuration | display set`) policy & route parser.

Parses SRX security zones, address-books, custom applications, security policies,
static routes, interfaces, and EX/QFX firewall filters.
Pure module with zero I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import shlex
from typing import Any, Dict, List, Optional, Set, Tuple

from services.policy_test.model import (
    Cube, FieldSet, PortSet, Route, RouteTable, Rule, proto_from_name,
)


@dataclass
class JunosPolicyEnvironment:
    """Extracted Junos policy, filter, zone, object and routing environment."""
    policies: List[Rule] = field(default_factory=list)
    route_table: RouteTable = field(default_factory=RouteTable)
    interfaces: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    zones: Dict[str, List[str]] = field(default_factory=dict)
    iface_to_zone: Dict[str, str] = field(default_factory=dict)
    addresses: Dict[str, List[Cube]] = field(default_factory=dict)
    applications: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    unresolved: List[str] = field(default_factory=list)
    hostname: str = ""


_JUNOS_BUILTIN_APPS: Dict[str, Tuple[Optional[int], Optional[PortSet]]] = {
    "any": (None, None),
    "junos-http": (6, PortSet.from_list([(80, 80)])),
    "junos-https": (6, PortSet.from_list([(443, 443)])),
    "junos-ssh": (6, PortSet.from_list([(22, 22)])),
    "junos-telnet": (6, PortSet.from_list([(23, 23)])),
    "junos-dns-udp": (17, PortSet.from_list([(53, 53)])),
    "junos-dns-tcp": (6, PortSet.from_list([(53, 53)])),
    "junos-icmp-all": (1, None),
    "junos-ping": (1, None),
    "junos-ntp": (17, PortSet.from_list([(123, 123)])),
    "junos-syslog": (17, PortSet.from_list([(514, 514)])),
    "junos-modbus": (6, PortSet.from_list([(502, 502)])),
}


def _net_cube(cidr: str) -> Optional[Cube]:
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            return Cube.from_cidr(str(net.network_address), net.prefixlen)
    except ValueError:
        return None
    return None


def _parse_junos_ports(spec: str) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for p in str(spec or "").replace(",", " ").split():
        if "-" in p:
            a, b = p.split("-", 1)
            if a.isdigit() and b.isdigit():
                out.append((min(int(a), int(b)), max(int(a), int(b))))
        elif p.isdigit():
            v = int(p)
            out.append((v, v))
    return out


def parse_junos_config(content: str) -> JunosPolicyEnvironment:
    """Parse Junos `set ...` configuration text into JunosPolicyEnvironment."""
    env = JunosPolicyEnvironment()
    routes: List[Route] = []
    srx_policies: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    srx_order: List[Tuple[str, str, str]] = []
    static_entries: Dict[str, Dict[str, Any]] = {}
    addr_raw: Dict[str, str] = {}

    for raw in (content or "").splitlines():
        s = raw.strip()
        if not s or s.startswith("#") or not s.lower().startswith("set "):
            continue
        try:
            toks = [t for t in shlex.split(s) if t not in ("[", "]")]
        except ValueError:
            toks = [t for t in s.split() if t not in ("[", "]")]
        if len(toks) < 3:
            continue

        # set system host-name SRX-01
        if toks[1] == "system" and toks[2] == "host-name" and len(toks) >= 4:
            env.hostname = toks[3]
            continue

        # set interfaces <if> unit <u> family inet address <ip/cidr>
        if toks[1] == "interfaces" and "address" in toks:
            idx = toks.index("address")
            if idx + 1 < len(toks):
                ifname = toks[2]
                unit = toks[4] if len(toks) > 4 and toks[3] == "unit" else "0"
                full_if = f"{ifname}.{unit}" if "." not in ifname else ifname
                ip_cidr = toks[idx + 1]
                try:
                    iface_ip = str(ipaddress.ip_interface(ip_cidr).ip)
                    net = ipaddress.ip_network(ip_cidr, strict=False)
                    env.interfaces[full_if] = {"ip": iface_ip, "network": str(net), "ip_cidr": ip_cidr}
                    if isinstance(net, ipaddress.IPv4Network):
                        routes.append(Route(
                            prefix=str(net),
                            prefix_cube=Cube.from_cidr(str(net.network_address), net.prefixlen),
                            interface=full_if,
                            source="connected",
                            distance=0,
                        ))
                except ValueError:
                    pass
            continue

        # set routing-options static route <prefix> next-hop <ip>
        if toks[1] == "routing-options" and len(toks) >= 6 and toks[2] == "static" and toks[3] == "route":
            prefix = toks[4]
            sr = static_entries.setdefault(prefix, {"prefix": prefix, "ad": 5})
            if toks[5] == "next-hop" and len(toks) >= 7:
                sr["next_hop"] = toks[6]
            elif toks[5] == "preference" and len(toks) >= 7 and toks[6].isdigit():
                sr["ad"] = int(toks[6])
            continue

        # set applications application <name> protocol tcp|udp destination-port <port>
        if toks[1] == "applications" and len(toks) >= 6 and toks[2] == "application":
            aname = toks[3]
            app = env.applications.setdefault(aname, {})
            if "protocol" in toks:
                pi = toks.index("protocol")
                if pi + 1 < len(toks):
                    app["proto"] = toks[pi + 1].lower()
            if "destination-port" in toks:
                di = toks.index("destination-port")
                if di + 1 < len(toks):
                    app["port"] = toks[di + 1]
            continue

        # set security zones security-zone <zone> interfaces <if>
        if toks[1] == "security" and toks[2] == "zones" and len(toks) >= 6 and toks[3] == "security-zone":
            zname = toks[4]
            if toks[5] == "interfaces" and len(toks) >= 7:
                ifn = toks[6]
                env.zones.setdefault(zname, []).append(ifn)
                env.iface_to_zone[ifn.lower()] = zname
                env.interfaces.setdefault(ifn, {})["zone"] = zname
            elif toks[5] == "address-book" and len(toks) >= 9 and toks[6] == "address":
                aname = toks[7]
                addr_raw[aname] = toks[8]
            continue

        # set security address-book global address <name> <cidr>
        if toks[1] == "security" and toks[2] == "address-book" and "address" in toks:
            ai = toks.index("address")
            if ai + 2 < len(toks):
                addr_raw[toks[ai + 1]] = toks[ai + 2]
            continue

        # set security policies from-zone <z1> to-zone <z2> policy <pname> match|then ...
        if (toks[1] == "security" and toks[2] == "policies" and len(toks) >= 9
                and toks[3] == "from-zone" and toks[5] == "to-zone" and toks[7] == "policy"):
            fz, tz, pname = toks[4], toks[6], toks[8]
            key = (fz, tz, pname)
            if key not in srx_policies:
                srx_order.append(key)
                srx_policies[key] = {
                    "id": f"{fz}->{tz}:{pname}",
                    "name": pname,
                    "from_zone": fz,
                    "to_zone": tz,
                    "src": [],
                    "dst": [],
                    "apps": [],
                    "action": "permit",
                    "raw": [],
                }
            pol = srx_policies[key]
            pol["raw"].append(s)
            if "match" in toks:
                mi = toks.index("match")
                if mi + 2 < len(toks):
                    mf = toks[mi + 1]
                    mv = toks[mi + 2:]
                    if mf == "source-address":
                        pol["src"].extend(mv)
                    elif mf == "destination-address":
                        pol["dst"].extend(mv)
                    elif mf == "application":
                        pol["apps"].extend(mv)
            elif "then" in toks:
                ti = toks.index("then")
                if ti + 1 < len(toks):
                    act = toks[ti + 1].lower()
                    pol["action"] = "permit" if act == "permit" else "deny"
            continue

    for aname, cidr in addr_raw.items():
        c = _net_cube(cidr)
        if c is not None:
            env.addresses[aname] = [c]

    for sr in static_entries.values():
        c = _net_cube(sr["prefix"])
        if c is not None:
            routes.append(Route(
                prefix=sr["prefix"],
                prefix_cube=c,
                next_hop=sr.get("next_hop"),
                interface="",
                source="static",
                distance=sr.get("ad", 5),
            ))
    env.route_table = RouteTable(routes=routes)

    for key in srx_order:
        pol = srx_policies[key]
        r_unres: List[str] = []

        def _res_addr(names: List[str]) -> List[Cube]:
            if not names or any(n.lower() == "any" for n in names):
                return [Cube.any()]
            out: List[Cube] = []
            for n in names:
                c = _net_cube(n)
                if c is not None:
                    out.append(c)
                elif n in env.addresses:
                    out.extend(env.addresses[n])
                elif n not in r_unres:
                    r_unres.append(n)
            return out or [Cube.any()]

        s_cubes = _res_addr(pol["src"])
        d_cubes = _res_addr(pol["dst"])
        protos: Set[int] = set()
        dports: List[Tuple[int, int]] = []
        app_any = False
        for app_name in pol["apps"] or ["any"]:
            low = app_name.lower()
            if low == "any":
                app_any = True
                break
            if low in _JUNOS_BUILTIN_APPS:
                pr, ps = _JUNOS_BUILTIN_APPS[low]
                if pr is not None:
                    protos.add(pr)
                if ps is not None:
                    dports.extend(ps.intervals)
            elif app_name in env.applications:
                spec = env.applications[app_name]
                pr = proto_from_name(spec.get("proto") or "")
                if pr is not None:
                    protos.add(pr)
                dports.extend(_parse_junos_ports(spec.get("port") or ""))
            elif app_name not in r_unres:
                r_unres.append(app_name)

        p_set: Optional[Set[int]] = None if (app_any or not protos) else protos
        dp_set = PortSet.from_list(dports) if dports and not app_any else None

        in_set = None if pol["from_zone"].lower() == "any" else {pol["from_zone"]}
        out_set = None if pol["to_zone"].lower() == "any" else {pol["to_zone"]}
        fs = FieldSet(
            src_ips=[Cube.any()] if r_unres else s_cubes,
            dst_ips=[Cube.any()] if r_unres else d_cubes,
            dst_ports=None if r_unres else dp_set,
            protos=None if r_unres else p_set,
            ingress_intfs=in_set,
            egress_intfs=out_set,
            opaque=bool(r_unres),
        )
        env.policies.append(Rule(
            id=pol["id"],
            name=pol["name"],
            action="unknown" if r_unres else pol["action"],
            fields=fs,
            disabled=False,
            raw_text="\n".join(pol["raw"]),
            unresolved=r_unres,
        ))
        for u in r_unres:
            if u not in env.unresolved:
                env.unresolved.append(u)

    return env
