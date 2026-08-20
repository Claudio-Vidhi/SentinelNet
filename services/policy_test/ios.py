# -*- coding: utf-8 -*-
"""Cisco IOS / IOS-XE ACE parser, route table builder and policy environment.

Parses ACLs, object-groups, interface bindings, connected and static routes,
and dynamic routing presence from Cisco IOS running configs. Pure with zero I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from services.policy_test.model import (
    Cube, FieldSet, PortSet, Route, RouteTable, Rule, RuleSet,
    int_to_ip, ip_to_int, mask_to_prefix_len, proto_from_name,
)

# Standard IOS port name to number mapping
_PORT_NAMES: Dict[str, int] = {
    "echo": 7,
    "discard": 9,
    "daytime": 13,
    "chargen": 19,
    "ftp-data": 20,
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "time": 37,
    "tacacs": 49,
    "domain": 53,
    "dns": 53,
    "bootps": 67,
    "dhcps": 67,
    "bootpc": 68,
    "dhcpc": 68,
    "tftp": 69,
    "gopher": 70,
    "finger": 79,
    "www": 80,
    "http": 80,
    "kerberos": 88,
    "pop2": 109,
    "pop3": 110,
    "sunrpc": 111,
    "ident": 113,
    "nntp": 119,
    "ntp": 123,
    "netbios-ns": 137,
    "netbios-dgm": 138,
    "netbios-ssn": 139,
    "imap": 143,
    "snmp": 161,
    "snmptrap": 162,
    "bgp": 179,
    "ldap": 389,
    "https": 443,
    "ssl": 443,
    "ldaps": 636,
    "syslog": 514,
    "rip": 520,
    "l2tp": 1701,
    "pptp": 1723,
    "radius": 1812,
    "radius-acct": 1813,
    "ms-sql-s": 1433,
    "oracle": 1521,
    "mysql": 3306,
    "rdp": 3389,
    "sip": 5060,
}


def _parse_port_val(tok: str) -> Optional[int]:
    """Parse port token to int (handles '80', 'www', 'https', etc.)."""
    s = tok.strip().lower()
    if s.isdigit():
        val = int(s)
        return val if 0 <= val <= 65535 else None
    return _PORT_NAMES.get(s)


def _is_ip(tok: str) -> bool:
    """Check if token is a dotted-quad IPv4 address."""
    parts = tok.split('.')
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


@dataclass
class IOSObjectGroup:
    """Parsed Cisco IOS object group."""
    name: str
    kind: str  # network | service | port
    cubes: List[Cube] = field(default_factory=list)
    ports: List[Tuple[int, int]] = field(default_factory=list)
    group_refs: List[str] = field(default_factory=list)


def parse_object_groups(lines: List[str]) -> Dict[str, IOSObjectGroup]:
    """Parse object-group network/service/port definitions."""
    groups: Dict[str, IOSObjectGroup] = {}
    current: Optional[IOSObjectGroup] = None

    for raw in lines:
        s = raw.strip()
        if not s:
            continue
        if s.startswith('!'):
            current = None
            continue

        indent = len(raw) - len(raw.lstrip())
        low = s.lower()
        if indent == 0 and not low.startswith('object-group '):
            current = None
            continue

        if low.startswith('object-group '):
            toks = s.split()
            if len(toks) >= 3:
                kind = toks[1].lower()
                name = toks[2]
                current = IOSObjectGroup(name=name, kind=kind)
                groups[name] = current
            else:
                current = None
            continue

        if current is None:
            continue

        # Indented items within an object-group
        toks = s.split()
        if not toks:
            continue

        if current.kind == "network":
            # host X | X Y (netmask or wildcard) | group-object X
            if toks[0].lower() == "host" and len(toks) >= 2 and _is_ip(toks[1]):
                current.cubes.append(Cube.from_ip(toks[1]))
            elif toks[0].lower() == "group-object" and len(toks) >= 2:
                current.group_refs.append(toks[1])
            elif len(toks) >= 2 and _is_ip(toks[0]) and _is_ip(toks[1]):
                ip_s, mask_s = toks[0], toks[1]
                m_int = ip_to_int(mask_s)
                if m_int & 0x80000000 and mask_to_prefix_len(m_int) is not None:
                    current.cubes.append(Cube.from_netmask(ip_s, mask_s))
                else:
                    current.cubes.append(Cube.from_wildcard(ip_s, mask_s))
            elif len(toks) >= 1 and _is_ip(toks[0]):
                current.cubes.append(Cube.from_ip(toks[0]))

        elif current.kind in ("service", "port"):
            if toks[0].lower() == "group-object" and len(toks) >= 2:
                current.group_refs.append(toks[1])
            else:
                for idx, t in enumerate(toks):
                    t_low = t.lower()
                    if t_low == "eq" and idx + 1 < len(toks):
                        pval = _parse_port_val(toks[idx + 1])
                        if pval is not None:
                            current.ports.append((pval, pval))
                    elif t_low == "range" and idx + 2 < len(toks):
                        p1 = _parse_port_val(toks[idx + 1])
                        p2 = _parse_port_val(toks[idx + 2])
                        if p1 is not None and p2 is not None:
                            current.ports.append((min(p1, p2), max(p1, p2)))
                    elif t_low == "gt" and idx + 1 < len(toks):
                        pval = _parse_port_val(toks[idx + 1])
                        if pval is not None and pval < 65535:
                            current.ports.append((pval + 1, 65535))
                    elif t_low == "lt" and idx + 1 < len(toks):
                        pval = _parse_port_val(toks[idx + 1])
                        if pval is not None and pval > 1:
                            current.ports.append((1, pval - 1))

    # Resolve nested group-object references (flat)
    resolved_groups: Dict[str, IOSObjectGroup] = {}
    for name, grp in groups.items():
        all_cubes = list(grp.cubes)
        all_ports = list(grp.ports)
        seen_refs = {name}
        queue = list(grp.group_refs)
        while queue:
            ref = queue.pop(0)
            if ref in seen_refs or ref not in groups:
                continue
            seen_refs.add(ref)
            sub = groups[ref]
            all_cubes.extend(sub.cubes)
            all_ports.extend(sub.ports)
            queue.extend(sub.group_refs)
        resolved_groups[name] = IOSObjectGroup(
            name=name,
            kind=grp.kind,
            cubes=all_cubes,
            ports=all_ports,
            group_refs=grp.group_refs,
        )

    return resolved_groups


def _consume_ip_spec(
    toks: List[str],
    idx: int,
    obj_groups: Dict[str, IOSObjectGroup],
    unresolved: List[str],
) -> Tuple[Optional[List[Cube]], int]:
    """Parse IP spec starting at index. Returns (cubes, next_index). Returns (None, idx) if invalid."""
    if idx >= len(toks):
        return None, idx

    tok = toks[idx].lower()
    if tok == "any" or tok == "any4":
        return [Cube.any()], idx + 1

    if tok == "host":
        if idx + 1 < len(toks) and _is_ip(toks[idx + 1]):
            return [Cube.from_ip(toks[idx + 1])], idx + 2
        return None, idx

    if tok == "object-group":
        if idx + 1 < len(toks):
            gname = toks[idx + 1]
            if gname in obj_groups:
                grp = obj_groups[gname]
                if grp.cubes:
                    return list(grp.cubes), idx + 2
            unresolved.append(f"object-group '{gname}' not found or empty")
            return [Cube.any()], idx + 2
        return None, idx

    if _is_ip(toks[idx]):
        ip_s = toks[idx]
        if idx + 1 < len(toks) and _is_ip(toks[idx + 1]):
            wild_s = toks[idx + 1]
            return [Cube.from_wildcard(ip_s, wild_s)], idx + 2
        return [Cube.from_ip(ip_s)], idx + 1

    return None, idx


def _consume_port_spec(
    toks: List[str],
    idx: int,
    obj_groups: Dict[str, IOSObjectGroup],
    unresolved: List[str],
) -> Tuple[Optional[PortSet], int]:
    """Parse port operator if present starting at index. Returns (PortSet, next_index)."""
    if idx >= len(toks):
        return None, idx

    tok = toks[idx].lower()
    if tok == "eq" and idx + 1 < len(toks):
        p = _parse_port_val(toks[idx + 1])
        if p is not None:
            return PortSet.from_op("eq", p), idx + 2
        return None, idx + 2

    if tok == "gt" and idx + 1 < len(toks):
        p = _parse_port_val(toks[idx + 1])
        if p is not None:
            return PortSet.from_op("gt", p), idx + 2
        return None, idx + 2

    if tok == "lt" and idx + 1 < len(toks):
        p = _parse_port_val(toks[idx + 1])
        if p is not None:
            return PortSet.from_op("lt", p), idx + 2
        return None, idx + 2

    if tok == "neq" and idx + 1 < len(toks):
        p = _parse_port_val(toks[idx + 1])
        if p is not None:
            return PortSet.from_op("neq", p), idx + 2
        return None, idx + 2

    if tok == "range" and idx + 2 < len(toks):
        p1 = _parse_port_val(toks[idx + 1])
        p2 = _parse_port_val(toks[idx + 2])
        if p1 is not None and p2 is not None:
            return PortSet.from_op("range", p1, p2), idx + 3
        return None, idx + 3

    if tok == "object-group" and idx + 1 < len(toks):
        gname = toks[idx + 1]
        if gname in obj_groups:
            grp = obj_groups[gname]
            if grp.kind in ("service", "port") or grp.ports:
                return PortSet.from_list(grp.ports), idx + 2
        return None, idx

    return None, idx


def _static_route_distance(tail: List[str]) -> int:
    """Administrative distance from the tail of an 'ip route' line.

    Grammar: ``ip route <net> <mask> <next-hop> [<distance>] [name X]
    [tag Y] [track Z] [permanent]``. The distance is a BARE number; every
    other number in the tail belongs to a keyword.

    Taking the first digit token found made ``ip route ... tag 250`` a route
    with distance 250, which reorders the table and changes which route wins
    a longest-prefix tie. So keyword/value pairs are consumed as pairs, and
    only a number that stands on its own counts.
    """
    keywords_with_value = {"name", "tag", "track", "metric"}
    idx = 0
    while idx < len(tail):
        tok = tail[idx].lower()
        if tok in keywords_with_value:
            idx += 2  # skip the keyword and the value that belongs to it
            continue
        if tail[idx].isdigit():
            return int(tail[idx])
        idx += 1
    return 1


def _opaque_rule(rule_id: Optional[str], action: str, raw_line: str,
                 reason: str) -> Rule:
    """An ACE the parser could not read, carrying WHY it could not.

    The reason is not decoration. An opaque rule with an empty ``unresolved``
    list produced no finding and no note anywhere in the trace, so the engine
    answered with full confidence over an ACL it had failed to parse — the
    common ``permit object-group SVC object-group SRC any`` form was silently
    dropped and the verdict came from whatever ACE happened to follow it.
    """
    return Rule(
        id=rule_id or "opaque",
        action=action,
        fields=FieldSet(opaque=True),
        raw_text=raw_line,
        unresolved=[f"ACE not parsed: {reason}"],
    )


def parse_ace_line(
    raw_line: str,
    seq: str = "",
    kind: str = "extended",
    obj_groups: Optional[Dict[str, IOSObjectGroup]] = None,
) -> Optional[Rule]:
    """Parse a single Cisco IOS ACE line into a Rule object.

    Handles standard, extended, named, and numbered ACL lines.
    Returns None for remarks or empty lines.
    Returns Rule with opaque=True for unparseable lines, always carrying a
    reason in ``unresolved`` — see ``_opaque_rule``.
    """
    s = raw_line.strip()
    if not s or s.startswith('!'):
        return None

    groups = obj_groups or {}
    unresolved: List[str] = []

    # Strip leading access-list <num> or line sequence number
    m_num = re.match(r'^access-list\s+(\d+)\s+(.*)$', s, re.IGNORECASE)
    if m_num:
        num = m_num.group(1)
        rest = m_num.group(2).strip()
        n = int(num)
        kind = "standard" if (1 <= n <= 99 or 1300 <= n <= 1999) else "extended"
        rule_id = seq or num
        s = rest
    else:
        m_seq = re.match(r'^(\d+)\s+(.*)$', s)
        if m_seq:
            rule_id = m_seq.group(1)
            s = m_seq.group(2).strip()
        else:
            rule_id = seq or ""

    if s.lower().startswith('remark ') or s.lower() == 'remark':
        return None

    toks = s.split()
    if not toks:
        return None

    action_tok = toks[0].lower()
    if action_tok not in ("permit", "deny"):
        return Rule(
            id=rule_id or "opaque",
            action="unknown",
            fields=FieldSet(opaque=True),
            raw_text=raw_line,
            unresolved=["Unrecognized ACE action: " + action_tok],
        )

    action = action_tok
    curr_idx = 1

    try:
        if kind == "standard" or (kind.startswith("standard") or kind == "named-std"):
            src_cubes, curr_idx = _consume_ip_spec(toks, curr_idx, groups, unresolved)
            if src_cubes is None:
                return _opaque_rule(rule_id, action, raw_line,
                                    "source address specification not understood")
            return Rule(
                id=rule_id or "std",
                action=action,
                fields=FieldSet(
                    src_ips=src_cubes,
                    dst_ips=[Cube.any()],
                    src_ports=None,
                    dst_ports=None,
                    protos=None,
                ),
                raw_text=raw_line,
                unresolved=unresolved,
            )

        # Extended ACL: permit|deny <proto> <src_spec> [<src_port>] <dst_spec> [<dst_port>] [established] ...
        if curr_idx >= len(toks):
            return _opaque_rule(rule_id, action, raw_line,
                                "ACE ends before a protocol is given")

        proto_tok = toks[curr_idx].lower()
        curr_idx += 1
        proto_num = proto_from_name(proto_tok)
        if proto_num is None and proto_tok not in ("ip", "ipv4", "ip4", "any", "all"):
            # Unrecognized protocol token. Covers the object-group service form
            # ('permit object-group SVC ...'), which puts an object name where
            # the protocol belongs.
            return _opaque_rule(rule_id, action, raw_line,
                                f"protocol token '{proto_tok}' not understood")
        protos = {proto_num} if proto_num is not None else None

        # Source IP spec
        src_cubes, curr_idx = _consume_ip_spec(toks, curr_idx, groups, unresolved)
        if src_cubes is None:
            return _opaque_rule(rule_id, action, raw_line,
                                "source address specification not understood")

        # Source port spec (optional)
        src_ports, curr_idx = _consume_port_spec(toks, curr_idx, groups, unresolved)

        # Destination IP spec
        dst_cubes, curr_idx = _consume_ip_spec(toks, curr_idx, groups, unresolved)
        if dst_cubes is None:
            return _opaque_rule(rule_id, action, raw_line,
                                "destination address specification not understood")

        # Destination port spec (optional)
        dst_ports, curr_idx = _consume_port_spec(toks, curr_idx, groups, unresolved)

        # Check remaining tokens for 'established', 'log', etc.
        established = False
        while curr_idx < len(toks):
            t_low = toks[curr_idx].lower()
            if t_low == "established":
                established = True
            curr_idx += 1

        return Rule(
            id=rule_id or "ext",
            action=action,
            fields=FieldSet(
                src_ips=src_cubes,
                dst_ips=dst_cubes,
                src_ports=src_ports,
                dst_ports=dst_ports,
                protos=protos,
                established=established,
            ),
            raw_text=raw_line,
            unresolved=unresolved,
        )

    except Exception as exc:
        return Rule(
            id=rule_id or "opaque",
            action=action,
            fields=FieldSet(opaque=True),
            raw_text=raw_line,
            unresolved=[f"Error parsing ACE: {exc}"],
        )


@dataclass
class IOSPolicyEnvironment:
    """Full extracted policy and routing environment from an IOS running-config."""
    acls: Dict[str, RuleSet] = field(default_factory=dict)
    interfaces: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    route_table: RouteTable = field(default_factory=RouteTable)
    object_groups: Dict[str, IOSObjectGroup] = field(default_factory=dict)
    unresolved: List[str] = field(default_factory=list)


def parse_ios_config(config_text: str) -> IOSPolicyEnvironment:
    """Parse Cisco IOS running-config into IOSPolicyEnvironment."""
    lines = [ln.rstrip() for ln in (config_text or "").splitlines()]
    env = IOSPolicyEnvironment()

    # 1. Parse object-groups first
    env.object_groups = parse_object_groups(lines)

    # 2. Block extraction
    current_block_type: Optional[str] = None
    current_block_header = ""
    current_block_lines: List[str] = []

    blocks: List[Tuple[str, str, List[str]]] = []

    for line in lines:
        s = line.strip()
        if not s or s.startswith('!'):
            continue

        indent = len(line) - len(line.lstrip())
        if indent == 0:
            if current_block_type is not None:
                blocks.append((current_block_type, current_block_header, current_block_lines))
                current_block_lines = []
                current_block_type = None

            low = s.lower()
            if low.startswith('interface '):
                current_block_type = "interface"
                current_block_header = s
            elif low.startswith('ip access-list standard '):
                current_block_type = "named_std_acl"
                current_block_header = s
            elif low.startswith('ip access-list extended '):
                current_block_type = "named_ext_acl"
                current_block_header = s
            elif low.startswith('access-list '):
                blocks.append(("numbered_acl", s, []))
            elif low.startswith('ip route '):
                blocks.append(("static_route", s, []))
            elif low.startswith('router '):
                current_block_type = "router"
                current_block_header = s
        else:
            if current_block_type is not None:
                current_block_lines.append(s)

    if current_block_type is not None:
        blocks.append((current_block_type, current_block_header, current_block_lines))

    # 3. Process blocks
    connected_routes: List[Route] = []
    static_routes: List[Route] = []
    dynamic_protocols: List[str] = []

    for btype, header, body in blocks:
        if btype == "numbered_acl":
            m = re.match(r'access-list\s+(\d+)\s+(.*)$', header, re.IGNORECASE)
            if m:
                num = m.group(1)
                n = int(num)
                kind = "standard" if (1 <= n <= 99 or 1300 <= n <= 1999) else "extended"
                acl = env.acls.setdefault(num, RuleSet(name=num, kind=f"numbered-{kind}"))
                rule = parse_ace_line(header, seq=str(len(acl.rules) + 1), kind=kind, obj_groups=env.object_groups)
                if rule:
                    acl.rules.append(rule)

        elif btype in ("named_std_acl", "named_ext_acl"):
            kind = "named-std" if btype == "named_std_acl" else "named-ext"
            acl_name = header.split()[-1]
            acl = env.acls.setdefault(acl_name, RuleSet(name=acl_name, kind=kind))
            for b_line in body:
                rule = parse_ace_line(b_line, kind=kind, obj_groups=env.object_groups)
                if rule:
                    acl.rules.append(rule)

        elif btype == "interface":
            intf_name = header[10:].strip()
            iface_info: Dict[str, Any] = {
                "name": intf_name,
                "ip": "",
                "mask": "",
                "prefix": "",
                "secondary_ips": [],
                "acl_in": None,
                "acl_out": None,
                "shutdown": False,
            }
            for b_line in body:
                low = b_line.lower()
                if low == "shutdown":
                    iface_info["shutdown"] = True
                elif low.startswith("ip address "):
                    toks = b_line.split()
                    if len(toks) >= 4 and toks[1].lower() == "address":
                        ip_val, mask_val = toks[2], toks[3]
                        pfx_len = mask_to_prefix_len(ip_to_int(mask_val)) if _is_ip(mask_val) else None
                        cidr = f"{ip_val}/{pfx_len}" if pfx_len is not None else ip_val
                        if "secondary" in low:
                            iface_info["secondary_ips"].append({"ip": ip_val, "mask": mask_val, "prefix": cidr})
                        else:
                            iface_info["ip"] = ip_val
                            iface_info["mask"] = mask_val
                            iface_info["prefix"] = cidr
                elif low.startswith("ip access-group "):
                    toks = b_line.split()
                    if len(toks) >= 4:
                        grp_name = toks[2]
                        direction = toks[3].lower()
                        if direction == "in":
                            iface_info["acl_in"] = grp_name
                        elif direction == "out":
                            iface_info["acl_out"] = grp_name

            env.interfaces[intf_name] = iface_info

            # Connected route if interface is up and has an IP
            if not iface_info["shutdown"] and iface_info["ip"] and iface_info["mask"]:
                try:
                    p_cube = Cube.from_netmask(iface_info["ip"], iface_info["mask"])
                    pfx_len = mask_to_prefix_len(p_cube.mask) or 24
                    pfx_str = f"{int_to_ip(p_cube.value)}/{pfx_len}"
                    connected_routes.append(Route(
                        prefix=pfx_str,
                        prefix_cube=p_cube,
                        next_hop=None,
                        interface=intf_name,
                        source="connected",
                        distance=0,
                    ))
                except Exception:
                    pass

        elif btype == "static_route":
            toks = header.split()
            rest = toks[2:]
            vrf = ""
            if rest[:1] == ['vrf'] and len(rest) >= 2:
                vrf = rest[1]
                rest = rest[2:]
            if len(rest) >= 3:
                net, mask, nexthop = rest[0], rest[1], rest[2]
                try:
                    p_cube = Cube.from_netmask(net, mask)
                    pfx_len = mask_to_prefix_len(p_cube.mask) or 0
                    pfx_str = f"{int_to_ip(p_cube.value)}/{pfx_len}"
                    egress_iface = ""
                    next_hop_ip: Optional[str] = None
                    if _is_ip(nexthop):
                        next_hop_ip = nexthop
                    else:
                        egress_iface = nexthop

                    ad = _static_route_distance(rest[3:])

                    static_routes.append(Route(
                        prefix=pfx_str,
                        prefix_cube=p_cube,
                        next_hop=next_hop_ip,
                        interface=egress_iface,
                        source="static",
                        distance=ad,
                    ))
                except Exception:
                    pass

        elif btype == "router":
            toks = header.split()
            proto_name = toks[1] if len(toks) > 1 else "dynamic"
            dynamic_protocols.append(proto_name)

    # 4. Resolve static route egress interfaces from connected subnets when next_hop is an IP
    resolved_static: List[Route] = []
    for sr in static_routes:
        if sr.next_hop and not sr.interface:
            nh_int = ip_to_int(sr.next_hop)
            matched_conn = next((cr for cr in connected_routes if cr.prefix_cube.contains_ip(nh_int)), None)
            if matched_conn:
                resolved_static.append(Route(
                    prefix=sr.prefix,
                    prefix_cube=sr.prefix_cube,
                    next_hop=sr.next_hop,
                    interface=matched_conn.interface,
                    source=sr.source,
                    distance=sr.distance,
                ))
            else:
                resolved_static.append(sr)
        else:
            resolved_static.append(sr)

    # 5. Build route table
    all_routes = connected_routes + resolved_static
    env.route_table = RouteTable(
        routes=all_routes,
        dynamic_routing_present=len(dynamic_protocols) > 0,
        protocols=dynamic_protocols,
    )

    return env
