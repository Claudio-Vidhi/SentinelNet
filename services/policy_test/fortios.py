# -*- coding: utf-8 -*-
"""FortiOS (FortiGate) policy, address, service, interface and route resolution.

Extracts firewall policies, custom and factory address objects, address groups,
custom and factory services, service groups, connected interface subnets, and
static routes from FortiOS configurations. Pure with zero I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from fw_analyzers.fortios import _forti_get, _forti_set1, _forti_tokens, _forti_tree
from services.policy_test.builtins import lookup_builtin_address, lookup_builtin_service
from services.policy_test.model import (
    Cube, FieldSet, Flow, PortSet, Route, RouteTable, Rule, RuleSet,
    int_to_ip, ip_to_int, mask_to_prefix_len, proto_from_name,
)


def _is_ip(tok: str) -> bool:
    parts = tok.split('.')
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


@dataclass
class FortiOSPolicyEnvironment:
    """Full extracted policy and routing environment from FortiOS config."""
    policies: List[Rule] = field(default_factory=list)
    route_table: RouteTable = field(default_factory=RouteTable)
    interfaces: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    addresses: Dict[str, List[Cube]] = field(default_factory=dict)
    services: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    unresolved: List[str] = field(default_factory=list)


def parse_port_ranges(spec: str) -> List[Tuple[int, int]]:
    """Parse a FortiOS portrange spec into destination-port intervals.

    The syntax is ``dst[-dst][:src[-src]]``: ``80:8080`` means destination 80
    from source 8080, NOT the range 80-8080. Treating ':' as a range separator
    turned a single-port service into thousands of ports, and a spec whose
    source half carried a range ('443:1024-65535') parsed to nothing at all —
    which the caller then read as "no port constraint" and widened to ANY.

    Only the destination half is returned: the callers bind the result to
    ``dst_ports`` and ignore source ports entirely.
    """
    intervals: List[Tuple[int, int]] = []
    if not spec:
        return intervals

    for chunk in spec.split():
        dst_half = chunk.split(':', 1)[0]
        for sub in dst_half.split(','):
            sub = sub.strip()
            if not sub:
                continue
            if '-' in sub:
                parts = sub.split('-', 1)
                try:
                    p1, p2 = int(parts[0]), int(parts[1])
                    intervals.append((min(p1, p2), max(p1, p2)))
                except Exception:
                    pass
            elif sub.isdigit():
                p = int(sub)
                intervals.append((p, p))
    return intervals


def _collect_policy_address(name: str, pid: Any, env: FortiOSPolicyEnvironment,
                            out: List[Cube], unresolved: List[str]) -> None:
    """Append the cubes of address object ``name`` to ``out``.

    Three outcomes, and the middle one is the reason this is not inline. An
    object that is DEFINED but resolves to zero cubes — an FQDN, a dynamic or
    geography object, an address group whose members are all of those — is not
    an object covering nothing. It is an object whose coverage cannot be known
    from a backup. Contributing nothing silently left the cube list empty, and
    the caller's ``or [Cube.any()]`` fallback then widened the policy to every
    address on the internet: a policy restricted to one vendor portal answered
    PERMIT for an arbitrary destination, with no warning attached.
    """
    builtin = lookup_builtin_address(name)
    if builtin is not None:
        out.extend(builtin)
        return
    if name in env.addresses:
        cubes = env.addresses[name]
        if cubes:
            out.extend(cubes)
        else:
            unresolved.append(
                f"address '{name}' referenced by policy {pid} cannot be resolved "
                "offline (FQDN, dynamic or geography object)")
        return
    unresolved.append(f"address '{name}' referenced by policy {pid} is not defined")


def parse_fortios_config(config_text: str) -> FortiOSPolicyEnvironment:
    """Parse FortiOS config text into FortiOSPolicyEnvironment."""
    root = _forti_tree(config_text or "")
    env = FortiOSPolicyEnvironment()

    # 1. Parse custom firewall addresses
    addr_node = _forti_get(root, "firewall address")
    raw_addresses: Dict[str, List[Cube]] = {}
    if addr_node:
        for name, entry in addr_node.get("children", {}).items():
            sets = entry.get("sets", {})
            atype = sets.get("type", ["ipmask"])[0].lower()
            if atype == "ipmask":
                subnet = sets.get("subnet", [])
                if len(subnet) >= 2 and _is_ip(subnet[0]) and _is_ip(subnet[1]):
                    try:
                        cube = Cube.from_netmask(subnet[0], subnet[1])
                        raw_addresses[name] = [cube]
                    except Exception:
                        pass
                elif len(subnet) == 1 and "/" in subnet[0]:
                    ip_part, pfx_part = subnet[0].split("/", 1)
                    if _is_ip(ip_part) and pfx_part.isdigit():
                        raw_addresses[name] = [Cube.from_cidr(ip_part, int(pfx_part))]
            elif atype == "iprange":
                # Start and end IP
                start_ip = _forti_set1(entry, "start-ip")
                end_ip = _forti_set1(entry, "end-ip")
                if _is_ip(start_ip) and _is_ip(end_ip):
                    # We can represent exact or best-effort cubes for range
                    try:
                        s_int, e_int = ip_to_int(start_ip), ip_to_int(end_ip)
                        # If single IP:
                        if s_int == e_int:
                            raw_addresses[name] = [Cube.from_ip(start_ip)]
                        else:
                            # Generate covering cubes
                            cubes = []
                            for net in ipaddress.summarize_address_range(
                                ipaddress.IPv4Address(s_int), ipaddress.IPv4Address(e_int)
                            ):
                                cubes.append(Cube.from_cidr(str(net.network_address), net.prefixlen))
                            raw_addresses[name] = cubes
                    except Exception:
                        pass
            elif atype == "fqdn":
                # FQDN cannot be resolved offline -> mark as unresolved / empty
                raw_addresses[name] = []

    # 2. Parse firewall address groups (recursive resolution)
    addrgrp_node = _forti_get(root, "firewall addrgrp")
    addr_groups_raw: Dict[str, List[str]] = {}
    if addrgrp_node:
        for name, entry in addrgrp_node.get("children", {}).items():
            members = entry.get("sets", {}).get("member", [])
            addr_groups_raw[name] = list(members)

    resolved_addresses: Dict[str, List[Cube]] = dict(raw_addresses)
    for gname, members in addr_groups_raw.items():
        all_cubes: List[Cube] = []
        seen = {gname}
        queue = list(members)
        while queue:
            m = queue.pop(0)
            if m in seen:
                continue
            seen.add(m)
            # Check builtin first, then raw_addresses, then addr_groups
            b_cubes = lookup_builtin_address(m)
            if b_cubes is not None:
                all_cubes.extend(b_cubes)
            elif m in raw_addresses:
                all_cubes.extend(raw_addresses[m])
            elif m in addr_groups_raw:
                queue.extend(addr_groups_raw[m])
        resolved_addresses[gname] = all_cubes

    env.addresses = resolved_addresses

    # 3. Parse custom services
    svc_node = _forti_get(root, "firewall service custom")
    raw_services: Dict[str, Dict[str, Any]] = {}
    if svc_node:
        for name, entry in svc_node.get("children", {}).items():
            sets = entry.get("sets", {})
            protocol = _forti_set1(entry, "protocol", "TCP/UDP/SCTP").upper()
            tcp_range = _forti_set1(entry, "tcp-portrange")
            udp_range = _forti_set1(entry, "udp-portrange")
            proto_num = _forti_set1(entry, "protocol-number")

            if protocol == "IP" and proto_num:
                try:
                    p_num = int(proto_num)
                    raw_services[name] = {"protos": {p_num}, "dst_ports": None}
                except Exception:
                    pass
            elif protocol == "ICMP":
                raw_services[name] = {"protos": {1}, "dst_ports": None}
            else:
                protos: Set[int] = set()
                ports: List[Tuple[int, int]] = []
                if tcp_range:
                    protos.add(6)
                    ports.extend(parse_port_ranges(tcp_range))
                if udp_range:
                    protos.add(17)
                    ports.extend(parse_port_ranges(udp_range))
                if not protos:
                    protos = {6, 17}
                raw_services[name] = {
                    "protos": protos if protos else None,
                    "dst_ports": ports if ports else None,
                }

    # 4. Parse service groups
    svcgrp_node = _forti_get(root, "firewall service group")
    svc_groups_raw: Dict[str, List[str]] = {}
    if svcgrp_node:
        for name, entry in svcgrp_node.get("children", {}).items():
            members = entry.get("sets", {}).get("member", [])
            svc_groups_raw[name] = list(members)

    resolved_services: Dict[str, Dict[str, Any]] = dict(raw_services)
    for gname, members in svc_groups_raw.items():
        all_protos: Set[int] = set()
        all_ports: List[Tuple[int, int]] = []
        any_proto = False
        any_ports = False

        seen = {gname}
        queue = list(members)
        while queue:
            m = queue.pop(0)
            if m in seen:
                continue
            seen.add(m)
            b_svc = lookup_builtin_service(m)
            svc_def = b_svc if b_svc is not None else raw_services.get(m)
            if svc_def is not None:
                if svc_def["protos"] is None:
                    any_proto = True
                else:
                    all_protos.update(svc_def["protos"])
                if svc_def["dst_ports"] is None:
                    any_ports = True
                else:
                    all_ports.extend(svc_def["dst_ports"])
            elif m in svc_groups_raw:
                queue.extend(svc_groups_raw[m])

        resolved_services[gname] = {
            "protos": None if any_proto else (all_protos if all_protos else None),
            "dst_ports": None if any_ports else (all_ports if all_ports else None),
        }

    env.services = resolved_services

    # 5. Parse system interfaces
    intf_node = _forti_get(root, "system interface")
    connected_routes: List[Route] = []
    if intf_node:
        for name, entry in intf_node.get("children", {}).items():
            sets = entry.get("sets", {})
            ip_tokens = sets.get("ip", [])
            status = _forti_set1(entry, "status", "up").lower()
            if len(ip_tokens) >= 2 and _is_ip(ip_tokens[0]) and _is_ip(ip_tokens[1]):
                ip_str, mask_str = ip_tokens[0], ip_tokens[1]
                iface_info = {
                    "name": name,
                    "ip": ip_str,
                    "mask": mask_str,
                    "status": status,
                }
                env.interfaces[name] = iface_info

                if status == "up" and ip_str != "0.0.0.0":
                    try:
                        p_cube = Cube.from_netmask(ip_str, mask_str)
                        pfx_len = mask_to_prefix_len(p_cube.mask) or 24
                        pfx_str = f"{int_to_ip(p_cube.value)}/{pfx_len}"
                        connected_routes.append(Route(
                            prefix=pfx_str,
                            prefix_cube=p_cube,
                            next_hop=None,
                            interface=name,
                            source="connected",
                            distance=0,
                        ))
                    except Exception:
                        pass

    # 6. Parse static routes
    static_node = _forti_get(root, "router static")
    static_routes: List[Route] = []
    if static_node:
        for rid, entry in static_node.get("children", {}).items():
            sets = entry.get("sets", {})
            status = _forti_set1(entry, "status", "enable").lower()
            if status == "disable":
                continue

            dst = sets.get("dst", ["0.0.0.0", "0.0.0.0"])
            gw = _forti_set1(entry, "gateway")
            device = _forti_set1(entry, "device")
            distance = int(_forti_set1(entry, "distance", "10") or 10)

            if len(dst) >= 2 and _is_ip(dst[0]) and _is_ip(dst[1]):
                net_str, mask_str = dst[0], dst[1]
                try:
                    p_cube = Cube.from_netmask(net_str, mask_str)
                    pfx_len = mask_to_prefix_len(p_cube.mask) or 0
                    pfx_str = f"{int_to_ip(p_cube.value)}/{pfx_len}"

                    egress_intf = device
                    if gw and not egress_intf:
                        gw_int = ip_to_int(gw)
                        matched = next((cr for cr in connected_routes if cr.prefix_cube.contains_ip(gw_int)), None)
                        if matched:
                            egress_intf = matched.interface

                    static_routes.append(Route(
                        prefix=pfx_str,
                        prefix_cube=p_cube,
                        next_hop=gw or None,
                        interface=egress_intf,
                        source="static",
                        distance=distance,
                    ))
                except Exception:
                    pass

    # Dynamic routing check
    dynamic_present = bool(_forti_get(root, "router ospf") or _forti_get(root, "router bgp"))
    env.route_table = RouteTable(
        routes=connected_routes + static_routes,
        dynamic_routing_present=dynamic_present,
        protocols=["ospf" if _forti_get(root, "router ospf") else "bgp"] if dynamic_present else [],
    )

    # 7. Parse firewall policies in sequence order
    pol_node = _forti_get(root, "firewall policy")
    if pol_node:
        for pid, entry in pol_node.get("children", {}).items():
            sets = entry.get("sets", {})
            name = _forti_set1(entry, "name", "")
            action_raw = _forti_set1(entry, "action", "deny").lower()
            action = "permit" if action_raw == "accept" else "deny"
            status = _forti_set1(entry, "status", "enable").lower()
            disabled = (status == "disable")
            nat_raw = _forti_set1(entry, "nat", "disable").lower()
            nat_enabled = (nat_raw == "enable")

            srcintf_list = sets.get("srcintf", ["any"])
            dstintf_list = sets.get("dstintf", ["any"])
            srcaddr_list = sets.get("srcaddr", ["all"])
            dstaddr_list = sets.get("dstaddr", ["all"])
            service_list = sets.get("service", ["ALL"])

            policy_unresolved: List[str] = []

            # Ingress interfaces
            ingress_intfs = None if "any" in srcintf_list else set(srcintf_list)
            # Egress interfaces
            egress_intfs = None if "any" in dstintf_list else set(dstintf_list)

            # Source addresses
            src_cubes: List[Cube] = []
            for a in srcaddr_list:
                _collect_policy_address(a, pid, env, src_cubes, policy_unresolved)

            # Destination addresses
            dst_cubes: List[Cube] = []
            for a in dstaddr_list:
                _collect_policy_address(a, pid, env, dst_cubes, policy_unresolved)

            # Services
            pol_protos: Optional[Set[int]] = None
            pol_ports: Optional[List[Tuple[int, int]]] = None
            has_service = False
            service_protos: Set[int] = set()
            service_ports: List[Tuple[int, int]] = []
            any_proto = False
            any_port = False

            for s in service_list:
                b_svc = lookup_builtin_service(s)
                s_def = b_svc if b_svc is not None else env.services.get(s)
                if s_def is not None:
                    has_service = True
                    if s_def["protos"] is None:
                        any_proto = True
                    else:
                        service_protos.update(s_def["protos"])
                    if s_def["dst_ports"] is None:
                        any_port = True
                    else:
                        service_ports.extend(s_def["dst_ports"])
                else:
                    policy_unresolved.append(f"service '{s}' referenced by policy {pid} is not defined")

            if has_service:
                pol_protos = None if any_proto else (service_protos if service_protos else None)
                pol_ports = None if any_port else (service_ports if service_ports else None)

            # Check internet-service
            if _forti_set1(entry, "internet-service") == "enable" or sets.get("internet-service-name"):
                policy_unresolved.append(f"policy {pid} references ISDB internet-service which cannot be resolved offline")

            field_set = FieldSet(
                src_ips=src_cubes if src_cubes else [Cube.any()],
                dst_ips=dst_cubes if dst_cubes else [Cube.any()],
                src_ports=None,
                dst_ports=PortSet.from_list(pol_ports) if pol_ports is not None else None,
                protos=pol_protos,
                ingress_intfs=ingress_intfs,
                egress_intfs=egress_intfs,
                opaque=len(policy_unresolved) > 0,
            )

            raw_txt = f"edit {pid}\n" + "\n".join(f"  set {k} {' '.join(v)}" for k, v in sets.items())
            rule = Rule(
                id=str(pid),
                name=name,
                action="unknown" if policy_unresolved else action,
                fields=field_set,
                disabled=disabled,
                raw_text=raw_txt,
                nat_enabled=nat_enabled,
                unresolved=policy_unresolved,
            )
            env.policies.append(rule)
            if policy_unresolved:
                env.unresolved.extend(policy_unresolved)

    return env
