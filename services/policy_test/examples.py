# -*- coding: utf-8 -*-
"""Per-rule example traffic generator.

Synthesizes representative matching flows and near-miss flows for each rule in
an ACL or Firewall Policy RuleSet. Pure with zero I/O, supports optional
hint_addresses to prefer real host addresses when available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from services.policy_test.model import (
    Cube, FieldSet, Flow, PortSet, Rule, RuleSet, int_to_ip, ip_to_int,
    mask_to_prefix_len,
)

_PROTO_NAMES_REV: Dict[int, str] = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    47: "gre",
    50: "esp",
    51: "ah",
    88: "eigrp",
    89: "ospf",
    103: "pim",
    132: "sctp",
}


@dataclass
class RuleExample:
    """Generated example traffic and near-miss flow for a single rule."""
    rule_id: str
    rule_name: str
    action: str
    raw_text: str
    # None when the rule could not be parsed: no flow can be claimed to match
    # a rule whose coverage is unknown.
    matching_flow: Optional[Flow] = None
    near_miss_flow: Optional[Flow] = None
    near_miss_reason: str = ""
    # True when every field of the rule is ANY. The example flow is then one
    # arbitrary member of "all traffic" and must be presented as such.
    matches_all: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "action": self.action,
            "raw_text": self.raw_text,
            "matches_all": self.matches_all,
            "matching_flow": self.matching_flow.to_dict() if self.matching_flow else None,
            "near_miss_flow": self.near_miss_flow.to_dict() if self.near_miss_flow else None,
            "near_miss_reason": self.near_miss_reason,
        }


def _pick_ip_in_cubes(
    cubes: Sequence[Cube],
    hint_addresses: Optional[Sequence[str]] = None,
    default_fallback: str = "192.0.2.50",
) -> str:
    """Pick an IP that matches at least one cube in cubes."""
    hints = hint_addresses or []
    # Check if any hint matches
    for h in hints:
        try:
            h_int = ip_to_int(h)
            if any(c.contains_ip(h_int) for c in cubes):
                return h
        except Exception:
            continue

    if not cubes:
        return default_fallback

    first = cubes[0]
    if first.is_any():
        return default_fallback
    if first.is_exact():
        return int_to_ip(first.value)

    # Subnet or wildcard cube
    pfx = mask_to_prefix_len(first.mask)
    if pfx is not None:
        if pfx >= 31:
            return int_to_ip(first.value)
        # Pick .10 or .1 inside subnet
        offset = 10 if (1 << (32 - pfx)) > 15 else 1
        return int_to_ip(first.value + offset)

    # Non-contiguous wildcard: the free bits are scattered through the address,
    # so arithmetic on the whole value walks straight out of the cube.
    # 'permit ip 192.0.2.0 0.0.255.0' has its LAST octet significant, and
    # value + 1 produced 192.0.0.1 — an example that does not match the rule
    # it is meant to illustrate. Set a free bit instead; that always lands
    # inside.
    return int_to_ip(_scatter_into_free_bits(first, 1))


def _scatter_into_free_bits(cube: Cube, n: int) -> int:
    """Address inside ``cube``, with ``n`` written across its don't-care bits.

    Only wildcard positions are touched, so the result satisfies the cube by
    construction whatever shape the mask has.
    """
    free = (~cube.mask) & 0xFFFFFFFF
    out = 0
    remaining = n
    for bit in range(32):
        if not (free & (1 << bit)):
            continue
        if remaining & 1:
            out |= (1 << bit)
        remaining >>= 1
        if remaining == 0:
            break
    return (cube.value | out) & 0xFFFFFFFF


def _pick_outside_ip(cube: Cube) -> str:
    """Pick an IP that lies strictly outside the given cube."""
    if cube.is_any():
        return "192.0.2.1"

    # Flip the lowest significant bit of the mask
    lsb = cube.mask & (-cube.mask) if cube.mask else 1
    outside_val = (cube.value ^ lsb) & 0xFFFFFFFF
    return int_to_ip(outside_val)


def generate_rule_example(
    rule: Rule,
    hint_addresses: Optional[Sequence[str]] = None,
) -> RuleExample:
    """Generate a representative matching Flow and a near-miss Flow for a Rule."""
    fields = rule.fields
    if fields.opaque:
        # No example can be synthesised for a rule the parser could not read:
        # its coverage is unknown, not empty. Emitting a concrete flow here
        # would assert a match nobody verified.
        return RuleExample(
            rule_id=rule.id,
            rule_name=rule.name,
            action=rule.action,
            raw_text=rule.raw_text,
            matching_flow=None,
            near_miss_flow=None,
            near_miss_reason="; ".join(rule.unresolved) or
                             "rule could not be parsed: coverage unknown",
        )

    # 1. Pick Source IP
    src_ip = _pick_ip_in_cubes(fields.src_ips, hint_addresses, "192.0.2.50")

    # 2. Pick Destination IP
    dst_ip = _pick_ip_in_cubes(fields.dst_ips, hint_addresses, "198.51.100.20")

    # 3. Pick Protocol
    proto_str = "tcp"
    proto_num = 6
    if fields.protos:
        proto_num = next(iter(fields.protos))
        proto_str = _PROTO_NAMES_REV.get(proto_num, str(proto_num))

    # 4. Pick Destination Port
    dport: Optional[int] = None
    if proto_num in (6, 17):  # TCP or UDP
        if fields.dst_ports and fields.dst_ports.intervals:
            lo, hi = fields.dst_ports.intervals[0]
            dport = lo if lo > 0 else (80 if proto_num == 6 else 53)
        else:
            dport = 443 if proto_num == 6 else 53

    # 5. Pick Source Port
    sport: Optional[int] = None
    if proto_num in (6, 17):
        if fields.src_ports and fields.src_ports.intervals:
            sport = fields.src_ports.intervals[0][0]
        else:
            sport = 52100

    # 5b. Pick ICMP message type, when the rule names one
    icmp_type: Optional[int] = None
    if fields.icmp_types:
        icmp_type = next(iter(fields.icmp_types))

    # 6. Ingress and Egress interfaces
    ingress_intf = next(iter(fields.ingress_intfs)) if fields.ingress_intfs else None
    egress_intf = next(iter(fields.egress_intfs)) if fields.egress_intfs else None

    matching_flow = Flow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=proto_str,
        sport=sport,
        dport=dport,
        ingress_intf=ingress_intf,
        egress_intf=egress_intf,
        established=fields.established,
        icmp_type=icmp_type,
    )

    # 7. Generate Near-Miss Flow (single most discriminating mutation)
    near_miss_flow: Optional[Flow] = None
    near_miss_reason = ""

    # Check 0: ICMP message type. For a rule that names one, the sharpest
    # near miss is the same packet carrying a different message: an echo
    # request is not caught by an echo-reply rule, however identical the
    # addresses are.
    if icmp_type is not None:
        other_type = 0 if icmp_type == 8 else 8
        near_miss_flow = Flow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=proto_str,
            sport=sport,
            dport=dport,
            ingress_intf=ingress_intf,
            egress_intf=egress_intf,
            established=fields.established,
            icmp_type=other_type,
        )
        near_miss_reason = (
            f"ICMP message type {other_type} instead of {icmp_type}")

    # Check 1: Destination Port constraint
    elif fields.dst_ports and fields.dst_ports.intervals and dport is not None:
        # Mutate port to one just outside the allowed intervals
        intervals = fields.dst_ports.intervals
        mutated_port: Optional[int] = None
        for lo, hi in intervals:
            if hi < 65535 and not fields.dst_ports.contains_port(hi + 1):
                mutated_port = hi + 1
                break
            if lo > 1 and not fields.dst_ports.contains_port(lo - 1):
                mutated_port = lo - 1
                break
        if mutated_port is None:
            mutated_port = 65534 if not fields.dst_ports.contains_port(65534) else 1

        if not fields.dst_ports.contains_port(mutated_port):
            near_miss_flow = Flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                proto=proto_str,
                sport=sport,
                dport=mutated_port,
                ingress_intf=ingress_intf,
                egress_intf=egress_intf,
                established=fields.established,
                icmp_type=icmp_type,
            )
            near_miss_reason = f"Destination port {mutated_port} outside allowed ports"

    # Check 2: Destination IP constraint (if not ANY)
    elif not all(c.is_any() for c in fields.dst_ips):
        outside_dst = _pick_outside_ip(fields.dst_ips[0])
        near_miss_flow = Flow(
            src_ip=src_ip,
            dst_ip=outside_dst,
            proto=proto_str,
            sport=sport,
            dport=dport,
            ingress_intf=ingress_intf,
            egress_intf=egress_intf,
            established=fields.established,
            icmp_type=icmp_type,
        )
        near_miss_reason = f"Destination IP {outside_dst} outside target network"

    # Check 3: Source IP constraint (if not ANY)
    elif not all(c.is_any() for c in fields.src_ips):
        outside_src = _pick_outside_ip(fields.src_ips[0])
        near_miss_flow = Flow(
            src_ip=outside_src,
            dst_ip=dst_ip,
            proto=proto_str,
            sport=sport,
            dport=dport,
            ingress_intf=ingress_intf,
            egress_intf=egress_intf,
            established=fields.established,
            icmp_type=icmp_type,
        )
        near_miss_reason = f"Source IP {outside_src} outside allowed source network"

    # Check 4: Protocol constraint
    elif fields.protos is not None:
        mutated_proto = "udp" if proto_num == 6 else "tcp"
        near_miss_flow = Flow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=mutated_proto,
            sport=sport,
            dport=dport,
            ingress_intf=ingress_intf,
            egress_intf=egress_intf,
            established=fields.established,
            icmp_type=icmp_type,
        )
        near_miss_reason = f"Protocol {mutated_proto} does not match allowed protocol ({proto_str})"

    # Check 5: Established flag
    elif fields.established:
        near_miss_flow = Flow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=proto_str,
            sport=sport,
            dport=dport,
            ingress_intf=ingress_intf,
            egress_intf=egress_intf,
            established=False,
        )
        near_miss_reason = "Connection is not established (SYN packet without ACK/RST)"

    else:
        # Rule matches ANY-ANY: no field is constrained, so there is nothing to
        # move just outside and no near-miss exists.
        near_miss_flow = None
        near_miss_reason = "Rule matches all traffic (no near-miss)"

    return RuleExample(
        rule_id=rule.id,
        rule_name=rule.name,
        action=rule.action,
        raw_text=rule.raw_text,
        # Flagged, not left for the reader to infer from the prose. Every field
        # of such a rule is ANY, so the generated flow is one arbitrary member
        # of "everything" — shown bare it reads as a claim about HTTPS, which
        # is exactly the wrong conclusion.
        matches_all=fields.is_any_any(),
        matching_flow=matching_flow,
        near_miss_flow=near_miss_flow,
        near_miss_reason=near_miss_reason,
    )


def generate_ruleset_examples(
    rules: Sequence[Rule],
    hint_addresses: Optional[Sequence[str]] = None,
) -> List[RuleExample]:
    """Generate examples for a sequence of rules."""
    return [generate_rule_example(r, hint_addresses) for r in rules]
