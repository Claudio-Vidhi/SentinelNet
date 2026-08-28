# -*- coding: utf-8 -*-
"""Data models and matching primitives for Policy & Route Validation.

Pure model with zero I/O. Represents IP fields as ternary cubes (value, mask),
ports as closed integer intervals (lo, hi), protocols as sets of protocol
numbers, and interfaces/zones as sets of names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union


def ip_to_int(ip: str) -> int:
    """Convert an IPv4 address string to a 32-bit unsigned integer."""
    try:
        return int(ipaddress.IPv4Address(ip.strip()))
    except Exception as exc:
        raise ValueError(f"Invalid IPv4 address: {ip}") from exc


def int_to_ip(val: int) -> str:
    """Convert a 32-bit unsigned integer to an IPv4 address string."""
    return str(ipaddress.IPv4Address(val & 0xFFFFFFFF))


def mask_to_prefix_len(mask: int) -> Optional[int]:
    """Return prefix length if mask is contiguous from MSB, else None."""
    mask = mask & 0xFFFFFFFF
    if mask == 0:
        return 0
    # Check if inverted mask + 1 is a power of 2
    inv = (~mask) & 0xFFFFFFFF
    if ((inv + 1) & inv) == 0:
        # Count leading 1s
        bits = bin(mask).count('1')
        if mask == ((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF):
            return bits
    return None


@dataclass(frozen=True)
class Cube:
    """Ternary cube representing an IPv4 subnet or wildcard pattern.

    value: 32-bit int, non-masked bits are 0.
    mask: 32-bit int, 1 = significant bit (must match value), 0 = wildcard bit (don't care).
    """
    value: int
    mask: int

    def __post_init__(self) -> None:
        object.__setattr__(self, 'value', (self.value & self.mask) & 0xFFFFFFFF)
        object.__setattr__(self, 'mask', self.mask & 0xFFFFFFFF)

    def contains_ip(self, ip: int) -> bool:
        """Check if an IPv4 address (as int) matches this cube."""
        return ((ip & self.mask) ^ self.value) == 0

    def contains_cube(self, other: Cube) -> bool:
        """Check if this cube is a superset of or equal to other."""
        # self.mask must be a subset of other.mask (meaning self specifies fewer or same constraints)
        # and on self's significant bits, values must agree.
        if (self.mask & other.mask) != self.mask:
            return False
        return ((self.value ^ other.value) & self.mask) == 0

    def intersects(self, other: Cube) -> bool:
        """Check if this cube and other have at least one common IP."""
        common_mask = self.mask & other.mask
        return ((self.value ^ other.value) & common_mask) == 0

    def is_any(self) -> bool:
        return self.mask == 0

    def is_exact(self) -> bool:
        return self.mask == 0xFFFFFFFF

    @classmethod
    def from_ip(cls, ip: str) -> Cube:
        return cls(ip_to_int(ip), 0xFFFFFFFF)

    @classmethod
    def from_cidr(cls, ip: str, prefix: int) -> Cube:
        if prefix < 0 or prefix > 32:
            raise ValueError(f"Invalid prefix length: {prefix}")
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix > 0 else 0
        val = ip_to_int(ip) & mask
        return cls(val, mask)

    @classmethod
    def from_netmask(cls, ip: str, netmask: str) -> Cube:
        mask = ip_to_int(netmask)
        val = ip_to_int(ip) & mask
        return cls(val, mask)

    @classmethod
    def from_wildcard(cls, ip: str, wildcard: str) -> Cube:
        wildcard_int = ip_to_int(wildcard)
        mask = (~wildcard_int) & 0xFFFFFFFF
        val = ip_to_int(ip) & mask
        return cls(val, mask)

    @classmethod
    def any(cls) -> Cube:
        return cls(0, 0)


@dataclass(frozen=True)
class PortSet:
    """A collection of closed port intervals [(lo, hi), ...] with 0 <= lo <= hi <= 65535."""
    intervals: Tuple[Tuple[int, int], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.intervals, tuple):
            norm = self._normalize(self.intervals)
            object.__setattr__(self, 'intervals', norm)

    @staticmethod
    def _normalize(intervals: Iterable[Tuple[int, int]]) -> Tuple[Tuple[int, int], ...]:
        cleaned = []
        for lo, hi in intervals:
            lo = max(0, min(65535, int(lo)))
            hi = max(0, min(65535, int(hi)))
            if lo > hi:
                lo, hi = hi, lo
            cleaned.append((lo, hi))
        if not cleaned:
            return ()
        cleaned.sort(key=lambda x: (x[0], x[1]))
        merged = [cleaned[0]]
        for cur_lo, cur_hi in cleaned[1:]:
            prev_lo, prev_hi = merged[-1]
            if cur_lo <= prev_hi + 1:
                merged[-1] = (prev_lo, max(prev_hi, cur_hi))
            else:
                merged.append((cur_lo, cur_hi))
        return tuple(merged)

    def contains_port(self, port: int) -> bool:
        for lo, hi in self.intervals:
            if lo <= port <= hi:
                return True
        return False

    def contains_portset(self, other: PortSet) -> bool:
        """Check if self is a superset of other."""
        for o_lo, o_hi in other.intervals:
            # o_lo..o_hi must be completely covered by self.intervals
            # Since self.intervals is disjoint and merged, exactly one interval must cover it
            covered = any(s_lo <= o_lo and o_hi <= s_hi for s_lo, s_hi in self.intervals)
            if not covered:
                return False
        return True

    def intersects(self, other: PortSet) -> bool:
        for s_lo, s_hi in self.intervals:
            for o_lo, o_hi in other.intervals:
                if max(s_lo, o_lo) <= min(s_hi, o_hi):
                    return True
        return False

    def is_any(self) -> bool:
        return len(self.intervals) == 1 and self.intervals[0][0] <= 1 and self.intervals[0][1] == 65535

    @classmethod
    def from_list(cls, intervals: Iterable[Tuple[int, int]]) -> PortSet:
        return cls(cls._normalize(intervals))

    @classmethod
    def from_op(cls, op: str, val1: int, val2: Optional[int] = None) -> PortSet:
        op = op.lower()
        if op == "eq":
            return cls.from_list([(val1, val1)])
        elif op == "gt":
            return cls.from_list([(val1 + 1, 65535)])
        elif op == "lt":
            return cls.from_list([(1, max(1, val1 - 1))])
        elif op == "range":
            v2 = val2 if val2 is not None else val1
            return cls.from_list([(min(val1, v2), max(val1, v2))])
        elif op == "neq":
            res = []
            if val1 > 1:
                res.append((1, val1 - 1))
            if val1 < 65535:
                res.append((val1 + 1, 65535))
            return cls.from_list(res)
        return cls.any()

    @classmethod
    def any(cls) -> PortSet:
        return cls(((0, 65535),))


# Protocol name to integer mappings
_PROTO_MAP: Dict[str, Optional[int]] = {
    "ip": None,
    "ipv4": None,
    "ip4": None,
    "any": None,
    "all": None,
    "icmp": 1,
    "igmp": 2,
    "tcp": 6,
    "udp": 17,
    "gre": 47,
    "esp": 50,
    "ah": 51,
    "eigrp": 88,
    "ospf": 89,
    "pim": 103,
    "sctp": 132,
}

_PROTO_NUM_TO_NAME: Dict[int, str] = {
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


def proto_from_name(name_or_num: Union[str, int, None]) -> Optional[int]:
    """Parse a protocol name or number. Returns int protocol number, or None for ANY."""
    if name_or_num is None:
        return None
    if isinstance(name_or_num, int):
        return name_or_num
    s = str(name_or_num).strip().lower()
    if s in _PROTO_MAP:
        return _PROTO_MAP[s]
    if s.isdigit():
        return int(s)
    return None


@dataclass
class Flow:
    """A packet flow to trace through the policy and route chain."""
    src_ip: str
    dst_ip: str
    proto: str = "tcp"
    sport: Optional[int] = None
    dport: Optional[int] = None
    ingress_intf: Optional[str] = None
    egress_intf: Optional[str] = None
    tcp_flags: Optional[str] = None
    established: bool = False
    # ICMP message type. An echo request (8) and an echo reply (0) are
    # different packets, and an ACE naming one does not catch the other.
    icmp_type: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "proto": self.proto,
            "sport": self.sport,
            "dport": self.dport,
            "ingress_intf": self.ingress_intf,
            "egress_intf": self.egress_intf,
            "tcp_flags": self.tcp_flags,
            "established": self.established,
            "icmp_type": self.icmp_type,
        }


@dataclass
class FieldSet:
    """Multidimensional packet domain for an ACE or firewall rule."""
    src_ips: List[Cube] = field(default_factory=lambda: [Cube.any()])
    dst_ips: List[Cube] = field(default_factory=lambda: [Cube.any()])
    src_ports: Optional[PortSet] = None  # None = ANY
    dst_ports: Optional[PortSet] = None  # None = ANY
    protos: Optional[Set[int]] = None  # None = ANY
    ingress_intfs: Optional[Set[str]] = None  # None = ANY
    egress_intfs: Optional[Set[str]] = None  # None = ANY
    established: bool = False
    opaque: bool = False  # True for unparseable rules that match nothing
    icmp_types: Optional[Set[int]] = None  # None = ANY ICMP message type
    # Qualifiers the ACE carries that this model does not evaluate — dscp,
    # tos, precedence, fragments, time-range, TCP flag bits. Every one of them
    # NARROWS the rule on the device, so a FieldSet carrying any of them is
    # wider here than the real rule is. It may therefore never be used to
    # claim it covers another rule: dropping 'echo-reply' off an ACE is what
    # made an ICMP echo rule look shadowed by a reply rule it can never catch.
    narrowing_quals: Tuple[str, ...] = ()

    def is_any_any(self) -> bool:
        """Check if rule matches any source, any destination, any service and any interface.

        The interface test is not optional. A FortiOS policy scoped
        ``srcintf port1 / dstintf port2`` with all/all/ALL is the ordinary
        shape of a LAN-to-WAN rule, not a wide-open one; flagging it any_any
        also made it a covering rule, so every policy after it was reported
        unreachable. Three correctly scoped policies produced three findings,
        all false.
        """
        if self.opaque:
            return False
        src_any = all(c.is_any() for c in self.src_ips)
        dst_any = all(c.is_any() for c in self.dst_ips)
        sport_any = self.src_ports is None or self.src_ports.is_any()
        dport_any = self.dst_ports is None or self.dst_ports.is_any()
        proto_any = self.protos is None and self.icmp_types is None
        intf_any = self.ingress_intfs is None and self.egress_intfs is None
        return (src_any and dst_any and sport_any and dport_any and proto_any
                and intf_any and not self.established and not self.narrowing_quals)

    def contains(self, other: FieldSet) -> bool:
        """Superset containment test: returns True if self fully covers other."""
        # ponytail: single-rule superset check. Multi-rule subtraction requires BDD.
        if self.opaque or other.opaque:
            return False

        # A rule carrying a qualifier this model ignores is narrower on the
        # device than it is here, so it cannot be trusted to cover anything.
        # Only self's qualifiers matter: if OTHER is narrower than modelled,
        # covering the modelled version still covers the real one.
        if self.narrowing_quals:
            return False

        # Established: if self requires established, it cannot cover non-established other
        if self.established and not other.established:
            return False

        # Protocols
        if self.protos is not None:
            if other.protos is None:
                return False
            if not other.protos.issubset(self.protos):
                return False

        # ICMP message types
        if self.icmp_types is not None:
            if other.icmp_types is None:
                return False
            if not other.icmp_types.issubset(self.icmp_types):
                return False

        # Source IPs: every cube in other must be contained in at least one cube in self
        for o_cube in other.src_ips:
            if not any(s_cube.contains_cube(o_cube) for s_cube in self.src_ips):
                return False

        # Destination IPs
        for o_cube in other.dst_ips:
            if not any(s_cube.contains_cube(o_cube) for s_cube in self.dst_ips):
                return False

        # Source ports
        if self.src_ports is not None:
            if other.src_ports is None:
                return False
            if not self.src_ports.contains_portset(other.src_ports):
                return False

        # Destination ports
        if self.dst_ports is not None:
            if other.dst_ports is None:
                return False
            if not self.dst_ports.contains_portset(other.dst_ports):
                return False

        # Ingress interfaces
        if self.ingress_intfs is not None:
            if other.ingress_intfs is None:
                return False
            s_low = {i.lower() for i in self.ingress_intfs}
            o_low = {i.lower() for i in other.ingress_intfs}
            if not o_low.issubset(s_low):
                return False

        # Egress interfaces
        if self.egress_intfs is not None:
            if other.egress_intfs is None:
                return False
            s_low = {i.lower() for i in self.egress_intfs}
            o_low = {i.lower() for i in other.egress_intfs}
            if not o_low.issubset(s_low):
                return False

        return True

    def intersects(self, other: FieldSet) -> bool:
        """Check if self and other have any common packet in their domain."""
        if self.opaque or other.opaque:
            return False

        # Protocols
        if self.protos is not None and other.protos is not None:
            if not (self.protos & other.protos):
                return False

        # ICMP message types
        if self.icmp_types is not None and other.icmp_types is not None:
            if not (self.icmp_types & other.icmp_types):
                return False

        # Source IPs: any cube in self must intersect any cube in other
        src_match = any(s.intersects(o) for s in self.src_ips for o in other.src_ips)
        if not src_match:
            return False

        # Destination IPs
        dst_match = any(s.intersects(o) for s in self.dst_ips for o in other.dst_ips)
        if not dst_match:
            return False

        # Source ports
        if self.src_ports is not None and other.src_ports is not None:
            if not self.src_ports.intersects(other.src_ports):
                return False

        # Destination ports
        if self.dst_ports is not None and other.dst_ports is not None:
            if not self.dst_ports.intersects(other.dst_ports):
                return False

        # Ingress interfaces
        if self.ingress_intfs is not None and other.ingress_intfs is not None:
            s_low = {i.lower() for i in self.ingress_intfs}
            o_low = {i.lower() for i in other.ingress_intfs}
            if not (s_low & o_low):
                return False

        # Egress interfaces
        if self.egress_intfs is not None and other.egress_intfs is not None:
            s_low = {i.lower() for i in self.egress_intfs}
            o_low = {i.lower() for i in other.egress_intfs}
            if not (s_low & o_low):
                return False

        return True

    def matches(self, flow: Flow) -> bool:
        """Check if a flow DEFINITELY matches this field set.

        An opaque rule can never match definitely: at least one of its
        dimensions could not be resolved from the backup, so no confident
        answer is available. Use ``may_match`` to ask whether it could.
        """
        if self.opaque:
            return False
        return self._match_known_dimensions(flow)

    def may_match(self, flow: Flow) -> bool:
        """Check if a flow COULD match, treating unresolved dimensions as ANY.

        For a fully resolved rule this is exactly ``matches``. For an opaque
        one it answers the only honest question available: the dimensions that
        were parsed are tested normally, and the ones that could not be are
        already widened to ANY by the vendor front end, so they cannot exclude
        the flow. True here means "we cannot tell" — the caller must stop and
        report UNKNOWN rather than walk past the rule.

        Skipping an opaque rule instead is what let an unresolvable *deny* be
        bypassed so the next permit could answer with full confidence.
        """
        return self._match_known_dimensions(flow)

    def _match_known_dimensions(self, flow: Flow) -> bool:
        # Established flag
        if self.established:
            if not (flow.established or (flow.tcp_flags and "established" in flow.tcp_flags.lower())):
                return False

        # Protocol
        flow_pnum = proto_from_name(flow.proto)
        if self.protos is not None:
            if flow_pnum is not None and flow_pnum not in self.protos:
                return False

        # ICMP message type. Unset on the flow means the caller did not say
        # which ICMP message this is, so the dimension cannot exclude it.
        if self.icmp_types is not None and flow.icmp_type is not None:
            if flow.icmp_type not in self.icmp_types:
                return False

        # Source IP
        try:
            s_ip = ip_to_int(flow.src_ip)
            if not any(c.contains_ip(s_ip) for c in self.src_ips):
                return False
        except Exception:
            return False

        # Destination IP
        try:
            d_ip = ip_to_int(flow.dst_ip)
            if not any(c.contains_ip(d_ip) for c in self.dst_ips):
                return False
        except Exception:
            return False

        # Source port
        if self.src_ports is not None and flow.sport is not None:
            if not self.src_ports.contains_port(flow.sport):
                return False

        # Destination port
        if self.dst_ports is not None and flow.dport is not None:
            if not self.dst_ports.contains_port(flow.dport):
                return False

        # Ingress interface
        if self.ingress_intfs is not None and flow.ingress_intf is not None:
            s_low = {i.lower() for i in self.ingress_intfs}
            if flow.ingress_intf.lower() not in s_low:
                return False

        # Egress interface
        if self.egress_intfs is not None and flow.egress_intf is not None:
            s_low = {i.lower() for i in self.egress_intfs}
            if flow.egress_intf.lower() not in s_low:
                return False

        return True


@dataclass
class Rule:
    """Single ACE or firewall policy rule."""
    id: str
    name: str = ""
    action: str = "permit"  # permit | deny | unknown
    fields: FieldSet = field(default_factory=FieldSet)
    disabled: bool = False
    raw_text: str = ""
    line_no: Optional[int] = None
    nat_enabled: bool = False
    unresolved: List[str] = field(default_factory=list)


@dataclass
class RuleSet:
    """Ordered collection of rules with a default action."""
    name: str
    kind: str = "acl"  # acl | firewall_policy
    rules: List[Rule] = field(default_factory=list)
    default_action: str = "deny"
    unresolved: List[str] = field(default_factory=list)


@dataclass
class Route:
    """Static or connected route entry."""
    prefix: str
    prefix_cube: Cube
    next_hop: Optional[str] = None
    interface: str = ""
    source: str = "static"  # connected | static | manual
    distance: int = 1
    metric: int = 0


@dataclass
class RouteTable:
    """Collection of routes supporting longest-prefix match."""
    routes: List[Route] = field(default_factory=list)
    dynamic_routing_present: bool = False
    protocols: List[str] = field(default_factory=list)

    def lookup(self, dst_ip: str) -> Optional[Route]:
        """Perform longest-prefix match for dst_ip."""
        try:
            ip_val = ip_to_int(dst_ip)
        except Exception:
            return None

        best_match: Optional[Route] = None
        best_prefix_len = -1

        for r in self.routes:
            if r.prefix_cube.contains_ip(ip_val):
                p_len = mask_to_prefix_len(r.prefix_cube.mask) or 0
                if p_len > best_prefix_len:
                    best_prefix_len = p_len
                    best_match = r
                elif p_len == best_prefix_len and best_match is not None:
                    # Prefer connected over static, then lower distance
                    if r.source == "connected" and best_match.source != "connected":
                        best_match = r
                    elif r.distance < best_match.distance:
                        best_match = r

        return best_match

    def connected_subnets(self) -> List[Route]:
        return [r for r in self.routes if r.source == "connected"]


@dataclass
class Step:
    """Single evaluation step in the trace chain."""
    kind: str  # acl_in | route | acl_out | policy | skipped_policy | note
    acl: Optional[str] = None
    matched: Optional[str] = None
    action: str = "permit"  # permit | deny | unknown | skip
    rule_id: Optional[str] = None
    raw_text: Optional[str] = None
    prefix: Optional[str] = None
    next_hop: Optional[str] = None
    egress: Optional[str] = None
    source: Optional[str] = None
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"kind": self.kind, "action": self.action}
        if self.acl is not None:
            out["acl"] = self.acl
        if self.matched is not None:
            out["matched"] = self.matched
        if self.rule_id is not None:
            out["rule_id"] = self.rule_id
        if self.raw_text is not None:
            out["raw_text"] = self.raw_text
        if self.prefix is not None:
            out["prefix"] = self.prefix
        if self.next_hop is not None:
            out["next_hop"] = self.next_hop
        if self.egress is not None:
            out["egress"] = self.egress
        if self.source is not None:
            out["source"] = self.source
        if self.note is not None:
            out["note"] = self.note
        return out


@dataclass
class Trace:
    """Full path verdict and evaluation steps."""
    verdict: str  # PERMIT | DENY | UNKNOWN
    steps: List[Step] = field(default_factory=list)
    implicit_deny: bool = False
    dynamic_routing_present: bool = False
    unresolved: List[str] = field(default_factory=list)
    nat_applied: bool = False
    flow: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        # The same reason reaches the trace twice when a rule's unresolved list
        # is also carried on the environment. Repeating it in the UI reads as
        # two separate problems.
        seen: Set[str] = set()
        deduped: List[str] = []
        for item in self.unresolved:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        self.unresolved = deduped

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "steps": [s.to_dict() for s in self.steps],
            "implicit_deny": self.implicit_deny,
            "dynamic_routing_present": self.dynamic_routing_present,
            "unresolved": self.unresolved,
            "nat_applied": self.nat_applied,
            "flow": self.flow,
        }


@dataclass
class Finding:
    """Static finding on an ACL or policy configuration."""
    key: str  # shadowed | unreachable | any_any | route_to_nowhere | unresolved_object
    severity: str = "medium"  # high | medium | low | info
    rule_id: Optional[str] = None
    acl_name: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    message_key: str = ""
    # A packet that demonstrates the finding instead of asserting it. For a
    # shadowed rule it is a flow the rule was written to catch; tracing it
    # lands on the earlier rule, which is the whole claim made checkable.
    # None where the defect is not about packet coverage.
    witness: Optional[Dict[str, Any]] = None
    # What tracing the witness must show for the finding to hold.
    expected_rule_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "severity": self.severity,
            "witness": self.witness,
            "expected_rule_id": self.expected_rule_id,
            "rule_id": self.rule_id,
            "acl_name": self.acl_name,
            "params": self.params,
            "message_key": self.message_key or f"finding.{self.key}",
        }
