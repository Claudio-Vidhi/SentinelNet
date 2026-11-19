# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Passive OT protocol classification from flow, syslog, and mirror metadata.

Recognizes industrial control protocols without sending any active packets to PLCs:
- Modbus TCP (TCP 502)
- S7comm (TCP 102, ISO-on-TCP RFC 1006)
- EtherNet/IP (TCP 44818, UDP 2222)
- OPC-UA (TCP 4840)
- PROFINET (UDP 34962, 34963, 34964, EtherType 0x8892)
- BACnet (UDP 47808 / 0xBAC0)
- IEC 60870-5-104 (TCP 2404)
- DNP3 (TCP/UDP 20000)
"""
import re
from typing import Any, Dict, Optional, Tuple

OT_PROTOCOLS: Dict[str, Dict[str, Any]] = {
    "modbus_tcp": {
        "id": "modbus_tcp",
        "name": "Modbus TCP",
        "transports": ("TCP",),
        "ports": (502,),
    },
    "s7comm": {
        "id": "s7comm",
        "name": "S7comm",
        "transports": ("TCP",),
        "ports": (102,),
    },
    "ethernet_ip": {
        "id": "ethernet_ip",
        "name": "EtherNet/IP",
        "transports": ("TCP", "UDP"),
        "ports": (44818, 2222),
    },
    "opc_ua": {
        "id": "opc_ua",
        "name": "OPC-UA",
        "transports": ("TCP",),
        "ports": (4840,),
    },
    "profinet": {
        "id": "profinet",
        "name": "PROFINET",
        "transports": ("UDP", "L2"),
        "ports": (34962, 34963, 34964),
        "ethertypes": (0x8892,),
    },
    "bacnet": {
        "id": "bacnet",
        "name": "BACnet",
        "transports": ("UDP",),
        "ports": (47808,),
    },
    "iec_104": {
        "id": "iec_104",
        "name": "IEC 60870-5-104",
        "transports": ("TCP",),
        "ports": (2404,),
    },
    "dnp3": {
        "id": "dnp3",
        "name": "DNP3",
        "transports": ("TCP", "UDP"),
        "ports": (20000,),
    },
}

# (transport, port) -> protocol key
_PORT_INDEX: Dict[Tuple[str, int], str] = {
    ("TCP", 502): "modbus_tcp",
    ("TCP", 102): "s7comm",
    ("TCP", 44818): "ethernet_ip",
    ("UDP", 44818): "ethernet_ip",
    ("UDP", 2222): "ethernet_ip",
    ("TCP", 4840): "opc_ua",
    ("UDP", 34962): "profinet",
    ("UDP", 34963): "profinet",
    ("UDP", 34964): "profinet",
    ("TCP", 34962): "profinet",
    ("TCP", 34963): "profinet",
    ("TCP", 34964): "profinet",
    ("UDP", 47808): "bacnet",
    ("TCP", 2404): "iec_104",
    ("TCP", 20000): "dnp3",
    ("UDP", 20000): "dnp3",
}

# Port-only fallback when transport protocol is omitted in flow/syslog metadata
_ANY_PORT_INDEX: Dict[int, Tuple[str, str]] = {
    502: ("modbus_tcp", "TCP"),
    102: ("s7comm", "TCP"),
    44818: ("ethernet_ip", "TCP"),
    2222: ("ethernet_ip", "UDP"),
    4840: ("opc_ua", "TCP"),
    34962: ("profinet", "UDP"),
    34963: ("profinet", "UDP"),
    34964: ("profinet", "UDP"),
    47808: ("bacnet", "UDP"),
    2404: ("iec_104", "TCP"),
    20000: ("dnp3", "TCP"),
}

_ETHERTYPE_INDEX: Dict[int, str] = {
    0x8892: "profinet",
}

_KEYWORD_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bmodbus(?:[-_\s]?tcp)?\b", re.I), "modbus_tcp"),
    (re.compile(r"\bs7comm(?:[-_\s]?plus)?\b|\biso[-_\s]?on[-_\s]?tcp\b", re.I), "s7comm"),
    (re.compile(r"\bethernet/ip\b|\benip\b|\bcip\b", re.I), "ethernet_ip"),
    (re.compile(r"\bopc[-_\s]?ua\b|\bopcua\b", re.I), "opc_ua"),
    (re.compile(r"\bprofinet(?:[-_\s]?(?:rt|io|dcp|ptcp))?\b|\bpn[-_]?dcp\b|0x8892\b", re.I), "profinet"),
    (re.compile(r"\bbacnet(?:/ip)?\b", re.I), "bacnet"),
    (re.compile(r"\biec[-_\s]?(?:60870[-_\s]?5[-_\s]?)?104\b|\biec104\b", re.I), "iec_104"),
    (re.compile(r"\bdnp3\b", re.I), "dnp3"),
)

_PROTO_NUM = {"6": "TCP", "17": "UDP", "1": "ICMP"}


def _norm_transport(protocol: Optional[str]) -> Optional[str]:
    if not protocol:
        return None
    s = str(protocol).strip().upper()
    s = _PROTO_NUM.get(s, s)
    if s in ("TCP", "UDP"):
        return s
    if s.startswith("TCP/"):
        return "TCP"
    if s.startswith("UDP/"):
        return "UDP"
    return None


def _parse_int(val: Any) -> Optional[int]:
    if val is None or val == "":
        return None
    if isinstance(val, int):
        return val
    s = str(val).strip()
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    except (TypeError, ValueError):
        return None


def identify_ot_protocol(
    protocol: Optional[str] = None,
    src_port: Any = None,
    dst_port: Any = None,
    message: Optional[str] = None,
    ethertype: Any = None,
) -> Optional[dict]:
    """Passively classify an OT protocol from transport/port, EtherType, or
    syslog/mirror metadata text. Returns a dict
    ``{"id": ..., "name": ..., "transport": ..., "port": ...}`` or ``None``."""
    et = _parse_int(ethertype)
    if et is not None and et in _ETHERTYPE_INDEX:
        key = _ETHERTYPE_INDEX[et]
        meta = OT_PROTOCOLS[key]
        return {
            "id": meta["id"],
            "name": meta["name"],
            "transport": "L2",
            "port": None,
            "ethertype": f"0x{et:04x}",
        }

    trans = _norm_transport(protocol)
    dp = _parse_int(dst_port)
    sp = _parse_int(src_port)

    # Check destination port first (client -> PLC/server), then source port (PLC reply)
    for port in (dp, sp):
        if port is None:
            continue
        if trans:
            key = _PORT_INDEX.get((trans, port))
            if key:
                meta = OT_PROTOCOLS[key]
                return {
                    "id": meta["id"],
                    "name": meta["name"],
                    "transport": trans,
                    "port": port,
                }
        else:
            hit = _ANY_PORT_INDEX.get(port)
            if hit:
                key, default_trans = hit
                meta = OT_PROTOCOLS[key]
                return {
                    "id": meta["id"],
                    "name": meta["name"],
                    "transport": default_trans,
                    "port": port,
                }

    # Check service/protocol string or syslog/mirror text keywords
    for candidate in (protocol, message):
        if not candidate:
            continue
        text = str(candidate)
        for rx, key in _KEYWORD_PATTERNS:
            if rx.search(text):
                meta = OT_PROTOCOLS[key]
                default_port = meta["ports"][0] if meta.get("ports") else None
                return {
                    "id": meta["id"],
                    "name": meta["name"],
                    "transport": trans or meta["transports"][0],
                    "port": dp or sp or default_port,
                }

    return None


def tag_record(record: dict) -> dict:
    """Enrich a flow/syslog/mirror metadata dict with passive OT protocol tags
    (``ot_protocol`` and ``ot_protocol_name``) when matched."""
    out = dict(record)
    info = identify_ot_protocol(
        protocol=out.get("protocol") or out.get("proto") or out.get("service"),
        src_port=out.get("src_port") or out.get("srcport"),
        dst_port=out.get("dst_port") or out.get("dstport"),
        message=out.get("message") or out.get("raw"),
        ethertype=out.get("ethertype") or out.get("ether_type"),
    )
    if info:
        out["ot_protocol"] = info["id"]
        out["ot_protocol_name"] = info["name"]
    return out
