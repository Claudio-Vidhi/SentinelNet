# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Per-port facts for the map, read from a device backup: the configured mode
(access or trunk) and, when the backup carries 'show interfaces status', the
medium (copper, multimode or singlemode fibre, DAC) and the speed. The map
colours cables by them and flags an uplink that is not a trunk."""
import re

STATUS_TAG = "--- SHOW INTERFACES STATUS ---"
_STATUSES = {"connected", "notconnect", "disabled", "err-disabled", "inactive",
             "sfpabsent", "monitoring", "suspended", "xcvrabsen", "noxcvr"}
# Speed column: a-1000, 1000, 10G, a-10G, 25000...
_SPEED_COL = {"100": "100M", "1000": "1G", "10g": "10G", "10000": "10G", "25g": "25G",
              "25000": "25G", "40g": "40G", "40000": "40G", "100g": "100G", "100000": "100G"}
_PORT_SPEED = (("hu", "100G"), ("fo", "40G"), ("twe", "25G"), ("te", "10G"),
               ("gi", "1G"), ("fa", "100M"))
# Type column, e.g. "10/100/1000BaseTX", "1000BaseSX SFP", "SFP-10GBase-LR",
# "QSFP-40G-SR4", "SFP-H10GB-CU1M" (DAC), "Not Present".
_DAC = re.compile(r"CU\d|-CU|CX\d|TWINAX|DAC")
_COPPER = re.compile(r"BASE-?TX?(?![A-Z])|RJ45")
_MM = re.compile(r"BASE-?(SX|SR\d?|LRM)(?![A-Z])|-(SR\d?|SX|LRM)(?![A-Z])")
_SM = re.compile(r"BASE-?(LX|LR\d?|ER\d?|ZR|ZX|LH|BX|EX)|-(LX|LR\d?|ER\d?|ZR|ZX|LH|BX|EX)(?![A-Z])")


def classify(xcvr_type, speed="", port=""):
    """(medium, speed) of a port from the Type and Speed columns, the port
    name as the last resort for the speed. medium is 'copper', 'mm', 'sm',
    'dac', or None when nothing is plugged in or the type does not say."""
    t = (xcvr_type or "").upper()
    medium = ("dac" if _DAC.search(t) else "copper" if _COPPER.search(t)
              else "mm" if _MM.search(t) else "sm" if _SM.search(t) else None)
    s = (speed or "").lower()
    sp = _SPEED_COL.get(s[2:] if s.startswith("a-") else s)
    if not sp:
        m = re.search(r"(100|40|25|10)G", t)
        sp = f"{m.group(1)}G" if m else "1G" if "1000BASE" in t else "100M" if "100BASE" in t else None
    if not sp:
        p = (port or "").lower()
        sp = next((v for k, v in _PORT_SPEED if p.startswith(k)), None)
    return medium, sp


def parse_interfaces_status(content):
    """{normalized port: {"type", "speed"}} from 'show interfaces status'.
    The Name column may hold spaces, so a row is read from its status word."""
    from core.core_engine import _normalize_iface
    out, inside = {}, False
    for ln in (content or "").splitlines():
        s = ln.strip()
        if s == STATUS_TAG:
            inside = True
            continue
        if not inside:
            continue
        if s.startswith("--- ") or s.startswith("==="):
            break
        toks = s.split()
        i = next((k for k, tok in enumerate(toks[1:], 1) if tok.lower() in _STATUSES), None)
        # Status, Vlan, Duplex, Speed, then Type (may have spaces: "Not Present").
        if i is None or len(toks) < i + 5:
            continue
        out[_normalize_iface(toks[0])] = {"speed": toks[i + 3], "type": " ".join(toks[i + 4:])}
    return out


def port_facts(content):
    """{normalized port: {"mode", "medium", "speed"}} for one backup."""
    from ai import config_analyzer
    from core.core_engine import _normalize_iface
    facts = {}
    for header, body in config_analyzer._iter_blocks(config_analyzer.running_config(content)):
        if header.lower().startswith("interface "):
            iface = config_analyzer._parse_interface(header, body)
            if iface["mode"] in ("access", "trunk"):
                facts[_normalize_iface(iface["name"])] = {"mode": iface["mode"]}
    for port, row in parse_interfaces_status(content).items():
        medium, speed = classify(row["type"], row["speed"], port)
        f = facts.setdefault(port, {})
        if medium:
            f["medium"] = medium
        if speed:
            f["speed"] = speed
    return facts
