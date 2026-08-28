# -*- coding: utf-8 -*-
"""Config Analyzer — analysis of the Cisco IOS/IOS-XE running-configs collected
as backups, to extract a structured view (VLAN, Routing/VPN, ACL, Interfaces) +
cross-validation of objects (unused ACLs/VLANs, missing references).

The module is deliberately tolerant: it must NEVER raise exceptions on strange
or partial configs. The central function ``analyze_config`` is pure (no I/O)
and is therefore easily testable; ``analyze_device``/``analyze_all`` add
reading of the freshest backup and scoping by site/tenant.
"""

import functools
import os
import re
from typing import Any, Dict, List, Optional

# Firewall parsing primitives and IP utilities: now live in the fw_analyzers
# package (per-vendor analyzers). Re-imported here for the converters and for
# analyze_fortios_config, without duplication.
from fw_analyzers._ip import _mask_to_prefix, _ip_addr_to_cidr
from fw_analyzers.fortios import (
    _forti_tokens, _forti_tree, _forti_get, _forti_set1, _forti_ip_cidr,
)
from fw_analyzers.panos import (
    _panos_tokens, _panos_lines, _panos_collect, _panos_attr, _panos_attr_all,
)

# --- Low-level utilities ----------------------------------------------

def _expand_vlan_list(spec):
    """Expands '10,20,30-35' into ['10','20','30','31',...]. Tolerant."""
    out = []
    if not spec:
        return out
    for chunk in spec.replace(' ', '').split(','):
        if not chunk:
            continue
        if '-' in chunk:
            try:
                a, b = chunk.split('-', 1)
                a, b = int(a), int(b)
                if a <= b and (b - a) < 5000:
                    out.extend(str(x) for x in range(a, b + 1))
            except Exception:
                continue
        else:
            if chunk.isdigit():
                out.append(chunk)
    return out


def running_config(content):
    """Returns only the 'running-config' part of the backup, cutting off the
    appended sections (=== ... === and --- SHOW ... ---)."""
    lines = []
    for ln in (content or '').splitlines():
        s = ln.strip()
        if s.startswith('===') or s.startswith('--- SHOW'):
            break
        lines.append(ln)
    return lines


_SHOW_VLAN_ROW = re.compile(r'^(\d{1,4})\s+(\S+)\s+(?:active|act/\S+|suspended|sus/\S+)', re.I)

def parse_show_vlan(content):
    """VLANs learned via VTP from the '--- SHOW VLAN ---' section appended to
    the backup: {vlan_id: name}. On access switches VLANs are defined on the
    VTP server, not in the local running-config: without this section they
    would be falsely reported as 'undefined'."""
    out = {}
    m = re.search(r'--- SHOW VLAN ---\s*\n(.*?)(?=\n--- [A-Z]|\n===|\Z)',
                  content or '', re.DOTALL | re.IGNORECASE)
    if not m:
        return out
    for ln in m.group(1).splitlines():
        row = _SHOW_VLAN_ROW.match(ln.strip())
        if row:
            out[row.group(1)] = row.group(2)
    return out


def parse_vtp_status(content):
    """Extracts mode/domain from the '--- SHOW VTP STATUS ---' section appended
    to the backup. Returns {"mode": "server", "domain": "OLITALIA-VTP-DOM"}
    (mode lowercased); empty strings if the section or individual lines are
    missing."""
    out = {"mode": "", "domain": ""}
    m = re.search(r'--- SHOW VTP STATUS ---\s*\n(.*?)(?=\n--- [A-Z]|\n===|\Z)',
                  content or '', re.DOTALL | re.IGNORECASE)
    if not m:
        return out
    section = m.group(1)
    mm = re.search(r'VTP Operating Mode\s*:\s*(\S+)', section, re.IGNORECASE)
    if mm:
        out["mode"] = mm.group(1).strip().lower()
    md = re.search(r'VTP Domain Name\s*:\s*(\S+)', section, re.IGNORECASE)
    if md:
        out["domain"] = md.group(1).strip()
    return out


def _iter_blocks(lines):
    """Iterates the top-level blocks of the config. A block starts on a line at
    column 0 (not '!', not empty) and continues with the following indented
    lines. Yields (header, [body_lines])."""
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped == '!' or raw[:1] in (' ', '\t'):
            i += 1
            continue
        header = raw.rstrip()
        body = []
        i += 1
        while i < n:
            nxt = lines[i]
            if nxt[:1] in (' ', '\t') and nxt.strip() and nxt.strip() != '!':
                body.append(nxt.rstrip())
                i += 1
            else:
                break
        yield header, body


# --- Parsing of individual objects -------------------------------------------

def _parse_interface(header, body):
    """Extracts the fields of an 'interface X' block."""
    name = header.split(None, 1)[1].strip() if len(header.split(None, 1)) > 1 else ''
    iface = {
        "name": name, "description": "", "mode": "", "access_vlan": "",
        "voice_vlan": "", "trunk_allowed": "", "trunk_native": "", "ip": "",
        "acl_in": "", "acl_out": "", "shutdown": False, "channel_group": "",
        "raw": "\n".join([header] + body),
    }
    has_switchport = False
    sw_mode = ""
    ip_secondary_only = False
    for b in body:
        s = b.strip()
        low = s.lower()
        if low.startswith('description '):
            iface["description"] = s[12:].strip()
        elif low.startswith('switchport access vlan '):
            has_switchport = True
            iface["access_vlan"] = s.split()[-1]
        elif low.startswith('switchport voice vlan '):
            has_switchport = True
            iface["voice_vlan"] = s.split()[-1]
        elif low.startswith('switchport trunk allowed vlan '):
            has_switchport = True
            val = s.split('vlan', 1)[1].strip()
            # 'add' on continuation lines
            val = val.replace('add ', '').strip()
            iface["trunk_allowed"] = (iface["trunk_allowed"] + ',' + val).strip(',') if iface["trunk_allowed"] else val
        elif low.startswith('switchport trunk native vlan '):
            has_switchport = True
            iface["trunk_native"] = s.split()[-1]
        elif low.startswith('switchport mode '):
            has_switchport = True
            sw_mode = s.split()[-1]
        elif low == 'switchport' or low.startswith('switchport '):
            has_switchport = True
        elif low.startswith('ip address ') or low.startswith('ipv4 address '):
            toks = s.split()
            # ip address A.B.C.D MASK [secondary]
            if 'secondary' in low:
                ip_secondary_only = True if not iface["ip"] else ip_secondary_only
            else:
                cidr = _ip_addr_to_cidr(toks[2:4])
                if cidr:
                    iface["ip"] = cidr
        elif low.startswith('ip access-group '):
            toks = s.split()
            if len(toks) >= 4:
                if toks[-1] == 'in':
                    iface["acl_in"] = toks[2]
                elif toks[-1] == 'out':
                    iface["acl_out"] = toks[2]
        elif low == 'shutdown':
            iface["shutdown"] = True
        elif low.startswith('channel-group '):
            iface["channel_group"] = s.split()[1] if len(s.split()) > 1 else ''
    # Mode determination
    nm = name.lower()
    if nm.startswith('vlan'):
        iface["mode"] = "svi"
    elif sw_mode == 'trunk' or (iface["trunk_allowed"] or iface["trunk_native"]):
        iface["mode"] = "trunk"
    elif sw_mode == 'access' or iface["access_vlan"] or iface["voice_vlan"]:
        iface["mode"] = "access"
    elif iface["ip"]:
        iface["mode"] = "routed"
    elif has_switchport:
        iface["mode"] = "access"
    elif iface["shutdown"]:
        iface["mode"] = "shutdown-only"
    else:
        iface["mode"] = ""
    return iface


def _parse_static_route(line):
    """Parses an 'ip route ...' line. Returns dict or None."""
    toks = line.split()
    # toks[0]=ip toks[1]=route
    rest = toks[2:]
    vrf = ""
    if rest[:1] == ['vrf'] and len(rest) >= 2:
        vrf = rest[1]
        rest = rest[2:]
    if len(rest) < 3:
        return None
    net, mask, nexthop = rest[0], rest[1], rest[2]
    pfx = _mask_to_prefix(mask)
    prefix = f"{net}/{pfx}" if pfx is not None else f"{net} {mask}"
    tail = rest[3:]
    name = ""
    ad = None
    if 'name' in tail:
        idx = tail.index('name')
        name = ' '.join(tail[idx + 1:]).strip()
        tail = tail[:idx]
    for t in tail:
        if t.isdigit():
            ad = t
            break
    return {"prefix": prefix, "next_hop": nexthop, "ad": ad, "name": name, "vrf": vrf,
             "raw_lines": [line]}


def _parse_router_block(header, body):
    """router ospf|eigrp|bgp|rip <id>."""
    toks = header.split()
    proto = toks[1] if len(toks) > 1 else ""
    rid = toks[2] if len(toks) > 2 else ""
    details = []
    dist_refs = []  # (acl, direction)
    for b in body:
        s = b.strip()
        low = s.lower()
        if low.startswith(('network ', 'neighbor ', 'redistribute ', 'distribute-list ')):
            details.append(s)
        if low.startswith('distribute-list '):
            m = re.match(r'distribute-list\s+(?:prefix\s+)?(\S+)\s+(in|out)', low)
            if m:
                dist_refs.append((m.group(1), m.group(2)))
    return {
        "proto": proto, "id": rid, "details": details,
        "raw": "\n".join([header] + body),
    }, dist_refs


# --- Main analysis (pure, testable) ----------------------------------

def policy_findings(content, config_type='ios'):
    """Shadowed / unreachable / any-any / route defects for a config.

    Delegates to the ``services.policy_test`` engine instead of growing a
    second overlap analysis here: the Policy & Routing tab answers exactly
    this question, and two implementations of rule containment would drift
    apart on the first wildcard nobody thought about.

    Tolerant like the rest of this module: a parse failure yields no findings
    rather than an exception, because a validation extra must never take down
    an analysis that works without it.
    """
    try:
        from services.policy_test import findings as pt_findings
        if config_type == 'fortios':
            from services.policy_test.fortios import parse_fortios_config
            env = parse_fortios_config(content)
        else:
            from services.policy_test.ios import parse_ios_config
            env = parse_ios_config(content)
        return [f.to_dict() for f in pt_findings.analyze_policy_findings(env)]
    except Exception:
        return []


def analyze_config(content):
    """Analyzes the text of a running-config and returns the contract structure
    (without the ip/hostname/tenant meta fields, added downstream)."""
    lines = running_config(content)

    interfaces = []
    svis = {}            # vlan_id -> {"ip","shutdown"}
    vlan_defs = {}       # vlan_id -> name
    static_routes = []
    protocols = []
    vrfs = {}            # name -> {"name","rd","interfaces"[]}
    acls = {}            # name -> {"name","kind","entries"[]}
    acl_refs = []        # {"name","where","target","direction","context","routing"}
    vpn = []

    access_use = {}      # vlan_id -> "IFACE (access)" (for undefined)
    used_vlans = set()

    for header, body in _iter_blocks(lines):
        low = header.lower()

        # --- Interfaces ---
        if low.startswith('interface '):
            iface = _parse_interface(header, body)
            interfaces.append(iface)
            nm = iface["name"]
            nml = nm.lower()
            # SVI
            if nml.startswith('vlan'):
                vid = nm[4:] if nm[:4].lower() == 'vlan' else ''
                vid = vid.strip()
                if vid.isdigit():
                    svis[vid] = {"ip": iface["ip"], "shutdown": iface["shutdown"]}
                    used_vlans.add(vid)
            # VLAN usage
            if iface["access_vlan"]:
                used_vlans.add(iface["access_vlan"])
                access_use.setdefault(iface["access_vlan"], f"{nm} (access)")
            if iface["voice_vlan"]:
                used_vlans.add(iface["voice_vlan"])
                access_use.setdefault(iface["voice_vlan"], f"{nm} (voice)")
            for v in _expand_vlan_list(iface["trunk_allowed"]):
                used_vlans.add(v)
            # ACL references on interface
            if iface["acl_in"]:
                acl_refs.append({"name": iface["acl_in"], "where": "interface",
                                 "target": nm, "direction": "in",
                                 "context": f"interface {nm} (in)", "routing": False})
            if iface["acl_out"]:
                acl_refs.append({"name": iface["acl_out"], "where": "interface",
                                 "target": nm, "direction": "out",
                                 "context": f"interface {nm} (out)", "routing": False})
            # VRF forwarding on interface
            for b in body:
                s = b.strip().lower()
                m = re.match(r'(?:ip\s+)?vrf forwarding (\S+)', s)
                if m:
                    vname = b.strip().split()[-1]
                    vrfs.setdefault(vname, {"name": vname, "rd": "", "interfaces": []})
                    vrfs[vname]["interfaces"].append(nm)
            # Tunnel -> VPN
            if nml.startswith('tunnel'):
                vpn.append({"kind": "tunnel", "name": nm,
                            "raw": "\n".join([header] + body)})
            continue

        # --- VLAN definitions ---
        m = re.match(r'vlan (\d[\d,\-]*)\s*$', low)
        if m and not low.startswith('vlan configuration') and not low.startswith('vlan internal'):
            ids = _expand_vlan_list(m.group(1))
            name = ""
            for b in body:
                bs = b.strip()
                if bs.lower().startswith('name '):
                    name = bs[5:].strip()
            for vid in ids:
                vlan_defs[vid] = name if len(ids) == 1 else vlan_defs.get(vid, "")
            continue

        # --- Static routes ---
        if low.startswith('ip route '):
            r = _parse_static_route(header.strip())
            if r:
                static_routes.append(r)
            continue

        # --- Router blocks ---
        if low.startswith('router '):
            proto_info, dist_refs = _parse_router_block(header.strip(), body)
            protocols.append(proto_info)
            ctx = f"router {proto_info['proto']} {proto_info['id']}".strip()
            for acl, direction in dist_refs:
                acl_refs.append({"name": acl, "where": "route-map", "target": ctx,
                                 "direction": direction,
                                 "context": f"distribute-list in {ctx}", "routing": True})
            continue

        # --- VRF ---
        m = re.match(r'(?:ip vrf|vrf definition) (\S+)', low)
        if m:
            vname = header.strip().split()[-1]
            v = vrfs.setdefault(vname, {"name": vname, "rd": "", "interfaces": []})
            for b in body:
                bs = b.strip()
                if bs.lower().startswith('rd '):
                    v["rd"] = bs[3:].strip()
            continue

        # --- Numbered ACLs ---
        m = re.match(r'access-list (\d+) (.*)$', header.strip(), re.IGNORECASE)
        if m:
            num = m.group(1)
            rest = m.group(2).strip()
            n = int(num)
            kind = "standard" if (1 <= n <= 99 or 1300 <= n <= 1999) else "extended"
            acl = acls.setdefault(num, {"name": num, "kind": kind, "entries": []})
            action = rest.split()[0] if rest else ""
            acl["entries"].append({"seq": "", "action": action, "text": rest})
            continue

        # --- Named ACLs ---
        m = re.match(r'ip access-list (standard|extended) (\S+)', low)
        if m:
            kind = "named-std" if m.group(1) == 'standard' else "named-ext"
            aname = header.strip().split()[-1]
            acl = acls.setdefault(aname, {"name": aname, "kind": kind, "entries": []})
            acl["kind"] = kind
            for b in body:
                bs = b.strip()
                mm = re.match(r'(\d+)\s+(.*)$', bs)
                if mm:
                    seq, txt = mm.group(1), mm.group(2)
                else:
                    seq, txt = "", bs
                action = txt.split()[0] if txt else ""
                acl["entries"].append({"seq": seq, "action": action, "text": txt})
            continue

        # --- line vty/con: access-class ---
        if low.startswith('line '):
            for b in body:
                bs = b.strip()
                mm = re.match(r'access-class (\S+) (in|out)', bs, re.IGNORECASE)
                if mm:
                    acl_refs.append({"name": mm.group(1), "where": "line",
                                     "target": header.strip()[5:], "direction": mm.group(2).lower(),
                                     "context": f"{header.strip()} (access-class {mm.group(2).lower()})",
                                     "routing": False})
            continue

        # --- route-map: match ip address ---
        m = re.match(r'route-map (\S+)(?:\s+(permit|deny)\s+(\d+))?', low)
        if m:
            rmname = header.strip().split()[1] if len(header.strip().split()) > 1 else ""
            seq = m.group(3) or ""
            ctx = f"route-map {rmname} seq {seq}".strip()
            for b in body:
                bs = b.strip()
                mm = re.match(r'match ip address (?:prefix-list )?(.+)$', bs, re.IGNORECASE)
                if mm:
                    for acl in mm.group(1).split():
                        acl_refs.append({"name": acl, "where": "route-map",
                                         "target": rmname, "direction": "",
                                         "context": ctx, "routing": True})
            continue

        # --- crypto (VPN best-effort) ---
        if low.startswith('crypto map '):
            toks = header.strip().split()
            vpn.append({"kind": "crypto-map", "name": toks[2] if len(toks) > 2 else "",
                        "raw": "\n".join([header] + body)})
            continue
        if low.startswith('crypto isakmp'):
            toks = header.strip().split()
            vpn.append({"kind": "isakmp", "name": toks[-1] if len(toks) > 2 else "",
                        "raw": "\n".join([header] + body)})
            continue
        if low.startswith('crypto ipsec profile') or low.startswith('crypto ipsec transform-set'):
            toks = header.strip().split()
            vpn.append({"kind": "ipsec-profile", "name": toks[-1],
                        "raw": "\n".join([header] + body)})
            continue

        # --- snmp community with ACL / ip nat inside source list (single lines) ---
        # (also handled as headers without body)
        # snmp-server community <str> [RO|RW] [acl]
        mm = re.match(r'snmp-server community (\S+)(?:\s+(ro|rw))?(?:\s+(\S+))?', low)
        if mm and mm.group(3):
            acl = header.strip().split()[-1]
            acl_refs.append({"name": acl, "where": "snmp", "target": mm.group(1),
                             "direction": "", "context": f"snmp-server community {mm.group(1)}",
                             "routing": False})
            continue
        mm = re.match(r'ip nat inside source list (\S+)', low)
        if mm:
            acl = header.strip().split()[5]
            acl_refs.append({"name": acl, "where": "nat", "target": "nat",
                             "direction": "", "context": "ip nat inside source list",
                             "routing": False})
            continue

    # --- VLAN view construction ---
    # VLANs learned via VTP (SHOW VLAN section of the backup): count as defined
    # and enrich the names; they enter the list only if used locally.
    vtp_vlans = parse_show_vlan(content)
    all_vids = set(vlan_defs) | set(svis) | {v for v in vtp_vlans if v in used_vlans}
    access_by_vlan = {}
    trunk_by_vlan = {}
    for iface in interfaces:
        if iface["mode"] == "access" and iface["access_vlan"]:
            access_by_vlan.setdefault(iface["access_vlan"], []).append(iface["name"])
        for v in _expand_vlan_list(iface["trunk_allowed"]):
            trunk_by_vlan.setdefault(v, []).append(iface["name"])
    vlans = []
    for vid in sorted(all_vids, key=lambda x: int(x) if x.isdigit() else 0):
        vlans.append({
            "id": vid,
            "name": vlan_defs.get(vid) or vtp_vlans.get(vid, ""),
            "svi": svis.get(vid),
            "access_ifaces": access_by_vlan.get(vid, []),
            "trunk_ifaces": trunk_by_vlan.get(vid, []),
        })

    # --- Validation ---
    defined_acls = set(acls)
    applied_names = {r["name"] for r in acl_refs}
    # applied per-acl
    for name, acl in acls.items():
        acl["applied"] = [{"where": r["where"], "target": r["target"],
                           "direction": r["direction"]}
                          for r in acl_refs if r["name"] == name]

    unused_acls = sorted(defined_acls - applied_names)
    missing_acls = []
    seen_missing = set()
    for r in acl_refs:
        if r["name"] not in defined_acls and r["name"] not in seen_missing:
            seen_missing.add(r["name"])
            missing_acls.append({"name": r["name"], "referenced_in": r["context"]})

    route_acl_refs = [{"context": r["context"], "acl": r["name"]}
                      for r in acl_refs if r["routing"]]

    # Defined = local vlan blocks + SVIs + VTP; "unused" only among those
    # defined LOCALLY (reporting VTP VLANs unused on an access switch would be
    # noise: they live on the VTP server).
    defined_vlans = all_vids | set(vtp_vlans)
    unused_vlans = sorted(
        [v for v in (set(vlan_defs) | set(svis))
         if v not in used_vlans and v != "1"],
        key=lambda x: int(x) if x.isdigit() else 0)
    undefined_vlans = []
    seen_undef = set()
    for vid, ctx in access_use.items():
        if vid not in defined_vlans and vid != "1" and vid not in seen_undef:
            seen_undef.add(vid)
            undefined_vlans.append({"vlan": vid, "referenced_in": ctx})

    return {
        "vlans": vlans,
        "interfaces": interfaces,
        "routing": {
            "static": static_routes,
            "protocols": protocols,
            "vrfs": list(vrfs.values()),
        },
        "acls": [dict(a) for a in acls.values()],
        "vpn": vpn,
        "validation": {
            "unused_acls": unused_acls,
            "missing_acls": missing_acls,
            "unused_vlans": unused_vlans,
            "undefined_vlans": undefined_vlans,
            "route_acl_refs": route_acl_refs,
            # An ACE that can never fire is a worse defect than an unused ACL:
            # the ACL is applied, the intent is written down, and it silently
            # does nothing.
            "policy_findings": policy_findings(content, 'ios'),
        },
    }


# --- Config type detection (multi-vendor) ----------------------------------

_FORTIOS_VENDORS = {'fortinet', 'fortigate', 'fortios'}
_WLC_AIREOS_VENDORS = {'cisco_wlc'}
_PANOS_VENDORS = {'palo_alto', 'paloalto', 'panos', 'pan-os', 'palo alto'}
_LINUX_VENDORS = {'linux', 'ubuntu', 'debian', 'rhel', 'redhat', 'centos',
                  'rocky', 'almalinux', 'suse', 'proxmox'}


def detect_config_type(content, device=None):
    """Determines the configuration type: 'ios' | 'fortios' | 'wlc-aireos'.
    Uses the Vendor field from inventory if available, otherwise recognizes
    the format from the content (sniffing). Tolerant: default 'ios'."""
    try:
        if device:
            vendor = (device.get('Vendor') or '').strip().lower()
            if vendor in _FORTIOS_VENDORS:
                return 'fortios'
            if vendor in _WLC_AIREOS_VENDORS:
                return 'wlc-aireos'
            if vendor in _PANOS_VENDORS:
                return 'panos'
            if vendor in _LINUX_VENDORS:
                return 'linux'
            if vendor:
                # cisco_9800 (IOS-XE) and others: IOS format
                return 'ios'
        text = content or ''
        head = text[:4000]
        # FortiOS: starts with #config-version= and uses config/edit/next/end blocks
        if '#config-version=' in head:
            return 'fortios'
        if re.search(r'^config system (global|interface)\b', text, re.MULTILINE):
            return 'fortios'
        # PAN-OS (set-CLI): lines 'set deviceconfig ...' / 'set mgt-config ...'.
        # NB: PAN-OS XML is not supported (v1) — 'set' format only.
        if re.search(r'^set (deviceconfig|mgt-config) ', text, re.MULTILINE):
            return 'panos'
        # AireOS 'show run-config commands': lines 'config sysname/wlan/interface ...'
        if re.search(r'^config (sysname|wlan|interface|radius|mobility|network)\b',
                     text, re.MULTILINE):
            return 'wlc-aireos'
        # AireOS tabular 'show run-config'
        if re.search(r'^System Name\.{3,}', text, re.MULTILINE):
            return 'wlc-aireos'
        # Linux: the markers are written by drivers/linux.py, so they are exact.
        if re.search(r'^--- /etc/(os-release|ssh/sshd_config|fstab) ---',
                     text, re.MULTILINE):
            return 'linux'
    except Exception:
        pass
    return 'ios'


# --- FortiOS ------------------------------------------------------------------
# The primitives _forti_tokens/_forti_tree/_forti_get/_forti_set1/_forti_ip_cidr
# are defined in fw_analyzers.fortios and re-imported at the top of the module.


def analyze_fortios_config(content):
    """Analyzes a FortiOS (FortiGate) configuration. Pure, tolerant.
    Returns interfaces, firewall policies, address/service objects, VIPs,
    static routes, VPNs, VLANs and the specific validation checks."""
    root = _forti_tree(content)

    # --- Hostname ---
    hostname = ''
    glob = _forti_get(root, 'system global')
    if glob:
        hostname = _forti_set1(glob, 'hostname')

    # --- Interfaces (+ VLANs) ---
    interfaces = []
    vlans = []
    ifs = _forti_get(root, 'system interface')
    if ifs:
        for name, n in ifs["children"].items():
            iface = {
                "name": name,
                "ip": _forti_ip_cidr(n),
                "allowaccess": n["sets"].get('allowaccess', []),
                "vdom": _forti_set1(n, 'vdom'),
                "role": _forti_set1(n, 'role'),
                "description": _forti_set1(n, 'description'),
                "vlanid": _forti_set1(n, 'vlanid'),
                "parent": _forti_set1(n, 'interface'),
                "status": _forti_set1(n, 'status', 'up'),
            }
            interfaces.append(iface)
            if iface["vlanid"]:
                vlans.append({"id": iface["vlanid"], "name": name,
                              "parent": iface["parent"], "ip": iface["ip"]})

    # --- Firewall policies ---
    policies = []
    pol = _forti_get(root, 'firewall policy')
    if pol:
        for pid, n in pol["children"].items():
            policies.append({
                "id": pid,
                "name": _forti_set1(n, 'name'),
                "srcintf": n["sets"].get('srcintf', []),
                "dstintf": n["sets"].get('dstintf', []),
                "srcaddr": n["sets"].get('srcaddr', []),
                "dstaddr": n["sets"].get('dstaddr', []),
                "service": n["sets"].get('service', []),
                "action": _forti_set1(n, 'action', 'deny'),
                "schedule": _forti_set1(n, 'schedule'),
                "nat": _forti_set1(n, 'nat', 'disable'),
                "status": _forti_set1(n, 'status', 'enable'),
                "logtraffic": _forti_set1(n, 'logtraffic', ''),
            })

    # --- Address/service objects, groups, VIPs ---
    def _names_of(section, extra=None):
        node = _forti_get(root, section)
        out = []
        if node:
            for name, n in node["children"].items():
                item = {"name": name}
                for k in (extra or []):
                    item[k] = (n["sets"].get(k, [])
                               if k == 'member' else _forti_set1(n, k))
                out.append(item)
        return out

    addresses = _names_of('firewall address', ['subnet', 'type', 'comment'])
    addr_groups = _names_of('firewall addrgrp', ['member'])
    services = _names_of('firewall service custom',
                         ['tcp-portrange', 'udp-portrange', 'protocol'])
    service_groups = _names_of('firewall service group', ['member'])
    vips = _names_of('firewall vip',
                     ['extip', 'mappedip', 'extintf', 'extport', 'mappedport'])

    # --- Static routes ---
    static_routes = []
    rst = _forti_get(root, 'router static')
    if rst:
        for seq, n in rst["children"].items():
            dst = n["sets"].get('dst') or []
            static_routes.append({
                "seq": seq,
                "prefix": _ip_addr_to_cidr(dst) or ' '.join(dst) or '0.0.0.0/0',
                "next_hop": _forti_set1(n, 'gateway'),
                "device": _forti_set1(n, 'device'),
                "distance": _forti_set1(n, 'distance'),
            })

    # --- IPsec VPN (phase 1 / phase 2 names) ---
    phase1 = []
    phase2 = []
    for sec in ('vpn ipsec phase1-interface', 'vpn ipsec phase1'):
        node = _forti_get(root, sec)
        if node:
            phase1.extend(node["children"].keys())
    for sec in ('vpn ipsec phase2-interface', 'vpn ipsec phase2'):
        node = _forti_get(root, sec)
        if node:
            phase2.extend(node["children"].keys())

    # --- Validation ---
    any_any = []
    disabled_pol = []
    unlogged_pol = []
    for p in policies:
        label = f"{p['id']}" + (f" ({p['name']})" if p['name'] else '')
        src_all = any(a.lower() == 'all' for a in p['srcaddr'])
        dst_all = any(a.lower() == 'all' for a in p['dstaddr'])
        if p['action'] == 'accept' and src_all and dst_all:
            any_any.append(label)
        if p['status'] == 'disable':
            disabled_pol.append(label)
        if p['logtraffic'] == 'disable':
            unlogged_pol.append(label)

    # Unused objects: defined but never referenced by policies / groups
    used_addr = set()
    used_svc = set()
    for p in policies:
        used_addr.update(a.lower() for a in p['srcaddr'] + p['dstaddr'])
        used_svc.update(s.lower() for s in p['service'])
    for g in addr_groups:
        used_addr.update(m.lower() for m in g.get('member', []))
    for g in service_groups:
        used_svc.update(m.lower() for m in g.get('member', []))
    vip_names = {v['name'].lower() for v in vips}
    unused_addresses = sorted(
        a['name'] for a in addresses
        if a['name'].lower() not in used_addr and a['name'].lower() != 'all')
    unused_services = sorted(
        s['name'] for s in services
        if s['name'].lower() not in used_svc and s['name'].lower() != 'all')
    unused_addr_groups = sorted(
        g['name'] for g in addr_groups
        if g['name'].lower() not in used_addr and g['name'].lower() not in vip_names)

    # Insecure management access (http/telnet in allowaccess)
    insecure_mgmt = []
    for i in interfaces:
        bad = [a for a in i['allowaccess'] if a.lower() in ('http', 'telnet')]
        if bad:
            insecure_mgmt.append({"name": i['name'], "allowaccess": bad})

    # Admins without trusthost
    admins_no_trusthost = []
    adm = _forti_get(root, 'system admin')
    if adm:
        for name, n in adm["children"].items():
            if not any(k.startswith('trusthost') for k in n["sets"]):
                admins_no_trusthost.append(name)

    # Logging: at least one 'log ... setting' section with 'set status enable'
    logging_enabled = False
    for sec_name, node in root["children"].items():
        if re.match(r'^log\b.*\bsetting$', sec_name):
            if _forti_set1(node, 'status') == 'enable':
                logging_enabled = True
                break

    return {
        "hostname": hostname,
        "interfaces": interfaces,
        "vlans": vlans,
        "policies": policies,
        "addresses": addresses,
        "addr_groups": addr_groups,
        "services": services,
        "service_groups": service_groups,
        "vips": vips,
        "routing": {"static": static_routes},
        "vpn": {"phase1": phase1, "phase2": phase2},
        "validation": {
            "policy_findings": policy_findings(content, 'fortios'),
            "any_any_policies": any_any,
            "disabled_policies": disabled_pol,
            "unlogged_policies": unlogged_pol,
            "unused_addresses": unused_addresses,
            "unused_addr_groups": unused_addr_groups,
            "unused_services": unused_services,
            "insecure_mgmt_interfaces": insecure_mgmt,
            "admins_without_trusthost": admins_no_trusthost,
            "logging_disabled": not logging_enabled,
        },
    }


# --- Cisco WLC (AireOS) -------------------------------------------------------

def analyze_wlc_config(content):
    """Analyzes the config of a Cisco AireOS WLC ('show run-config commands').
    Also tolerates the IOS-XE format (Catalyst 9800): in that case it reuses
    the IOS parser as a base and adds extraction of the wlan blocks. Pure."""
    text = content or ''
    is_aireos = bool(re.search(
        r'^config (sysname|wlan|interface|radius|mobility|network)\b',
        text, re.MULTILINE))

    wlans = {}   # id -> dict
    dyn_ifaces = {}
    radius = []
    mobility_group = ''
    hostname = ''
    mgmt_http = False
    base = None

    def _wlan(wid):
        return wlans.setdefault(wid, {
            "id": wid, "ssid": "", "profile": "", "enabled": False,
            "interface": "", "security": "open", "tkip": False,
            "broadcast_ssid": True,
        })

    if is_aireos:
        for raw in text.splitlines():
            s = raw.strip()
            low = s.lower()
            try:
                if low.startswith('config sysname '):
                    hostname = s.split(None, 2)[2]
                elif low.startswith('config wlan create '):
                    toks = _forti_tokens(s)
                    # config wlan create <id> <profile> [<ssid>]
                    if len(toks) >= 4:
                        w = _wlan(toks[3])
                        w["profile"] = toks[4] if len(toks) > 4 else ''
                        w["ssid"] = toks[5] if len(toks) > 5 else w["profile"]
                elif re.match(r'config wlan (enable|disable) (\S+)', low):
                    m = re.match(r'config wlan (enable|disable) (\S+)', low)
                    if m and m.group(2) != 'all':
                        _wlan(m.group(2))["enabled"] = (m.group(1) == 'enable')
                elif low.startswith('config wlan interface '):
                    toks = s.split()
                    if len(toks) >= 5:
                        _wlan(toks[3])["interface"] = toks[4]
                elif low.startswith('config wlan broadcast-ssid disable '):
                    _wlan(s.split()[-1])["broadcast_ssid"] = False
                elif low.startswith('config wlan security '):
                    toks = low.split()
                    wid = toks[-1]
                    rest = ' '.join(toks[3:-1])
                    w = _wlan(wid)
                    if rest == 'wpa disable':
                        w["security"] = 'open'
                    elif 'wpa wpa2 enable' in rest:
                        w["security"] = 'WPA2'
                    elif 'wpa wpa3 enable' in rest or 'wpa akm sae enable' in rest:
                        w["security"] = 'WPA3'
                    elif rest == 'wpa enable' and w["security"] == 'open':
                        w["security"] = 'WPA'
                    elif 'wpa wpa1 enable' in rest:
                        w["security"] = 'WPA'
                    if 'ciphers tkip enable' in rest:
                        w["tkip"] = True
                elif low.startswith('config interface create '):
                    toks = s.split()
                    if len(toks) >= 4:
                        dyn_ifaces[toks[3]] = {"name": toks[3],
                                               "vlan": toks[4] if len(toks) > 4 else '',
                                               "ip": ''}
                elif low.startswith('config interface address '):
                    toks = s.split()
                    # config interface address [dynamic-interface] <name> <ip> <mask> [gw]
                    t = toks[3:]
                    if t and t[0] == 'dynamic-interface':
                        t = t[1:]
                    if len(t) >= 3:
                        d = dyn_ifaces.setdefault(t[0], {"name": t[0], "vlan": '', "ip": ''})
                        d["ip"] = _ip_addr_to_cidr(t[1:3])
                elif low.startswith('config interface vlan '):
                    toks = s.split()
                    if len(toks) >= 5:
                        d = dyn_ifaces.setdefault(toks[3], {"name": toks[3], "vlan": '', "ip": ''})
                        d["vlan"] = toks[4]
                elif re.match(r'config radius (auth|acct) add ', low):
                    toks = s.split()
                    if len(toks) >= 6:
                        radius.append({"kind": toks[2], "index": toks[4],
                                       "ip": toks[5],
                                       "port": toks[6] if len(toks) > 6 else ''})
                elif low.startswith('config mobility group domain '):
                    mobility_group = s.split()[-1]
                elif low == 'config network webmode enable':
                    mgmt_http = True
            except Exception:
                continue
    else:
        # IOS-XE (Catalyst 9800): IOS base + 'wlan <profile> <id> <ssid>' blocks
        try:
            base = analyze_config(text)
        except Exception:
            base = None
        for header, body in _iter_blocks(running_config(text)):
            m = re.match(r'wlan (\S+) (\d+) (\S+)', header.strip(), re.IGNORECASE)
            if not m:
                continue
            w = _wlan(m.group(2))
            w["profile"], w["ssid"] = m.group(1), m.group(3)
            w["enabled"] = True
            sec = 'WPA2'
            for b in body:
                bl = b.strip().lower()
                if bl == 'shutdown':
                    w["enabled"] = False
                elif bl == 'no security wpa':
                    sec = 'open'
                elif 'security wpa wpa3' in bl or 'sae' in bl:
                    sec = 'WPA3'
                elif 'security wpa wpa1' in bl:
                    sec = 'WPA'
                elif 'tkip' in bl:
                    w["tkip"] = True
                elif bl == 'no broadcast-ssid':
                    w["broadcast_ssid"] = False
            w["security"] = sec
        m = re.search(r'^hostname (\S+)', text, re.MULTILINE)
        if m:
            hostname = m.group(1)

    wlan_list = sorted(wlans.values(),
                       key=lambda w: int(w["id"]) if w["id"].isdigit() else 0)

    # --- Validation ---
    def _label(w):
        return f"{w['id']}" + (f" ({w['ssid']})" if w['ssid'] else '')

    validation = {
        "open_wlans": [_label(w) for w in wlan_list if w["security"] == 'open'],
        "legacy_tkip_wlans": [_label(w) for w in wlan_list
                              if w["tkip"] or w["security"] == 'WPA'],
        "disabled_wlans": [_label(w) for w in wlan_list if not w["enabled"]],
        "broadcast_ssid_off": [_label(w) for w in wlan_list
                               if not w["broadcast_ssid"]],
        "management_http": mgmt_http,
    }

    result = {
        "hostname": hostname,
        "platform": "aireos" if is_aireos else "iosxe",
        "wlans": wlan_list,
        "dynamic_interfaces": list(dyn_ifaces.values()),
        "radius_servers": radius,
        "mobility_group": mobility_group,
        "validation": validation,
    }
    if base:
        result["ios_base"] = base
    return result


# --- Config Converter (deterministic, FortiOS <-> PAN-OS) -------------------
# Firewall vendors only: the converter no longer handles switches/routers (ios).

FIREWALL_VENDORS = {'fortios', 'panos'}


def _prefix_to_mask(pfx):
    """From prefix length (int) to dotted mask. '' if not valid."""
    try:
        n = int(pfx)
        if not 0 <= n <= 32:
            return ''
        v = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF if n else 0
        return '.'.join(str((v >> s) & 0xFF) for s in (24, 16, 8, 0))
    except Exception:
        return ''


def _cidr_split(cidr):
    """'a.b.c.d/nn' -> ('a.b.c.d', 'dotted mask') or (None, None)."""
    if not cidr or '/' not in cidr:
        return None, None
    ip, _, pfx = cidr.partition('/')
    mask = _prefix_to_mask(pfx)
    return (ip, mask) if mask else (None, None)


def _forti_render_stanza(section, key, node):
    """Reconstructs the text of a FortiOS stanza (config/edit/set/next/end)
    from a tree node. Only the 'sets' level (sufficient as a raw stanza)."""
    lines = [f'config {section}', f'    edit "{key}"']
    for k, vals in node["sets"].items():
        rendered = ' '.join(f'"{v}"' if (' ' in v or v == '') else v for v in vals)
        lines.append(f'        set {k} {rendered}'.rstrip())
    lines.extend(['    next', 'end'])
    return '\n'.join(lines)


# The primitives _panos_tokens/_panos_lines/_panos_collect/_panos_attr/
# _panos_attr_all are defined in fw_analyzers.panos and re-imported at the top.


def _convert_fortios_to_panos(source_text):
    """FortiOS -> PAN-OS (set-CLI), best-effort preview."""
    root = _forti_tree(source_text)
    mapped = []
    unmapped = []
    handled = {'system interface', 'router static', 'firewall address',
               'firewall service custom', 'firewall policy', 'system global'}

    ifs = _forti_get(root, 'system interface')
    if ifs:
        for name, n in ifs["children"].items():
            src = _forti_render_stanza('system interface', name, n)
            cidr = _forti_ip_cidr(n)
            if not cidr:
                unmapped.append(src)
                continue
            lines = [f'set network interface ethernet {name} layer3 ip {cidr}']
            note = ''
            desc = _forti_set1(n, 'description') or _forti_set1(n, 'alias')
            if desc:
                lines.append(f'set address-object {name}-desc comment "{desc}"')
                note = 'descrizione riportata come commento separato (PAN-OS non ha description sull\'interfaccia L3)'
            if _forti_set1(n, 'status', 'up').lower() == 'down':
                note = (note + '; ' if note else '') + 'interfaccia down: disabilitare manualmente in PAN-OS'
            mapped.append({"source": src, "target": '\n'.join(lines), "note": note})

    adr = _forti_get(root, 'firewall address')
    if adr:
        for name, n in adr["children"].items():
            src = _forti_render_stanza('firewall address', name, n)
            subnet = n["sets"].get('subnet') or []
            atype = _forti_set1(n, 'type', 'ipmask')
            if atype not in ('ipmask', '') or len(subnet) < 2:
                unmapped.append(src)
                continue
            cidr = _ip_addr_to_cidr(subnet)
            if not cidr:
                unmapped.append(src)
                continue
            mapped.append({"source": src,
                           "target": f'set address {name} ip-netmask {cidr}',
                           "note": ''})

    svc = _forti_get(root, 'firewall service custom')
    if svc:
        for name, n in svc["children"].items():
            src = _forti_render_stanza('firewall service custom', name, n)
            tcp = n["sets"].get('tcp-portrange')
            udp = n["sets"].get('udp-portrange')
            if tcp:
                mapped.append({"source": src,
                               "target": f'set service {name} protocol tcp port {tcp[0]}',
                               "note": ''})
            elif udp:
                mapped.append({"source": src,
                               "target": f'set service {name} protocol udp port {udp[0]}',
                               "note": ''})
            else:
                unmapped.append(src)

    rst = _forti_get(root, 'router static')
    if rst:
        for seq, n in rst["children"].items():
            src = _forti_render_stanza('router static', seq, n)
            dst = n["sets"].get('dst') or ['0.0.0.0', '0.0.0.0']
            cidr = _ip_addr_to_cidr(dst) or f"{dst[0]}/0"
            gw = _forti_set1(n, 'gateway')
            dev = _forti_set1(n, 'device')
            if not gw:
                unmapped.append(src)
                continue
            rname = f"route-{seq}"
            lines = [f'set network virtual-router default routing-table ip static-route {rname} destination {cidr}',
                     f'set network virtual-router default routing-table ip static-route {rname} nexthop ip-address {gw}']
            note = f"interfaccia in uscita FortiOS '{dev}' non riportata (PAN-OS usa il virtual-router)" if dev else ''
            mapped.append({"source": src, "target": '\n'.join(lines), "note": note})

    pol = _forti_get(root, 'firewall policy')
    if pol:
        for pid, n in pol["children"].items():
            src = _forti_render_stanza('firewall policy', pid, n)
            name = _forti_set1(n, 'name') or f'rule{pid}'
            srcintf = n["sets"].get('srcintf', ['any'])
            dstintf = n["sets"].get('dstintf', ['any'])
            srcaddr = n["sets"].get('srcaddr', ['any'])
            dstaddr = n["sets"].get('dstaddr', ['any'])
            service = n["sets"].get('service', ['any'])
            action = 'allow' if _forti_set1(n, 'action', 'deny') == 'accept' else 'deny'
            lines = []
            for z in srcintf:
                lines.append(f'set rulebase security rules "{name}" from {z}')
            for z in dstintf:
                lines.append(f'set rulebase security rules "{name}" to {z}')
            for a in srcaddr:
                lines.append(f'set rulebase security rules "{name}" source {a}')
            for a in dstaddr:
                lines.append(f'set rulebase security rules "{name}" destination {a}')
            for s in service:
                lines.append(f'set rulebase security rules "{name}" service {s}')
            lines.append(f'set rulebase security rules "{name}" action {action}')
            note = ''
            if _forti_set1(n, 'nat', 'disable') == 'enable':
                lines.append(f'set rulebase nat rules "{name}" from {srcintf[0]}')
                lines.append(f'set rulebase nat rules "{name}" to {dstintf[0]}')
                note = 'NAT abilitato: regola NAT creata come anteprima separata, verificare source-translation'
            mapped.append({"source": src, "target": '\n'.join(lines), "note": note})

    # Any other unhandled section -> unmapped (raw stanza)
    for section, node in root["children"].items():
        if section in handled:
            continue
        if node["children"]:
            for key, child in node["children"].items():
                unmapped.append(_forti_render_stanza(section, key, child))
        elif node["sets"]:
            unmapped.append(_forti_render_stanza(section, '', node)
                            .replace('    edit ""\n', '').replace('    next\n', ''))
    return mapped, unmapped


def _convert_panos_to_fortios(source_text):
    """PAN-OS (set-CLI) -> FortiOS, best-effort preview."""
    lines = _panos_lines(source_text)
    mapped = []
    unmapped = []
    consumed_raw = set()

    # --- L3 interfaces ---
    iface_re = re.compile(r'^network\s+interface\s+ethernet\s+(\S+)\s+layer3\s+ip\s+(\S+)$', re.IGNORECASE)
    for toks, raw in lines:
        m = iface_re.match(' '.join(toks))
        if not m:
            continue
        name, cidr = m.group(1), m.group(2)
        ip, mask = _cidr_split(cidr)
        if not ip:
            unmapped.append(raw)
            consumed_raw.add(raw)
            continue
        target = (f'config system interface\n    edit "{name}"\n'
                  f'        set ip {ip} {mask}\n    next\nend')
        mapped.append({"source": raw, "target": target, "note": ''})
        consumed_raw.add(raw)

    # --- Address objects ---
    addr = _panos_collect(lines, ('address',))
    for name, entry in addr.items():
        cidr = _panos_attr(entry, 'ip-netmask')
        if not cidr:
            unmapped.extend(entry["raw"])
            consumed_raw.update(entry["raw"])
            continue
        ip, mask = _cidr_split(cidr)
        if not ip:
            unmapped.extend(entry["raw"])
            consumed_raw.update(entry["raw"])
            continue
        target = (f'config firewall address\n    edit "{name}"\n'
                  f'        set subnet {ip} {mask}\n    next\nend')
        mapped.append({"source": '\n'.join(entry["raw"]), "target": target, "note": ''})
        consumed_raw.update(entry["raw"])

    # --- Service objects ---
    svc_re = re.compile(r'^service\s+(\S+)\s+protocol\s+(tcp|udp)\s+port\s+(\S+)$', re.IGNORECASE)
    for toks, raw in lines:
        m = svc_re.match(' '.join(toks))
        if not m:
            continue
        name, proto, port = m.group(1), m.group(2).lower(), m.group(3)
        target = (f'config firewall service custom\n    edit "{name}"\n'
                  f'        set {proto}-portrange {port}\n    next\nend')
        mapped.append({"source": raw, "target": target, "note": ''})
        consumed_raw.add(raw)

    # --- Static routes ---
    route = _panos_collect(lines, ('network', 'virtual-router'))
    # actual structure: network virtual-router <vr> routing-table ip static-route <name> ...
    route_names = {}
    route_re = re.compile(
        r'^network\s+virtual-router\s+(\S+)\s+routing-table\s+ip\s+static-route\s+(\S+)\s+(destination|nexthop)\s+(?:ip-address\s+)?(\S+)$',
        re.IGNORECASE)
    for toks, raw in lines:
        m = route_re.match(' '.join(toks))
        if not m:
            continue
        rname = m.group(2)
        entry = route_names.setdefault(rname, {"destination": '', "nexthop": '', "raw": []})
        entry[m.group(3).lower()] = m.group(4)
        entry["raw"].append(raw)
    for seq, (rname, entry) in enumerate(route_names.items(), start=1):
        consumed_raw.update(entry["raw"])
        if not entry["destination"] or not entry["nexthop"]:
            unmapped.extend(entry["raw"])
            continue
        net, mask = _cidr_split(entry["destination"])
        if not net:
            unmapped.extend(entry["raw"])
            continue
        target = (f'config router static\n    edit {seq}\n'
                  f'        set dst {net} {mask}\n'
                  f'        set gateway {entry["nexthop"]}\n    next\nend')
        mapped.append({"source": '\n'.join(entry["raw"]), "target": target, "note": ''})

    # --- Policy (security rules) ---
    rules = _panos_collect(lines, ('rulebase', 'security', 'rules'))
    nat_rules = _panos_collect(lines, ('rulebase', 'nat', 'rules'))
    for seq, (name, entry) in enumerate(rules.items(), start=1):
        consumed_raw.update(entry["raw"])
        srcintf = _panos_attr_all(entry, 'from') or ['any']
        dstintf = _panos_attr_all(entry, 'to') or ['any']
        srcaddr = _panos_attr_all(entry, 'source') or ['any']
        dstaddr = _panos_attr_all(entry, 'destination') or ['any']
        service = _panos_attr_all(entry, 'service') or ['ALL']
        action = 'accept' if _panos_attr(entry, 'action').lower() == 'allow' else 'deny'
        lines_out = [
            'config firewall policy', f'    edit {seq}',
            f'        set name "{name}"',
            '        set srcintf ' + ' '.join(f'"{z}"' for z in srcintf),
            '        set dstintf ' + ' '.join(f'"{z}"' for z in dstintf),
            '        set srcaddr ' + ' '.join(f'"{a}"' for a in srcaddr),
            '        set dstaddr ' + ' '.join(f'"{a}"' for a in dstaddr),
            '        set service ' + ' '.join(f'"{s}"' for s in service),
            f'        set action {action}',
        ]
        note = ''
        if name in nat_rules:
            lines_out.append('        set nat enable')
            consumed_raw.update(nat_rules[name]["raw"])
            note = 'regola NAT associata rilevata: source-translation non riportata, verificare manualmente'
        lines_out.extend(['    next', 'end'])
        mapped.append({"source": '\n'.join(entry["raw"]), "target": '\n'.join(lines_out), "note": note})

    # --- Unrecognized lines -> unmapped ---
    for _toks, raw in lines:
        if raw not in consumed_raw:
            unmapped.append(raw)
    return mapped, unmapped


def convert_config(source_text, source_vendor, target_vendor):
    """Deterministic conversion (preview) between firewall vendors
    ('fortios', 'panos'). Returns {"mapped": [{source,target,note}],
    "unmapped": [str], "preview_text": str}. Raises ValueError on invalid
    or matching vendors."""
    sv = (source_vendor or '').strip().lower()
    tv = (target_vendor or '').strip().lower()
    if sv not in FIREWALL_VENDORS or tv not in FIREWALL_VENDORS:
        raise ValueError(f"Vendor non supportato: {source_vendor!r} -> {target_vendor!r} "
                         f"(solo vendor firewall supportati: {sorted(FIREWALL_VENDORS)})")
    if sv == tv:
        raise ValueError("Vendor sorgente e destinazione coincidono.")
    if sv == 'fortios':
        mapped, unmapped = _convert_fortios_to_panos(source_text or '')
    else:
        mapped, unmapped = _convert_panos_to_fortios(source_text or '')
    comment = '#' if tv == 'fortios' else '!'
    header = (f"{comment} Anteprima conversione {sv} -> {tv} — SentinelNet Config Converter\n"
              f"{comment} {len(mapped)} elementi mappati, {len(unmapped)} non mappati "
              f"(vedi elenco 'unmapped').\n")
    preview_text = header + '\n' + '\n\n'.join(m["target"] for m in mapped) + '\n'
    return {"mapped": mapped, "unmapped": unmapped, "preview_text": preview_text}


# --- I/O: backup reading + scoping ------------------------------------------

def _find_freshest_backup(ip):
    """Finds the freshest backup file for the given IP. Returns
    (path, tenant_folder) or (None, None)."""
    from core import core_engine
    best = None
    best_mtime = -1
    best_tenant = None
    folder = core_engine.BACKUP_FOLDER
    if not os.path.exists(folder):
        return None, None
    for root, _dirs, files in os.walk(folder):
        for f in files:
            if f.endswith(f"-{ip}.txt") or f.endswith(f"_{ip}.txt") or f == f"{ip}.txt":
                path = os.path.join(root, f)
                try:
                    mt = os.path.getmtime(path)
                except OSError:
                    mt = 0
                if mt > best_mtime:
                    best_mtime = mt
                    best = path
                    rel = os.path.relpath(root, folder)
                    best_tenant = rel.split(os.sep)[0] if rel != '.' else ''
    return best, best_tenant


def analyze_device(ip):
    """Reads the freshest backup for the IP and returns analysis + meta.
    Returns None if no backup exists."""
    path, tenant_folder = _find_freshest_backup(ip)
    if not path:
        return None
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return None

    # Inventory lookup before analysis: the Vendor drives type detection
    dev = None
    tenant = tenant_folder or ""
    try:
        from services import inventory_manager
        dev = next((d for d in inventory_manager.get_all_devices()
                    if d.get('IP') == ip), None)
    except Exception:
        dev = None

    config_type = detect_config_type(content, dev)

    import fw_analyzers

    is_firewall = False
    firewall = None
    server = None
    result: Dict[str, Any]
    if config_type == 'fortios':
        result = dict(analyze_fortios_config(content))
        hostname = result.pop("hostname", "")
        is_firewall = True
        firewall = fw_analyzers.fortios.analyze(content)
    elif config_type == 'panos':
        # PAN-OS: no dedicated "generic" analyzer (the other tabs reuse the
        # IOS parser in tolerant mode); the Firewall tab uses the sectioned
        # envelope.
        result = dict(analyze_config(content))
        m = re.search(r'^set deviceconfig system hostname (\S+)', content,
                      re.MULTILINE)
        hostname = m.group(1) if m else ""
        is_firewall = True
        firewall = fw_analyzers.panos.analyze(content)
    elif config_type == 'wlc-aireos':
        result = dict(analyze_wlc_config(content))
        hostname = result.pop("hostname", "")
    elif config_type == 'linux':
        # No VLANs, no ACLs, no interfaces in the Cisco sense: the "generic"
        # result stays empty on purpose and all the content lives in the
        # ``server`` envelope.
        from ai import linux_analyzer
        result = {
            "vlans": [], "interfaces": [], "acls": [], "vpn": [],
            "routing": {"static": [], "protocols": [], "vrfs": []},
            "validation": {"unused_acls": [], "missing_acls": [],
                           "unused_vlans": [], "undefined_vlans": [],
                           "route_acl_refs": []},
        }
        server = linux_analyzer.analyze(content)
        m = re.search(r'^\s*hostname (\S+)', content, re.MULTILINE)
        hostname = m.group(1) if m else ""
    else:
        result = dict(analyze_config(content))
        hostname = ""
        m = re.search(r'^hostname (\S+)', content, re.MULTILINE)
        if m:
            hostname = m.group(1)
        result["vtp"] = parse_vtp_status(content)

    if dev:
        tenant = dev.get('Group', tenant) or tenant
        if not hostname:
            hostname = dev.get('Hostname', '') or ''
        # Non-FortiGate firewall (e.g. detected from inventory/CDP): Firewall
        # tab visible but without dedicated parsing (FortiGate only).
        if not is_firewall and (dev.get('Type') or '').strip().lower() == 'firewall':
            is_firewall = True

    result["ip"] = ip
    result["hostname"] = hostname
    result["tenant"] = tenant
    # Age of the displayed data. The backup was already chosen by mtime in
    # _find_freshest_backup: here it is re-read instead of widening its
    # signature, which has three callers unpacking two values.
    try:
        result["backup_ts"] = int(os.path.getmtime(path))
    except OSError:
        result["backup_ts"] = None
    result["config_type"] = config_type
    result["is_firewall"] = is_firewall
    result["firewall"] = firewall
    result["server"] = server
    return result


def _backup_mtime(ip):
    """mtime of the freshest backup, or None. Memo invalidation key."""
    path, _ = _find_freshest_backup(ip)
    if not path:
        return None
    try:
        return int(os.path.getmtime(path))
    except OSError:
        return None


@functools.lru_cache(maxsize=128)
def _analyze_device_at(ip, _mtime):
    # _mtime is not used: it is in the signature so that a new backup produces
    # a new key. The LRU cap is for backup rotation, which otherwise would make
    # the keys grow without end.
    return analyze_device(ip)


def analyze_device_cached(ip):
    """``analyze_device`` with memoization on (ip, backup mtime).

    A single diagnosis re-reads the same backup at every hop of the chain and
    at every candidate of the gateway derivation: parsing is the expensive
    part, and the file does not change while responding.
    """
    return _analyze_device_at(ip, _backup_mtime(ip))


def analyze_all(group_filter=None, allowed_groups=None):
    """Analyzes all devices in inventory that have a backup, applying scoping
    by site (allowed_groups) and an optional group filter."""
    from services import inventory_manager
    devices = []
    for dev in inventory_manager.get_all_devices():
        ip = dev.get('IP')
        if not ip:
            continue
        group = dev.get('Group', 'Generale') or 'Generale'
        if allowed_groups is not None and group not in allowed_groups:
            continue
        if group_filter and group_filter != 'all' and group != group_filter:
            continue
        try:
            res = analyze_device_cached(ip)
        except Exception:
            res = None
        if res:
            devices.append(res)
    return {"devices": devices}
