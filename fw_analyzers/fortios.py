# -*- coding: utf-8 -*-
"""FortiOS (FortiGate) firewall analyzer.

Exposes ``analyze(text)`` which returns the generic envelope
``{"vendor": "fortios", "sections": [...]}`` rendered generically by the
frontend (T7). Also contains the parsing primitives for the
``config/edit/set/next/end`` block structure (``_forti_tree`` & co.), reused by
the converters in ``config_analyzer`` (which re-imports them from here — no
duplication).

Pure and tolerant: ``analyze`` NEVER raises exceptions.
"""
import logging
import re

from ._ip import _ip_addr_to_cidr

logger = logging.getLogger(__name__)

# Keys whose value is a secret and must be masked in the envelope.
_SECRET_KEYS = {
    'passwd', 'password', 'psksecret', 'secret', 'key', 'private-key',
    'passphrase', 'auth-pwd', 'ppk-secret', 'ldap-password',
}
_MASK = '***REDACTED***'

_FORTI_TOKEN = re.compile(r'"[^"]*"|\S+')


def _forti_tokens(s):
    """Tokenizes a FortiOS line, respecting double-quoted strings."""
    return [t[1:-1] if t.startswith('"') and t.endswith('"') and len(t) >= 2 else t
            for t in _FORTI_TOKEN.findall(s)]


def _forti_tree(content):
    """Parses the FortiOS config/edit/next/end block structure into a tree:
    node = {"sets": {key: [values]}, "children": {name: node}}. Tolerant of
    unclosed blocks or anomalous nesting."""
    root = {"sets": {}, "children": {}}
    stack = [root]
    for raw in (content or '').splitlines():
        s = raw.strip()
        if not s or s.startswith('#'):
            continue
        low = s.lower()
        try:
            if low.startswith('config '):
                name = s[7:].strip().strip('"')
                node = stack[-1]["children"].setdefault(
                    name, {"sets": {}, "children": {}})
                stack.append(node)
            elif low.startswith('edit '):
                key = s[5:].strip().strip('"')
                node = stack[-1]["children"].setdefault(
                    key, {"sets": {}, "children": {}})
                stack.append(node)
            elif low in ('next', 'end'):
                if len(stack) > 1:
                    stack.pop()
            elif low.startswith('set '):
                toks = _forti_tokens(s)
                if len(toks) >= 2:
                    stack[-1]["sets"][toks[1].lower()] = toks[2:]
        except Exception:
            continue
    return root


def _forti_get(root, path):
    """Navigates the FortiOS tree by section name (e.g. 'firewall policy').
    Returns the node or None."""
    return root["children"].get(path)


def _forti_set1(node, key, default=''):
    """First value of a 'set' (string), or default."""
    vals = node["sets"].get(key)
    return vals[0] if vals else default


def _forti_ip_cidr(node):
    """'set ip A.B.C.D MASK' -> 'A.B.C.D/nn'."""
    vals = node["sets"].get('ip') or []
    return _ip_addr_to_cidr(vals) if vals else ''


# --- Envelope helpers --------------------------------------------------------

def _col(key):
    return {"key": key, "label_key": f"fw.col.{key}"}


def _join(vals):
    return ', '.join(vals) if isinstance(vals, (list, tuple)) else (vals or '')


def _multi(vals):
    """Multi-element value kept as a LIST up to the UI.

    A policy can reference dozens of address objects: flattening them here into a
    string forces the table into one huge cell, and the client no longer has a way
    to expand it on demand because the structure is gone. Reassembling it
    browser-side by splitting on ", " is not equivalent: an object name can
    contain a comma.
    """
    if isinstance(vals, (list, tuple)):
        return [str(v) for v in vals]
    return [str(vals)] if vals else []


def _section(sid, columns, rows):
    return {
        "id": sid,
        "label_key": f"fw.sec.{sid}",
        "columns": [_col(k) for k in columns],
        "rows": rows,
    }


def _children(root, path):
    node = _forti_get(root, path)
    return node["children"].items() if node else []


def analyze(text):
    """FortiOS -> generic sectioned envelope. Pure and tolerant."""
    try:
        return _analyze(text)
    except Exception:
        # An empty envelope is also what a genuinely empty config produces:
        # without ``error`` the UI would show a parser crash as "no policies",
        # i.e. a failed analysis read as a clean firewall.
        logger.exception("FortiOS analysis failed")
        return {"vendor": "fortios", "sections": [], "vlan_interfaces": [],
                "error": True}


def _analyze(text):
    root = _forti_tree(text or '')
    sections = []

    # 1) Policy
    rows = []
    for pid, n in _children(root, 'firewall policy'):
        rows.append({
            "id": pid,
            "name": _forti_set1(n, 'name'),
            "srcintf": _multi(n["sets"].get('srcintf', [])),
            "dstintf": _multi(n["sets"].get('dstintf', [])),
            "srcaddr": _multi(n["sets"].get('srcaddr', [])),
            "dstaddr": _multi(n["sets"].get('dstaddr', [])),
            "service": _multi(n["sets"].get('service', [])),
            "action": _forti_set1(n, 'action', 'deny'),
            "nat": _forti_set1(n, 'nat', 'disable'),
            "status": _forti_set1(n, 'status', 'enable'),
            "schedule": _forti_set1(n, 'schedule'),
            "logtraffic": _forti_set1(n, 'logtraffic'),
        })
    sections.append(_section(
        "policies",
        ["id", "name", "srcintf", "dstintf", "srcaddr", "dstaddr",
         "service", "action", "nat", "status", "schedule", "logtraffic"],
        rows))

    # 2) Address objects
    rows = []
    for name, n in _children(root, 'firewall address'):
        rows.append({
            "name": name,
            "type": _forti_set1(n, 'type', 'ipmask'),
            "subnet": (_ip_addr_to_cidr(n["sets"].get('subnet', []))
                       or _forti_set1(n, 'fqdn')
                       or _join(n["sets"].get('start-ip', []) + n["sets"].get('end-ip', []))),
            "comment": _forti_set1(n, 'comment'),
        })
    sections.append(_section("addresses", ["name", "type", "subnet", "comment"], rows))

    # 3) Address groups
    rows = [{"name": name, "members": _multi(n["sets"].get('member', []))}
            for name, n in _children(root, 'firewall addrgrp')]
    sections.append(_section("address_groups", ["name", "members"], rows))

    # 4) Services (custom)
    rows = []
    for name, n in _children(root, 'firewall service custom'):
        rows.append({
            "name": name,
            "protocol": _forti_set1(n, 'protocol'),
            "tcp_portrange": _multi(n["sets"].get('tcp-portrange', [])),
            "udp_portrange": _multi(n["sets"].get('udp-portrange', [])),
        })
    sections.append(_section(
        "services", ["name", "protocol", "tcp_portrange", "udp_portrange"], rows))

    # 5) Schedules (recurring + onetime)
    rows = []
    for section, kind in (('firewall schedule recurring', 'recurring'),
                          ('firewall schedule onetime', 'onetime')):
        for name, n in _children(root, section):
            rows.append({
                "name": name,
                "type": kind,
                "day": _multi(n["sets"].get('day', [])),
                "start": _forti_set1(n, 'start'),
                "end": _forti_set1(n, 'end'),
            })
    sections.append(_section("schedules", ["name", "type", "day", "start", "end"], rows))

    # 6) VIP
    rows = []
    for name, n in _children(root, 'firewall vip'):
        rows.append({
            "name": name,
            "extip": _join(n["sets"].get('extip', [])),
            "mappedip": _join(n["sets"].get('mappedip', [])),
            "extintf": _forti_set1(n, 'extintf'),
            "extport": _forti_set1(n, 'extport'),
            "mappedport": _forti_set1(n, 'mappedport'),
        })
    sections.append(_section(
        "vips", ["name", "extip", "mappedip", "extintf", "extport", "mappedport"], rows))

    # 7) IP pools
    rows = []
    for name, n in _children(root, 'firewall ippool'):
        rows.append({
            "name": name,
            "type": _forti_set1(n, 'type', 'overload'),
            "startip": _forti_set1(n, 'startip'),
            "endip": _forti_set1(n, 'endip'),
        })
    sections.append(_section("ippools", ["name", "type", "startip", "endip"], rows))

    # 8) Interfaces (+ zone)
    zone_of_iface = {}
    for zname, n in _children(root, 'system zone'):
        for member in n["sets"].get('interface', []):
            zone_of_iface[member] = zname
    rows = []
    vlan_ifaces = []
    for name, n in _children(root, 'system interface'):
        rows.append({
            "name": name,
            "ip": _forti_ip_cidr(n),
            "zone": zone_of_iface.get(name, ''),
            "vdom": _forti_set1(n, 'vdom'),
            "allowaccess": _multi(n["sets"].get('allowaccess', [])),
            "status": _forti_set1(n, 'status', 'up'),
        })
        # VLAN sub-interface: it is the FortiOS equivalent of an SVI, and it is
        # what makes a gateway sitting on the firewall deducible.
        vlanid = _forti_set1(n, 'vlanid')
        if vlanid:
            vlan_ifaces.append({
                "name": name,
                "vlan": vlanid,
                "ip": _forti_ip_cidr(n),
                "status": _forti_set1(n, 'status', 'up'),
                "parent": _forti_set1(n, 'interface'),
            })
    sections.append(_section(
        "interfaces", ["name", "ip", "zone", "vdom", "allowaccess", "status"], rows))

    # 9) VPN IPsec (phase1 + phase2 joined by phase1 name)
    p2_by_p1 = {}
    for sec in ('vpn ipsec phase2-interface', 'vpn ipsec phase2'):
        for name, n in _children(root, sec):
            p1 = _forti_set1(n, 'phase1name') or _forti_set1(n, 'phase1')
            p2_by_p1.setdefault(p1, []).append(name)
    rows = []
    for sec in ('vpn ipsec phase1-interface', 'vpn ipsec phase1'):
        for name, n in _children(root, sec):
            rows.append({
                "name": name,
                "remote_gw": _forti_set1(n, 'remote-gw'),
                "interface": _forti_set1(n, 'interface'),
                "proposal": _multi(n["sets"].get('proposal', [])),
                "phase2": _multi(p2_by_p1.get(name, [])),
            })
    sections.append(_section(
        "vpn_ipsec", ["name", "remote_gw", "interface", "proposal", "phase2"], rows))

    # 10) VPN SSL settings (key/value)
    rows = []
    ssl = _forti_get(root, 'vpn ssl settings')
    if ssl:
        for k, vals in ssl["sets"].items():
            val = _MASK if k in _SECRET_KEYS else _join(vals)
            rows.append({"key": k, "value": val})
    sections.append(_section("vpn_ssl", ["key", "value"], rows))

    # 11) Administrators
    rows = []
    for name, n in _children(root, 'system admin'):
        trusthosts = [' '.join(v) for k, v in sorted(n["sets"].items())
                      if (k.startswith('trusthost') or k.startswith('ip6-trusthost'))
                      and ' '.join(v) not in ('0.0.0.0 0.0.0.0', '::/0')]
        rows.append({
            "name": name,
            "accprofile": _forti_set1(n, 'accprofile'),
            "trusthost": _multi(trusthosts),
            "remote_auth": _forti_set1(n, 'remote-auth', 'disable'),
        })
    sections.append(_section(
        "administrators", ["name", "accprofile", "trusthost", "remote_auth"], rows))

    # 12) Authentication (radius/tacacs+/ldap/fsso + user group with SSO flag)
    rows = []
    for section, kind in (('user radius', 'radius'),
                          ('user tacacs+', 'tacacs+'),
                          ('user ldap', 'ldap'),
                          ('user fsso', 'fsso')):
        for name, n in _children(root, section):
            rows.append({
                "name": name,
                "kind": kind,
                # A list even when the value is a single one: the same column
                # hosts the members of a group, and two different types in the same
                # column is an error that awaits the right data.
                "server": _multi(_forti_set1(n, 'server')
                                 or _forti_set1(n, 'primary-server')
                                 or _forti_set1(n, 'host')),
                "sso": "yes" if kind == 'fsso' else "",
            })
    for name, n in _children(root, 'user group'):
        gtype = _forti_set1(n, 'group-type')
        rows.append({
            "name": name,
            "kind": "group",
            "server": _multi(n["sets"].get('member', [])),
            "sso": "yes" if 'fsso' in gtype.lower() else "",
        })
    sections.append(_section(
        "authentication", ["name", "kind", "server", "sso"], rows))

    return {"vendor": "fortios", "sections": sections,
            "vlan_interfaces": vlan_ifaces}
