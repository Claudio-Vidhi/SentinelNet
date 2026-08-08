# -*- coding: utf-8 -*-
"""PAN-OS (Palo Alto) firewall analyzer in ``set`` CLI format.

Exposes ``analyze(text)`` which returns the generic envelope
``{"vendor": "panos", "sections": [...]}``. Contains the parsing primitives for
``set`` lines (``_panos_tokens``/``_panos_lines``/``_panos_collect`` & co.),
reused by the converters in ``config_analyzer`` (which re-imports them from here).

Known limitation (v1): ONLY the ``set`` CLI format is supported. PAN-OS configs
exported as XML are not handled (out of scope).

Pure and tolerant: ``analyze`` NEVER raises exceptions.
"""
import logging
import re

logger = logging.getLogger(__name__)

_SECRET_ATTRS = {'phash', 'passphrase', 'secret', 'pre-shared-key', 'password'}
_MASK = '***REDACTED***'

_PANOS_TOKEN = re.compile(r'"[^"]*"|\S+')


def _panos_tokens(s):
    """Tokenizes a PAN-OS 'set' line, respecting quoted strings."""
    return [t[1:-1] if t.startswith('"') and t.endswith('"') and len(t) >= 2 else t
            for t in _PANOS_TOKEN.findall(s)]


def _panos_lines(text):
    """Returns [(tokens-after-'set', raw-line), ...] for every PAN-OS line
    that starts with 'set '. Tolerant of blank lines/comments."""
    out = []
    for raw in (text or '').splitlines():
        s = raw.strip()
        if not s or not s.lower().startswith('set '):
            continue
        out.append((_panos_tokens(s[4:]), s))
    return out


def _panos_collect(lines, prefix):
    """Groups lines whose path starts with 'prefix' (tuple of tokens) and
    has a name right after (e.g. prefix=('address',) on 'set address NAME ip-netmask X').
    Returns {name: {"parts": [[rest-token...], ...], "raw": [line, ...]}}."""
    out = {}
    n = len(prefix)
    for toks, raw in lines:
        if len(toks) <= n or tuple(t.lower() for t in toks[:n]) != prefix:
            continue
        name = toks[n]
        rest = toks[n + 1:]
        entry = out.setdefault(name, {"parts": [], "raw": []})
        if rest:
            entry["parts"].append(rest)
        entry["raw"].append(raw)
    return out


def _panos_attr(entry, attr):
    """First value associated with attribute 'attr' among the collected 'parts'
    (e.g. parts=[['from','LAN'], ['action','allow']], attr='action' -> 'allow')."""
    for p in entry["parts"]:
        if p and p[0].lower() == attr and len(p) > 1:
            return p[1]
    return ''


def _panos_attr_all(entry, attr):
    """All values associated with attribute 'attr' (one line per value)."""
    return [p[1] for p in entry["parts"] if p and p[0].lower() == attr and len(p) > 1]


# --- Envelope helpers --------------------------------------------------------

def _values(entry, *path):
    """Extracts the values after 'path' (sequence of tokens) from a _panos_collect
    entry, handling lists in square brackets '[ a b c ]' and single values.
    Returns a (flat) list of strings."""
    plen = len(path)
    low = tuple(p.lower() for p in path)
    out = []
    for part in entry["parts"]:
        if len(part) <= plen or tuple(t.lower() for t in part[:plen]) != low:
            continue
        rest = part[plen:]
        if rest and rest[0] == '[':
            for tok in rest[1:]:
                if tok == ']':
                    break
                out.append(tok)
        else:
            out.extend(rest)
    return out


def _first(entry, *path):
    vals = _values(entry, *path)
    return vals[0] if vals else ''


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


def analyze(text):
    """PAN-OS (set-CLI) -> generic sectioned envelope. Pure and tolerant."""
    try:
        return _analyze(text)
    except Exception:
        # See fortios.analyze: an empty envelope alone cannot be told apart
        # from a clean config, so a crash must be marked as such.
        logger.exception("PAN-OS analysis failed")
        return {"vendor": "panos", "sections": [], "error": True}


def _analyze(text):
    lines = _panos_lines(text or '')
    sections = []

    # 1) Address objects
    rows = []
    for name, e in _panos_collect(lines, ('address',)).items():
        atype, val = 'ip-netmask', _first(e, 'ip-netmask')
        if not val:
            for t in ('ip-range', 'fqdn', 'ip-wildcard'):
                v = _first(e, t)
                if v:
                    atype, val = t, v
                    break
        rows.append({"name": name, "type": atype, "value": val})
    sections.append(_section("addresses", ["name", "type", "value"], rows))

    # 2) Address groups
    rows = []
    for name, e in _panos_collect(lines, ('address-group',)).items():
        members = _values(e, 'static') or _values(e, 'dynamic', 'filter')
        rows.append({"name": name, "members": _multi(members)})
    sections.append(_section("address_groups", ["name", "members"], rows))

    # 3) Services
    rows = []
    for name, e in _panos_collect(lines, ('service',)).items():
        proto = 'tcp' if _values(e, 'protocol', 'tcp') else (
            'udp' if _values(e, 'protocol', 'udp') else '')
        port = _first(e, 'protocol', 'tcp', 'port') or _first(e, 'protocol', 'udp', 'port')
        rows.append({"name": name, "protocol": proto, "port": port})
    sections.append(_section("services", ["name", "protocol", "port"], rows))

    # 4) Service groups
    rows = []
    for name, e in _panos_collect(lines, ('service-group',)).items():
        rows.append({"name": name, "members": _multi(_values(e, 'members'))})
    sections.append(_section("service_groups", ["name", "members"], rows))

    # 5) Security rules
    rows = []
    for name, e in _panos_collect(lines, ('rulebase', 'security', 'rules')).items():
        rows.append({
            "name": name,
            "from": _multi(_values(e, 'from')),
            "to": _multi(_values(e, 'to')),
            "source": _multi(_values(e, 'source')),
            "destination": _multi(_values(e, 'destination')),
            "application": _multi(_values(e, 'application')),
            "service": _multi(_values(e, 'service')),
            "action": _first(e, 'action'),
        })
    sections.append(_section(
        "security_rules",
        ["name", "from", "to", "source", "destination", "application", "service", "action"],
        rows))

    # 6) NAT rules
    rows = []
    for name, e in _panos_collect(lines, ('rulebase', 'nat', 'rules')).items():
        translation = (_first(e, 'source-translation', 'dynamic-ip-and-port', 'translated-address')
                       or _first(e, 'source-translation', 'static-ip', 'translated-address')
                       or _first(e, 'destination-translation', 'translated-address'))
        rows.append({
            "name": name,
            "from": _multi(_values(e, 'from')),
            "to": _multi(_values(e, 'to')),
            "source": _multi(_values(e, 'source')),
            "destination": _multi(_values(e, 'destination')),
            "service": _first(e, 'service'),
            "translation": translation,
        })
    sections.append(_section(
        "nat_rules",
        ["name", "from", "to", "source", "destination", "service", "translation"],
        rows))

    # 7) Zones
    rows = []
    for name, e in _panos_collect(lines, ('zone',)).items():
        ifaces = (_values(e, 'network', 'layer3') or _values(e, 'network', 'layer2')
                  or _values(e, 'network', 'tap'))
        rows.append({"name": name, "interfaces": _multi(ifaces)})
    sections.append(_section("zones", ["name", "interfaces"], rows))

    # 8) VPN (IKE gateway + tunnel IPsec)
    rows = []
    for name, e in _panos_collect(lines, ('network', 'ike', 'gateway')).items():
        rows.append({
            "name": name,
            "kind": "ike-gateway",
            "peer": (_first(e, 'peer-address', 'ip') or _first(e, 'peer-address', 'fqdn')),
            "interface": _first(e, 'local-address', 'interface'),
        })
    for name, e in _panos_collect(lines, ('network', 'tunnel', 'ipsec')).items():
        rows.append({
            "name": name,
            "kind": "ipsec-tunnel",
            "peer": _first(e, 'auto-key', 'ike-gateway'),
            "interface": _first(e, 'tunnel-interface'),
        })
    sections.append(_section("vpn_ipsec", ["name", "kind", "peer", "interface"], rows))

    # 9) Administrators
    rows = []
    for name, e in _panos_collect(lines, ('mgt-config', 'users')).items():
        role = (_first(e, 'permissions', 'role-based', 'superuser')
                and 'superuser') or _first(e, 'permissions', 'role-based', 'custom', 'profile')
        rows.append({"name": name, "role": role or 'custom'})
    sections.append(_section("administrators", ["name", "role"], rows))

    # 10) Authentication (authentication-profile + server-profile)
    rows = []
    for name, e in _panos_collect(lines, ('shared', 'authentication-profile')).items():
        rows.append({"name": name, "kind": "auth-profile",
                     "server": _first(e, 'method')})
    for proto in ('radius', 'tacplus', 'ldap'):
        for name, e in _panos_collect(lines, ('shared', 'server-profile', proto)).items():
            server = _panos_server_addr(e) or _first(e, 'server')
            rows.append({"name": name, "kind": proto, "server": server})
    sections.append(_section("authentication", ["name", "kind", "server"], rows))

    return {"vendor": "panos", "sections": sections}


def _panos_server_addr(entry):
    """PAN-OS: 'server <SRV> address <IP>' or 'server <SRV> ip-address <IP>'.
    Returns the first address found among the parts."""
    for p in entry["parts"]:
        if len(p) >= 4 and p[0].lower() == 'server' and p[2].lower() in ('address', 'ip-address', 'host'):
            return p[3]
    return ''
