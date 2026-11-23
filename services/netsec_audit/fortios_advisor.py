# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The live FortiGate advisor, run on a configuration backup.

``fortigate_service.advise`` holds the rules and reads REST-shaped rows. This
module only turns FortiOS config text into those rows, so a backup and a live
unit get the same recommendations from the same code.

Neither ``parser.parse_with_lines`` nor ``fw_analyzers.fortios._forti_tree``
fits: both file ``config`` and ``edit`` children under one key, and the
advisor needs the REST shapes, where a ``config`` sub-block is a dict
(``https`` of an SSL/SSH profile) and a block of ``edit`` entries is a list
(``entries`` of an IPS sensor, ``filters`` of a web filter).
"""

from typing import Any, Dict, List, Optional

from fw_analyzers.fortios import _forti_tokens
from services.fortigate_hw_profiles import detect_from_config

# Live-only checks: a backup carries no traffic counters, so policy order by
# volume (ADV-ORDER) cannot be judged from it. ``advise`` reads absent bytes
# as 0 and never fires it; the result says so instead of staying silent.
LIVE_ONLY = ["ADV-ORDER"]

# Config path of each family ``advise`` reads, as in the REST cmdb paths.
_FAMILY_PATHS = {
    "ips": "ips sensor",
    "ssl_ssh": "firewall ssl-ssh-profile",
    "antivirus": "antivirus profile",
    "application": "application list",
    "webfilter": "webfilter profile",
    "dnsfilter": "dnsfilter profile",
    # Read only for their feature-set; an absent section is an empty family.
    "emailfilter": "emailfilter profile",
    "dlp": "dlp profile",
    "file_filter": "file-filter profile",
}

# A full-configuration dump prints every system global key (several hundred on
# 7.x); a normal backup only the changed ones, a few dozen at most.
_FULL_GLOBAL_KEYS = 80


def parse_tree(text: Optional[str]) -> Dict[str, Any]:
    """FortiOS config text as nested REST-like values.

    ``config X`` becomes a dict, or a list when its children are ``edit``
    entries; each entry is a dict carrying its edit key under ``_key``.
    ``set k v`` is a str for one value, a list of str otherwise. Quotes are
    stripped. Malformed nesting is skipped, never raised, like the other
    FortiOS parsers here."""
    root: Dict[str, Any] = {}
    # (node, parent, key in parent): a config block turns into a list in its
    # parent the moment its first edit shows up.
    stack: List[tuple] = [(root, None, None)]
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        low = s.lower()
        node, parent, key = stack[-1]
        if low.startswith("config "):
            name = s[7:].strip().strip('"')
            child = node.get(name) if isinstance(node, dict) else None
            if not isinstance(child, (dict, list)):
                child = {}
                if isinstance(node, dict):
                    node[name] = child
            stack.append((child, node, name))
        elif low.startswith("edit "):
            if isinstance(node, dict) and not node and isinstance(parent, dict):
                node = []
                parent[key] = node
                stack[-1] = (node, parent, key)
            ek = s[5:].strip().strip('"')
            # Re-editing a key re-enters its entry, as FortiOS does: a
            # multi-VDOM backup declares the VDOMs in a first ``config vdom``
            # and fills them in a second one.
            found = [e for e in node if e.get("_key") == ek] if isinstance(node, list) else []
            entry: Dict[str, Any] = found[0] if found else {"_key": ek}
            if isinstance(node, list) and not found:
                node.append(entry)
            stack.append((entry, node, None))
        elif low in ("next", "end"):
            if len(stack) > 1:
                stack.pop()
        elif low.startswith("set ") and isinstance(node, dict):
            toks = _forti_tokens(s)
            if len(toks) >= 2:
                vals = toks[2:]
                node[toks[1].lower()] = vals[0] if len(vals) == 1 else vals
    return root


def _entries(tree: Dict[str, Any], path: str) -> List[Dict[str, Any]]:
    rows = tree.get(path)
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def _is_full_config(glob: Any, policies: List[Dict[str, Any]]) -> bool:
    """True for a ``show full-configuration`` dump.

    Policies first: ``set status enable`` is the default, so a normal backup
    never writes it while a full dump writes it on every enabled policy
    (``disable`` shows up in both, so it proves nothing). No enabled policy:
    the size of ``system global``, which a full dump prints whole. A key that
    happens to be default-valued (admintimeout, language) is no marker: an
    admin can set it and a normal backup then carries it too."""
    if any(str(p.get("status") or "").lower() == "enable" for p in policies):
        return True
    return isinstance(glob, dict) and len(glob) >= _FULL_GLOBAL_KEYS


def _wan_names(ifaces: List[Dict[str, Any]]) -> set:
    """Same WAN resolution as the live path: role wan, else conventional names."""
    names = [(str(e["_key"]).lower(), str(e.get("role") or "").lower()) for e in ifaces]
    by_role = {n for n, role in names if role == "wan"}
    return {"virtual-wan-link"} | (
        by_role or {n for n, _r in names if n.startswith("wan") or n == "port1"})


def _scope_inputs(scope: Dict[str, Any]) -> tuple:
    """Policies, VIP name -> mapping and profiles of one scope (whole file or
    one VDOM). A VIP group has no mapping of its own."""
    from services.fortigate_service import _vip_mapping
    policies = [{**e, "policyid": e["_key"]} for e in _entries(scope, "firewall policy")]
    vip_names = {str(e["_key"]).strip().lower(): _vip_mapping(e) if path == "firewall vip" else ""
                 for path in ("firewall vip", "firewall vipgrp")
                 for e in _entries(scope, path)}
    profiles = {fam: [{**e, "name": e["_key"]} for e in _entries(scope, path)]
                for fam, path in _FAMILY_PATHS.items()}
    return policies, vip_names, profiles


def backup_advisor(config_text: str, lang: str = "it") -> Dict[str, Any]:
    """Advisor recommendations for a FortiOS backup, same shape as the live data.

    A multi-VDOM backup runs ``advise`` once per VDOM, on that VDOM's
    sections and on the interfaces ``config global`` assigns to it; each
    recommendation then carries its ``vdom`` and an id prefixed with it."""
    from services.fortigate_service import advise, merge_vdom_advice

    tree = parse_tree(config_text)
    hw = detect_from_config(config_text)
    # A VDOM entry with nothing but its key is only the declaration list.
    vdoms = [e for e in _entries(tree, "vdom") if len(e) > 1]
    if not vdoms:
        policies, vip_names, profiles = _scope_inputs(tree)
        data = advise(policies, vip_names, profiles, {},
                      _wan_names(_entries(tree, "system interface")), hw, lang, {})
        data["source"] = {
            "kind": "backup",
            "full_config": _is_full_config(tree.get("system global"), policies),
            "vdoms": [],
            "live_only": LIVE_ONLY,
        }
        return data

    glob = tree.get("global") if isinstance(tree.get("global"), dict) else {}
    ifaces = _entries(glob, "system interface")
    all_policies: List[Dict[str, Any]] = []
    per = []
    for vd in vdoms:
        name = str(vd["_key"])
        policies, vip_names, profiles = _scope_inputs(vd)
        own = [i for i in ifaces if str(i.get("vdom") or "").lower() == name.lower()]
        per.append((name, advise(policies, vip_names, profiles, {}, _wan_names(own),
                                 hw, lang, {})))
        all_policies += policies
    data = merge_vdom_advice(per)
    data["source"] = {
        "kind": "backup",
        "full_config": _is_full_config(glob.get("system global"), all_policies),
        "vdoms": [str(vd["_key"]) for vd in vdoms],
        "live_only": LIVE_ONLY,
    }
    return data
