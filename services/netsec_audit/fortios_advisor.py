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
            entry: Dict[str, Any] = {"_key": s[5:].strip().strip('"')}
            if isinstance(node, list):
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


def _is_full_config(tree: Dict[str, Any], policies: List[Dict[str, Any]]) -> bool:
    """True for a ``show full-configuration`` dump.

    Policies first: ``set status enable`` is the default, so a normal backup
    never writes it while a full dump writes it on every enabled policy
    (``disable`` shows up in both, so it proves nothing). No enabled policy:
    the size of ``system global``, which a full dump prints whole. A key that happens to be default-valued (admintimeout,
    language) is no marker: an admin can set it and a normal backup then
    carries it too."""
    if any(str(p.get("status") or "").lower() == "enable" for p in policies):
        return True
    glob = tree.get("system global")
    return isinstance(glob, dict) and len(glob) >= _FULL_GLOBAL_KEYS


def backup_advisor(config_text: str, lang: str = "it") -> Dict[str, Any]:
    """Advisor recommendations for a FortiOS backup, same shape as the live data.

    Only top-level sections are read, as the audit rules do
    (``rules.section_entries``): a multi-VDOM backup keeps its policies under
    ``config vdom`` and yields none here; ``source.multi_vdom`` says so."""
    from services.fortigate_service import advise

    tree = parse_tree(config_text)
    policies = [{**e, "policyid": e["_key"]} for e in _entries(tree, "firewall policy")]
    vip_names = {str(e["_key"]).strip().lower()
                 for path in ("firewall vip", "firewall vipgrp")
                 for e in _entries(tree, path)}
    profiles = {fam: [{**e, "name": e["_key"]} for e in _entries(tree, path)]
                for fam, path in _FAMILY_PATHS.items()}

    # Same WAN resolution as the live path: role wan, else conventional names.
    names = [(str(e["_key"]).lower(), str(e.get("role") or "").lower())
             for e in _entries(tree, "system interface")]
    by_role = {n for n, role in names if role == "wan"}
    wan_names = {"virtual-wan-link"} | (
        by_role or {n for n, _r in names if n.startswith("wan") or n == "port1"})

    data = advise(policies, vip_names, profiles, {}, wan_names,
                  detect_from_config(config_text), lang, {})
    data["source"] = {
        "kind": "backup",
        "full_config": _is_full_config(tree, policies),
        "multi_vdom": "vdom" in tree and "firewall policy" not in tree,
        "live_only": LIVE_ONLY,
    }
    return data
