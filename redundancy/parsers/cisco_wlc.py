# -*- coding: utf-8 -*-
"""Cisco wireless controller HA (SSO) from the CLI backup.

Two platforms, two different outputs:

- **AireOS** (5508/8540 and friends) answers ``show redundancy summary`` with a
  flat key = value block. It reports the pair from the point of view of the
  box we asked: our own state and the peer's, no per-chassis table.
- **Catalyst 9800** (IOS-XE) answers ``show chassis`` with one row per chassis
  -- the richest source, so it wins when present -- and ``show redundancy``
  with a "Current Processor" / "Peer Processor" pair as the fallback.

A controller with SSO disabled is not a group: the parsers return None so the
caller dissolves any group previously detected for that device.
"""
import re
from typing import Optional

# Roles and states use the vocabulary of redundancy.models.
_AIREOS_STATE = {
    "active": ("active", "ready"),
    "standby hot": ("standby", "standby_hot"),
    "standby": ("standby", "standby_hot"),
}

_IOSXE_STATE = {
    "active": ("active", "ready"),
    "standby hot": ("standby", "standby_hot"),
    "standby cold": ("standby", "down"),
    "disabled": ("standby", "down"),
}

_CHASSIS_STATE = {
    "ready": "ready",
    "progressing": "ready",
    "v-mismatch": "version_mismatch",
    "version mismatch": "version_mismatch",
    "removed": "down",
}


def _section(content: str, tag: str) -> Optional[str]:
    """The block appended to the backup under '--- <TAG> ---'."""
    sec = re.search(rf"--- {tag} ---\s*\n(.*?)(?=\n--- |\n===|\Z)",
                    content, re.DOTALL | re.IGNORECASE)
    return sec.group(1) if sec else None


def _kv(block: str, key: str) -> Optional[str]:
    """Value of a 'Key = Value' line, whatever the padding around it."""
    m = re.search(rf"^[ \t]*{key}[ \t]*=[ \t]*(.+?)[ \t]*$",
                  block, re.MULTILINE | re.IGNORECASE)
    return m.group(1).strip() if m else None


def parse_aireos_sso(content: str) -> Optional[list[dict]]:
    """Members of an AireOS HA SSO pair, or None when it is standalone.

    Expected shape (Cisco documentation):

        Redundancy Mode = SSO ENABLED
             Local State = ACTIVE
              Peer State = STANDBY HOT
                    Unit = Primary
         Redundancy Port = UP
    """
    block = _section(content, "SHOW REDUNDANCY SUMMARY")
    if not block:
        return None
    mode = (_kv(block, "Redundancy Mode") or "").lower()
    # "SSO ENABLED" is the only mode that makes a pair. Anything else -- most
    # often "SSO DISABLED" -- is a single controller.
    if "enabled" not in mode:
        return None

    members = []
    for idx, (key, label) in enumerate(
            (("Local State", "local"), ("Peer State", "peer")), start=1):
        raw = (_kv(block, key) or "").strip().lower()
        if not raw or raw in ("n/a", "none", "disabled", "unknown"):
            # A peer that never came up leaves the group with one member,
            # which compute_health reports as degraded rather than healthy.
            continue
        role, state = _AIREOS_STATE.get(raw, ("unknown", "unknown"))
        members.append({
            "member_index": idx,
            "role": role,
            "state": state,
            "serial": None,
            "model": None,
            "details": {"unit": label},
        })
    return members or None


def _parse_show_chassis(content: str) -> Optional[list[dict]]:
    """
        Chassis#  Role     Mac Address     Priority Version State          IP
        *1        Active   aabb.ccdd.eeff     1      V02    Ready      192.0.2.1
         2        Standby  aabb.ccdd.ee00     2      V02    Ready      192.0.2.2
    """
    block = _section(content, "SHOW CHASSIS")
    if not block:
        return None
    members = []
    for m in re.finditer(
        r"^[ \t]*\*?[ \t]*(\d+)[ \t]+(Active|Standby|Member)[ \t]+"
        r"([0-9a-fA-F.:]{12,17})[ \t]+\S+[ \t]+\S+[ \t]+"
        r"(Ready|Progressing|V-Mismatch|Version Mismatch|Removed)"
        r"(?:[ \t]+(\d{1,3}(?:\.\d{1,3}){3}))?[ \t]*$",
        block, re.MULTILINE | re.IGNORECASE,
    ):
        role_raw = m.group(2).lower()
        members.append({
            "member_index": int(m.group(1)),
            "role": "active" if role_raw == "active" else "standby",
            "state": _CHASSIS_STATE.get(m.group(4).lower(), "unknown"),
            "serial": None,
            "model": None,
            "details": {"mac": m.group(3), "mgmt_ip": m.group(5)},
        })
    # One chassis is a standalone controller, not a pair.
    return members if len(members) >= 2 else None


def _parse_show_redundancy(content: str) -> Optional[list[dict]]:
    """
        Operating Redundancy Mode = sso
        Current Processor Information :
                Current Software state = ACTIVE
        Peer Processor Information :
                Current Software state = STANDBY HOT
    """
    block = _section(content, "SHOW REDUNDANCY")
    if not block:
        return None
    mode = (_kv(block, "Operating Redundancy Mode") or "").lower()
    if "sso" not in mode:
        return None

    # Two "Current Software state" lines: the first belongs to the processor we
    # are talking to, the second to its peer. Splitting on the peer heading
    # keeps them apart even when a box prints extra fields between them.
    parts = re.split(r"Peer Processor Information[ \t]*:", block, maxsplit=1,
                     flags=re.IGNORECASE)
    members = []
    for idx, part in enumerate(parts, start=1):
        raw = (_kv(part, "Current Software state") or "").strip().lower()
        if not raw:
            continue
        role, state = _IOSXE_STATE.get(raw, ("unknown", "unknown"))
        members.append({
            "member_index": idx,
            "role": role,
            "state": state,
            "serial": None,
            "model": None,
            "details": {},
        })
    return members or None


def parse_iosxe_sso(content: str) -> Optional[list[dict]]:
    """Members of a Catalyst 9800 HA pair, or None when it is standalone.

    'show chassis' first -- it names every chassis with its own role and
    state -- then 'show redundancy' as the fallback for a box that does not
    answer the former.
    """
    return _parse_show_chassis(content) or _parse_show_redundancy(content)


# Vendor key in the inventory -> parser. The keys are the ones
# core.core_engine.DRIVER_REGISTRY uses for the two controller families.
SSO_PARSERS = {
    "cisco_wlc": parse_aireos_sso,
    "cisco_9800": parse_iosxe_sso,
}


def parse_wlc_sso(content: str, vendor: str) -> Optional[list[dict]]:
    """HA members of a wireless controller, or None if it is not a pair (or
    the vendor is not a controller)."""
    parser = SSO_PARSERS.get(str(vendor or "").lower())
    return parser(content) if parser else None
