# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The probe agent's local device policy (ADR-0009).

Lives in the agent's data directory and is edited only on the agent host:
no RPC, heartbeat field or pushed record writes to it. Format::

    {"allowed_subnets": ["10.20.0.0/24"],   # the only addresses the agent dials
     "change": ["10.20.0.1/32"],            # where configuration changes may run
     "bootstrap": true}                     # written by the agent, not reviewed yet

Nothing is installed in the central process, so there every check is a no-op
except allows_change(), which only the agent's job runner calls.
"""

import ipaddress
import json
import os

POLICY_FILE = "device_policy.json"

_active = None   # {"allowed": [networks], "change": [networks], "state": str, "path": str}


def _networks(values, path: str, key: str) -> list:
    if not isinstance(values, list):
        raise ValueError(f"{path}: '{key}' deve essere una lista di subnet.")
    try:
        return [ipaddress.ip_network(str(v).strip(), strict=False) for v in values]
    except ValueError as e:
        raise ValueError(f"{path}: subnet non valida in '{key}': {e}") from e


def load_or_bootstrap(data_dir: str, inventory_ips) -> dict:
    """Read the policy, or write the bootstrap one: a /32 per address already
    in the local inventory, no change grants. A broken file stops the agent
    (ValueError) rather than running without a boundary."""
    path = os.path.join(data_dir, POLICY_FILE)
    if not os.path.exists(path):
        ips = sorted({ip for ip in inventory_ips if ip})
        data = {"allowed_subnets": [f"{ip}/32" for ip in ips], "change": [], "bootstrap": True}
        os.makedirs(data_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    with open(path, encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except ValueError as e:
            raise ValueError(f"{path}: JSON non valido: {e}") from e
    return {"allowed": _networks(data.get("allowed_subnets", []), path, "allowed_subnets"),
            "change": _networks(data.get("change", []), path, "change"),
            "state": "bootstrap" if data.get("bootstrap") else "reviewed",
            "path": path}


def install(policy) -> None:
    global _active
    _active = policy


def _inside(ip: str, networks: list) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return any(addr in n for n in networks)


def allows_address(ip: str) -> bool:
    """May a credential be presented to this address? Always yes off-agent."""
    return _active is None or _inside(ip, _active["allowed"])


def allows_change(ip: str) -> bool:
    """May a configuration change run on this device? Only an agent policy
    grants it, and only inside allowed_subnets too."""
    return _active is not None and _inside(ip, _active["change"]) \
        and _inside(ip, _active["allowed"])


def summary() -> dict:
    """What the heartbeat reports upward: counts and state, not the subnets."""
    if _active is None:
        return {"state": "none"}
    return {"state": _active["state"], "allowed_subnets": len(_active["allowed"]),
            "change": len(_active["change"])}
