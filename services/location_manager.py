# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Physical locations of an organization (spec 2026-10-09
organizations-locations). A location belongs to exactly one organization (the
tenant key), owns the subnets that probes used to carry, and names a default
probe that prefills new devices. Ids are immutable slugs, like tenant keys."""
import ipaddress
import json
import threading

from core import data_config

ROLES = ("hq", "branch", "datacenter", "warehouse", "other")
_lock = threading.RLock()


def _load() -> dict:
    from services import inventory_manager, inventory_store
    with inventory_manager._db() as conn:
        return inventory_store.read_locations(conn)


def _save(data: dict) -> None:
    from services import inventory_manager, inventory_store
    with inventory_manager._db() as conn:
        inventory_store.write_locations(conn, data)


def _clean_subnets(subnets) -> list:
    out = []
    for raw in subnets or []:
        raw = str(raw).strip()
        if not raw:
            continue
        try:
            out.append(str(ipaddress.ip_network(raw, strict=False)))
        except ValueError:
            raise ValueError(f"Subnet non valida: {raw}")
    return sorted(set(out))


def _check(org=None, role=None, probe=None) -> None:
    # Local imports: probe_manager._public calls back into this module.
    from services import inventory_manager, probe_manager
    if org is not None and org not in inventory_manager.get_all_groups():
        raise ValueError(f"Organizzazione '{org}' inesistente.")
    if role is not None and role not in ROLES:
        raise ValueError(f"Ruolo non valido: {role}")
    if probe is not None and not probe_manager.get_probe(probe):
        raise ValueError(f"Sonda '{probe}' inesistente.")


def list_locations(org=None) -> list:
    with _lock:
        data = _load()
    return [dict(v, id=k) for k, v in sorted(data.items())
            if org is None or v.get("org") == org]


def get_location(loc_id: str):
    with _lock:
        v = _load().get(loc_id)
    return dict(v, id=loc_id) if v else None


def create_location(org, name, role="branch", subnets=None, probe="central") -> dict:
    from services.probe_manager import _slugify
    name = (name or "").strip()
    if not name:
        raise ValueError("Il nome della sede è obbligatorio.")
    _check(org=org, role=role, probe=probe)
    clean = _clean_subnets(subnets)
    with _lock:
        data = _load()
        base = _slugify(name)
        loc_id, n = base, 2
        while loc_id in data:
            loc_id, n = f"{base}-{n}", n + 1
        data[loc_id] = {"org": org, "name": name, "role": role,
                        "subnets": clean, "probe": probe}
        _save(data)
    return dict(data[loc_id], id=loc_id)


def update_location(loc_id, name=None, role=None, subnets=None, probe=None) -> dict:
    _check(role=role, probe=probe)
    clean = _clean_subnets(subnets) if subnets is not None else None
    with _lock:
        data = _load()
        if loc_id not in data:
            raise ValueError(f"Sede '{loc_id}' inesistente.")
        loc = data[loc_id]
        if name is not None:
            if not name.strip():
                raise ValueError("Il nome della sede è obbligatorio.")
            loc["name"] = name.strip()
        if role is not None:
            loc["role"] = role
        if clean is not None:
            loc["subnets"] = clean
        if probe is not None:
            loc["probe"] = probe
        _save(data)
    return dict(loc, id=loc_id)


def devices_in(loc_id: str) -> int:
    """Devices referencing the location, active and decommissioned: a
    decommissioned row can be reactivated, so it still needs its location."""
    from services import inventory_manager
    rows = inventory_manager.get_all_devices() + inventory_manager.get_decommissioned_devices()
    return sum(1 for d in rows if d.get("Location") == loc_id)


def delete_location(loc_id: str) -> None:
    n = devices_in(loc_id)
    if n:
        raise ValueError(f"La sede contiene {n} apparati: spostali o eliminali prima.")
    with _lock:
        data = _load()
        data.pop(loc_id, None)
        _save(data)


def probe_subnets(probe_id) -> list:
    with _lock:
        data = _load()
    return sorted({s for v in data.values() if v.get("probe") == probe_id
                   for s in v.get("subnets") or []})


def apply_probe_to_devices(loc_id: str) -> int:
    """«Applica a tutti i device della sede»: the location's probe onto its
    devices. Explicit, never implicit — a device's probe is its own column."""
    from services import inventory_manager
    loc = get_location(loc_id)
    if not loc:
        raise ValueError(f"Sede '{loc_id}' inesistente.")
    with inventory_manager._io_lock:
        rows = inventory_manager.get_all_devices()
        n = 0
        for d in rows:
            if d.get("Location") == loc_id and d.get("Probe") != loc["probe"]:
                d["Probe"] = loc["probe"]
                n += 1
        if n:
            inventory_manager.safe_write_hosts_csv(rows)
    return n
