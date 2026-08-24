# -*- coding: utf-8 -*-
"""Last-known AP inventory, written by the WLC tab and read by the export.

CDP/LLDP makes an access point visible but advertises no serial number; only
the controller knows it. Querying every controller during an export would put
SSH back inside a request, so the WLC tab writes what it saw and the export
only ever reads this file.
"""
import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional

from core import data_config

_lock = threading.Lock()


def _path() -> str:
    return data_config.get_path("ap_inventory.json")


def normalize_ap_name(name: str) -> str:
    """Match key for an AP name.

    CDP announces the access point with whatever hostname it carries, which may
    be an FQDN in a different case from the controller's short AP name.
    """
    return (name or "").strip().lower().split(".")[0]


def read_all() -> dict:
    """Load the whole store. Public so a caller that resolves many AP names
    (e.g. an export row loop) can read the file once instead of once per row."""
    try:
        with open(_path(), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def record_aps(wlc_ip: str, tenant: str, aps: list) -> int:
    """Store the serials this controller just reported.

    Entries of OTHER controllers are left alone: two controllers own different
    access points, and a visit to one must not erase what the other reported.
    An AP with no serial is skipped rather than stored empty -- an entry here
    is a claim to know the serial.

    A harvest that carried no serial at all (inventory command failed, no
    privilege, ...) writes nothing: an empty result must not erase what this
    same controller already reported on a previous visit.
    """
    if not any((ap.get("serial") or "").strip() for ap in aps or []):
        return 0

    seen_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _lock:
        store = {k: v for k, v in read_all().items()
                 if (v or {}).get("wlc_ip") != wlc_ip}
        written = 0
        for ap in aps or []:
            serial = (ap.get("serial") or "").strip()
            name = normalize_ap_name(ap.get("name", ""))
            if not name or not serial:
                continue
            ip = (ap.get("ip") or "").strip()
            mac = (ap.get("mac") or "").strip()
            entry = {
                "serial": serial,
                "model": (ap.get("model") or "").strip(),
                "ip": ip,
                "mac": mac,
                "wlc_ip": wlc_ip,
                "tenant": tenant,
                "seen_at": seen_at,
            }
            store[name] = entry
            if ip:
                store[f"ip:{ip}"] = entry
            # Also index stripped short names (e.g. "gc-ap01" -> "ap01")
            parts = name.split("-")
            if len(parts) > 1 and parts[-1]:
                store.setdefault(parts[-1], entry)
                store.setdefault("-".join(parts[1:]), entry)
            written += 1
        tmp = _path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2)
        os.replace(tmp, _path())
    return written


def lookup_in(store: dict, ap_name: str, tenant: Optional[str] = None, ip: Optional[str] = None) -> Optional[dict]:
    """Resolve an AP name or IP against an already-loaded store dict (see
    read_all()), optionally scoped to a tenant.

    Passing a tenant requires the stored entry's tenant to match (or be
    Generale/unscoped), so an AP name that collides across two distinct tenants
    never hands one customer another's serial.
    """
    def _allowed(ent: Optional[dict]) -> bool:
        if ent is None:
            return False
        if tenant is None:
            return True
        ent_t = ent.get("tenant")
        if ent_t == tenant or ent_t in ("Generale", "", None) or tenant in ("Generale", "", None):
            return True
        return False

    # 1. Exact normalized name
    norm = normalize_ap_name(ap_name)
    entry = store.get(norm)
    if _allowed(entry):
        return entry

    # 2. Match by IP if provided
    if ip:
        ip_entry = store.get(f"ip:{ip.strip()}")
        if _allowed(ip_entry):
            return ip_entry

    # 3. Match without prefix or suffix (e.g. "GC-AP04-VOLTA" matching "AP04-VOLTA")
    parts = norm.split("-")
    if len(parts) > 1:
        for sub in ("-".join(parts[1:]), parts[-1]):
            entry = store.get(sub)
            if _allowed(entry):
                return entry

    # 4. Search in store for substring / suffix matches
    clean_norm = norm.replace("-", "").replace("_", "")
    for k, ent in store.items():
        if k.startswith("ip:") or k.startswith("mac:"):
            continue
        clean_k = k.replace("-", "").replace("_", "")
        if clean_k and (clean_k in clean_norm or clean_norm in clean_k):
            if _allowed(ent):
                return ent

    return None


def lookup(ap_name: str, tenant: Optional[str] = None, ip: Optional[str] = None) -> Optional[dict]:
    return lookup_in(read_all(), ap_name, tenant, ip=ip)
