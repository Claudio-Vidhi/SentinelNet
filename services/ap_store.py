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


def _read() -> dict:
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
    """
    seen_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _lock:
        store = {k: v for k, v in _read().items()
                 if (v or {}).get("wlc_ip") != wlc_ip}
        written = 0
        for ap in aps or []:
            serial = (ap.get("serial") or "").strip()
            name = normalize_ap_name(ap.get("name", ""))
            if not name or not serial:
                continue
            store[name] = {"serial": serial, "model": (ap.get("model") or "").strip(),
                           "wlc_ip": wlc_ip, "tenant": tenant, "seen_at": seen_at}
            written += 1
        tmp = _path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2)
        os.replace(tmp, _path())
    return written


def lookup(ap_name: str) -> Optional[dict]:
    return _read().get(normalize_ap_name(ap_name))
