# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Lifecycle log of the inventory: which device was added, changed or removed
in which tenant, by whom, and what it looked like at that moment.

Fed from ``inventory_manager.safe_write_hosts_csv``, the single place every
inventory write goes through (UI, CSV import, probe-agent sync, rename,
reassign, promote), by diffing the rows before and after the write. The
running-config itself is not copied here: Config Drift already archives every
version under '.history', and the snapshot below carries what is needed to find
it again after the device has left the inventory.
"""
import glob
import json
import os
import re
import threading
import time
import uuid

from core import data_config
from security import crypto_vault

# Credentials never enter the log, not even encrypted: only whether one is set
# and whether it changed.
_SECRETS = ("Password", "Enable Secret", "SNMP Community")
_FIELDS = ("IP", "Hostname", "Vendor", "Profile", "Group", "Probe", "Username",
           "SSH Port", "Transports", "SNMP Disabled")

_lock = threading.Lock()


def _path() -> str:
    return data_config.get_path("device_history.jsonl")


def _key(row: dict) -> tuple:
    return (row.get("Group") or "Generale", row.get("IP") or "")


def _snapshot(row: dict) -> dict:
    snap = {f: row.get(f) or "" for f in _FIELDS}
    snap["Group"] = snap["Group"] or "Generale"
    for s in _SECRETS:
        snap[s] = "set" if row.get(s) else ""
    return snap


def _changes(old: dict, new: dict) -> dict:
    out = {f: [old.get(f) or "", new.get(f) or ""] for f in _FIELDS
           if (old.get(f) or "") != (new.get(f) or "")}
    for s in _SECRETS:
        # Fernet is not deterministic: the same password re-entered in the
        # form yields a different ciphertext. Compare the plaintext.
        if crypto_vault.decrypt_password(old.get(s) or "") != \
                crypto_vault.decrypt_password(new.get(s) or ""):
            out[s] = ["set" if old.get(s) else "", "set" if new.get(s) else ""]
    return out


def diff(old_rows: list, new_rows: list) -> list:
    """Events turning ``old_rows`` into ``new_rows``. Identity is (tenant, IP):
    a device moved to another tenant reads as removed there, added here."""
    old = {_key(r): r for r in old_rows}
    new = {_key(r): r for r in new_rows}
    out = []
    for k, row in new.items():
        if k not in old:
            out.append({"event": "added", "device": _snapshot(row)})
        else:
            ch = _changes(old[k], row)
            if ch:
                out.append({"event": "changed", "device": _snapshot(row), "changes": ch})
    for k, row in old.items():
        if k not in new:
            out.append({"event": "removed", "device": _snapshot(row)})
    return out


def record(old_rows: list, new_rows: list) -> None:
    found = diff(old_rows, new_rows)
    if not found:
        return
    from security import security_manager
    actor = security_manager.current_actor() or "system"
    ts = time.time()
    # ponytail: one append-only file, read whole on every query. Fine for
    # thousands of events; rotate or move to SQLite if it grows past that.
    with _lock, open(_path(), "a", encoding="utf-8") as fh:
        for e in found:
            e.update(id=uuid.uuid4().hex, ts=ts, actor=actor,
                     tenant=e["device"]["Group"])
            fh.write(json.dumps(e, separators=(",", ":")) + "\n")


# --- Backfill from the audit log -------------------------------------------
# The log above starts the day it was installed, but audit.log has carried a
# line for every inventory write for months. Those lines are rebuilt into
# events once, marked source="audit", so the UI can say they were rebuilt and
# show only what the line actually recorded (no credentials, no profile).
_AUDIT_TS = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ - \[AUDIT\] - (.*)$")
_A_UPSERT = re.compile(r"^Dispositivo '([^']+)' \(vendor: '([^']*)', gruppo: '([^']*)'(?:, sede: '([^']*)')?\) "
                       r"aggiunto/aggiornato dall'utente '([^']*)'")
_A_DELETE = re.compile(r"^Dispositivo '([^']+)' eliminato dall'inventario dall'utente '([^']*)'")
_A_GROUP = re.compile(r"^Dispositivo '([^']+)' spostato dal gruppo '([^']*)' al gruppo '([^']*)' dall'utente '([^']*)'")
_A_PROBE = re.compile(r"^Dispositivo '([^']+)' spostato dalla (?:sede|sonda) '([^']*)' alla (?:sede|sonda) '([^']*)' dall'utente '([^']*)'")
_A_PROMOTE = re.compile(r"^Dispositivo scoperto '([^']*)' promosso a gestito \(IP ([0-9.]+), vendor ([^,]*), sede ([^)]*)\) da '([^']*)'")
_backfilled: "set[str]" = set()  # log paths already merged in this process


def _audit_lines() -> list:
    """(ts, message) from audit.log and its rotations, oldest first."""
    base = data_config.get_path("audit.log")
    # RotatingFileHandler: audit.log.3 is older than audit.log.1.
    rotated = sorted((p for p in glob.glob(base + ".*") if p.rsplit(".", 1)[1].isdigit()),
                     key=lambda p: int(p.rsplit(".", 1)[1]), reverse=True)
    out = []
    for path in rotated + [base]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = _AUDIT_TS.match(line.rstrip("\n"))
                    if m:
                        ts = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
                        out.append((ts, m.group(2)))
        except OSError:
            continue
    return out


def backfill_from_audit(lines: list, inventory: list, live: list) -> list:
    """Events rebuilt from audit ``lines`` older than the first ``live`` event,
    plus one 'baseline' entry for every device in ``inventory`` that neither
    the log nor the live events ever saw arrive."""
    before = min((e["ts"] for e in live), default=time.time())
    out = []
    known = {}    # (tenant, ip) -> snapshot, as far as the log tells
    tenant_of = {}  # ip -> last tenant seen, for lines that do not name one
    current = {(r.get("Group") or "Generale", r.get("IP")): r for r in inventory}

    def snap(ip, tenant, vendor="", probe=""):
        cur = current.get((tenant, ip), {})
        return {"IP": ip, "Hostname": cur.get("Hostname") or "", "Vendor": vendor,
                "Group": tenant, "Probe": probe}

    def emit(kind, ts, actor, device, changes=None):
        e = {"event": kind, "device": device, "id": uuid.uuid4().hex, "ts": ts,
             "actor": actor or "system", "tenant": device["Group"], "source": "audit"}
        if changes is not None:
            e["changes"] = changes
        out.append(e)

    for ts, msg in lines:
        if ts >= before:
            break
        if m := _A_UPSERT.match(msg):
            ip, vendor, tenant, probe, actor = m.groups()
            tenant = tenant or "Generale"
            prev = known.get((tenant, ip))
            new = snap(ip, tenant, vendor.lower(), probe or (prev or {}).get("Probe", ""))
            if prev is None:
                emit("added", ts, actor, new)
            else:
                emit("changed", ts, actor, new, {k: [prev[k], new[k]] for k in ("Vendor", "Probe")
                                                if prev[k] and new[k] and prev[k] != new[k]})
            known[(tenant, ip)] = new
            tenant_of[ip] = tenant
        elif m := _A_DELETE.match(msg):
            ip, actor = m.groups()
            tenant = tenant_of.pop(ip, None) or next((t for t, i in current if i == ip), "Generale")
            emit("removed", ts, actor, known.pop((tenant, ip), None) or snap(ip, tenant))
        elif m := _A_GROUP.match(msg):
            ip, old_t, new_t, actor = m.groups()
            prev = known.pop((old_t, ip), None) or snap(ip, old_t)
            emit("removed", ts, actor, prev)
            moved = dict(prev, Group=new_t, Hostname=current.get((new_t, ip), {}).get("Hostname") or prev["Hostname"])
            emit("added", ts, actor, moved)
            known[(new_t, ip)] = moved
            tenant_of[ip] = new_t
        elif m := _A_PROBE.match(msg):
            ip, old_s, new_s, actor = m.groups()
            tenant = tenant_of.get(ip) or next((t for t, i in current if i == ip), "Generale")
            prev = known.get((tenant, ip)) or snap(ip, tenant, probe=old_s)
            new = dict(prev, Probe=new_s)
            emit("changed", ts, actor, new, {"Probe": [old_s, new_s]})
            known[(tenant, ip)] = new
        elif m := _A_PROMOTE.match(msg):
            name, ip, vendor, probe, actor = m.groups()
            tenant = next((t for t, i in current if i == ip), "Generale")
            new = dict(snap(ip, tenant, vendor.lower(), probe), Hostname=snap(ip, tenant)["Hostname"] or name)
            emit("added", ts, actor, new)
            known[(tenant, ip)] = new
            tenant_of[ip] = tenant

    # Devices in inventory today that the log never saw arrive: they predate
    # the log. Dated at its first line, and labelled as such, not invented.
    start = lines[0][0] if lines else before
    added = {(e["tenant"], e["device"]["IP"]) for e in out + live if e["event"] == "added"}
    for (tenant, ip), row in current.items():
        if (tenant, ip) not in added:
            out.append({"event": "added", "device": dict(snap(ip, tenant, row.get("Vendor") or "",
                                                          row.get("Probe") or "")),
                        "id": uuid.uuid4().hex, "ts": start, "actor": "", "tenant": tenant,
                        "source": "baseline"})
    return out


def _ensure_backfill() -> None:
    """Once per data dir: merge the rebuilt past into the log, in time order."""
    path = _path()
    if path in _backfilled:
        return
    # Read before taking _lock: record() runs under the inventory's CSV lock
    # and then takes _lock, so the opposite order here could deadlock.
    from services import inventory_manager
    inventory = inventory_manager.get_all_devices()
    with _lock:
        live = []
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        live.append(json.loads(line))
                    except ValueError:
                        continue  # torn line: dropped, never the whole file
        except OSError:
            pass
        if not any(e.get("source") for e in live):
            past = backfill_from_audit(_audit_lines(), inventory, live)
            if past:
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    for e in sorted(past + live, key=lambda e: e["ts"]):
                        fh.write(json.dumps(e, separators=(",", ":")) + "\n")
                os.replace(tmp, path)
        _backfilled.add(path)


def events(tenants=None, ip: str = "", limit: int = 500) -> list:
    """Newest first. ``tenants`` None = every tenant."""
    _ensure_backfill()
    try:
        with open(_path(), encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            e = json.loads(line)
        except ValueError:
            continue  # a line torn by a crash mid-write
        if tenants is not None and e.get("tenant") not in tenants:
            continue
        if ip and e.get("device", {}).get("IP") != ip:
            continue
        out.append(e)
        if len(out) >= limit:
            break
    return out


def get(event_id: str) -> "dict | None":
    return next((e for e in events(limit=10**9) if e.get("id") == event_id), None)
