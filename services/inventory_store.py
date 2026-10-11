# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""SQLite storage of the inventory: organizations, locations, active and
decommissioned hosts (spec 2026-10-10 inventory-sqlite-import).

Host rows keep the CSV-era shape — dicts keyed by the column names below — so
callers of inventory_manager read what they always read. stdlib only and no
data paths at import: the startup migration imports it before any service."""
import json
import sqlite3
import threading

HOST_FIELDS = ['IP', 'Vendor', 'Profile', 'Username', 'Password', 'Enable Secret', 'Group',
               'Hostname', 'Probe', 'Location', 'SSH Port', 'Transports', 'SNMP Community',
               'SNMP Disabled']
DECOM_FIELDS = ['Decommissioned', 'Decommissioned By']
_FIELDS = {"hosts": HOST_FIELDS, "decommissioned_hosts": HOST_FIELDS + DECOM_FIELDS}


def _host_table(name: str, fields: list) -> str:
    cols = []
    for f in fields:
        if f in ("IP", "Group"):
            cols.append(f'"{f}" TEXT NOT NULL')
        elif f == "Location":
            cols.append('"Location" TEXT REFERENCES locations(id)')
        else:
            cols.append(f'"{f}" TEXT NOT NULL DEFAULT \'\'')
    return (f'CREATE TABLE IF NOT EXISTS {name} ({", ".join(cols)}, '
            f'PRIMARY KEY ("IP", "Group"));')


_SCHEMA = "\n".join([
    "CREATE TABLE IF NOT EXISTS organizations (key TEXT PRIMARY KEY, name TEXT, "
    "description TEXT NOT NULL DEFAULT '');",
    "CREATE TABLE IF NOT EXISTS locations (id TEXT PRIMARY KEY, "
    "org TEXT NOT NULL REFERENCES organizations(key), name TEXT NOT NULL, "
    "role TEXT NOT NULL, subnets TEXT NOT NULL DEFAULT '[]', "
    "probe TEXT NOT NULL DEFAULT 'central');",
    _host_table("hosts", _FIELDS["hosts"]),
    _host_table("decommissioned_hosts", _FIELDS["decommissioned_hosts"]),
])
_ready: set = set()
_ready_lock = threading.Lock()


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    with _ready_lock:
        if path not in _ready:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(_SCHEMA)
            _ready.add(path)
    return conn


def _quoted(fields) -> str:
    return ", ".join(f'"{f}"' for f in fields)


def read_hosts(conn, table: str) -> list:
    fields = _FIELDS[table]
    rows = []
    for r in conn.execute(f"SELECT {_quoted(fields)} FROM {table} ORDER BY rowid"):
        row = {f: (r[f] or "") for f in fields}
        # Read defaults the CSV reader applied to legacy rows.
        row["Probe"] = row["Probe"] or "central"
        row["SSH Port"] = row["SSH Port"] or "22"
        rows.append(row)
    return rows


def _values(row: dict, fields) -> tuple:
    out = []
    for f in fields:
        v = row.get(f)
        v = "" if v is None else str(v)
        out.append((v or None) if f == "Location" else v)
    return tuple(out)


def write_hosts(conn, table: str, old: list, new: list) -> None:
    """Turn the table from ``old`` into ``new`` touching only the rows that
    differ. One transaction: a refused row (unknown location) leaves the table
    as it was."""
    fields = _FIELDS[table]
    before = {(r.get("IP"), r.get("Group")): _values(r, fields) for r in old}
    after = {}
    for r in new:
        after[(r.get("IP"), r.get("Group"))] = _values(r, fields)   # duplicate key: last wins
    gone = [k for k in before if k not in after]
    changed = [v for k, v in after.items() if before.get(k) != v]
    sets = ", ".join(f'"{f}" = excluded."{f}"' for f in fields if f not in ("IP", "Group"))
    with conn:
        conn.executemany(f'DELETE FROM {table} WHERE "IP" = ? AND "Group" = ?', gone)
        conn.executemany(
            f"INSERT INTO {table} ({_quoted(fields)}) VALUES ({', '.join('?' * len(fields))}) "
            f'ON CONFLICT ("IP", "Group") DO UPDATE SET {sets}', changed)


def read_orgs(conn) -> dict:
    out = {}
    for r in conn.execute("SELECT key, name, description FROM organizations ORDER BY rowid"):
        entry = {"description": r["description"]}
        if r["name"]:
            entry["name"] = r["name"]
        out[r["key"]] = entry
    return out


def write_orgs(conn, groups: dict) -> None:
    keep = list(groups)
    with conn:
        conn.execute(f"DELETE FROM organizations WHERE key NOT IN ({', '.join('?' * len(keep))})", keep)
        conn.executemany(
            "INSERT INTO organizations (key, name, description) VALUES (?, ?, ?) "
            "ON CONFLICT (key) DO UPDATE SET name = excluded.name, description = excluded.description",
            [(k, v.get("name"), v.get("description") or "") for k, v in groups.items()])


def read_locations(conn) -> dict:
    return {r["id"]: {"org": r["org"], "name": r["name"], "role": r["role"],
                      "subnets": json.loads(r["subnets"]), "probe": r["probe"]}
            for r in conn.execute("SELECT * FROM locations ORDER BY id")}


def write_locations(conn, data: dict) -> None:
    keep = list(data)
    with conn:
        conn.execute(f"DELETE FROM locations WHERE id NOT IN ({', '.join('?' * len(keep))})", keep)
        conn.executemany(
            "INSERT INTO locations (id, org, name, role, subnets, probe) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (id) DO UPDATE SET org = excluded.org, name = excluded.name, "
            "role = excluded.role, subnets = excluded.subnets, probe = excluded.probe",
            [(k, v["org"], v["name"], v["role"], json.dumps(v.get("subnets") or []),
              v.get("probe") or "central") for k, v in data.items()])
