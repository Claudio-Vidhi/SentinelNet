# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""One-shot migration of the inventory files to inventory.db (spec 2026-10-10
inventory-sqlite-import). Runs on central (lifespan) and on each agent (config
load). The database is built in a temp file and renamed into place after the
commit, so a crash half-way reruns the whole thing; each source is then
renamed to *.pre-sqlite, which is both its backup and the sign it was
consumed."""
import csv
import json
import os

from services import inventory_store   # stdlib-only module, no data paths

_SOURCES = ("groups.json", "locations.json", "network_hosts.csv", "decommissioned_hosts.csv")


class MigrationError(RuntimeError):
    pass


def _rows(path, fields):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as f:
        return [{k: (r.get(k) or "") for k in fields} for r in csv.DictReader(f)]


def _json(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _consume(data_dir):
    for name in _SOURCES:
        src = os.path.join(data_dir, name)
        if os.path.exists(src):
            os.replace(src, src + ".pre-sqlite")


def migrate(data_dir: str) -> list:
    db = os.path.join(data_dir, "inventory.db")
    if os.path.exists(db):
        _consume(data_dir)   # a crash between the two renames left sources behind
        return []
    if not any(os.path.exists(os.path.join(data_dir, n)) for n in _SOURCES):
        return []
    groups = _json(os.path.join(data_dir, "groups.json"))
    locations = _json(os.path.join(data_dir, "locations.json"))
    hosts = _rows(os.path.join(data_dir, "network_hosts.csv"), inventory_store.HOST_FIELDS)
    dec = _rows(os.path.join(data_dir, "decommissioned_hosts.csv"),
                inventory_store.HOST_FIELDS + inventory_store.DECOM_FIELDS)
    steps = []
    if not os.path.exists(os.path.join(data_dir, "locations.json")):
        # An agent keeps no locations: a Location its rows carry names nothing
        # here, so blank it rather than refuse the migration.
        for name, rows in (("network_hosts.csv", hosts), ("decommissioned_hosts.csv", dec)):
            blanked = [r for r in rows if r["Location"]]
            for r in blanked:
                r["Location"] = ""
            if blanked:
                steps.append(f"{name}: {len(blanked)} righe con sede sconosciuta, "
                             "sede svuotata (agente senza sedi)")
    orphans = [f"{r['IP']} ({r['Group']}) -> {r['Location']}" for r in hosts + dec
               if r["Location"] and r["Location"] not in locations]
    if orphans:
        raise MigrationError("Migrazione inventario interrotta: righe con sede inesistente: "
                             + "; ".join(orphans))
    dupes = len(hosts) - len({(r["IP"], r["Group"]) for r in hosts})
    if dupes:
        steps.append(f"network_hosts.csv: {dupes} righe duplicate (IP, organizzazione), tenuta l'ultima")
    for v in locations.values():
        groups.setdefault(v["org"], {"description": ""})
    tmp = db + ".tmp"
    for leftover in (tmp, tmp + "-wal", tmp + "-shm"):
        if os.path.exists(leftover):
            os.remove(leftover)
    inventory_store._ready.discard(tmp)   # a previous attempt's schema flag
    conn = inventory_store.connect(tmp)
    try:
        inventory_store.write_orgs(conn, groups)
        inventory_store.write_locations(conn, locations)
        inventory_store.write_hosts(conn, "hosts", [], hosts)
        inventory_store.write_hosts(conn, "decommissioned_hosts", [], dec)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    inventory_store._ready.discard(tmp)
    os.replace(tmp, db)
    _consume(data_dir)
    steps.insert(0, f"inventario su SQLite: {len(groups)} organizzazioni, {len(locations)} sedi, "
                    f"{len(hosts)} apparati, {len(dec)} dismessi")
    return steps
