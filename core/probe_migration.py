# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""One-shot rename of the persisted pre-0.52 names to 'probe'.

Each step is keyed on the old name still being present, so it is idempotent
on its own: an install that never wrote the registry file still gets its CSV
header renamed, and a crash half-way finishes on the next start."""
import csv
import io
import json
import os
import shutil
import sqlite3

OLD = "site"  # check-site-name: ok


def _backup(path: str) -> None:
    bak = path + ".pre-probe"
    if not os.path.exists(bak):
        shutil.copy2(path, bak)


def _registry(d: str) -> list:
    old, new = os.path.join(d, OLD + "s.json"), os.path.join(d, "probes.json")
    if not os.path.exists(old) or os.path.exists(new):
        return []
    _backup(old)
    os.replace(old, new)
    return ["registro sonde: " + OLD + "s.json -> probes.json"]


def _hosts_header(d: str) -> list:
    path = os.path.join(d, "network_hosts.csv")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as f:
        text = f.read()
    rows = list(csv.reader(io.StringIO(text)))
    if not rows or OLD.capitalize() not in rows[0]:
        return []
    _backup(path)
    rows[0] = ["Probe" if h == OLD.capitalize() else h for h in rows[0]]
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows(rows)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(buf.getvalue())
    os.replace(tmp, path)
    return ["network_hosts.csv: colonna " + OLD.capitalize() + " -> Probe"]


def _device_history(d: str) -> list:
    """Events carry the field name inside the device snapshot and, for a
    change, as a key of the diff. Values are left alone."""
    path = os.path.join(d, "device_history.jsonl")
    if not os.path.exists(path):
        return []
    field = OLD.capitalize()
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    out, renamed = [], False
    for line in lines:
        if f'"{field}"' in line:  # cheap prefilter; values may match too
            try:
                e = json.loads(line)
            except ValueError:  # torn line from a crash mid-write: keep verbatim
                out.append(line)
                continue
            for key in ("device", "changes"):
                if field in e.get(key, {}):
                    e[key] = {("Probe" if k == field else k): v for k, v in e[key].items()}
                    renamed = True
            line = json.dumps(e, separators=(",", ":"))
        out.append(line)
    if not renamed:
        return []
    _backup(path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(out) + "\n")
    os.replace(tmp, path)
    return ["device_history.jsonl: campo " + field + " -> Probe"]


def _columns(db: str, table: str) -> list:
    with sqlite3.connect(db) as c:
        return [r[1] for r in c.execute(f"PRAGMA table_info({table})")]


def _mac_history(d: str) -> list:
    db = os.path.join(d, "mac_history.db")
    if not os.path.exists(db):
        return []
    done = []
    for table in ("mac_sightings", "arp_entries"):
        if OLD not in _columns(db, table):
            continue
        with sqlite3.connect(db) as c:
            c.execute(f"ALTER TABLE {table} RENAME COLUMN {OLD} TO probe")
        done.append(f"mac_history: {table} colonna {OLD} -> probe")
    return done


def _jobs(d: str) -> list:
    db = os.path.join(d, "agent_jobs.db")
    if not os.path.exists(db) or OLD + "_id" not in _columns(db, "command_jobs"):
        return []
    # Queued jobs are transient and the test probes are reinstalled.
    with sqlite3.connect(db) as c:
        c.execute("DROP TABLE command_jobs")
    return ["agent_jobs: tabella command_jobs ricreata"]


def _user_tabs() -> list:
    from security import user_manager
    users = user_manager.rename_allowed_tab("tab-" + OLD + "s", "tab-probes")
    return [f"scheda Sonde negli accessi di {', '.join(users)}"] if users else []


def migrate(data_dir: str) -> list:
    """Run every pending step; returns what was done ([] = nothing)."""
    steps = []
    for step in (_registry, _hosts_header, _device_history, _mac_history, _jobs):
        steps += step(data_dir)
    return steps + _user_tabs()
