# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""One-shot migration to locations (spec 2026-10-09 organizations-locations).

Every distinct (Group, Probe) pair of the inventory becomes a location of that
organization, named after the probe and carrying the probe's subnets; every
row, active and decommissioned, gets the matching `Location`. stdlib and
direct file access only, like probe_migration: it runs before any service
reads these files. `locations.json` is written last and is the done-flag, so a
crash half-way reruns the whole thing on the next start."""
import csv
import io
import json
import os
import re
import shutil

_CSVS = ("network_hosts.csv", "decommissioned_hosts.csv")


def _backup(path: str) -> None:
    bak = path + ".pre-locations"
    if os.path.exists(path) and not os.path.exists(bak):
        shutil.copy2(path, bak)


def _read_json(path: str, default):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else default
    except (OSError, ValueError):
        return default


def _write(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    os.replace(tmp, path)


def _write_json(path: str, data) -> None:
    _write(path, json.dumps(data, indent=2))


def _read_csv(path: str):
    if not os.path.exists(path):
        return None, []
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        return list(reader.fieldnames or []), rows


def _slug(name: str) -> str:
    # Same rule as probe_manager._slugify, kept local: no service imports here.
    return re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-") or "location"


def migrate(data_dir: str) -> list:
    """Run the migration if `locations.json` is missing; returns the steps
    done ([] = nothing to do, a fresh install included)."""
    loc_path = os.path.join(data_dir, "locations.json")
    if os.path.exists(loc_path):
        return []
    groups_path = os.path.join(data_dir, "groups.json")
    probes_path = os.path.join(data_dir, "probes.json")
    for name in ("groups.json", "probes.json") + _CSVS:
        _backup(os.path.join(data_dir, name))

    tables = {name: _read_csv(os.path.join(data_dir, name)) for name in _CSVS}
    pairs = set()
    for _, rows in tables.values():
        for r in rows:
            # Empty Group was read as the fallback tenant everywhere; it is
            # written down here, after which no code falls back to it.
            r["Group"] = (r.get("Group") or "").strip() or "Generale"  # check-generale: ok
            pairs.add((r["Group"], (r.get("Probe") or "").strip() or "central"))

    probes = _read_json(probes_path, {})
    groups = _read_json(groups_path, {})
    locations, by_pair = {}, {}
    for org, probe_id in sorted(pairs):
        probe = probes.get(probe_id) or {}
        name = probe.get("name") or probe_id
        base = _slug(name)
        loc_id, n = base, 2
        while loc_id in locations:
            loc_id, n = f"{base}-{n}", n + 1
        locations[loc_id] = {"org": org, "name": name,
                             "role": "hq" if probe_id == "central" else "branch",
                             "subnets": sorted(set(probe.get("subnets") or [])),
                             "probe": probe_id}
        by_pair[(org, probe_id)] = loc_id
        groups.setdefault(org, {"description": ""})

    steps = []
    for name, (header, rows) in tables.items():
        if header is None:
            continue
        if "Location" not in header:
            at = header.index("Probe") + 1 if "Probe" in header else len(header)
            header.insert(at, "Location")
        for r in rows:
            r["Location"] = by_pair[(r["Group"], (r.get("Probe") or "").strip() or "central")]
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=header, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
        _write(os.path.join(data_dir, name), buf.getvalue())
        if rows:
            steps.append(f"{name}: colonna Location su {len(rows)} righe")

    if locations:
        _write_json(groups_path, groups)
    if any("subnets" in p for p in probes.values()):
        for p in probes.values():
            p.pop("subnets", None)
        _write_json(probes_path, probes)
        steps.append("probes.json: subnet spostate sulle sedi")
    if locations:
        settings_path = os.path.join(data_dir, "app_settings.json")
        settings = _read_json(settings_path, {})
        settings["locations_review_pending"] = True
        _write_json(settings_path, settings)
        steps.insert(0, f"{len(locations)} sedi create dalle coppie organizzazione-sonda")

    _write_json(loc_path, locations)
    return steps
