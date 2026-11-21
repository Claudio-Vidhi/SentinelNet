# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Network status report, phase B: stored snapshots and their diff.

A snapshot is stored exactly as build_snapshot() returned it, so a stored one
renders the same .docx later and two of them compare without the mapping that
produced them. One is taken per tenant per calendar month (UTC) by the
scheduler tick; more can be saved by hand.
"""

import json
import logging
import time

from core import db
from services import inventory_manager
from services.status_report import evidence

_log = logging.getLogger("sentinelnet.status_report")

# Worse is higher. not_available has no rank: it is neither better nor worse.
_RANK = {"ok": 0, "partial": 1, "gap": 2}


def save(tenant: str, generated_by: str, source: str) -> int:
    snap = evidence.build_snapshot(tenant, generated_by)
    conn = db.get_observability_connection()
    try:
        cur = conn.execute(
            "INSERT INTO status_report_snapshots (ts, tenant, generated_by, source, "
            "schema_version, snapshot_json) VALUES (?,?,?,?,?,?)",
            (int(time.time()), tenant, generated_by, source, snap["schema_version"],
             json.dumps(snap, ensure_ascii=False)))
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        conn.close()


def list_for(tenant: str) -> list:
    """Newest first, with each evidence status: enough to pick two to compare."""
    conn = db.get_observability_connection()
    try:
        rows = conn.execute(
            "SELECT id, ts, generated_by, source, schema_version, snapshot_json "
            "FROM status_report_snapshots WHERE tenant = ? ORDER BY ts DESC, id DESC",
            (tenant,)).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        snap = json.loads(r["snapshot_json"])
        out.append({"id": r["id"], "ts": r["ts"], "generated_at": snap["generated_at"],
                    "generated_by": r["generated_by"], "source": r["source"],
                    "schema_version": r["schema_version"],
                    "statuses": {k: e["status"] for k, e in snap["evidence"].items()}})
    return out


def get(snapshot_id: int):
    """(tenant, snapshot) or None. The caller checks the tenant scope."""
    conn = db.get_observability_connection()
    try:
        r = conn.execute("SELECT tenant, snapshot_json FROM status_report_snapshots WHERE id = ?",
                         (snapshot_id,)).fetchone()
    finally:
        conn.close()
    return None if r is None else (r["tenant"], json.loads(r["snapshot_json"]))


def _change(old, new) -> str:
    if old is None:
        return "added"
    if new is None:
        return "removed"
    if old["status"] == new["status"]:
        return "same"
    a, b = _RANK.get(old["status"]), _RANK.get(new["status"])
    if a is None or b is None:
        return "changed"
    return "improved" if b < a else "worsened"


def _num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def diff(a: dict, b: dict) -> dict:
    """What changed from snapshot a to snapshot b. Refuses snapshots of two
    tenants or of incompatible schema versions instead of guessing."""
    if a["schema_version"] != b["schema_version"]:
        raise ValueError(f"Snapshot non confrontabili: schema {a['schema_version']} "
                         f"contro {b['schema_version']}.")
    if a["tenant"] != b["tenant"]:
        raise ValueError("Snapshot di tenant diversi.")
    ea, eb = a["evidence"], b["evidence"]
    items = []
    for key in list(eb) + [k for k in ea if k not in eb]:
        old, new = ea.get(key), eb.get(key)
        om, nm = (old or {}).get("metrics", {}), (new or {}).get("metrics", {})
        metrics = [{"metric": m, "from": om.get(m), "to": nm.get(m),
                    "delta": round(nm[m] - om[m], 2) if _num(om.get(m)) and _num(nm.get(m)) else None}
                   for m in list(nm) + [x for x in om if x not in nm]
                   if om.get(m) != nm.get(m)]
        items.append({"key": key, "title": (new or old)["title"],
                      "from": old and old["status"], "to": new and new["status"],
                      "change": _change(old, new), "metrics": metrics})
    counts = {}
    for it in items:
        counts[it["change"]] = counts.get(it["change"], 0) + 1

    def meta(s):
        return {"generated_at": s["generated_at"], "generated_by": s["generated_by"],
                "mapping_version": s["mapping_version"], "app_version": s["app_version"]}

    return {"tenant": a["tenant"], "schema_version": a["schema_version"],
            "from": meta(a), "to": meta(b),
            # Thresholds may differ between the two: each status was judged by
            # the rules its own snapshot carries.
            "mapping_changed": a["mapping_version"] != b["mapping_version"],
            "summary": counts, "evidence": items}


def take_monthly_due() -> list:
    """One scheduled snapshot per tenant with devices, per calendar month (UTC).
    Returns the tenants snapshotted. Cheap when nothing is due: one query."""
    month = time.strftime("%Y-%m", time.gmtime())
    conn = db.get_observability_connection()
    try:
        last = {r["tenant"]: r["ts"] for r in conn.execute(
            "SELECT tenant, MAX(ts) AS ts FROM status_report_snapshots "
            "WHERE source = 'scheduled' GROUP BY tenant")}
    finally:
        conn.close()
    with_devices = {d.get("Group") for d in inventory_manager.get_all_devices()}
    done = []
    for tenant in inventory_manager.get_all_groups():
        if tenant not in with_devices:
            continue
        if tenant in last and time.strftime("%Y-%m", time.gmtime(last[tenant])) == month:
            continue
        try:
            save(tenant, "system", "scheduled")
            done.append(tenant)
        except Exception:
            # One tenant's broken collector must not stop the others' snapshots.
            _log.warning("scheduled status snapshot failed for %s", tenant, exc_info=True)
    return done
