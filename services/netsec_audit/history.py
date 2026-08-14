# -*- coding: utf-8 -*-
"""Persistence for saved NetSec Audit runs.

Only the scan route writes here, and only with the result it just computed:
the client asks to keep a run, it does not supply one. A stored score is meant
to be usable as evidence later, which it is not if the browser can dictate it.
"""

import json
import time
from typing import Optional

from core import db


def save(result: dict, *, tenant: Optional[str], device_name: Optional[str],
         device_ip: Optional[str], actor: str, run_name: Optional[str] = None) -> int:
    summary = result.get("summary") or {}
    # None means "not determinable" (every rule UNKNOWN). It stays None: coercing
    # it to 0 would record a perfect failure where the engine recorded no verdict.
    raw = result.get("score")
    score = int(raw) if isinstance(raw, (int, float)) else None
    conn = db.get_observability_connection()
    try:
        cur = conn.execute(
            "INSERT INTO netsec_audit_runs (ts, tenant, device_name, device_ip, "
            "benchmark, benchmark_title, vendor, lang, score, "
            "summary_json, result_json, actor, run_name) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (int(time.time()), tenant, device_name, device_ip,
             result.get("benchmark", ""), result.get("benchmark_title", ""),
             result.get("vendor", ""), result.get("lang", ""),
             score,
             json.dumps(summary), json.dumps(result), actor, run_name))
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        conn.close()


def prune(days: int) -> int:
    """Drop runs older than ``days``. Returns how many rows went."""
    if days <= 0:
        return 0
    cutoff = int(time.time()) - days * 86400
    conn = db.get_observability_connection()
    try:
        cur = conn.execute("DELETE FROM netsec_audit_runs WHERE ts < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()
