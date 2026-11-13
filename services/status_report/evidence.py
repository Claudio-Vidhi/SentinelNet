# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Network status report: evidence collectors and the JSON snapshot.

Design: docs/superpowers/specs/2026-11-13-network-status-report-design.md.
Each collector reads data SentinelNet already holds for ONE tenant and returns
``{"available", "metrics", "rows"}``; the status comes from the thresholds in
mapping.json, never from code. The snapshot is self-contained (it carries the
control references and the thresholds it was judged with) so two snapshots
can be compared later without the mapping that produced them.
"""

import json
import os
import time
from datetime import datetime, timezone

from core import db
from core.version import __version__
from services import cve_intel, inventory_manager, segment_manager
from services.config_drift import history

SCHEMA_VERSION = 1
MAPPING_PATH = os.path.join(os.path.dirname(__file__), "mapping.json")
_UNKNOWN = (None, "", "Unknown", "Non Scansionato", "Non Rilevato")


def load_mapping() -> dict:
    with open(MAPPING_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _label(device: dict) -> str:
    return device.get("Hostname") or device.get("IP") or ""


def _age_days(stamp: str):
    hours = cve_intel.age_hours(stamp)
    return None if hours is None else round(hours / 24, 1)


def collect_asset_inventory(tenant: str, devices: list, period_days: int) -> dict:
    detected = inventory_manager.get_detected_versions()
    rows: list = []
    for d in devices:
        entry = detected.get(d.get("IP"), {})
        entry = entry if isinstance(entry, dict) else {}
        version = entry.get("version")
        model = entry.get("model")
        rows.append({"device": _label(d), "ip": d.get("IP", ""), "vendor": d.get("Vendor", ""),
                     "model": "" if model in _UNKNOWN else model,
                     "firmware": "" if version in _UNKNOWN else version,
                     "last_seen": entry.get("seen_at", "")})
    unknown = sum(1 for r in rows if not r["firmware"])
    return {"available": bool(devices),
            "metrics": {"devices": len(rows), "firmware_unknown": unknown,
                        "firmware_unknown_pct": round(100 * unknown / len(rows), 1) if rows else None,
                        "model_unknown": sum(1 for r in rows if not r["model"])},
            "rows": rows}


def collect_vulnerabilities(tenant: str, devices: list, period_days: int) -> dict:
    summary = cve_intel.summary(devices)
    if not summary:
        return {"available": False, "metrics": {}, "rows": []}
    row = summary[0]
    detail = row["devices_detail"]
    evaluated = [d for d in detail if d["confidence"] != "none"]
    age = cve_intel.age_hours(row["oldest_version_seen_at"])
    return {"available": bool(evaluated),
            "metrics": {"devices": row["devices"], "with_version": row["with_version"],
                        "devices_not_evaluated": len(detail) - len(evaluated),
                        "critical": row["counts"]["critical"], "high": row["counts"]["high"],
                        "exploited": sum(d["exploited"] for d in detail),
                        "data_age_hours": None if age is None else round(age, 1),
                        "not_evaluated": row["not_evaluated"]},
            "rows": [{"device": d["hostname"] or d["ip"], "ip": d["ip"], "firmware": d["version"],
                      "confidence": d["confidence"], "critical": d["counts"]["critical"],
                      "high": d["counts"]["high"], "exploited": d["exploited"],
                      "version_seen_at": d["version_seen_at"]} for d in detail]}


def collect_config_backup(tenant: str, devices: list, period_days: int) -> dict:
    rows: list = []
    for d in devices:
        last = history.last_seen_at(d)
        rows.append({"device": _label(d), "ip": d.get("IP", ""), "last_backup": last,
                     "age_days": _age_days(last), "versions": len(history.list_versions(d))})
    ages = [r["age_days"] for r in rows if r["age_days"] is not None]
    return {"available": bool(devices),
            "metrics": {"devices": len(rows),
                        "never_backed_up": sum(1 for r in rows if not r["last_backup"]),
                        "max_age_days": max(ages) if ages else None,
                        "versions_kept": sum(r["versions"] for r in rows)},
            "rows": rows}


def collect_config_drift(tenant: str, devices: list, period_days: int) -> dict:
    # ponytail: reuses the Config Drift route's helper rather than a copy of it.
    from routers.config_drift import drift_summary_for
    drift = drift_summary_for(devices)
    cutoff = time.strftime("%Y%m%dT%H%M%S", time.gmtime(time.time() - period_days * 86400))
    changes = sum(1 for d in devices for v in history.list_versions(d)
                  if v.get("seen_at", "") >= cutoff)
    return {"available": drift["checked"] > 0,
            "metrics": {"devices": drift["devices"], "checked": drift["checked"],
                        "deviating": len(drift["deviating"]),
                        "deviations": sum(d["deviations"] for d in drift["deviating"]),
                        "changes_in_period": changes},
            "rows": [{"device": d["hostname"] or d["ip"], "ip": d["ip"],
                      "deviations": d["deviations"]} for d in drift["deviating"]]}


def collect_hardening(tenant: str, devices: list, period_days: int) -> dict:
    conn = db.get_observability_connection()
    try:
        # Latest run per (device, benchmark): an older run superseded by a
        # newer one is history, not the current state.
        runs = conn.execute(
            "SELECT r.ts, r.device_name, r.device_ip, r.benchmark, r.benchmark_title, "
            "r.score, r.summary_json FROM netsec_audit_runs r "
            "WHERE r.tenant = ? AND r.ts = (SELECT MAX(ts) FROM netsec_audit_runs s "
            "WHERE s.tenant = r.tenant AND s.device_ip IS r.device_ip "
            "AND s.benchmark = r.benchmark) ORDER BY r.device_ip, r.benchmark",
            (tenant,)).fetchall()
    finally:
        conn.close()
    rows: list = []
    for r in runs:
        summary = json.loads(r["summary_json"] or "{}")
        rows.append({"device": r["device_name"] or r["device_ip"] or "", "ip": r["device_ip"] or "",
                     "benchmark": r["benchmark_title"] or r["benchmark"], "score": r["score"],
                     "failed": summary.get("failed", 0),
                     "run_at": datetime.fromtimestamp(r["ts"], timezone.utc).isoformat()})
    audited = {r["ip"] for r in rows}
    scores = [r["score"] for r in rows if r["score"] is not None]
    return {"available": bool(rows),
            "metrics": {"runs": len(rows), "devices": len(devices),
                        "devices_audited": len(audited),
                        "devices_not_audited": sum(1 for d in devices if d.get("IP") not in audited),
                        "min_score": min(scores) if scores else None,
                        "failed": sum(r["failed"] for r in rows)},
            "rows": rows}


def collect_segmentation(tenant: str, devices: list, period_days: int) -> dict:
    data = segment_manager.list_segments(tenant)
    segs, links = data["segments"], data["links"]
    return {"available": bool(segs),
            "metrics": {"zones": len(segs),
                        "reviewed_links": len(links),
                        "gateway_links": sum(1 for x in links if x["decision"] == "gateway"),
                        "allowed_links": sum(1 for x in links if x["decision"] == "allowed")},
            "rows": [{"zone": s["name"], "subnets": ", ".join(s["subnets"]),
                      "members": len(s["members"]), "cores": len(s["cores"])} for s in segs]}


def collect_logging(tenant: str, devices: list, period_days: int) -> dict:
    from core import data_config
    obs = data_config.obs_config()
    since = int(time.time()) - period_days * 86400
    conn = db.get_observability_connection()
    try:
        seen = {r["device_ip"]: (r["n"], r["last"]) for r in conn.execute(
            "SELECT device_ip, COUNT(*) AS n, MAX(ts) AS last FROM syslog_events "
            "WHERE tenant = ? AND ts >= ? GROUP BY device_ip", (tenant, since))}
    finally:
        conn.close()
    rows: list = []
    for d in devices:
        n, last = seen.get(d.get("IP"), (0, None))
        rows.append({"device": _label(d), "ip": d.get("IP", ""), "events": n,
                     "last_event": datetime.fromtimestamp(last, timezone.utc).isoformat() if last else ""})
    logging = sum(1 for r in rows if r["events"])
    syslog_on = bool(obs["syslog"]["enabled"])
    return {"available": bool(devices) and (syslog_on or bool(seen)),
            "metrics": {"devices": len(rows), "devices_logging": logging,
                        "logging_pct": round(100 * logging / len(rows), 1) if rows else None,
                        "events": sum(n for n, _ in seen.values()),
                        "syslog_listener": syslog_on,
                        "retention_days": obs["retention_days"]["syslog_events"]},
            "rows": rows}


def collect_platform_access(tenant: str, devices: list, period_days: int) -> dict:
    from security import user_manager
    from security.security_manager import verify_audit_chain
    rows: list = []
    for u in user_manager.list_users():
        unscoped = u["role"] == "super_admin" or not u["groups"]
        if not unscoped and tenant not in u["groups"]:
            continue
        # Scope is "all" or "restricted", never the list: it would name other tenants.
        rows.append({"user": u["username"], "role": u["role"],
                     "scope": "all" if unscoped else "restricted",
                     "disabled": bool(u["disabled"]), "last_login": u["last_login"]})
    broken = verify_audit_chain()
    return {"available": True,
            "metrics": {"users": len(rows),
                        "admins": sum(1 for r in rows if r["role"] in ("super_admin", "admin")),
                        "unscoped": sum(1 for r in rows if r["scope"] == "all"),
                        "disabled": sum(1 for r in rows if r["disabled"]),
                        "audit_chain_ok": 1 if broken is None else 0,
                        "audit_chain_broken_line": broken,
                        "mfa_available": 0},
            "rows": rows}


COLLECTORS = {
    "asset_inventory": collect_asset_inventory,
    "vulnerabilities": collect_vulnerabilities,
    "config_backup": collect_config_backup,
    "config_drift": collect_config_drift,
    "hardening": collect_hardening,
    "segmentation": collect_segmentation,
    "logging": collect_logging,
    "platform_access": collect_platform_access,
}

_OPS = {">": lambda a, b: a > b, ">=": lambda a, b: a >= b, "<": lambda a, b: a < b,
        "<=": lambda a, b: a <= b, "==": lambda a, b: a == b}


def status_of(result: dict, spec: dict) -> str:
    if not result["available"]:
        return "not_available"
    for rule in spec["rules"]:
        value = result["metrics"].get(rule["metric"])
        if value is not None and _OPS[rule["op"]](value, rule["value"]):
            return rule["status"]
    return spec["default"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_snapshot(tenant: str, generated_by: str) -> dict:
    mapping = load_mapping()
    period = int(mapping["period_days"])
    devices = [d for d in inventory_manager.get_all_devices() if d.get("Group") == tenant]
    evidence = {}
    for key, spec in mapping["evidence"].items():
        result = COLLECTORS[key](tenant, devices, period)
        evidence[key] = {"status": status_of(result, spec), "available": result["available"],
                         "metrics": result["metrics"], "rows": result["rows"],
                         "collected_at": _now_iso(),
                         # Carried so the snapshot is judged by what it was built with.
                         "title": spec["title"], "controls": spec["controls"],
                         "rules": spec["rules"], "default": spec["default"],
                         "source": spec["source"], "note": spec.get("note")}
    return {"schema_version": SCHEMA_VERSION, "mapping_version": mapping["mapping_version"],
            "app_version": __version__, "generated_at": _now_iso(),
            "generated_by": generated_by, "tenant": tenant, "period_days": period,
            "evidence": evidence,
            "references": {"frameworks": mapping["frameworks"], "controls": mapping["controls"],
                           "out_of_scope": mapping["out_of_scope"]}}
