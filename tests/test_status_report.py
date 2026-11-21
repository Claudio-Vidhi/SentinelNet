# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Network status report: mapping contract, snapshot statuses, tenant
isolation and the route's gate."""

import ast
import inspect
import io
import time

import pytest
from fastapi.testclient import TestClient

from core import db
from services.config_drift import history
from services.netsec_audit import history as audit_history
from services.status_report import evidence
from tests.conftest import seed_inventory

PASS = "PasswordSicura1!"
CSRF = {"X-Requested-With": "SentinelNet"}
T, OTHER = "rpt-acme", "rpt-other"
SW1 = {"IP": "192.0.2.1", "Hostname": "switch-01", "Vendor": "cisco_ios", "Group": T}
SW2 = {"IP": "192.0.2.2", "Hostname": "switch-02", "Vendor": "cisco_ios", "Group": T}
FOREIGN = {"IP": "198.51.100.9", "Hostname": "switch-09", "Vendor": "cisco_ios", "Group": OTHER}


def test_mapping_matches_the_collectors():
    mapping = evidence.load_mapping()
    assert set(mapping["evidence"]) == set(evidence.COLLECTORS)
    for spec in mapping["evidence"].values():
        assert spec["default"] in ("ok", "partial", "gap")
        assert {"it", "en"} <= set(spec["title"]) and {"it", "en"} <= set(spec["source"])
        for fw, ids in spec["controls"].items():
            assert fw in mapping["frameworks"]
            for cid in ids:
                assert cid in mapping["controls"][fw], (fw, cid)
        for rule in spec["rules"]:
            assert rule["op"] in evidence._OPS
            assert rule["status"] in ("ok", "partial", "gap")
    # MFA absence must always be stated, never omitted.
    assert any("multi-factor" in i["en"] and "SentinelNet" in i["en"] for i in mapping["out_of_scope"])


def test_every_emitted_key_has_a_label_in_both_languages(seeded):
    # Keys come from the collectors' source (some stay empty for the seeded tenant)
    # plus the seeded snapshot itself.
    keys = set()
    src = ast.parse(inspect.getsource(evidence))
    for fn in src.body:
        if isinstance(fn, ast.FunctionDef) and fn.name.startswith("collect_"):
            for node in ast.walk(fn):
                if isinstance(node, ast.Dict):
                    keys |= {k.value for k in node.keys if isinstance(k, ast.Constant)}
    keys -= {"available", "metrics", "rows"}
    for e in evidence.build_snapshot(T, "tester")["evidence"].values():
        keys |= set(e["metrics"]) | {c for r in e["rows"] for c in r}
    labels = evidence.load_mapping()["labels"]
    for key in keys:
        assert {"it", "en"} <= set(labels.get(key, {})), key


def test_status_rules_first_match_wins_and_null_is_skipped():
    spec = {"rules": [{"status": "gap", "metric": "a", "op": ">", "value": 0},
                      {"status": "partial", "metric": "b", "op": "<", "value": 80}],
            "default": "ok"}
    assert evidence.status_of({"available": False, "metrics": {"a": 5}}, spec) == "not_available"
    assert evidence.status_of({"available": True, "metrics": {"a": 1, "b": 10}}, spec) == "gap"
    assert evidence.status_of({"available": True, "metrics": {"a": None, "b": 10}}, spec) == "partial"
    assert evidence.status_of({"available": True, "metrics": {"a": 0, "b": 90}}, spec) == "ok"


@pytest.fixture
def seeded(monkeypatch):
    db.migrate()
    seed_inventory(hosts=[SW1, SW2, FOREIGN])
    monkeypatch.setattr(
        "services.inventory_manager.get_detected_versions",
        lambda: {"192.0.2.1": {"version": "17.9.4", "model": "C9300-48P", "seen_at": history._now()},
                 "198.51.100.9": {"version": "17.9.4", "model": "C9300-48P", "seen_at": history._now()}})
    history.record_version(SW1, "hostname switch-01\n")
    history.record_version(FOREIGN, "hostname switch-09\n")
    run = {"benchmark": "cis", "benchmark_title": "CIS", "vendor": "ios", "lang": "en",
           "summary": {"failed": 3}, "rules": []}
    audit_history.save(dict(run, score=70), tenant=T, device_name="switch-01",
                       device_ip="192.0.2.1", actor="test")
    audit_history.save(dict(run, score=10), tenant=OTHER, device_name="switch-09",
                       device_ip="198.51.100.9", actor="test")
    from services import segment_manager
    segment_manager.save_segment(OTHER, None, "OT", "amber", subnets=["198.51.100.0/24"])
    now = int(time.time())
    conn = db.get_observability_connection()
    try:
        conn.execute("DELETE FROM syslog_events WHERE tenant IN (?, ?)", (T, OTHER))
        for tenant, ip in ((T, "192.0.2.1"), (T, "192.0.2.2"), (OTHER, "198.51.100.9")):
            conn.execute("INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message) "
                         "VALUES (?, ?, ?, 6, '', 'test')", (now, tenant, ip))
        conn.commit()
    finally:
        conn.close()
    from security import user_manager
    for name, groups in (("rpt_admin", None), ("rpt_scoped", [T]), ("rpt_foreign", [OTHER])):
        if user_manager.get_role(name) is None:
            user_manager.create_user(name, PASS, role="admin" if name == "rpt_admin" else "operator",
                                     groups=groups)


def test_snapshot_statuses_and_tenant_isolation(seeded):
    snap = evidence.build_snapshot(T, "tester")
    assert snap["schema_version"] == 1 and snap["tenant"] == T
    ev = snap["evidence"]
    status = {k: v["status"] for k, v in ev.items()}
    assert status == {
        "asset_inventory": "gap",        # 1 of 2 firmware unknown: 50% > 10%
        "vulnerabilities": "not_available",
        "config_backup": "gap",          # switch-02 never backed up
        "ot_vault": "not_available",     # no OT devices or artifacts in seeded tenant
        "config_drift": "not_available",  # no baseline
        "hardening": "partial",          # score 70 < 80
        "segmentation": "not_available",  # the zone belongs to the other tenant
        "ot_insecure_protocols": "ok",   # no telnet/http/snmpv1-v2c/unsegregated OT flows
        "ot_unused_ports": "not_available",  # no interface.state telemetry
        "ot_remote_access": "not_available",  # no OT devices or remote bypasses
        "ot_compensating_controls": "not_available",  # no OT asset with a CVE snapshot
        "logging": "ok",                 # both devices sent syslog
        "platform_access": "ok",
    }, status
    # Every threshold names a metric its collector really returns.
    for key, e in ev.items():
        for rule in e["rules"]:
            assert rule["metric"] in e["metrics"], (key, rule["metric"])
    # Nothing from the other tenant: no device, no audit run, no user.
    dump = str(ev)
    assert "198.51.100.9" not in dump and "switch-09" not in dump
    assert ev["hardening"]["metrics"]["min_score"] == 70
    users = {r["user"] for r in ev["platform_access"]["rows"]}
    assert {"rpt_admin", "rpt_scoped"} <= users and "rpt_foreign" not in users
    assert OTHER not in dump


def _login(name):
    import app_server
    c = TestClient(app_server.app)
    r = c.post("/api/auth/login", json={"username": name, "password": PASS})
    assert r.status_code == 200, r.text
    return c


def test_route_gate_and_formats(seeded):
    import app_server
    url = "/api/reports/network-status"
    assert TestClient(app_server.app).get(url, params={"tenant": T}).status_code == 401

    scoped = _login("rpt_scoped")
    assert scoped.get(url, params={"tenant": OTHER}, headers=CSRF).status_code == 403
    assert scoped.get(url, params={"tenant": "all"}, headers=CSRF).status_code == 400
    assert scoped.get(url, headers=CSRF).status_code == 400

    r = scoped.get(url, params={"tenant": T, "format": "json"}, headers=CSRF)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tenant"] == T and body["schema_version"] == 1
    assert set(body["evidence"]) == set(evidence.COLLECTORS)

    admin = _login("rpt_admin")
    assert admin.get(url, params={"tenant": "rpt-missing"}, headers=CSRF).status_code == 404
    r = admin.get(url, params={"tenant": T, "lang": "en"}, headers=CSRF)
    assert r.status_code == 200, r.text
    from docx import Document
    doc = Document(io.BytesIO(r.content))
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "not a certification" in text
    assert "SentinelNet's own login has no multi-factor authentication" in text


# --- Phase B: stored snapshots and diff ---

def _clear_snapshots():
    conn = db.get_observability_connection()
    try:
        conn.execute("DELETE FROM status_report_snapshots")
        conn.commit()
    finally:
        conn.close()


def test_diff_ranks_status_changes_and_refuses_incompatible():
    from services.status_report import snapshots

    def snap(statuses, metric, schema=1, tenant=T):
        return {"schema_version": schema, "tenant": tenant, "generated_at": "x",
                "generated_by": "t", "mapping_version": "m", "app_version": "v",
                "evidence": {k: {"status": s, "title": {"en": k}, "metrics": {"n": metric}}
                             for k, s in statuses.items()}}

    a = snap({"backup": "gap", "logs": "ok", "vulns": "not_available", "gone": "ok"}, 5)
    b = snap({"backup": "ok", "logs": "partial", "vulns": "gap", "new": "ok"}, 2)
    d = snapshots.diff(a, b)
    change = {e["key"]: e["change"] for e in d["evidence"]}
    assert change == {"backup": "improved", "logs": "worsened", "vulns": "changed",
                      "new": "added", "gone": "removed"}
    backup = next(e for e in d["evidence"] if e["key"] == "backup")
    assert backup["metrics"] == [{"metric": "n", "from": 5, "to": 2, "delta": -3}]
    with pytest.raises(ValueError):
        snapshots.diff(a, snap({}, 0, schema=2))
    with pytest.raises(ValueError):
        snapshots.diff(a, snap({}, 0, tenant=OTHER))


def test_monthly_snapshot_once_per_tenant_with_devices(seeded, monkeypatch):
    from services.status_report import snapshots
    _clear_snapshots()
    monkeypatch.setattr("services.inventory_manager.get_all_groups",
                        lambda: {T: {}, OTHER: {}, "rpt-empty": {}})
    assert set(snapshots.take_monthly_due()) == {T, OTHER}   # no devices, no snapshot
    assert snapshots.take_monthly_due() == []                # same month: nothing due
    assert [s["source"] for s in snapshots.list_for(T)] == ["scheduled"]


def test_snapshot_routes_store_render_and_isolate(seeded):
    _clear_snapshots()
    base = "/api/reports/network-status"
    scoped, foreign = _login("rpt_scoped"), _login("rpt_foreign")
    r = scoped.post(base + "/snapshots", json={"tenant": T}, headers=CSRF)
    assert r.status_code == 200, r.text
    first = r.json()["id"]
    second = scoped.post(base + "/snapshots", json={"tenant": T}, headers=CSRF).json()["id"]
    assert scoped.post(base + "/snapshots", json={"tenant": OTHER}, headers=CSRF).status_code == 403

    listed = scoped.get(base + "/snapshots", params={"tenant": T}, headers=CSRF).json()["snapshots"]
    assert [s["id"] for s in listed] == [second, first]
    assert listed[0]["statuses"]["hardening"] == "partial"

    r = scoped.get(f"{base}/snapshots/{first}", params={"format": "json"}, headers=CSRF)
    assert r.status_code == 200 and r.json()["tenant"] == T
    assert scoped.get(f"{base}/snapshots/{first}", headers=CSRF).status_code == 200   # docx
    # Another tenant's user cannot tell the id exists.
    assert foreign.get(f"{base}/snapshots/{first}", headers=CSRF).status_code == 404
    assert foreign.get(base + "/diff", params={"a": first, "b": second}, headers=CSRF).status_code == 404

    d = scoped.get(base + "/diff", params={"a": first, "b": second}, headers=CSRF)
    assert d.status_code == 200, d.text
    assert d.json()["summary"].get("same") == len(evidence.COLLECTORS)
