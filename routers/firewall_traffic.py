# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router Firewall Traffic: traffico per policy sugli apparati in scope.

HTTP soltanto — scope, filtri e forma della risposta. La raccolta e la
normalizzazione stanno in services/firewall_traffic.py.
"""
import asyncio
from typing import Optional

from fastapi import APIRouter, Body, Depends, Query
from pydantic import BaseModel

from core.ssh_pool import run_ssh
from routers.deps import devices_in_scope, get_current_user, require_operator, require_tab
from services import firewall_traffic

router = APIRouter(dependencies=[Depends(require_tab("tab-flows"))], tags=["Firewall Traffic"])

# Come per /api/routes: un giro sulla flotta apre altrettante sessioni REST.
MAX_CONCURRENT_DEVICES = 8


class SnapshotRequest(BaseModel):
    device: str = ""


def _enrich_with_deltas(rows: list) -> list:
    by_ip: dict = {}
    for r in rows:
        by_ip.setdefault(r.get("device_ip") or "", []).append(r)
    out = []
    for ip, group_rows in by_ip.items():
        if ip:
            out.extend(firewall_traffic.compute_policy_deltas(ip, group_rows))
        else:
            out.extend(group_rows)
    return out


@router.get("/api/firewall-traffic/devices")
def list_policy_devices(current_user = Depends(get_current_user)):
    """I firewall selezionabili, letti dall'inventario.

    La lista serve PRIMA della query: senza, l'unico modo di sapere quali
    apparati esistono era interrogarli tutti e guardare le righe tornate."""
    return {"devices": [
        {"ip": d.get("IP"), "hostname": d.get("Hostname") or d.get("IP"),
         "group": d.get("Group") or ""}
        for d in firewall_traffic.policy_devices(devices_in_scope(current_user))]}


@router.get("/api/firewall-traffic/policies")
async def list_policy_traffic(
    device: str = Query("", max_length=2000),
    action: str = Query("", max_length=20),
    q: str = Query("", max_length=100),
    current_user = Depends(get_current_user),
):
    """Byte, sessioni e hit per policy, sui firewall CHIESTI dal chiamante.

    ``device`` e' l'elenco degli IP scelti, separati da virgola: senza
    selezione non si interroga niente. Aprire la vista non deve aprire una
    sessione REST su ogni firewall della flotta.

    I filtri si applicano qui e non solo nel browser: la vista mostra dei
    totali, e un totale calcolato su righe gia' filtrate altrove e' un numero
    che non corrisponde a niente.
    """
    wanted = {p.strip() for p in device.split(",") if p.strip()}
    targets = [d for d in firewall_traffic.policy_devices(devices_in_scope(current_user))
               if d.get("IP") in wanted]

    sem = asyncio.Semaphore(MAX_CONCURRENT_DEVICES)

    async def one(dev):
        async with sem:
            return await run_ssh(firewall_traffic.collect_for, dev)

    answers = await asyncio.gather(*(one(d) for d in targets)) if targets else []

    rows, errors = [], []
    for a in answers:
        if a.get("error"):
            errors.append({"device_ip": a["device_ip"], "error": a["error"]})
        if a.get("stats_error"):
            errors.append({"device_ip": a["device_ip"],
                           "error": f"contatori non disponibili: {a['stats_error']}"})
        rows.extend(a.get("rows") or [])

    if rows:
        rows = await asyncio.to_thread(_enrich_with_deltas, rows)

    if action:
        wanted_action = action.strip().lower()
        rows = [r for r in rows if r["action"] == wanted_action]
    if q:
        needle = q.strip().lower()
        rows = [r for r in rows
                if needle in str(r["policyid"]).lower()
                or needle in r["name"].lower()
                or needle in r["srcaddr"].lower()
                or needle in r["dstaddr"].lower()
                or needle in r["srcaddr_ips"].lower()
                or needle in r["dstaddr_ips"].lower()
                or needle in r["service"].lower()]

    # Le piu' cariche in cima: e' l'ordine in cui si guarda una tabella di
    # traffico, e mette sotto gli occhi la policy che sposta i dati.
    rows.sort(key=lambda r: (-(r["bytes"] or 0), r["device"], r["policyid"] or 0))
    from services import purdue_model, segment_manager
    scoped_devs = devices_in_scope(current_user)
    groups = {d.get("Group") for d in targets if d.get("Group")}
    segs = []
    for g in sorted(groups):
        segs.extend(segment_manager.list_segments(g).get("segments") or [])
    ot_violations = purdue_model.check_policy_violations(rows, scoped_devs, segs)
    return {"total": len(rows), "rows": rows, "errors": errors,
            "devices_queried": len(targets),
            "total_bytes": sum(r["bytes"] or 0 for r in rows),
            "total_sessions": sum(r["active_sessions"] or 0 for r in rows),
            "ot_violations": ot_violations}


@router.get("/api/firewall-traffic/hygiene")
async def get_firewall_hygiene(
    device: str = Query("", max_length=2000),
    days: int = Query(30, ge=1, le=365),
    current_user = Depends(get_current_user),
):
    """Firewall Hygiene & Rule Delta Tracker across scoped firewalls/devices."""
    scoped = firewall_traffic.hygiene_devices(devices_in_scope(current_user))
    wanted = {p.strip() for p in device.split(",") if p.strip()}
    if wanted:
        scoped = [d for d in scoped if d.get("IP") in wanted]
    report = await asyncio.to_thread(
        firewall_traffic.analyze_hygiene,
        scoped,
        None,
        days,
    )
    report["eligible_devices"] = [
        {
            "ip": d.get("IP"),
            "hostname": d.get("Hostname") or d.get("IP"),
            "vendor": d.get("Vendor") or "",
            "group": d.get("Group") or "",
        }
        for d in firewall_traffic.hygiene_devices(devices_in_scope(current_user))
    ]
    return report


def _capture_device_snapshot_sync(dev: dict) -> dict:
    """Capture and persist one policy counter snapshot for a single device."""
    from ai import config_analyzer

    ip = dev.get("IP") or ""
    rows = []
    source = "backup"
    if (dev.get("Vendor") or "").lower() == "fortinet":
        transports = dev.get("Transports") or {}
        if not (isinstance(transports, dict) and transports.get("manual")):
            ans = firewall_traffic.collect_for(dev)
            if ans.get("rows"):
                rows = ans["rows"]
                source = str(ans.get("source") or "live")

    if not rows:
        path, _ = config_analyzer._find_freshest_backup(ip, dev.get("Group"))
        if path:
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    content = "\n".join(config_analyzer.running_config(fh.read()))
                cfg_type = config_analyzer.detect_config_type(content, dev)
                rows, _ = firewall_traffic._extract_backup_rules(content, cfg_type, dev)
                hist = firewall_traffic.get_policy_snapshot_history(ip)
                latest = {str(h["policy_id"]): h for h in hist}
                for r in rows:
                    prev = latest.get(str(r.get("policyid")))
                    if prev:
                        r["hit_count"] = prev["hit_count"]
                        r["bytes"] = prev["bytes"]
                        r["last_used"] = prev["last_used"]
            except OSError:
                rows = []

    saved = firewall_traffic.record_policy_snapshots(dev, rows) if rows else 0
    return {"device_ip": ip, "hostname": dev.get("Hostname") or ip, "saved": saved, "source": source}


@router.post("/api/firewall-traffic/snapshot")
async def capture_policy_snapshot(
    req: Optional[SnapshotRequest] = Body(None),
    device: str = Query("", max_length=2000),
    current_user = Depends(require_operator),
):
    """Persist a periodic policy hit/bytes snapshot for selected or scoped firewalls."""
    raw_filter = (req.device if req and req.device else "") or device
    wanted = {p.strip() for p in raw_filter.split(",") if p.strip()}
    targets = firewall_traffic.hygiene_devices(devices_in_scope(current_user))
    if wanted:
        targets = [d for d in targets if d.get("IP") in wanted]

    results = []
    for dev in targets:
        res = await run_ssh(_capture_device_snapshot_sync, dev)
        results.append(res)

    return {
        "devices_snapshotted": len(results),
        "snapshots_saved": sum(r.get("saved", 0) for r in results),
        "results": results,
    }

