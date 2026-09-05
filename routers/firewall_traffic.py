# -*- coding: utf-8 -*-
"""Router Firewall Traffic: traffico per policy sugli apparati in scope.

HTTP soltanto — scope, filtri e forma della risposta. La raccolta e la
normalizzazione stanno in services/firewall_traffic.py.
"""
import asyncio

from fastapi import APIRouter, Depends, Query

from core.ssh_pool import run_ssh
from routers.deps import get_current_user, user_group_scope
from services import firewall_traffic, inventory_manager

router = APIRouter(tags=["Firewall Traffic"])

# Come per /api/routes: un giro sulla flotta apre altrettante sessioni REST.
MAX_CONCURRENT_DEVICES = 8


@router.get("/api/firewall-traffic/policies")
async def list_policy_traffic(
    device: str = Query("", max_length=100),
    action: str = Query("", max_length=20),
    q: str = Query("", max_length=100),
    current_user = Depends(get_current_user),
):
    """Byte, sessioni e hit per policy, sui firewall in scope.

    I filtri si applicano qui e non solo nel browser: la vista mostra dei
    totali, e un totale calcolato su righe gia' filtrate altrove e' un numero
    che non corrisponde a niente.
    """
    scope = user_group_scope(current_user)
    devices = inventory_manager.get_all_devices()
    if scope is not None:
        devices = [d for d in devices if (d.get("Group") or "Generale") in scope]
    targets = firewall_traffic.policy_devices(devices)
    if device:
        needle = device.lower()
        targets = [d for d in targets
                   if needle in (d.get("Hostname") or "").lower()
                   or needle in (d.get("IP") or "").lower()]

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

    if action:
        wanted = action.strip().lower()
        rows = [r for r in rows if r["action"] == wanted]
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
    return {"total": len(rows), "rows": rows, "errors": errors,
            "devices_queried": len(targets),
            "total_bytes": sum(r["bytes"] or 0 for r in rows),
            "total_sessions": sum(r["active_sessions"] or 0 for r in rows)}
