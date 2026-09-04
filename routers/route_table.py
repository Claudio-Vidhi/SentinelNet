# -*- coding: utf-8 -*-
"""Router Routes: una tabella di routing sola, per gli apparati in scope.

HTTP soltanto — scope, filtri e forma della risposta. La raccolta e la
normalizzazione stanno in services/route_table.py.
"""
import asyncio

from fastapi import APIRouter, Depends, Query

from core.ssh_pool import run_ssh
from routers.deps import get_current_user, user_group_scope
from services import inventory_manager, route_table

router = APIRouter(tags=["Routes"])

# Quanti apparati interrogare insieme. Un giro su tutta la flotta apre
# altrettante sessioni REST: il tetto tiene il tab reattivo e non trasforma
# l'apertura di una vista in una tempesta verso i firewall.
MAX_CONCURRENT_DEVICES = 8


@router.get("/api/routes")
async def list_routes(
    device: str = Query("", max_length=100),
    type: str = Query("", max_length=20),
    q: str = Query("", max_length=100),
    current_user = Depends(get_current_user),
):
    """Le tabelle di routing degli apparati in scope, in una sola risposta.

    I filtri si applicano qui e non solo nel browser: la vista mostra un
    conteggio, e un conteggio calcolato su righe gia' filtrate altrove e' un
    numero che non corrisponde a niente."""
    scope = user_group_scope(current_user)
    devices = inventory_manager.get_all_devices()
    if scope is not None:
        devices = [d for d in devices if (d.get("Group") or "Generale") in scope]
    targets = route_table.routable_devices(devices)
    if device:
        needle = device.lower()
        targets = [d for d in targets
                   if needle in (d.get("Hostname") or "").lower()
                   or needle in (d.get("IP") or "").lower()]

    sem = asyncio.Semaphore(MAX_CONCURRENT_DEVICES)

    async def one(dev):
        async with sem:
            return await run_ssh(route_table.collect_for, dev)

    answers = await asyncio.gather(*(one(d) for d in targets)) if targets else []

    rows, errors = [], []
    for a in answers:
        if a.get("error"):
            errors.append({"device_ip": a["device_ip"], "error": a["error"]})
        rows.extend(a.get("rows") or [])

    if type:
        wanted = type.strip().lower()
        rows = [r for r in rows if r["type"] == wanted]
    if q:
        needle = q.strip().lower()
        rows = [r for r in rows
                if needle in r["network"].lower()
                or needle in r["gateway"].lower()
                or needle in r["interface"].lower()]

    rows.sort(key=lambda r: (r["device"], r["type"], r["network"]))
    return {"total": len(rows), "rows": rows, "errors": errors,
            "devices_queried": len(targets),
            "counts": route_table.group_counts(rows)}
