# -*- coding: utf-8 -*-
"""Router Routes: una tabella di routing sola, per gli apparati in scope.

HTTP soltanto — scope, filtri e forma della risposta. La raccolta e la
normalizzazione stanno in services/route_table.py.
"""
import asyncio

from fastapi import APIRouter, Depends, Query

from core.ssh_pool import run_ssh
from routers.deps import devices_in_scope, get_current_user
from services import route_table

router = APIRouter(tags=["Routes"])

# Quanti apparati interrogare insieme. Un giro su tutta la flotta apre
# altrettante sessioni REST: il tetto tiene il tab reattivo e non trasforma
# l'apertura di una vista in una tempesta verso i firewall.
MAX_CONCURRENT_DEVICES = 8


@router.get("/api/routes/devices")
def list_routable_devices(current_user = Depends(get_current_user)):
    """Gli apparati selezionabili, letti dall'inventario.

    Firewall e switch insieme: la lista non si costruisce piu' dalle righe
    tornate, che e' il motivo per cui uno switch mai interrogato non compariva
    fra quelli scegliibili."""
    return {"devices": [
        {"ip": d.get("IP"), "hostname": d.get("Hostname") or d.get("IP"),
         "group": d.get("Group") or "Generale",
         "vendor": d.get("Vendor") or ""}
        for d in route_table.routable_devices(devices_in_scope(current_user))]}


@router.get("/api/routes")
async def list_routes(
    device: str = Query("", max_length=2000),
    type: str = Query("", max_length=20),
    q: str = Query("", max_length=100),
    current_user = Depends(get_current_user),
):
    """Le tabelle di routing degli apparati CHIESTI, in una sola risposta.

    ``device`` e' l'elenco degli IP scelti, separati da virgola: senza
    selezione non si interroga niente.

    I filtri si applicano qui e non solo nel browser: la vista mostra un
    conteggio, e un conteggio calcolato su righe gia' filtrate altrove e' un
    numero che non corrisponde a niente."""
    wanted = {p.strip() for p in device.split(",") if p.strip()}
    targets = [d for d in route_table.routable_devices(devices_in_scope(current_user))
               if d.get("IP") in wanted]

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
