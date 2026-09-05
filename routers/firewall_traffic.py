# -*- coding: utf-8 -*-
"""Router Firewall Traffic: traffico per policy sugli apparati in scope.

HTTP soltanto — scope, filtri e forma della risposta. La raccolta e la
normalizzazione stanno in services/firewall_traffic.py.
"""
import asyncio

from fastapi import APIRouter, Depends, Query

from core.ssh_pool import run_ssh
from routers.deps import devices_in_scope, get_current_user
from services import firewall_traffic

router = APIRouter(tags=["Firewall Traffic"])

# Come per /api/routes: un giro sulla flotta apre altrettante sessioni REST.
MAX_CONCURRENT_DEVICES = 8


@router.get("/api/firewall-traffic/devices")
def list_policy_devices(current_user = Depends(get_current_user)):
    """I firewall selezionabili, letti dall'inventario.

    La lista serve PRIMA della query: senza, l'unico modo di sapere quali
    apparati esistono era interrogarli tutti e guardare le righe tornate."""
    return {"devices": [
        {"ip": d.get("IP"), "hostname": d.get("Hostname") or d.get("IP"),
         "group": d.get("Group") or "Generale"}
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
