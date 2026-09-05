# -*- coding: utf-8 -*-
"""Router Routes: una tabella di routing sola, per gli apparati in scope.

HTTP soltanto — scope, filtri e forma della risposta. La raccolta e la
normalizzazione stanno in services/route_table.py.
"""
import asyncio
import ipaddress
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from core.ssh_pool import run_ssh
from routers.deps import (assert_device_allowed, devices_in_scope,
                          get_current_user, require_operator)
from security.security_manager import log_audit
from services import path_trace, route_table

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
        note = a.get("error") or ""
        if a.get("source") == "backup":
            # Le righe ci sono, ma non vengono dall'apparato: senza dirlo qui,
            # una configurazione vecchia di un mese si legge come la tabella
            # di adesso.
            when = a.get("backup_ts")
            stamp = (datetime.fromtimestamp(when).strftime("%d/%m/%Y %H:%M")
                     if when else "data sconosciuta")
            note = f"{note} — " if note else ""
            note += f"mostrate le sole rotte statiche dal backup del {stamp}"
        if note:
            errors.append({"device_ip": a["device_ip"], "error": note})
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


# --- Analisi di percorso -----------------------------------------------------


def _valid_ip(value: str) -> str:
    """L'indirizzo, o 400. Confine di sistema: quello che arriva di qui finisce
    in una risoluzione e, per la prova sul campo, in un comando su un
    apparato."""
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        raise HTTPException(status_code=400,
                            detail=f"'{value}' non e' un indirizzo IPv4 valido.")


async def _collect_selection(current_user, device: str):
    """Rotte e indirizzi degli apparati scelti, in una passata sola.

    Gli indirizzi delle interfacce sono il dato che permette di dire quale
    apparato possiede un next-hop: senza, il percorso si ferma al primo salto.
    """
    wanted = {p.strip() for p in device.split(",") if p.strip()}
    targets = [d for d in route_table.routable_devices(devices_in_scope(current_user))
               if d.get("IP") in wanted]
    sem = asyncio.Semaphore(MAX_CONCURRENT_DEVICES)

    async def one(dev):
        async with sem:
            answer = await run_ssh(route_table.collect_for, dev)
            rows = answer.get("rows") or []
            addrs = await run_ssh(path_trace.addresses_for, dev, rows)
            return dev, answer, rows, addrs

    collected = await asyncio.gather(*(one(d) for d in targets)) if targets else []

    rows_by_device, addresses, devices_by_ip, errors = {}, {}, {}, []
    for dev, answer, rows, addrs in collected:
        ip = dev.get("IP")
        rows_by_device[ip] = rows
        addresses[ip] = addrs
        devices_by_ip[ip] = dev
        if answer.get("error"):
            errors.append({"device_ip": ip, "error": answer["error"]})
    return rows_by_device, addresses, devices_by_ip, errors


@router.get("/api/routes/trace")
async def trace_path(
    device: str = Query("", max_length=2000),
    src: str = Query("", max_length=45),
    dst: str = Query("", max_length=45),
    current_user = Depends(get_current_user),
):
    """Il percorso verso ``dst`` a partire dall'apparato ``src``.

    Si ragiona sugli apparati SCELTI, gli stessi della tabella: un percorso
    calcolato su una flotta interrogata di nascosto sarebbe una sorpresa, e
    l'esito "non interrogato" dice esattamente quando la selezione e' troppo
    stretta per rispondere.

    Nessun pacchetto viene inviato: e' la tabella che viene interpretata. Per
    la prova sul campo c'e' l'endpoint separato qui sotto."""
    dst_ip = _valid_ip(dst)
    src_ip = _valid_ip(src)
    rows_by_device, addresses, devices_by_ip, errors = await _collect_selection(
        current_user, device)
    if src_ip not in rows_by_device:
        raise HTTPException(
            status_code=404,
            detail=f"{src_ip} non e' fra gli apparati selezionati e interrogabili.")
    result = path_trace.trace(dst_ip, src_ip, rows_by_device, addresses, devices_by_ip)
    result["errors"] = errors
    result["src"] = src_ip
    result["dst"] = dst_ip
    result["devices_queried"] = len(rows_by_device)
    return result


class ProbeSchema(BaseModel):
    device_ip: str                 # da dove parte il traceroute
    dst: str                       # verso dove


@router.post("/api/routes/trace/probe")
async def probe_path(payload: ProbeSchema,
                     current_user = Depends(require_operator)):
    """Traceroute VERO dall'apparato verso l'indirizzo.

    E' l'unica parte di questa vista che manda pacchetti, ed e' per questo un
    endpoint separato, in POST, riservato agli operatori e mai chiamato
    dall'apertura di un pannello: la prova sul campo la chiede l'utente."""
    dst_ip = _valid_ip(payload.dst)
    device = assert_device_allowed(current_user, _valid_ip(payload.device_ip))
    if device is None:
        raise HTTPException(status_code=404,
                            detail=f"Apparato {payload.device_ip} non in inventario.")
    log_audit(f"Traceroute da {device.get('IP')} verso {dst_ip} "
              f"richiesto da '{current_user.get('sub')}'.")
    answer = await run_ssh(path_trace.probe, device, dst_ip)
    answer["device_ip"] = device.get("IP")
    answer["device"] = device.get("Hostname") or device.get("IP")
    answer["dst"] = dst_ip
    return answer
