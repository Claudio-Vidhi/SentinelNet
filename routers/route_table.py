# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router Routes: una tabella di routing sola, per gli apparati in scope.

HTTP soltanto — scope, filtri e forma della risposta. La raccolta e la
normalizzazione stanno in services/route_table.py.
"""
import asyncio
import ipaddress
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from routers.deps import require_tab
from pydantic import BaseModel

from core.ssh_pool import run_ssh
from routers.deps import (assert_device_allowed, devices_in_scope,
                          get_current_user, require_operator)
from security.security_manager import log_audit
from services import path_trace, route_table

router = APIRouter(dependencies=[Depends(require_tab("tab-routes"))], tags=["Routes"])

# Quanti apparati interrogare insieme. Un giro su tutta la flotta apre
# altrettante sessioni REST: il tetto tiene il tab reattivo e non trasforma
# l'apertura di una vista in una tempesta verso i firewall.
MAX_CONCURRENT_DEVICES = 8

# Short-TTL collection cache so Path Trace reuses RIB/context just fetched by /api/routes
# without re-opening SSH/REST sessions to every device.
_ROUTE_CACHE_TTL = 180.0
_ROUTE_CACHE_MAX = 256
_route_cache_lock = threading.Lock()
_route_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}


def _cache_key(dev: dict) -> Tuple[str, str]:
    return (str(dev.get("Group") or ""), str(dev.get("IP") or ""))


def _cache_get(key: Tuple[str, str]) -> Optional[Dict[str, Any]]:
    now = time.monotonic()
    with _route_cache_lock:
        entry = _route_cache.get(key)
        if not entry:
            return None
        if now - float(entry.get("ts", 0.0)) > _ROUTE_CACHE_TTL:
            _route_cache.pop(key, None)
            return None
        return dict(entry)


def _cache_put(key: Tuple[str, str], updates: Dict[str, Any]) -> None:
    now = time.monotonic()
    with _route_cache_lock:
        if len(_route_cache) >= _ROUTE_CACHE_MAX and key not in _route_cache:
            # Evict expired entries first, then oldest
            expired = [k for k, v in _route_cache.items()
                       if now - float(v.get("ts", 0.0)) > _ROUTE_CACHE_TTL]
            for k in expired:
                _route_cache.pop(k, None)
            if len(_route_cache) >= _ROUTE_CACHE_MAX:
                oldest = min(_route_cache.items(), key=lambda kv: float(kv[1].get("ts", 0.0)))[0]
                _route_cache.pop(oldest, None)
        cur = _route_cache.get(key) or {"ts": now}
        cur.update(updates)
        cur["ts"] = now
        _route_cache[key] = cur


def clear_route_cache() -> None:
    """Clear the in-memory route collection cache (used by tests or explicit reset)."""
    with _route_cache_lock:
        _route_cache.clear()


@router.get("/api/routes/devices")
def list_routable_devices(current_user = Depends(get_current_user)):
    """Gli apparati selezionabili, letti dall'inventario.

    Firewall e switch insieme: la lista non si costruisce piu' dalle righe
    tornate, che e' il motivo per cui uno switch mai interrogato non compariva
    fra quelli scegliibili."""
    return {"devices": [
        {"ip": d.get("IP"), "hostname": d.get("Hostname") or d.get("IP"),
         "group": d.get("Group") or "",
         "vendor": d.get("Vendor") or ""}
        for d in route_table.routable_devices(devices_in_scope(current_user))]}


def _audit_read(current_user, targets, backup_only: bool = False) -> None:
    """Who opened the SSH sessions: send_custom_command logs the command and
    the device, not the user who asked (security review 2026-10-12, L2)."""
    if targets:
        how = "dai backup" if backup_only else "via SSH"
        log_audit(f"Tabelle di routing lette {how} da '{current_user.get('sub')}' su: "
                  f"{', '.join(str(d.get('IP')) for d in targets)}.")


@router.get("/api/routes")
async def list_routes(
    device: str = Query("", max_length=2000),
    type: str = Query("", max_length=20),
    q: str = Query("", max_length=100),
    backup_only: bool = Query(False),
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
    _audit_read(current_user, targets, backup_only)

    sem = asyncio.Semaphore(MAX_CONCURRENT_DEVICES)

    async def one(dev):
        async with sem:
            answer = await run_ssh(route_table.collect_for, dev, backup_only)
            # A backup answer has no "api" source, so fortigate_context asks
            # the device nothing for it.
            fctx = await run_ssh(route_table.fortigate_context, dev, answer)
            # Backup-only answers stay out of the cache the live views reuse.
            if answer.get("rows") and not backup_only:
                _cache_put(_cache_key(dev), {
                    "answer": dict(answer),
                    "fctx": dict(fctx),
                    "addrs": list(fctx.get("addresses") or []) if fctx.get("addresses") else None,
                    "hctx_base": None,
                    "hctx_flow": None,
                })
            answer["context"] = fctx
            return answer

    answers = await asyncio.gather(*(one(d) for d in targets)) if targets else []

    # Per device: interface addresses, HA members, IPsec tunnels. The route
    # graph uses them to tell which selected device a next hop is.
    context = {a["device_ip"]: a.pop("context") for a in answers}
    rows, errors = [], []
    # Per device answered from a backup: the file's mtime, for the summary.
    backup_ts = {}
    for a in answers:
        note = a.get("error") or ""
        if a.get("source") == "backup":
            backup_ts[a["device_ip"]] = a.get("backup_ts")
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
            "devices_queried": len(targets), "context": context,
            "backup_ts": backup_ts,
            "counts": route_table.group_counts(rows),
            "breakdown": route_table.breakdown(rows)}


# --- Analisi di percorso -----------------------------------------------------


def _valid_ip(value: str) -> str:
    """L'indirizzo, o 400. Confine di sistema: quello che arriva di qui finisce
    in una risoluzione e, per la prova sul campo, in un comando su un
    apparato."""
    # IPv4 e basta: le tabelle raccolte e i parser sono IPv4, e un indirizzo v6
    # accettato qui non darebbe un errore ma un "nessuna rotta" incomprensibile.
    try:
        return str(ipaddress.IPv4Address((value or "").strip()))
    except ipaddress.AddressValueError:
        raise HTTPException(status_code=400,
                            detail=f"'{value}' non e' un indirizzo IPv4 valido.")


async def _collect_selection(current_user, device: str, flow: bool = False, use_cache: bool = False):
    """Rotte e indirizzi degli apparati scelti, in una passata sola.

    Gli indirizzi delle interfacce sono il dato che permette di dire quale
    apparato possiede un next-hop: senza, il percorso si ferma al primo salto.
    """
    wanted = {p.strip() for p in device.split(",") if p.strip()}
    targets = [d for d in route_table.routable_devices(devices_in_scope(current_user))
               if d.get("IP") in wanted]

    # Due clienti possono avere lo stesso IP. Qui le tabelle si indicizzano per
    # indirizzo, quindi una selezione ambigua non darebbe un percorso sbagliato
    # a meta': ne darebbe uno che mescola due reti senza dirlo. Meglio fermarsi.
    seen: "dict[str, dict]" = {}
    for dev in targets:
        clash = seen.setdefault(str(dev.get("IP")), dev)
        if clash is not dev:
            tenants = ", ".join(sorted({clash.get("Group") or "",
                                        dev.get("Group") or ""}))
            raise HTTPException(
                status_code=409,
                detail=f"{dev.get('IP')} esiste in piu' tenant ({tenants}): "
                       "restringere la selezione a uno solo.")

    sem = asyncio.Semaphore(MAX_CONCURRENT_DEVICES)
    live_targets = []
    cached_map: Dict[Tuple[str, str], Optional[Dict[str, Any]]] = {}
    for dev in targets:
        key = _cache_key(dev)
        entry = _cache_get(key) if use_cache else None
        cached_map[key] = entry
        if not entry or not entry.get("answer"):
            live_targets.append(dev)
    _audit_read(current_user, live_targets)

    async def one(dev):
        async with sem:
            key = _cache_key(dev)
            entry = cached_map.get(key)
            from_cache = bool(entry and entry.get("answer"))
            if from_cache and entry is not None:
                answer = dict(entry["answer"])
                rows = [dict(r) for r in (answer.get("rows") or [])]
                addrs = entry.get("addrs")
                if addrs is None:
                    addrs = await run_ssh(path_trace.addresses_for, dev, rows)
                else:
                    addrs = [dict(a) for a in addrs]
                fctx = entry.get("fctx")
                if fctx is None:
                    fctx = await run_ssh(route_table.fortigate_context, dev, answer, addrs, False)
                hctx_key = "hctx_flow" if flow else "hctx_base"
                hctx = entry.get(hctx_key) or (entry.get("hctx_flow") if not flow else None)
                if hctx is None:
                    hctx = await run_ssh(path_trace.collect_hop_context, dev, fctx, answer, flow)
                _cache_put(key, {
                    "addrs": list(addrs),
                    "fctx": fctx,
                    hctx_key: hctx,
                })
            else:
                answer = await run_ssh(route_table.collect_for, dev)
                rows = [dict(r) for r in (answer.get("rows") or [])]
                addrs = await run_ssh(path_trace.addresses_for, dev, rows)
                # Reuse the addresses just read and skip HA (the trace never reads
                # it): two REST calls less per FortiGate. Live policy lookup and IP
                # pools only when a source IP asks for flow evaluation.
                fctx = await run_ssh(route_table.fortigate_context, dev, answer, addrs, False)
                hctx = await run_ssh(path_trace.collect_hop_context, dev, fctx, answer, flow)
                if rows:
                    _cache_put(key, {
                        "answer": dict(answer),
                        "addrs": list(addrs),
                        "fctx": fctx,
                        "hctx_flow" if flow else "hctx_base": hctx,
                    })
            rows, addrs = path_trace.supplement_from_backup_env(dev, rows, addrs, hctx)
            return dev, answer, rows, addrs, hctx, from_cache

    collected = await asyncio.gather(*(one(d) for d in targets)) if targets else []

    rows_by_device, addresses, devices_by_ip, hop_contexts, errors = {}, {}, {}, {}, []
    cached_devices = 0
    for dev, answer, rows, addrs, hctx, from_cache in collected:
        ip = dev.get("IP")
        rows_by_device[ip] = rows
        addresses[ip] = addrs
        devices_by_ip[ip] = dev
        hop_contexts[ip] = hctx
        if from_cache:
            cached_devices += 1
        if answer.get("error"):
            errors.append({"device_ip": ip, "error": answer["error"]})
    return rows_by_device, addresses, devices_by_ip, hop_contexts, errors, cached_devices


@router.get("/api/routes/trace")
async def trace_path(
    device: str = Query("", max_length=2000),
    src: str = Query("", max_length=45),
    dst: str = Query("", max_length=45),
    src_ip: str = Query("", max_length=45),
    proto: str = Query("", max_length=16),
    dport: "int | None" = Query(None, ge=1, le=65535),
    vrf: str = Query("", max_length=64),
    use_cache: bool = Query(False),
    current_user = Depends(get_current_user),
):
    """Il percorso verso ``dst`` a partire dall'apparato ``src``.

    Si ragiona sugli apparati SCELTI, gli stessi della tabella: un percorso
    calcolato su una flotta interrogata di nascosto sarebbe una sorpresa, e
    l'esito "non interrogato" dice esattamente quando la selezione e' troppo
    stretta per rispondere.

    Quando ``src_ip`` (ed eventualmente ``proto``, ``dport``, ``vrf``) sono
    indicati, valuta ad ogni salto anche VRF, PBR, SD-WAN, NAT/VIP e
    policy/ACL (Cisco IOS e FortiGate).

    Nessun pacchetto viene inviato: e' la tabella che viene interpretata. Per
    la prova sul campo c'e' l'endpoint separato qui sotto."""
    dst_ip = _valid_ip(dst)
    start_ip = _valid_ip(src)
    flow_src_ip = _valid_ip(src_ip) if (src_ip or "").strip() else ""
    flow_proto = (proto or "").strip().lower()
    if flow_proto and flow_proto not in ("tcp", "udp", "icmp", "ip"):
        raise HTTPException(status_code=400,
                            detail=f"Protocollo '{proto}' non valido (usa tcp, udp, icmp, ip).")
    rows_by_device, addresses, devices_by_ip, hop_contexts, errors, cached_devices = await _collect_selection(
        current_user, device, flow=bool(flow_src_ip), use_cache=use_cache)
    if start_ip not in rows_by_device:
        raise HTTPException(
            status_code=404,
            detail=f"{start_ip} non e' fra gli apparati selezionati e interrogabili.")
    result = path_trace.trace(
        dst_ip, start_ip, rows_by_device, addresses, devices_by_ip,
        src_ip=flow_src_ip, proto=flow_proto, dport=dport,
        vrf=(vrf or "").strip(), hop_contexts=hop_contexts,
    )
    result["errors"] = errors
    result["src"] = start_ip
    result["dst"] = dst_ip
    result["devices_queried"] = len(rows_by_device)
    result["cached"] = bool(rows_by_device and cached_devices == len(rows_by_device))
    result["cached_devices"] = cached_devices
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
