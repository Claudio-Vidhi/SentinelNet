# -*- coding: utf-8 -*-
"""Router Triage. Estratto da app_server.py (fase 6.6): percorsi, metodi,
parametri e risposte identici al monolite."""

import threading
from typing import Optional, List, Dict
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from services import inventory_manager
from core import core_engine
from security.security_manager import log_audit
from routers.deps import get_current_user, require_operator, user_group_scope, assert_device_allowed, assert_group_allowed

router = APIRouter(tags=["Triage"])

triage_lock = threading.Lock()
triage_job = {
    "status": "idle",
    "total": 0,
    "progress": 0,
    "results": [],
    "current_device": ""
}

class TriageRunRequest(BaseModel):
    group: str = "all"

class PingCheckRequest(BaseModel):
    group: str = "all"


# --- ROTTE ---

def run_triage_background(allowed_groups=None):
    global triage_job
    devices = inventory_manager.get_all_devices()
    if allowed_groups is not None:
        devices = [d for d in devices if d.get('Group') in allowed_groups]
    with triage_lock:
        triage_job["status"] = "running"
        triage_job["total"] = len(devices)
        triage_job["progress"] = 0
        triage_job["results"] = []
        triage_job["current_device"] = "Inizializzazione..."
    
    active_ips = set()
    
    def triage_worker(d):
        ip = d['IP']
        with triage_lock:
            active_ips.add(ip)
            triage_job["current_device"] = ", ".join(sorted(active_ips))
            
        try:
            res = core_engine.run_backup_and_triage(d)
        except Exception as e:
            res = {"status": "error", "message": str(e)}
            
        with triage_lock:
            if ip in active_ips:
                active_ips.remove(ip)
            triage_job["current_device"] = ", ".join(sorted(active_ips))
            triage_job["results"].append({"ip": ip, "result": res})
            triage_job["progress"] += 1

    # Avvia ThreadPoolExecutor per gestire fino a 10 triage simultanei in parallelo
    max_workers = min(10, len(devices)) if devices else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Esegue la mappatura concorrente sui dispositivi
        list(executor.map(triage_worker, devices))
        
    with triage_lock:
        triage_job["status"] = "complete"
        triage_job["current_device"] = ""

@router.post("/api/run-triage")
def run_triage(payload: TriageRunRequest = TriageRunRequest(),
               current_user = Depends(require_operator)):
    global triage_job

    # Determina le sedi da sottoporre a triage, rispettando lo scope dell'utente.
    scope = user_group_scope(current_user)
    if payload.group and payload.group != "all":
        assert_group_allowed(current_user, payload.group)
        target_groups = {payload.group}
    else:
        target_groups = scope  # None = tutte le sedi

    with triage_lock:
        if triage_job["status"] == "running":
            return {"status": "running", "message": "Scansione già in corso"}

        triage_job["status"] = "running"
        triage_job["progress"] = 0
        triage_job["total"] = 0
        triage_job["current_device"] = "Inizializzazione..."

    log_audit(
        f"Triage avviato dall'utente '{current_user.get('sub')}' "
        f"(sede: {payload.group})."
    )
    thread = threading.Thread(target=run_triage_background,
                              args=(target_groups,), daemon=True)
    thread.start()
    return {"status": "running", "message": "Scansione avviata in background"}

@router.post("/api/triage/{ip}")
def triage_single_device(ip: str, current_user = Depends(require_operator)):
    import re
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        raise HTTPException(status_code=400, detail="IP non valido.")
    devices = inventory_manager.get_all_devices()
    device = next((d for d in devices if d["IP"] == ip), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Dispositivo {ip} non trovato in inventario.")
    assert_group_allowed(current_user, device.get('Group', 'Generale'))
    result = core_engine.run_backup_and_triage(device)
    log_audit(f"Triage singolo eseguito su '{ip}' dall'utente '{current_user.get('sub')}': {result.get('status')}.")
    return result

@router.get("/api/triage-status")
def get_triage_status(current_user = Depends(get_current_user)):
    with triage_lock:
        return dict(triage_job)

@router.post("/api/ping-check")
def ping_check(payload: PingCheckRequest, current_user = Depends(require_operator)):
    """
    Verifica la raggiungibilità SSH (porta 22) di tutti i dispositivi
    nel gruppo selezionato, in parallelo con ThreadPoolExecutor.
    """
    from core.core_engine import is_reachable

    scope = user_group_scope(current_user)
    if payload.group != "all":
        assert_group_allowed(current_user, payload.group)

    devices = inventory_manager.get_all_devices()
    if payload.group != "all":
        devices = [d for d in devices if d.get('Group') == payload.group]
    elif scope is not None:
        devices = [d for d in devices if d.get('Group') in scope]

    results: dict[str, bool] = {}

    def _ping(d):
        results[d['IP']] = is_reachable(d['IP'], timeout=3)

    max_workers = min(20, len(devices)) if devices else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(_ping, devices))

    # Aggiorna lo stato nel file detected_versions.json
    try:
        data = inventory_manager.get_detected_versions()
        for d in devices:
            ip = d['IP']
            alive = results.get(ip, False)
            vendor = d.get('Vendor', 'cisco')
            version = 'Non Rilevata'
            if ip in data:
                vendor = data[ip].get('vendor', vendor)
                version = data[ip].get('version', version)
            inventory_manager.update_version_inventory(ip, vendor, version, "online" if alive else "offline")
    except Exception:
        pass

    log_audit(
        f"Ping check completato su {len(devices)} dispositivi "
        f"(gruppo: '{payload.group}') dall'utente '{current_user.get('sub')}')."
    )
    return {"results": results, "group": payload.group, "total": len(devices)}

@router.get("/api/ping/{ip}")
def ping_single(ip: str, current_user = Depends(require_operator)):
    from core.core_engine import is_reachable
    import re
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        raise HTTPException(status_code=400, detail="IP non valido.")
    # Scoping: se il dispositivo è in inventario, deve essere in una sede consentita
    _dev = next((d for d in inventory_manager.get_all_devices() if d['IP'] == ip), None)
    if _dev is not None:
        assert_group_allowed(current_user, _dev.get('Group', 'Generale'))
    alive = is_reachable(ip, timeout=3)

    # Aggiorna lo stato nel file detected_versions.json
    try:
        data = inventory_manager.get_detected_versions()
        vendor = "cisco"
        version = "Non Rilevata"
        if ip in data:
            vendor = data[ip].get("vendor", vendor)
            version = data[ip].get("version", version)
        else:
            devices = inventory_manager.get_all_devices()
            dev = next((d for d in devices if d["IP"] == ip), None)
            if dev:
                vendor = dev.get("Vendor", vendor)
        inventory_manager.update_version_inventory(ip, vendor, version, "online" if alive else "offline")
    except Exception:
        pass

    log_audit(f"Ping singolo verso '{ip}' eseguito dall'utente '{current_user.get('sub')}': {'raggiungibile' if alive else 'non raggiungibile'}.")
    return {"ip": ip, "reachable": alive}

