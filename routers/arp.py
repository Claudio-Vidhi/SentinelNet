# -*- coding: utf-8 -*-
"""Router ARP. Estratto da app_server.py (fase 6.6)."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks

from collectors import arp_collector
from services import inventory_manager
from collectors import mac_history
from routers.mac import MacScanSchema
from security.security_manager import log_audit
from routers.deps import get_current_user, require_operator, user_group_scope

router = APIRouter(tags=["ARP"])


# --- ENDPOINTS ---

@router.post("/api/arp/scan")
def arp_scan(payload: MacScanSchema, current_user = Depends(require_operator)):
    """Raccoglie le tabelle ARP dagli apparati selezionati (scoped per tenant)
    e storicizza i binding MAC<->IP. Nel mondo reale il gateway di una VLAN
    può essere uno switch L3 o un firewall: si interroga tutto ciò che è
    selezionato; chi non ruota VLAN torna vuoto ('empty'), non è un errore."""
    scope = user_group_scope(current_user)
    devices = inventory_manager.get_all_devices()

    want_ips = set(payload.ips or [])
    if payload.ip:
        want_ips.add(payload.ip)

    def allowed(d):
        g = d.get("Group") or "Generale"
        if scope is not None and g not in scope:
            return False
        if payload.group and payload.group != "all" and g != payload.group:
            return False
        if want_ips and d["IP"] not in want_ips:
            return False
        return True

    targets = [d for d in devices if allowed(d)]
    if not targets:
        raise HTTPException(status_code=404, detail="Nessun dispositivo idoneo per la scansione ARP.")

    summary = arp_collector.collect_all(targets)
    log_audit(f"ARP scan eseguita da '{current_user.get('sub')}' su {len(targets)} apparati "
              f"(nuovi: {summary['total_new']}, aggiornati: {summary['total_updated']}).")
    return summary

@router.get("/api/arp/search")
def arp_search(mac: Optional[str] = None, ip: Optional[str] = None,
               source_ip: Optional[str] = None, limit: int = 500,
               current_user = Depends(get_current_user)):
    """Ricerca i binding MAC<->IP raccolti (filtri combinabili, scoped per tenant)."""
    tenants = user_group_scope(current_user)
    return {"results": mac_history.search_arp(mac=mac, ip=ip, source_ip=source_ip,
                                              tenants=tenants, limit=limit)}

@router.get("/api/arp/client-map")
def arp_client_map(mac: Optional[str] = None, ip: Optional[str] = None,
                   tenant: Optional[str] = None, source_ip: Optional[str] = None,
                   limit: int = 500, current_user = Depends(get_current_user)):
    """Vista client unificata: MAC + IP (dal gateway che ruota la VLAN) +
    switch/porta di accesso (dalla MAC table). Risponde a 'chi è 10.0.0.5
    e a quale porta è attaccato'. tenant/source_ip restringono la vista
    (sempre dentro lo scope dell'utente)."""
    tenants = user_group_scope(current_user)
    if tenant and tenant != "all":
        tenants = [tenant] if (tenants is None or tenant in tenants) else []
    return {"results": mac_history.client_map(mac=mac, ip=ip, tenants=tenants,
                                              source_ip=source_ip or None,
                                              limit=limit)}

@router.get("/api/arp/stats")
def arp_stats_ep(current_user = Depends(get_current_user)):
    return mac_history.arp_stats(tenants=user_group_scope(current_user))

