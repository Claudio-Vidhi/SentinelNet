# -*- coding: utf-8 -*-
"""Router MAC. Estratto da app_server.py (fase 6.6)."""

import os
import time
from typing import Optional, List, Dict

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from pydantic import BaseModel

from services import inventory_manager
from core import core_engine
from collectors import mac_collector
from collectors import mac_history
from security.security_manager import log_audit
from routers.deps import get_current_user, require_operator, require_admin, user_group_scope, assert_group_allowed, assert_device_allowed

router = APIRouter(tags=["MAC"])

class MacScanSchema(BaseModel):
    group: str = "all"
    ip: Optional[str] = None
    ips: List[str] = []               # multi-selezione: più device in un'unica scansione
    transport: Optional[str] = None   # netconf | restconf | cli | None=auto

class MacRetentionSchema(BaseModel):
    days: int

class MacOverrideSchema(BaseModel):
    ip: str
    command: str
    fmt: str = "generic"    # bridge-domain | mac-address-table | generic

class MacOverrideDeleteSchema(BaseModel):
    ip: str

_MAC_INFRA_TYPES = {"switch", "router"}

# --- ENDPOINTS E HELPERS ---

# Classificazione uplink/accesso: vive in collectors/mac_history.py perche'
# la leggono in due — questa tab e la diagnosi client — e finche' stava qui
# la diagnosi usava il valore grezzo, con i Port-channel scambiati per porte
# di accesso. Stessa riga, due verdetti diversi a seconda di chi la leggeva.
_mac_topology_uplinks = mac_history.topology_uplinks
_reclassify_sightings = mac_history.reclassify_sightings

def _mac_group(rows):
    """Raggruppa gli avvistamenti (già riclassificati) per MAC in
    {mac, oui_vendor, origin[], transit[], status}. origin ordinato per recency."""
    by_mac, order = {}, []
    for s in rows:
        m = s["mac"]
        if m not in by_mac:
            order.append(m)
            by_mac[m] = []
        by_mac[m].append(s)

    results = []
    for m in order:
        grp = by_mac[m]
        origin = [s for s in grp if not s.get("is_uplink")]
        transit = [s for s in grp if s.get("is_uplink")]
        # Ordina per ultimo avvistamento (più recente prima).
        origin.sort(key=lambda s: s.get("last_seen", ""), reverse=True)
        transit.sort(key=lambda s: s.get("last_seen", ""), reverse=True)
        # Posizioni di accesso DISTINTE (switch, interfaccia): l'ambiguità reale.
        distinct = {(s.get("switch_ip"), (s.get("interface") or "").lower()) for s in origin}
        if not origin and not transit:
            status = "not_found"
        elif not origin:
            status = "transit_only"          # visto solo in transito → dietro switch non gestito
        elif len(distinct) > 1:
            status = "ambiguous"             # più porte d'accesso plausibili
        else:
            status = "resolved"
        oui = next((s["oui_vendor"] for s in grp if s.get("oui_vendor")), "")
        entry = {"mac": m, "oui_vendor": oui, "origin": origin,
                 "transit": transit, "status": status,
                 "access_count": len(distinct)}
        # MAC di un'interfaccia propria di uno switch: infrastruttura, non endpoint.
        si = next((s for s in grp if s.get("origin_type") == "switch-interface"), None)
        if si:
            entry["device_type"] = "switch-interface"
            entry["origin_type"] = "switch-interface"
            entry["origin_switch"] = si.get("origin_switch") or ""
            entry["origin_interface"] = si.get("origin_interface") or ""
        results.append(entry)
    # I gruppi switch-interface (infrastruttura) vanno dopo gli endpoint.
    results.sort(key=lambda e: 1 if e.get("origin_type") == "switch-interface" else 0)
    return results

@router.post("/api/mac/scan")
def mac_scan(payload: MacScanSchema, current_user = Depends(require_operator)):
    """Raccoglie la MAC-table degli apparati selezionati (scoped per tenant) e la
    storicizza. Manuale, parallelizzato; al termine applica la retention."""
    scope = user_group_scope(current_user)
    devices = inventory_manager.get_all_devices()

    # Insieme di IP richiesti esplicitamente (singolo 'ip' e/o multi-selezione 'ips').
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
        raise HTTPException(status_code=404, detail="Nessun dispositivo idoneo per la scansione MAC.")

    # Raccolta in parallelo e storicizzazione: la sequenza vive nel collector,
    # così la riscansione mirata della diagnosi client usa la stessa e non una
    # copia che col tempo diverge (uplink, override, MAC di interfaccia).
    out = mac_collector.collect_all(targets, transport=payload.transport)
    log_audit(f"MAC scan eseguita da '{current_user.get('sub')}' su {len(targets)} apparati "
              f"(pruned: {out['pruned']}).")
    return out

@router.get("/api/mac/search")
def mac_search(mac: Optional[str] = None, vlan: Optional[str] = None, interface: Optional[str] = None,
               switch: Optional[str] = None, frm: Optional[str] = None, to: Optional[str] = None,
               tenant: Optional[str] = None,
               current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    if tenant:
        if scope is not None and tenant not in scope:
            raise HTTPException(status_code=403, detail=f"Tenant '{tenant}' non consentito.")
        tenants = [tenant]
    else:
        tenants = scope
    rows = mac_history.search(mac=mac, vlan=vlan, interface=interface,
                              switch_ip=switch, tenants=tenants, frm=frm, to=to,
                              limit=10000)
    # Riclassifica accesso/transito contro la topologia globale (fix falsi positivi).
    _reclassify_sightings(rows)
    return {"results": rows, "count": len(rows)}

@router.get("/api/mac/locate")
def mac_locate(mac: str, current_user = Depends(get_current_user)):
    if not mac or not mac.strip():
        raise HTTPException(status_code=400, detail="Parametro mac obbligatorio")
    scope = user_group_scope(current_user)
    sightings = mac_history.search(mac=mac, tenants=scope, limit=500)
    if not sightings:
        return {"status": "not_found", "origin": [], "transit": [], "results": []}
    _reclassify_sightings(sightings)
    results = _mac_group(sightings)
    if len(results) == 1:
        r = results[0]
        return {"mac": r["mac"], "status": r["status"], "access_count": r["access_count"],
                "origin": r["origin"], "transit": r["transit"],
                "origin_type": r.get("origin_type"), "device_type": r.get("device_type"),
                "origin_switch": r.get("origin_switch"), "origin_interface": r.get("origin_interface"),
                "results": results}
    return {"results": results}

@router.get("/api/mac/switch/{ip}")
def mac_switch(ip: str, current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    return {"results": mac_history.switch_table(ip, tenants=scope)}

@router.get("/api/mac/stats")
def mac_stats(tenant: Optional[str] = None, current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    if tenant:
        if scope is not None and tenant not in scope:
            raise HTTPException(status_code=403, detail=f"Tenant '{tenant}' non consentito.")
        tenants = [tenant]
    else:
        tenants = scope
    return mac_history.stats(tenants=tenants)

@router.post("/api/mac/settings")
def mac_set_settings(payload: MacRetentionSchema, current_user = Depends(require_admin)):
    days = mac_history.set_retention_days(payload.days)
    log_audit(f"MAC retention impostata a {days} giorni da '{current_user.get('sub')}'.")
    return {"retention_days": days}

@router.get("/api/mac/overrides")
def mac_list_overrides(current_user = Depends(get_current_user)):
    return {"overrides": mac_history.list_overrides()}

@router.post("/api/mac/overrides")
def mac_set_override(payload: MacOverrideSchema, current_user = Depends(require_operator)):
    if payload.fmt not in mac_collector.CLI_FORMATS:
        raise HTTPException(status_code=400, detail="Formato di parsing non valido.")
    assert_device_allowed(current_user, payload.ip)
    if not mac_history.set_override(payload.ip, payload.command, payload.fmt):
        raise HTTPException(status_code=400, detail="IP e comando obbligatori.")
    log_audit(f"MAC override per '{payload.ip}' impostato ('{payload.command}' / {payload.fmt}) "
              f"da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/mac/overrides/delete")
def mac_delete_override(payload: MacOverrideDeleteSchema, current_user = Depends(require_operator)):
    assert_device_allowed(current_user, payload.ip)
    mac_history.delete_override(payload.ip)
    log_audit(f"MAC override per '{payload.ip}' rimosso da '{current_user.get('sub')}'.")
    return {"status": "success"}

