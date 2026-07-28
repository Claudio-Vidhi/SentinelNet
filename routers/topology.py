# -*- coding: utf-8 -*-
"""Router Topology. Estratto da app_server.py (fase 6.6): percorsi, metodi,
parametri e risposte identici al monolite."""

import asyncio
import json
import os
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from services import inventory_manager
from core import core_engine, db
from services import visio_export
from security.security_manager import log_audit
from routers.deps import get_current_user, require_admin, filter_map_to_scope, user_group_scope, require_operator

router = APIRouter(tags=["Topology"])

class VisioNodeSchema(BaseModel):
    id: str
    label: str = ""
    model: str = ""
    ip: str = ""
    x: float = 0
    y: float = 0
    # Dimensioni/colori reali del riquadro (mappa minimalista): opzionali.
    w: Optional[float] = None
    h: Optional[float] = None
    fill: Optional[str] = None
    border: Optional[str] = None

class VisioEdgeSchema(BaseModel):
    source: str
    target: str
    label: str = ""
    color: str = "#6A5FC1"

class VisioExportSchema(BaseModel):
    nodes: List[VisioNodeSchema] = []
    edges: List[VisioEdgeSchema] = []
    # Primitive grafiche registrate dal frontend (mappa minimalista): etichette
    # porta, pillole Po/vPC, contenitori Sede.
    primitives: Optional[dict] = None
    # Cavi strutturati (mappa minimalista): diventano forme 1-D continue
    # incollate (glue) ai connection point dei riquadri dispositivo.
    connectors: Optional[List[dict]] = None


# --- ROTTE ---

@router.get("/api/topology")
def get_topology_adjacency(group: str = "all", current_user = Depends(get_current_user)):
    """Restituisce la lista di adiacenza fisica per il triage testuale."""
    data = core_engine.generate_network_map(group_filter=group)
    return filter_map_to_scope(data, user_group_scope(current_user))

@router.get("/api/network-map")
def get_network_map(group: str = "all", current_user = Depends(get_current_user)):
    """Restituisce il grafo topologico strutturato per Vis.js."""
    data = core_engine.generate_network_map(group_filter=group)
    return filter_map_to_scope(data, user_group_scope(current_user))

@router.post("/api/map/export/vsdx")
def export_map_vsdx(payload: VisioExportSchema, current_user = Depends(get_current_user)):
    """Esporta la mappa di rete corrente (posizioni già calcolate dal frontend) come .vsdx nativo."""
    data = visio_export.build_vsdx(
        [n.dict() for n in payload.nodes],
        [e.dict() for e in payload.edges],
        payload.primitives,
        payload.connectors,
    )
    log_audit(f"Export Visio mappa richiesto dall'utente '{current_user.get('sub')}'.")
    return Response(
        content=data,
        media_type="application/vnd.ms-visio.drawing",
        headers={"Content-Disposition": "attachment; filename=sentinelnet-map.vsdx"}
    )

@router.get("/api/portchannels")
async def get_portchannels(group: str = "all",
                           current_user = Depends(get_current_user)):
    """Report Port-channel per apparato (per il tab Adjacency List).

    Due sorgenti, ciascuna per ciò che sa davvero:
    - la **configurazione** (backup) dice chi è MEMBRO dell'aggregato e chi è
      spento da comando;
    - lo **stato SNMP** dice chi è SU adesso.

    Prima il report si reggeva solo sul backup, e lo stato operativo veniva da
    un ``show etherchannel summary`` presente solo in alcuni backup vecchi: una
    porta caduta dopo l'ultimo backup non compariva, e un badge di due
    settimane prima si leggeva come se fosse di adesso.
    """
    scope = user_group_scope(current_user)
    if group != "all" and scope is not None and group not in scope:
        raise HTTPException(status_code=403, detail="Sede non consentita.")
    report = await asyncio.to_thread(core_engine.get_portchannel_report,
                                     group_filter=group)
    if scope is not None:
        report = [r for r in report if r["group"] in scope]
    await _attach_live_state(report)
    return {"devices": report}


async def _attach_live_state(report: list) -> None:
    """Aggiunge a ogni membro lo stato osservato via SNMP, quando c'è.

    I nomi vanno normalizzati: la configurazione scrive ``Ethernet0/0``, IF-MIB
    espone ``Et0/0``. Confrontarli così com'erano non avrebbe agganciato nulla.
    """
    if not report:
        return
    from collectors.mac_collector import expand_iface
    rows = await db.read(
        """SELECT device_ip, interface, attrs_json, ts FROM events
           WHERE event_type = 'interface.state'
             AND id IN (SELECT MAX(id) FROM events
                        WHERE event_type = 'interface.state'
                        GROUP BY tenant, entity_id)""")
    live: dict = {}
    for r in rows:
        try:
            attrs = json.loads(r["attrs_json"] or "{}")
        except (ValueError, TypeError):
            continue
        live[(r["device_ip"], expand_iface(r["interface"] or ""))] = {
            "link": attrs.get("link"), "admin_status": attrs.get("admin_status"),
            "ts": r["ts"]}

    for device in report:
        seen = False
        for po in device.get("portchannels") or []:
            states = {}
            for member in po.get("members") or []:
                state = live.get((device["ip"], expand_iface(member)))
                if state:
                    states[member] = state
                    seen = True
            po["live"] = states
            if states:
                # Conteggio dal vivo: sostituisce quello del backup quando c'è,
                # perché descrive adesso invece dell'ultimo salvataggio.
                po["live_up"] = sum(
                    1 for s in states.values()
                    if str(s.get("link")).lower() == "up")
                po["live_total"] = len(states)
        device["live_state"] = seen

@router.post("/api/topology/reset")
def reset_topology(current_user = Depends(require_operator)):
    backup_dir = "backup-config"
    deleted_count = 0
    if os.path.exists(backup_dir):
        # Ricorsivo: i backup sono organizzati in sottocartelle per gruppo/sede.
        for root, _dirs, files in os.walk(backup_dir):
            for f in files:
                if f.endswith(".txt"):
                    try:
                        os.remove(os.path.join(root, f))
                        deleted_count += 1
                    except Exception:
                        pass
    
    # Svuota detected_versions.json
    inventory_manager.safe_json_write(inventory_manager.VERSION_DATA_FILE, {})
    
    log_audit(f"Topologia resettata dall'utente '{current_user.get('sub')}'. Eliminati {deleted_count} file cache.")
    return {"status": "success", "deleted": deleted_count}

