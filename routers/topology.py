# -*- coding: utf-8 -*-
"""Router Topology. Estratto da app_server.py (fase 6.6): percorsi, metodi,
parametri e risposte identici al monolite."""

import os
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

import inventory_manager
import core_engine
import visio_export
from security_manager import log_audit
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
def get_portchannels(group: str = "all", current_user = Depends(get_current_user)):
    """Report Port-channel per apparato (per il tab Adjacency List), filtrato per sede."""
    scope = user_group_scope(current_user)
    if group != "all" and scope is not None and group not in scope:
        raise HTTPException(status_code=403, detail="Sede non consentita.")
    report = core_engine.get_portchannel_report(group_filter=group)
    if scope is not None:
        report = [r for r in report if r["group"] in scope]
    return {"devices": report}

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

