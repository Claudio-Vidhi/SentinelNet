# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router Topology. Estratto da app_server.py (fase 6.6): percorsi, metodi,
parametri e risposte identici al monolite."""

import asyncio
import json
import logging
import os
from typing import Annotated, Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from routers.deps import require_tab
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from services import inventory_manager
from core import core_engine, db
from services import visio_export
from security.security_manager import log_audit
from routers.deps import get_current_user, require_admin, filter_map_to_scope, user_group_scope, require_operator, assert_group_allowed
from routers.ai import chat_with_active_profile
from ai import map_layout

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


class AiLayoutNode(BaseModel):
    id: str = Field(max_length=256)
    type: str = Field("other", max_length=32)
    level: int = Field(0, ge=0, le=100)
    zone: str = Field("", max_length=256)

class AiLayoutLink(BaseModel):
    a: str = Field(max_length=256)
    b: str = Field(max_length=256)
    kind: str = Field("link", max_length=32)
    count: int = Field(1, ge=1, le=64)

class AiLayoutSchema(BaseModel):
    group: str = Field("all", max_length=256)
    nodes: List[AiLayoutNode] = Field(max_length=map_layout.MAX_NODES)
    links: List[AiLayoutLink] = Field([], max_length=map_layout.MAX_LINKS)
    goals: List[str] = Field([], max_length=len(map_layout.GOALS))
    selected: List[str] = Field([], max_length=map_layout.MAX_NODES)
    # Optional free-text direction from the user, and the names drawn on the
    # map (labels, sites) it is checked against. ``deny`` never leaves.
    instruction: str = Field("", max_length=map_layout.MAX_INSTRUCTION)
    deny: List[Annotated[str, Field(max_length=256)]] = Field([], max_length=4 * map_layout.MAX_NODES)


# --- ROTTE ---

@router.get("/api/topology", dependencies=[Depends(require_tab("tab-map", "tab-map-interactive"))])
def get_topology_adjacency(group: str = "all", current_user = Depends(get_current_user)):
    """Restituisce la lista di adiacenza fisica per il triage testuale."""
    data = core_engine.generate_network_map(group_filter=group)
    return filter_map_to_scope(data, user_group_scope(current_user))

def enrich_map_nodes(data: dict) -> dict:
    """Adds to the map the identity facts the app already holds elsewhere.

    The inspector panel showed "—" for data that was merely stored in another
    file: a discovered node carries the IP announced via CDP/LLDP, not its
    synthetic ``discovered_<hostname>`` id, and an access point never announces
    its own serial — only the controller that adopted it knows it. Same lookup
    order as the classification table, so the two never disagree.
    """
    from services import ap_store

    versions = inventory_manager.get_detected_versions()
    entries = ap_store.read_all()
    for node in data.get("nodes") or []:
        discovered = node.get("status") == "discovered"
        node["display_ip"] = (node.get("reported_ip") or "") if discovered else node["id"]
        if node.get("serial"):
            continue
        name = node.get("label") or node["id"]
        scan = (versions.get(node["id"])
                or (versions.get(node["display_ip"]) if node["display_ip"] else None)
                or {})
        entry = (ap_store.lookup_in(entries, name, node.get("group"),
                                    ip=node["display_ip"] or None)
                 or ap_store.lookup_in(entries, name, node.get("group")))
        node["serial"] = scan.get("serial") or (entry or {}).get("serial") or ""
        if entry:
            if entry.get("mac"):
                node["mac"] = entry["mac"]
            if entry.get("ip") and not node["display_ip"]:
                node["display_ip"] = entry["ip"]
            # Provenance: an access point has no backup and no management VLAN,
            # but the controller that adopted it knows which one it joined and
            # when it last reported it. Shown as coming from the WLC, never
            # mixed with data the device itself gave.
            if entry.get("wlc_ip"):
                node["wlc_ip"] = entry["wlc_ip"]
            if entry.get("seen_at"):
                node["wlc_seen_at"] = entry["seen_at"]
    return data


@router.get("/api/network-map", dependencies=[Depends(require_tab("tab-map", "tab-map-interactive", "tab-security"))])
def get_network_map(group: str = "all", current_user = Depends(get_current_user)):
    """Restituisce il grafo topologico strutturato per Vis.js."""
    data = core_engine.generate_network_map(group_filter=group)
    return enrich_map_nodes(filter_map_to_scope(data, user_group_scope(current_user)))

@router.post("/api/map/export/vsdx", dependencies=[Depends(require_tab("tab-map", "tab-map-interactive"))])
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

@router.post("/api/map/ai-layout", dependencies=[Depends(require_tab("tab-map-interactive"))])
def ai_map_layout(payload: AiLayoutSchema, current_user = Depends(get_current_user)):
    """Rows for the Schema map proposed by the active AI profile.

    Only an anonymous graph leaves (ai/map_layout.py): tokens, device types,
    levels and link kinds. The answer is read back to real ids here and goes
    only to the caller, who sent those ids in the first place.
    """
    if payload.group != "all":
        assert_group_allowed(current_user, payload.group)
    if not payload.nodes:
        raise HTTPException(status_code=400, detail="La mappa non ha apparati da disporre.")
    deny = [*payload.deny, payload.group,
            *(n.id for n in payload.nodes), *(n.zone for n in payload.nodes)]
    try:
        instruction = map_layout.check_instruction(payload.instruction, deny)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Direzione non inviata: {e}. "
                            "Indica gli apparati per tipo o selezionali sulla mappa.")
    data, token_map = map_layout.build_payload(
        [n.model_dump() for n in payload.nodes], [lk.model_dump() for lk in payload.links],
        payload.goals, payload.selected)
    try:
        messages = map_layout.build_messages(data, instruction)
    except ValueError as e:
        # The egress check refused: a bug in build_payload, never user error.
        logging.getLogger(__name__).error("AI layout payload refused: %s", e)
        raise HTTPException(status_code=500, detail="Dati della mappa non anonimi: invio bloccato.")
    reply, profile = chat_with_active_profile(messages)
    log_audit(f"Disposizione mappa via AI (provider='{profile.get('provider')}', "
              f"{len(data['nodes'])} nodi) richiesta dall'utente '{current_user.get('sub')}'.")
    try:
        rows, note = map_layout.parse_reply(reply, token_map)
    except ValueError as e:
        raise HTTPException(status_code=502, detail=f"Risposta AI non utilizzabile: {e}")
    return {"rows": rows, "note": note}

@router.get("/api/portchannels", dependencies=[Depends(require_tab("tab-map", "tab-map-interactive"))])
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
    # Joining the newest id per entity beats "id IN (subquery)": the latter made
    # SQLite scan every interface.state row to test membership, while the join
    # resolves the handful of winners by rowid. With idx_events_type_entity this
    # went from ~3.1s to ~0.4s on a 1M-row events table.
    rows = await db.read(
        """SELECT e.device_ip, e.interface, e.attrs_json, e.ts
           FROM events e
           JOIN (SELECT MAX(id) AS mid FROM events
                 WHERE event_type = 'interface.state'
                 GROUP BY tenant, entity_id) m ON m.mid = e.id""")
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

@router.post("/api/topology/reset", dependencies=[Depends(require_tab("tab-map", "tab-map-interactive"))])
def reset_topology(current_user = Depends(require_operator)):
    backup_dir = "backup-config"
    deleted_count = 0
    if os.path.exists(backup_dir):
        # Ricorsivo: i backup sono organizzati in sottocartelle per gruppo/sede.
        for root, _dirs, files in os.walk(backup_dir):
            for f in files:
                # ".txt" also matches archived versions under ".history"; their
                # "{ip}-index.json" sits in the same folder and must go with
                # them, or the drift tab lists versions whose files no longer
                # exist and every diff/baseline call for that device 404s.
                if f.endswith(".txt") or f.endswith("-index.json"):
                    try:
                        os.remove(os.path.join(root, f))
                        deleted_count += 1
                    except OSError as e:
                        # Il file resta: il conteggio dell'audit sarebbe una
                        # mezza verita' senza questa riga.
                        logging.warning("Reset topologia: %s non rimosso: %s", f, e)
    
    # Svuota detected_versions.json
    inventory_manager.safe_json_write(inventory_manager.VERSION_DATA_FILE, {})
    
    log_audit(f"Topologia resettata dall'utente '{current_user.get('sub')}'. Eliminati {deleted_count} file cache.")
    return {"status": "success", "deleted": deleted_count}

