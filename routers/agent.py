# -*- coding: utf-8 -*-
"""Router Agent. Estratto da app_server.py (fase 6.6)."""

import re
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from services import site_manager
from services import inventory_manager
from collectors import mac_history
from security.security_manager import log_audit

router = APIRouter(tags=["Agent"])

class AgentDeviceSchema(BaseModel):
    ip: str
    vendor: str = "cisco"
    hostname: str = ""

class AgentInventorySchema(BaseModel):
    devices: List[AgentDeviceSchema] = []

class AgentMacCollection(BaseModel):
    switch_ip: str
    switch_name: str = ""
    rows: List[dict] = []

class AgentMacSchema(BaseModel):
    collections: List[AgentMacCollection] = []

class AgentJobResultSchema(BaseModel):
    status: str = "done"           # "done" | "error"
    result: str = ""

def get_agent_site(request: Request):
    """Autentica un agente tramite header X-Site-Token (+ opzionale X-Site-Id).
    Ritorna il dict della sede agent. 401 se il token non corrisponde."""
    token = request.headers.get("X-Site-Token") or request.headers.get("x-site-token")
    claimed_id = request.headers.get("X-Site-Id") or request.headers.get("x-site-id")
    site_id = site_manager.authenticate(token)
    if not site_id or (claimed_id and claimed_id != site_id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token di sede non valido.")
    site_manager.touch_last_seen(site_id)
    return site_manager.get_site(site_id)

@router.post("/api/agent/heartbeat")
def agent_heartbeat(site = Depends(get_agent_site)):
    return {"ok": True, "site_id": site["id"], "name": site["name"], "subnets": site.get("subnets", [])}

@router.post("/api/agent/inventory")
def agent_push_inventory(payload: AgentInventorySchema, site = Depends(get_agent_site)):
    """L'agente spinge il proprio inventario locale: viene rispecchiato sul
    centrale, taggato con la sede. Le credenziali NON sono replicate (i comandi
    passano dal relay, eseguiti in locale dall'agente)."""
    site_id = site["id"]
    n = 0
    existing_groups = {d.get("IP"): d.get("Group") for d in inventory_manager.get_all_devices()}
    for d in payload.devices:
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", d.ip):
            continue
        # Preserva il Group esistente: non declassare a 'Generale' ad ogni push.
        group = existing_groups.get(d.ip) or "Generale"
        inventory_manager.add_or_update_device(
            d.ip, d.vendor, "custom", "", "", "", group, site=site_id)
        if d.hostname:
            inventory_manager.update_device_hostname(d.ip, d.hostname)
        n += 1
    log_audit(f"Agente sede '{site_id}': inventario aggiornato ({n} dispositivi).")
    return {"status": "success", "updated": n}

@router.post("/api/agent/mac")
def agent_push_mac(payload: AgentMacSchema, site = Depends(get_agent_site)):
    """L'agente spinge le MAC-table raccolte localmente. Vengono storicizzate con
    attribuzione alla sede (site) per il MAC tracker centrale."""
    site_id = site["id"]
    total = 0
    # Tenant = Group del device in inventario (coerente con la raccolta centrale),
    # non l'id sede: lo scoping utenti filtra per Group.
    groups_by_ip = {d.get("IP"): d.get("Group") for d in inventory_manager.get_all_devices()}
    for col in payload.collections:
        summ = mac_history.record_sightings(
            col.rows, switch_ip=col.switch_ip, switch_name=col.switch_name,
            tenant=groups_by_ip.get(col.switch_ip) or "Generale", site=site_id)
        total += summ.get("new", 0) + summ.get("updated", 0)
    pruned = mac_history.prune()
    log_audit(f"Agente sede '{site_id}': {len(payload.collections)} MAC-table ricevute "
              f"({total} avvistamenti, pruned {pruned}).")
    return {"status": "success", "recorded": total, "pruned": pruned}

@router.get("/api/agent/jobs")
def agent_poll_jobs(site = Depends(get_agent_site)):
    """L'agente preleva i job di comando pendenti (marcati 'running')."""
    return {"jobs": site_manager.claim_pending_jobs(site["id"])}

@router.post("/api/agent/jobs/{job_id}/result")
def agent_post_job_result(job_id: str, payload: AgentJobResultSchema,
                          site = Depends(get_agent_site)):
    if not site_manager.complete_job(job_id, site["id"], payload.status, payload.result):
        raise HTTPException(status_code=404, detail="Job non trovato per questa sede.")
    return {"status": "success"}

