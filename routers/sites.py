# -*- coding: utf-8 -*-
"""Router Sites. Estratto da app_server.py (fase 6.6)."""

import re
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel

from security.security_manager import log_audit
from routers.deps import require_admin, require_operator
from routers.commands import command_allowed, is_command_safe, _bypass_note
from services import site_manager

router = APIRouter(tags=["Sites"])

class SiteSchema(BaseModel):
    name: str
    mode: str = "central"          # "central" | "agent"
    subnets: List[str] = []

class SiteUpdateSchema(BaseModel):
    id: str
    name: Optional[str] = None
    mode: Optional[str] = None
    subnets: Optional[List[str]] = None

class SiteIdSchema(BaseModel):
    id: str

class SiteCommandSchema(BaseModel):
    ip: str
    command: str

@router.get("/api/sites")
def list_sites_ep(current_user = Depends(require_admin)):
    return {"sites": site_manager.list_sites()}

@router.post("/api/sites")
def create_site_ep(payload: SiteSchema, current_user = Depends(require_admin)):
    try:
        site, token = site_manager.create_site(payload.name, payload.mode, payload.subnets)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    log_audit(f"Sede '{site['id']}' (mode: {payload.mode}) creata da '{current_user.get('sub')}'.")
    # Il token in chiaro è restituito UNA SOLA VOLTA (poi solo hash su disco).
    return {"status": "success", "site": site, "token": token}

@router.post("/api/sites/update")
def update_site_ep(payload: SiteUpdateSchema, current_user = Depends(require_admin)):
    try:
        ok = site_manager.update_site(payload.id, payload.name, payload.mode, payload.subnets)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    log_audit(f"Sede '{payload.id}' aggiornata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/sites/delete")
def delete_site_ep(payload: SiteIdSchema, current_user = Depends(require_admin)):
    if not site_manager.delete_site(payload.id):
        raise HTTPException(status_code=400, detail="Sede non eliminabile o inesistente.")
    log_audit(f"Sede '{payload.id}' eliminata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/sites/regenerate-token")
def regenerate_site_token_ep(payload: SiteIdSchema, current_user = Depends(require_admin)):
    token = site_manager.regenerate_token(payload.id)
    if token is None:
        raise HTTPException(status_code=400, detail="Sede inesistente o non in modalità agent.")
    log_audit(f"Token della sede '{payload.id}' rigenerato da '{current_user.get('sub')}'.")
    return {"status": "success", "token": token}

@router.post("/api/sites/{site_id}/command")
def site_command_ep(site_id: str, payload: SiteCommandSchema,
                    current_user = Depends(require_operator)):
    """Accoda un comando CLI per un dispositivo di una sede agent. L'agente lo
    preleverà in polling, lo eseguirà localmente e ne posterà il risultato."""
    site = site_manager.get_site(site_id)
    if not site:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    if site.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Il relay comandi è disponibile solo per sedi in modalità agent.")
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", payload.ip):
        raise HTTPException(status_code=400, detail="IP non valido.")
    if not command_allowed(payload.command, current_user):
        log_audit(f"Relay comando bloccato (blacklist) '{payload.command}' su '{payload.ip}' "
                  f"sede '{site_id}' da '{current_user.get('sub')}'.")
        raise HTTPException(status_code=400, detail="Comando non consentito per motivi di sicurezza (in blacklist).")
    if not is_command_safe(payload.command):
        log_audit(f"Relay comando in blacklist '{payload.command}' su '{payload.ip}' sede '{site_id}' "
                  f"consentito a '{current_user.get('sub')}' {_bypass_note(current_user)}.")
    job = site_manager.enqueue_job(site_id, payload.ip, payload.command,
                                   requested_by=current_user.get("sub"))
    log_audit(f"Comando CLI accodato per sede agent '{site_id}' su '{payload.ip}' "
              f"da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "queued", "job_id": job["id"]}

@router.get("/api/command-jobs/{job_id}")
def get_command_job_ep(job_id: str, current_user = Depends(require_operator)):
    job = site_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job non trovato.")
    return job

@router.get("/api/sites/{site_id}/command-jobs")
def list_site_command_jobs_ep(site_id: str, current_user = Depends(require_operator)):
    return {"jobs": site_manager.list_jobs(site_id)}


class AgentConfigUpdateSchema(BaseModel):
    syslog_port: Optional[int] = None
    interval: Optional[int] = None
    syslog_enabled: Optional[bool] = None


@router.post("/api/sites/{site_id}/agent/update")
def agent_self_update_ep(site_id: str, current_user = Depends(require_admin)):
    """Accoda un comando RPC di self-update (git pull) per l'agente remoto."""
    site = site_manager.get_site(site_id)
    if not site:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    if site.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Gestione agente disponibile solo per sedi in modalità agent.")
    job = site_manager.enqueue_job(site_id, "127.0.0.1", "_agent_self_update", requested_by=current_user.get("sub"))
    log_audit(f"Self-update agent (git pull) accodato per sede '{site_id}' da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "queued", "job_id": job["id"]}


@router.post("/api/sites/{site_id}/agent/restart")
def agent_restart_ep(site_id: str, current_user = Depends(require_admin)):
    """Accoda un comando RPC di restart per l'agente remoto (systemctl auto-restart)."""
    site = site_manager.get_site(site_id)
    if not site:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    if site.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Gestione agente disponibile solo per sedi in modalità agent.")
    job = site_manager.enqueue_job(site_id, "127.0.0.1", "_agent_restart", requested_by=current_user.get("sub"))
    log_audit(f"Restart agent accodato per sede '{site_id}' da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "queued", "job_id": job["id"]}


@router.post("/api/sites/{site_id}/agent/config")
def agent_config_update_ep(site_id: str, payload: AgentConfigUpdateSchema, current_user = Depends(require_admin)):
    """Accoda un comando RPC per aggiornare i parametri di configurazione dell'agente remoto."""
    site = site_manager.get_site(site_id)
    if not site:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    if site.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Gestione agente disponibile solo per sedi in modalità agent.")
    cfg_json = payload.model_dump_json(exclude_none=True)
    cmd = f"_agent_config {cfg_json}"
    job = site_manager.enqueue_job(site_id, "127.0.0.1", cmd, requested_by=current_user.get("sub"))
    log_audit(f"Aggiornamento config agent accodato per sede '{site_id}' da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "queued", "job_id": job["id"]}


class AgentInventorySaveSchema(BaseModel):
    content: str


@router.post("/api/sites/{site_id}/agent/inventory/get")
def agent_get_inventory_ep(site_id: str, current_user = Depends(require_admin)):
    """Accoda un comando RPC per leggere l'inventario locale network_hosts.csv dell'agente."""
    site = site_manager.get_site(site_id)
    if not site:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    if site.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Gestione agente disponibile solo per sedi in modalità agent.")
    job = site_manager.enqueue_job(site_id, "127.0.0.1", "_agent_get_inventory", requested_by=current_user.get("sub"))
    log_audit(f"Lettura inventario agent accodato per sede '{site_id}' da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "queued", "job_id": job["id"]}


@router.post("/api/sites/{site_id}/agent/inventory/save")
def agent_save_inventory_ep(site_id: str, payload: AgentInventorySaveSchema, current_user = Depends(require_admin)):
    """Accoda un comando RPC per salvare l'inventario locale network_hosts.csv dell'agente."""
    site = site_manager.get_site(site_id)
    if not site:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    if site.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Gestione agente disponibile solo per sedi in modalità agent.")
    cmd = f"_agent_save_inventory {payload.content}"
    job = site_manager.enqueue_job(site_id, "127.0.0.1", cmd, requested_by=current_user.get("sub"))
    log_audit(f"Salvataggio inventario agent accodato per sede '{site_id}' da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "queued", "job_id": job["id"]}


class FlowControlSchema(BaseModel):
    active: bool


@router.post("/api/sites/{site_id}/agent/flow-control")
def agent_flow_control_ep(site_id: str, payload: FlowControlSchema, current_user = Depends(require_admin)):
    """Mette in pausa o riprende l'ingestione / streaming dati per la sede agent."""
    site = site_manager.get_site(site_id)
    if not site:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    if site.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Gestione flusso disponibile solo per sedi in modalità agent.")
    site_manager.set_site_flow_status(site_id, payload.active)
    cmd = "_agent_flow_start" if payload.active else "_agent_flow_stop"
    job = site_manager.enqueue_job(site_id, "127.0.0.1", cmd, requested_by=current_user.get("sub"))
    status_str = "riavviato" if payload.active else "interrotto (pausa)"
    log_audit(f"Flusso dati agente {status_str} per sede '{site_id}' da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "success", "flow_active": payload.active, "job_id": job["id"]}


