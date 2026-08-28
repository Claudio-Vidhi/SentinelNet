# -*- coding: utf-8 -*-
"""Router Sites. Estratto da app_server.py (fase 6.6)."""

import re
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel

from security.security_manager import log_audit
from routers.deps import require_admin, require_operator, user_group_scope
from routers.commands import command_allowed, is_command_safe, _bypass_note
from services import inventory_manager, site_manager

router = APIRouter(tags=["Sites"])


def _device_in_scope(current_user, device_ip: str) -> bool:
    """Il device ricade in una sede consentita all'utente (CONTRIBUTING §4).

    Predicato e non ``assert_device_allowed``: quello solleva 403 se il device
    esiste fuori scope ma ritorna ``None`` se non esiste, e qui i due casi vanno
    resi indistinguibili. Si autorizza sul device, non sul ``site_id``, perché è
    il gruppo del device a definire lo scope utente. Un device sconosciuto non è
    autorizzabile: falso, tranne per chi non ha restrizioni."""
    scope = user_group_scope(current_user)
    if scope is None:
        return True
    device = next((d for d in inventory_manager.get_all_devices()
                   if d["IP"] == device_ip), None)
    return device is not None and device.get("Group", "Generale") in scope

class SiteSchema(BaseModel):
    name: str
    mode: str = "central"          # "central" | "agent" | "jump"
    subnets: List[str] = []
    # Bastion fields, required by site_manager only when mode == "jump".
    jump_host: Optional[str] = None
    jump_port: Optional[int] = None
    jump_identity: Optional[str] = None
    # Default identity for the devices behind the bastion (not the bastion's own).
    device_identity: Optional[str] = None

class SiteUpdateSchema(BaseModel):
    id: str
    name: Optional[str] = None
    mode: Optional[str] = None
    subnets: Optional[List[str]] = None
    jump_host: Optional[str] = None
    jump_port: Optional[int] = None
    jump_identity: Optional[str] = None
    device_identity: Optional[str] = None

class SiteIdSchema(BaseModel):
    id: str

class SiteCommandSchema(BaseModel):
    ip: str
    command: str

@router.get("/api/sites")
def list_sites_ep(current_user = Depends(require_operator)):
    # Operators read this to fill the site selectors, so it is not admin-only.
    # They get the three fields those selectors need. The bastion address of a
    # jump site, its identity, its subnets and its token state stay with the
    # admins who configure them: a dropdown does not need any of it.
    # (Comment, not a docstring: a docstring here becomes the endpoint's
    # OpenAPI description and changes the contract snapshot.)
    sites = site_manager.list_sites()
    if current_user.get("role") != "admin":
        sites = [{"id": s["id"], "name": s["name"], "mode": s["mode"]} for s in sites]
    return {"sites": sites}

@router.post("/api/sites")
def create_site_ep(payload: SiteSchema, current_user = Depends(require_admin)):
    try:
        site, token = site_manager.create_site(
            payload.name, payload.mode, payload.subnets,
            jump_host=payload.jump_host, jump_port=payload.jump_port,
            jump_identity=payload.jump_identity,
            device_identity=payload.device_identity)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    log_audit(f"Sede '{site['id']}' (mode: {payload.mode}) creata da '{current_user.get('sub')}'.")
    # Il token in chiaro è restituito UNA SOLA VOLTA (poi solo hash su disco).
    return {"status": "success", "site": site, "token": token}

@router.post("/api/sites/update")
def update_site_ep(payload: SiteUpdateSchema, current_user = Depends(require_admin)):
    # Only forward jump fields the caller actually supplied: update_site merges
    # kwargs over the stored site before re-validating a jump site (see its
    # docstring), so an explicit None here would clobber an unrelated field
    # (e.g. renaming a jump site) with a blank and make it fail revalidation.
    jump_kwargs: Dict[str, Any] = {}
    if payload.jump_host is not None:
        jump_kwargs["jump_host"] = payload.jump_host
    if payload.jump_port is not None:
        jump_kwargs["jump_port"] = payload.jump_port
    if payload.jump_identity is not None:
        jump_kwargs["jump_identity"] = payload.jump_identity
    if payload.device_identity is not None:
        jump_kwargs["device_identity"] = payload.device_identity
    try:
        ok = site_manager.update_site(payload.id, payload.name, payload.mode,
                                      payload.subnets, **jump_kwargs)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    # An edited bastion login must take effect now. The transport cached for
    # this site was authenticated with the previous credentials and keeps
    # working, so without this the change only applies once that session dies.
    if any(k in jump_kwargs for k in ("jump_host", "jump_port", "jump_identity")):
        from core import net_ssh
        net_ssh.invalidate_site(payload.id)
    log_audit(f"Sede '{payload.id}' aggiornata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/sites/delete")
def delete_site_ep(payload: SiteIdSchema, current_user = Depends(require_admin)):
    if not site_manager.delete_site(payload.id):
        raise HTTPException(status_code=400, detail="Sede non eliminabile o inesistente.")
    log_audit(f"Sede '{payload.id}' eliminata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/sites/test-bastion")
def test_bastion_ep(payload: SiteIdSchema, current_user = Depends(require_admin)):
    # Answers the question the device errors cannot: is it the BASTION login
    # that is wrong? A refused bastion and a refused device both surface as
    # "authentication failed" on the device row, and the operator ends up
    # rotating the credential on the wrong machine.
    from core import net_ssh
    site = site_manager.get_site(payload.id)
    if not site:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    if site.get("mode") != "jump":
        raise HTTPException(status_code=400, detail="La sede non e' in modalita' jump.")
    try:
        net_ssh.probe_bastion(site)
    except net_ssh.BastionAuthError as e:
        log_audit(f"Test bastione sede '{payload.id}' da '{current_user.get('sub')}': credenziali rifiutate.")
        return {"status": "auth_failed", "message": str(e)}
    except Exception as e:
        log_audit(f"Test bastione sede '{payload.id}' da '{current_user.get('sub')}': irraggiungibile.")
        return {"status": "unreachable", "message": str(e)}
    log_audit(f"Test bastione sede '{payload.id}' da '{current_user.get('sub')}': OK.")
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
    if not _device_in_scope(current_user, payload.ip):
        log_audit(f"Relay comando negato (fuori scope) su '{payload.ip}' sede "
                  f"'{site_id}' a '{current_user.get('sub')}'.")
        raise HTTPException(
            status_code=403,
            detail=f"Dispositivo '{payload.ip}' non fra le sedi consentite.")
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
    # Job fuori scope: 404 identico al job inesistente, per non confermare
    # l'esistenza di attività in sedi altrui (stessa politica di /anomalies).
    if not _device_in_scope(current_user, job.get("device_ip", "")):
        raise HTTPException(status_code=404, detail="Job non trovato.")
    return job

@router.get("/api/sites/{site_id}/command-jobs")
def list_site_command_jobs_ep(site_id: str, current_user = Depends(require_operator)):
    jobs = site_manager.list_jobs(site_id)
    scope = user_group_scope(current_user)
    if scope is not None:
        # Filtro, non 403: la lista è la vista dell'utente sulla sede, e deve
        # contenere ciò che gli è consentito vedere e nient'altro.
        allowed = {d["IP"] for d in inventory_manager.get_all_devices()
                   if d.get("Group", "Generale") in scope}
        jobs = [j for j in jobs if j.get("device_ip") in allowed]
    return {"jobs": jobs}


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
    # Il CSV lo scriverà l'agente, ma se è illeggibile va detto adesso: dopo
    # l'accodamento l'errore arriverebbe solo al polling successivo, dentro il
    # risultato di un job, dove nessuno lo cerca.
    try:
        inventory_manager._read_inventory_csv(payload.content)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
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


