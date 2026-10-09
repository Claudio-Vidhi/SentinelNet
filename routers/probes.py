# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router Probes. Estratto da app_server.py (fase 6.6)."""

import re
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from routers.deps import require_tab
from pydantic import BaseModel

from security.security_manager import log_audit
from routers.deps import require_unscoped_admin, require_operator, user_group_scope, is_unscoped_admin
from routers.commands import command_allowed, is_command_safe, _bypass_note
from services import inventory_manager, probe_manager

router = APIRouter(tags=["Probes"])


def _device_in_scope(current_user, device_ip: str) -> bool:
    """Il device ricade in una sede consentita all'utente (CONTRIBUTING §4).

    Predicato e non ``assert_device_allowed``: quello solleva 403 se il device
    esiste fuori scope ma ritorna ``None`` se non esiste, e qui i due casi vanno
    resi indistinguibili. Si autorizza sul device, non sul ``probe_id``, perché è
    il gruppo del device a definire lo scope utente. Un device sconosciuto non è
    autorizzabile: falso, tranne per chi non ha restrizioni."""
    scope = user_group_scope(current_user)
    if scope is None:
        return True
    device = next((d for d in inventory_manager.get_all_devices()
                   if d["IP"] == device_ip), None)
    return device is not None and device.get("Group", "Generale") in scope

class ProbeCreateSchema(BaseModel):
    name: str
    mode: str = "central"          # "central" | "agent" | "jump"
    subnets: List[str] = []
    # Bastion fields, required by probe_manager only when mode == "jump".
    jump_host: Optional[str] = None
    jump_port: Optional[int] = None
    jump_identity: Optional[str] = None
    # Default identity for the devices behind the bastion (not the bastion's own).
    device_identity: Optional[str] = None
    # Fingerprint the operator confirmed in the wizard's test step.
    confirmed_fingerprint: Optional[str] = None

class ProbeUpdateSchema(BaseModel):
    id: str
    name: Optional[str] = None
    mode: Optional[str] = None
    subnets: Optional[List[str]] = None
    jump_host: Optional[str] = None
    jump_port: Optional[int] = None
    jump_identity: Optional[str] = None
    device_identity: Optional[str] = None
    # Il centrale gestisce l'inventario di questa sede e lo spinge all'agente.
    # Spento di default: acceso, le credenziali dei dispositivi lasciano la
    # sede e vivono anche sul centrale (vedi docs/probes.md, principio 2).
    central_manages_devices: Optional[bool] = None
    confirmed_fingerprint: Optional[str] = None

class ProbeIdSchema(BaseModel):
    id: str

class BastionDraftSchema(BaseModel):
    jump_host: str
    jump_port: int = 22
    jump_identity: str

class ProbeCommandSchema(BaseModel):
    ip: str
    command: str

@router.get("/api/probes", dependencies=[Depends(require_tab("tab-devices", "tab-import", "tab-provisioning", "tab-provisioner", "tab-probes"))])
def list_probes_ep(current_user = Depends(require_operator)):
    # Operators read this to fill the probe selectors, so it is not admin-only.
    # They get the three fields those selectors need. The bastion address of a
    # bastion probe, its identity, its subnets and its token state stay with the
    # admins who configure them: a dropdown does not need any of it.
    # (Comment, not a docstring: a docstring here becomes the endpoint's
    # OpenAPI description and changes the contract snapshot.)
    probes = probe_manager.list_probes()
    if not is_unscoped_admin(current_user):
        probes = [{"id": s["id"], "name": s["name"], "mode": s["mode"]} for s in probes]
    return {"probes": probes}

def _pin_or_409(host: str, port: int, fp: str) -> None:
    """Pin the key the draft test saw, or refuse: the confirmation is only
    worth something for the key the server itself observed."""
    from core import net_ssh
    if not net_ssh.pin_confirmed(host, port, fp):
        raise HTTPException(
            status_code=409,
            detail="Impronta non piu' valida per questo bastione: ripetere il test.")

@router.post("/api/probes", dependencies=[Depends(require_tab("tab-probes"))])
def create_probe_ep(payload: ProbeCreateSchema, current_user = Depends(require_unscoped_admin)):
    who = current_user.get('sub')
    fp = payload.confirmed_fingerprint if payload.mode == "jump" else None
    if fp:
        _pin_or_409((payload.jump_host or "").strip(), payload.jump_port or 22, fp)
    try:
        probe, token = probe_manager.create_probe(
            payload.name, payload.mode, payload.subnets,
            jump_host=payload.jump_host, jump_port=payload.jump_port,
            jump_identity=payload.jump_identity,
            device_identity=payload.device_identity)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    log_audit(f"Sonda '{probe['id']}' (mode: {payload.mode}) creata da '{who}'.")
    if fp:
        probe_manager.mark_bastion_verified(probe["id"])
        probe = probe_manager.get_probe(probe["id"]) or probe
        log_audit(f"Sonda '{probe['id']}': impronta del bastione {fp} confermata da '{who}'.")
    elif payload.mode == "jump":
        log_audit(f"Sonda '{probe['id']}' salvata con bastione non verificato da '{who}'.")
    # Il token in chiaro è restituito UNA SOLA VOLTA (poi solo hash su disco).
    return {"status": "success", "probe": probe, "token": token}

@router.post("/api/probes/update", dependencies=[Depends(require_tab("tab-probes"))])
def update_probe_ep(payload: ProbeUpdateSchema, current_user = Depends(require_unscoped_admin)):
    # Only forward jump fields the caller actually supplied: update_probe merges
    # kwargs over the stored probe before re-validating a bastion probe (see its
    # docstring), so an explicit None here would clobber an unrelated field
    # (e.g. renaming a bastion probe) with a blank and make it fail revalidation.
    jump_kwargs: Dict[str, Any] = {}
    if payload.jump_host is not None:
        jump_kwargs["jump_host"] = payload.jump_host
    if payload.jump_port is not None:
        jump_kwargs["jump_port"] = payload.jump_port
    if payload.jump_identity is not None:
        jump_kwargs["jump_identity"] = payload.jump_identity
    if payload.device_identity is not None:
        jump_kwargs["device_identity"] = payload.device_identity
    if payload.central_manages_devices is not None:
        jump_kwargs["central_manages_devices"] = bool(payload.central_manages_devices)
    who = current_user.get('sub')
    fp = payload.confirmed_fingerprint
    existing = probe_manager.get_probe(payload.id)
    if fp and existing:
        host = (payload.jump_host or existing.get("jump_host") or "").strip()
        port = payload.jump_port or existing.get("jump_port") or 22
        _pin_or_409(host, port, fp)
    try:
        ok = probe_manager.update_probe(payload.id, payload.name, payload.mode,
                                      payload.subnets, **jump_kwargs)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="Sonda non trovata.")
    # An edited bastion login must take effect now. The transport cached for
    # this probe was authenticated with the previous credentials and keeps
    # working, so without this the change only applies once that session dies.
    if any(k in jump_kwargs for k in ("jump_host", "jump_port", "jump_identity")):
        from core import net_ssh
        net_ssh.invalidate_probe(payload.id)
    # The wizard resends the jump fields on every save: compare the stored
    # bastion before and after, not the presence of the fields.
    after = probe_manager.get_probe(payload.id) or {}
    bastion_changed = any((existing or {}).get(k) != after.get(k)
                          for k in ("jump_host", "jump_port", "jump_identity"))
    if fp and existing:
        probe_manager.mark_bastion_verified(payload.id)
        log_audit(f"Sonda '{payload.id}': impronta del bastione {fp} confermata da '{who}'.")
    elif bastion_changed:
        log_audit(f"Sonda '{payload.id}': bastione modificato senza verifica da '{who}'.")
    log_audit(f"Sonda '{payload.id}' aggiornata da '{current_user.get('sub')}'.")
    out: Dict[str, Any] = {"status": "success"}
    # Passare a 'agent' senza token lascia una sede inservibile: update_probe
    # cambia la modalita' e non ne emette uno, quindi l'agente non ha con cosa
    # autenticarsi e nessuna schermata lo dice. Il token si emette qui, dove
    # il cambio di modalita' e' noto, e non nel browser: cosi' vale anche per
    # chi chiama l'API direttamente.
    updated = probe_manager.get_probe(payload.id)
    if updated and updated.get("mode") == "agent" and not updated.get("has_token"):
        token = probe_manager.regenerate_token(payload.id)
        if token:
            out["token"] = token       # in chiaro UNA SOLA VOLTA, come alla creazione
            log_audit(f"Token emesso per la sonda '{payload.id}' passata in modalità "
                      f"agent da '{current_user.get('sub')}'.")
    return out

@router.post("/api/probes/delete", dependencies=[Depends(require_tab("tab-probes"))])
def delete_probe_ep(payload: ProbeIdSchema, current_user = Depends(require_unscoped_admin)):
    if not probe_manager.delete_probe(payload.id):
        raise HTTPException(status_code=400, detail="Sonda non eliminabile o inesistente.")
    log_audit(f"Sonda '{payload.id}' eliminata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/probes/test-bastion", dependencies=[Depends(require_tab("tab-probes"))])
async def test_bastion_ep(payload: ProbeIdSchema, current_user = Depends(require_unscoped_admin)):
    # Answers the question the device errors cannot: is it the BASTION login
    # that is wrong? A refused bastion and a refused device both surface as
    # "authentication failed" on the device row, and the operator ends up
    # rotating the credential on the wrong machine.
    from core import net_ssh
    from core.ssh_pool import run_ssh
    probe = probe_manager.get_probe(payload.id)
    if not probe:
        raise HTTPException(status_code=404, detail="Sonda non trovata.")
    if probe.get("mode") != "jump":
        raise HTTPException(status_code=400, detail="La sonda non e' in modalita' jump.")
    who = current_user.get('sub')
    try:
        # WP11: il probe SSH del bastione gira sul pool dedicato.
        fp = await run_ssh(net_ssh.probe_bastion, probe)
    except net_ssh.BastionAuthError as e:
        log_audit(f"Test bastione sonda '{payload.id}' da '{who}': credenziali rifiutate.")
        return {"status": "auth_failed", "message": str(e)}
    except net_ssh.BastionHostKeyError as e:
        log_audit(f"Test bastione sonda '{payload.id}' da '{who}': chiave host diversa.")
        return {"status": "host_key_mismatch", "message": str(e)}
    except Exception as e:
        log_audit(f"Test bastione sonda '{payload.id}' da '{who}': irraggiungibile.")
        return {"status": "unreachable", "message": str(e)}
    probe_manager.mark_bastion_verified(payload.id)
    log_audit(f"Test bastione sonda '{payload.id}' da '{who}': OK.")
    return {"status": "success", "fingerprint": fp}


@router.post("/api/probes/test-bastion/draft", dependencies=[Depends(require_tab("tab-probes"))])
async def test_bastion_draft_ep(payload: BastionDraftSchema,
                                current_user = Depends(require_unscoped_admin)):
    # The wizard's test step: dial a bastion that is not saved yet. Nothing is
    # pinned here — the key waits for the operator to confirm its fingerprint.
    from core import net_ssh
    from core.ssh_pool import run_ssh
    host = payload.jump_host.strip()
    if not host or not (1 <= payload.jump_port <= 65535) or not payload.jump_identity:
        raise HTTPException(status_code=400, detail="Host, porta o identita' del bastione non validi.")
    who = current_user.get('sub')
    try:
        info = await run_ssh(net_ssh.probe_bastion_draft, host,
                             payload.jump_port, payload.jump_identity)
    except net_ssh.BastionAuthError as e:
        log_audit(f"Test bozza bastione {host} da '{who}': credenziali rifiutate.")
        return {"status": "auth_failed", "message": str(e)}
    except net_ssh.BastionHostKeyError as e:
        log_audit(f"Test bozza bastione {host} da '{who}': chiave host diversa.")
        return {"status": "host_key_mismatch", "message": str(e)}
    except ValueError as e:
        # The identity no longer exists (_dial): a form error, not the network.
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log_audit(f"Test bozza bastione {host} da '{who}': irraggiungibile.")
        return {"status": "unreachable", "message": str(e)}
    log_audit(f"Test bozza bastione {host} da '{who}': OK, impronta {info['fingerprint']}.")
    return {"status": "success", **info}

@router.post("/api/probes/regenerate-token", dependencies=[Depends(require_tab("tab-probes"))])
def regenerate_probe_token_ep(payload: ProbeIdSchema, current_user = Depends(require_unscoped_admin)):
    token = probe_manager.regenerate_token(payload.id)
    if token is None:
        raise HTTPException(status_code=400, detail="Sonda inesistente o non in modalità agent.")
    log_audit(f"Token della sonda '{payload.id}' rigenerato da '{current_user.get('sub')}'.")
    return {"status": "success", "token": token}

@router.post("/api/probes/{probe_id}/command", dependencies=[Depends(require_tab("tab-probes"))])
def probe_command_ep(probe_id: str, payload: ProbeCommandSchema,
                    current_user = Depends(require_operator)):
    """Accoda un comando CLI per un dispositivo di una sede agent. L'agente lo
    preleverà in polling, lo eseguirà localmente e ne posterà il risultato."""
    probe = probe_manager.get_probe(probe_id)
    if not probe:
        raise HTTPException(status_code=404, detail="Sonda non trovata.")
    if probe.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Il relay comandi è disponibile solo per sedi in modalità agent.")
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", payload.ip):
        raise HTTPException(status_code=400, detail="IP non valido.")
    if not _device_in_scope(current_user, payload.ip):
        log_audit(f"Relay comando negato (fuori scope) su '{payload.ip}' sonda "
                  f"'{probe_id}' a '{current_user.get('sub')}'.")
        raise HTTPException(
            status_code=403,
            detail=f"Dispositivo '{payload.ip}' non fra le sedi consentite.")
    if not command_allowed(payload.command, current_user):
        log_audit(f"Relay comando bloccato (blacklist) '{payload.command}' su '{payload.ip}' "
                  f"sonda '{probe_id}' da '{current_user.get('sub')}'.")
        raise HTTPException(status_code=400, detail="Comando non consentito per motivi di sicurezza (in blacklist).")
    blacklist_bypass = not is_command_safe(payload.command)
    if blacklist_bypass:
        log_audit(f"Relay comando in blacklist '{payload.command}' su '{payload.ip}' sonda '{probe_id}' "
                  f"consentito a '{current_user.get('sub')}' {_bypass_note(current_user)}.")
    job = probe_manager.enqueue_job(probe_id, payload.ip, payload.command,
                                   requested_by=current_user.get("sub"),
                                   blacklist_bypass=blacklist_bypass)
    log_audit(f"Comando CLI accodato per sonda agent '{probe_id}' su '{payload.ip}' "
              f"da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "queued", "job_id": job["id"]}

@router.get("/api/command-jobs/{job_id}", dependencies=[Depends(require_tab("tab-probes"))])
def get_command_job_ep(job_id: str, current_user = Depends(require_operator)):
    job = probe_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job non trovato.")
    # Job fuori scope: 404 identico al job inesistente, per non confermare
    # l'esistenza di attività in sedi altrui (stessa politica di /anomalies).
    if not _device_in_scope(current_user, job.get("device_ip", "")):
        raise HTTPException(status_code=404, detail="Job non trovato.")
    return job

@router.get("/api/probes/{probe_id}/command-jobs", dependencies=[Depends(require_tab("tab-probes"))])
def list_probe_command_jobs_ep(probe_id: str, current_user = Depends(require_operator)):
    jobs = probe_manager.list_jobs(probe_id)
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
    backup_interval: Optional[int] = None
    l2_interval: Optional[int] = None
    syslog_enabled: Optional[bool] = None


@router.post("/api/probes/{probe_id}/agent/update", dependencies=[Depends(require_tab("tab-probes"))])
def agent_self_update_ep(probe_id: str, current_user = Depends(require_unscoped_admin)):
    """Accoda un comando RPC di self-update (git pull) per l'agente remoto."""
    probe = probe_manager.get_probe(probe_id)
    if not probe:
        raise HTTPException(status_code=404, detail="Sonda non trovata.")
    if probe.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Gestione agente disponibile solo per sedi in modalità agent.")
    job = probe_manager.enqueue_job(probe_id, "127.0.0.1", "_agent_self_update", requested_by=current_user.get("sub"))
    log_audit(f"Self-update agent (git pull) accodato per sonda '{probe_id}' da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "queued", "job_id": job["id"]}


@router.post("/api/probes/{probe_id}/agent/restart", dependencies=[Depends(require_tab("tab-probes"))])
def agent_restart_ep(probe_id: str, current_user = Depends(require_unscoped_admin)):
    """Accoda un comando RPC di restart per l'agente remoto (systemctl auto-restart)."""
    probe = probe_manager.get_probe(probe_id)
    if not probe:
        raise HTTPException(status_code=404, detail="Sonda non trovata.")
    if probe.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Gestione agente disponibile solo per sedi in modalità agent.")
    job = probe_manager.enqueue_job(probe_id, "127.0.0.1", "_agent_restart", requested_by=current_user.get("sub"))
    log_audit(f"Restart agent accodato per sonda '{probe_id}' da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "queued", "job_id": job["id"]}


@router.post("/api/probes/{probe_id}/agent/logs", dependencies=[Depends(require_tab("tab-probes"))])
def agent_logs_ep(probe_id: str, current_user = Depends(require_unscoped_admin)):
    """Accoda un comando RPC che riporta le ultime righe di journal dell'agente."""
    probe = probe_manager.get_probe(probe_id)
    if not probe:
        raise HTTPException(status_code=404, detail="Sonda non trovata.")
    if probe.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Gestione agente disponibile solo per sedi in modalità agent.")
    job = probe_manager.enqueue_job(probe_id, "127.0.0.1", "_agent_logs", requested_by=current_user.get("sub"))
    log_audit(f"Lettura log agent accodata per sonda '{probe_id}' da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "queued", "job_id": job["id"]}


@router.post("/api/probes/{probe_id}/agent/config", dependencies=[Depends(require_tab("tab-probes"))])
def agent_config_update_ep(probe_id: str, payload: AgentConfigUpdateSchema, current_user = Depends(require_unscoped_admin)):
    """Accoda un comando RPC per aggiornare i parametri di configurazione dell'agente remoto."""
    probe = probe_manager.get_probe(probe_id)
    if not probe:
        raise HTTPException(status_code=404, detail="Sonda non trovata.")
    if probe.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Gestione agente disponibile solo per sedi in modalità agent.")
    cfg_json = payload.model_dump_json(exclude_none=True)
    cmd = f"_agent_config {cfg_json}"
    job = probe_manager.enqueue_job(probe_id, "127.0.0.1", cmd, requested_by=current_user.get("sub"))
    log_audit(f"Aggiornamento config agent accodato per sonda '{probe_id}' da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "queued", "job_id": job["id"]}


class AgentInventorySaveSchema(BaseModel):
    content: str


@router.post("/api/probes/{probe_id}/agent/inventory/get", dependencies=[Depends(require_tab("tab-probes"))])
def agent_get_inventory_ep(probe_id: str, current_user = Depends(require_unscoped_admin)):
    """Accoda un comando RPC per leggere l'inventario locale network_hosts.csv dell'agente."""
    probe = probe_manager.get_probe(probe_id)
    if not probe:
        raise HTTPException(status_code=404, detail="Sonda non trovata.")
    if probe.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Gestione agente disponibile solo per sedi in modalità agent.")
    job = probe_manager.enqueue_job(probe_id, "127.0.0.1", "_agent_get_inventory", requested_by=current_user.get("sub"))
    log_audit(f"Lettura inventario agent accodato per sonda '{probe_id}' da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "queued", "job_id": job["id"]}


@router.post("/api/probes/{probe_id}/agent/inventory/save", dependencies=[Depends(require_tab("tab-probes"))])
def agent_save_inventory_ep(probe_id: str, payload: AgentInventorySaveSchema, current_user = Depends(require_unscoped_admin)):
    """Accoda un comando RPC per salvare l'inventario locale network_hosts.csv dell'agente."""
    probe = probe_manager.get_probe(probe_id)
    if not probe:
        raise HTTPException(status_code=404, detail="Sonda non trovata.")
    if probe.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Gestione agente disponibile solo per sedi in modalità agent.")
    # Il CSV lo scriverà l'agente, ma se è illeggibile va detto adesso: dopo
    # l'accodamento l'errore arriverebbe solo al polling successivo, dentro il
    # risultato di un job, dove nessuno lo cerca.
    try:
        inventory_manager._read_inventory_csv(payload.content)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    cmd = f"_agent_save_inventory {payload.content}"
    job = probe_manager.enqueue_job(probe_id, "127.0.0.1", cmd, requested_by=current_user.get("sub"))
    log_audit(f"Salvataggio inventario agent accodato per sonda '{probe_id}' da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "queued", "job_id": job["id"]}


class FlowControlSchema(BaseModel):
    active: bool


@router.post("/api/probes/{probe_id}/agent/flow-control", dependencies=[Depends(require_tab("tab-probes"))])
def agent_flow_control_ep(probe_id: str, payload: FlowControlSchema, current_user = Depends(require_unscoped_admin)):
    """Mette in pausa o riprende l'ingestione / streaming dati per la sede agent."""
    probe = probe_manager.get_probe(probe_id)
    if not probe:
        raise HTTPException(status_code=404, detail="Sonda non trovata.")
    if probe.get("mode") != "agent":
        raise HTTPException(status_code=400, detail="Gestione flusso disponibile solo per sedi in modalità agent.")
    probe_manager.set_probe_flow_status(probe_id, payload.active)
    cmd = "_agent_flow_start" if payload.active else "_agent_flow_stop"
    job = probe_manager.enqueue_job(probe_id, "127.0.0.1", cmd, requested_by=current_user.get("sub"))
    status_str = "riavviato" if payload.active else "interrotto (pausa)"
    log_audit(f"Flusso dati agente {status_str} per sonda '{probe_id}' da '{current_user.get('sub')}' (job {job['id']}).")
    return {"status": "success", "flow_active": payload.active, "job_id": job["id"]}


