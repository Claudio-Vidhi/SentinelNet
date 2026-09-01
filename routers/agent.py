# -*- coding: utf-8 -*-
"""Router Agent. Estratto da app_server.py (fase 6.6)."""

import re
import time
import logging
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from services import site_manager
from services import inventory_manager
from collectors import mac_history
from security.security_manager import log_audit
from core import backup_store

router = APIRouter(tags=["Agent"])

class AgentDeviceSchema(BaseModel):
    ip: str
    vendor: str = "cisco"
    hostname: str = ""
    group: Optional[str] = None

class AgentInventorySchema(BaseModel):
    devices: List[AgentDeviceSchema] = []

class AgentMacCollection(BaseModel):
    switch_ip: str
    switch_name: str = ""
    rows: List[dict] = []

class AgentMacSchema(BaseModel):
    collections: List[AgentMacCollection] = []

class AgentArpCollection(BaseModel):
    source_ip: str                 # gateway L3 che ha risposto l'ARP
    source_name: str = ""
    source_type: str = ""          # firewall | switch
    entries: List[dict] = []

class AgentArpSchema(BaseModel):
    collections: List[AgentArpCollection] = []

class AgentJobResultSchema(BaseModel):
    status: str = "done"           # "done" | "error"
    result: str = ""

class AgentSyslogItemSchema(BaseModel):
    ts: int = 0
    src_ip: str
    raw: str

class AgentSyslogBatchSchema(BaseModel):
    events: List[AgentSyslogItemSchema] = []

class AgentStatusItemSchema(BaseModel):
    ip: str
    up: bool

class AgentStatusSchema(BaseModel):
    devices: List[AgentStatusItemSchema] = []

MAX_CONFIG_BYTES = 5 * 1024 * 1024

class AgentBackupSchema(BaseModel):
    ip: str
    hostname: str = ""
    vendor: str = "cisco"
    version: str = "Non Rilevata"
    model: str = ""
    serial: str = ""
    config: str

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
def agent_heartbeat(payload: Optional[dict] = None, site = Depends(get_agent_site)):
    if payload and isinstance(payload, dict):
        site_id = site["id"]
        updates = {}
        if "syslog_port" in payload:
            updates["syslog_port"] = payload["syslog_port"]
        if "interval" in payload:
            updates["interval"] = payload["interval"]
        if "backup_interval" in payload:
            updates["backup_interval"] = payload["backup_interval"]
        if updates:
            site_manager.update_site(site_id, **updates)
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
        req_group = (d.group or "").strip()
        group = req_group or existing_groups.get(d.ip) or "Generale"
        vendor = inventory_manager.normalize_vendor(d.vendor)
        inventory_manager.add_or_update_device(
            d.ip, vendor, "custom", "", "", "", group, site=site_id)
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

@router.post("/api/agent/arp")
def agent_push_arp(payload: AgentArpSchema, site = Depends(get_agent_site)):
    """L'agente spinge le tabelle ARP raccolte localmente: e' cio' che da' un
    IP ai client della sede remota. Senza, la MAC table dice a quale porta
    stanno ma non chi sono, e ogni vista a valle parte dall'IP."""
    site_id = site["id"]
    groups_by_ip = {d.get("IP"): d.get("Group") for d in inventory_manager.get_all_devices()}
    total = 0
    for col in payload.collections:
        summ = mac_history.record_arp_entries(
            col.entries, source_ip=col.source_ip,
            source_name=col.source_name, source_type=col.source_type,
            # Stessa attribuzione della MAC table: il tenant e' quello
            # dell'apparato che ha raccolto, la sede e' quella dell'agente
            # autenticato — mai un valore scelto dall'agente stesso.
            tenant=groups_by_ip.get(col.source_ip) or "Generale", site=site_id)
        total += summ.get("new", 0) + summ.get("updated", 0)
    log_audit(f"Agente sede '{site_id}': {len(payload.collections)} tabelle ARP "
              f"ricevute ({total} binding).")
    return {"status": "success", "recorded": total}

@router.post("/api/agent/status")
def agent_push_status(payload: AgentStatusSchema, site = Depends(get_agent_site)):
    """Esiti del ping che l'agente esegue sui PROPRI dispositivi.

    Il centrale non raggiunge i dispositivi di una sede con agente (vedi
    site_manager.has_direct_path): questo push e' l'unica fonte di stato
    up/down per quella sede."""
    site_id = site["id"]
    own = {d.get("IP"): d for d in inventory_manager.get_all_devices()
           if d.get("Site") == site_id}
    known = inventory_manager.get_detected_versions()
    n = 0
    for d in payload.devices:
        # Il token di una sede non deve poter alterare lo stato di un'altra.
        if d.ip not in own:
            continue
        prev = known.get(d.ip, {})
        # Il vendor reale e' gia' noto dallo scan d'inventario appena sopra:
        # "cisco" resta solo l'ultima spiaggia, non il default di partenza
        # per un apparato senza voce pregressa in detected_versions.
        vendor = own[d.ip].get("Vendor") or "cisco"
        inventory_manager.update_version_inventory(
            d.ip, vendor,
            prev.get("version", "Non Rilevata"),
            "online" if d.up else "offline")
        n += 1
    return {"status": "success", "updated": n}

@router.post("/api/agent/backup")
def agent_push_backup(payload: AgentBackupSchema, site = Depends(get_agent_site)):
    """Config e versione raccolte dall'agente sui propri dispositivi.

    Passa dalle STESSE funzioni del triage centrale (backup_store.save_backup e
    update_version_inventory), cosi' mappa, config drift e classificazione per
    modello si popolano senza nuovi lettori."""
    site_id = site["id"]
    device = next((d for d in inventory_manager.get_all_devices()
                   if d.get("IP") == payload.ip and d.get("Site") == site_id), None)
    if device is None:
        raise HTTPException(
            status_code=404,
            detail=f"Dispositivo {payload.ip} non appartiene alla sede '{site_id}'.")
    if len(payload.config.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Config oltre il limite di 5 MB: rifiutata, non troncata.")
    if not payload.config.strip():
        # Un push parziale o vuoto non deve MAI sovrascrivere un backup buono
        # gia' salvato: meglio rifiutare qui che scriverlo e perdere lo storico.
        raise HTTPException(
            status_code=400,
            detail="Config vuota: rifiutata, non sovrascrive il backup esistente.")
    sys_name = payload.hostname or payload.ip
    file_path = backup_store.save_backup(device, sys_name, payload.config)
    # Stesso punto unico di storicizzazione di core_engine: senza, la
    # scheda Config Drift resta vuota per ogni sede con agente.
    try:
        from services.config_drift import history
        history.record_version(device, payload.config)
    except Exception as e:
        logging.warning(f"Storico config non aggiornato per {payload.ip}: {e}")
    inventory_manager.update_version_inventory(
        payload.ip, payload.vendor, payload.version, "online",
        model=payload.model or None, serial=payload.serial or None)
    if payload.hostname:
        inventory_manager.update_device_hostname(payload.ip, payload.hostname)
    log_audit(f"Agente sede '{site_id}': backup ricevuto per {payload.ip} "
              f"({len(payload.config)} caratteri).")
    return {"status": "success", "file": file_path}

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

@router.post("/api/agent/syslog")
def agent_push_syslog(payload: AgentSyslogBatchSchema, site = Depends(get_agent_site)):
    """L'agente spinge un batch di eventi syslog raccolti localmente nella sede remota."""
    site_id = site["id"]
    groups_by_ip = {d.get("IP"): d.get("Group") for d in inventory_manager.get_all_devices()}
    count = 0
    from observability.ingesters import syslog as syslog_parser
    from core import db
    for item in payload.events:
        raw_bytes = item.raw.encode("utf-8", errors="replace")
        parsed_list = syslog_parser.parse(raw_bytes, item.src_ip)
        for ev in parsed_list:
            tenant = groups_by_ip.get(item.src_ip) or "Generale"
            ts_val = item.ts if item.ts > 0 else int(time.time())
            db.enqueue_write(
                "INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message, exporter_ip) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ts_val, tenant, ev.get("device_ip", item.src_ip), ev.get("severity"), ev.get("action"), ev.get("message"), item.src_ip)
            )
            count += 1
    return {"status": "success", "ingested": count}
