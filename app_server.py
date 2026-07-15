import os
import secrets as _secrets
import sys
import asyncio
import paramiko
import time
import json
import threading
import webbrowser
import requests
import re
from typing import Optional, List, Dict
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, Security, Request, Response, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
from pydantic import BaseModel, Field

import uuid

import data_config
import inventory_manager
import core_engine
import user_manager
import mac_history
import mac_collector
import arp_collector
import config_analyzer
import ai_assistant
import crypto_vault
import switch_provisioner
import fortigate_provisioner
import provisioning_secrets
import fortigate_service
import wlc_service
import site_manager
import mcp_server
import visio_export
from network_scanner import parse_network, scan_subnet
from security_manager import (
    create_access_token, verify_access_token, log_audit,
    is_locked_out, record_failed_attempt, reset_failed_attempts,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)


from app_settings import (  # noqa: F401
    PORT, _app_adv_setting, get_app_settings, save_app_settings,
    effective_port, list_local_ips, resolve_bind_host,
)

from contextlib import asynccontextmanager

import db


@asynccontextmanager
async def lifespan(app: "FastAPI"):
    """Avvio/arresto ordinato (fasi 2.4 + 3.6): (1) migrazione observability.db,
    (2) writer DB, (3) listener UDP e job di retention se abilitati; chiusura
    in ordine inverso con drain. Un errore in avvio fa terminare il processo
    (fail-closed) con messaggio in italiano."""
    try:
        db.start_writer()  # esegue anche migrate() con guardia di versione
    except db.SchemaTooNewError as e:
        print(f"ERRORE: {e}", file=sys.stderr)
        raise

    handles = []
    retention_task = None
    cfg = data_config.obs_config()
    if cfg["enabled"]:
        from observability import rollup
        from observability.ingesters import ipfix, sflow, syslog as syslog_parser
        from observability.ingesters.udp_server import start_udp_listener
        from routers import observability as _obs_router_mod
        listeners = (
            ("ipfix", cfg["ipfix"], ipfix.parse, "flow"),
            ("netflow", cfg["netflow"], ipfix.parse, "flow"),
            ("sflow", cfg["sflow"], sflow.parse, "flow"),
            ("syslog", cfg["syslog"], syslog_parser.parse, "syslog"),
        )
        for name, lcfg, parser, kind in listeners:
            if not lcfg["enabled"]:
                _obs_router_mod.listener_status[name] = {"active": False}
                continue
            try:
                handles.append(await start_udp_listener(
                    cfg["bind"], lcfg["port"], parser, kind, name))
                _obs_router_mod.listener_status[name] = {
                    "active": True, "bind": cfg["bind"], "port": lcfg["port"]}
                print(f"Observability: listener {name} attivo su "
                      f"{cfg['bind']}:{lcfg['port']} (UDP).")
            except OSError as e:
                from observability import metrics as _obs_metrics
                _obs_metrics.inc("listener_bind_failed", listener=name)
                _obs_router_mod.listener_status[name] = {
                    "active": False, "error": str(e)}
                print(f"ERRORE: bind del listener {name} su "
                      f"{cfg['bind']}:{lcfg['port']} fallito ({e}). "
                      "Listener saltato, l'applicazione resta attiva.",
                      file=sys.stderr)
        from observability import correlator
        retention_task = asyncio.create_task(rollup.retention_loop(),
                                             name="obs-retention")
        app.state.obs_correlation_task = asyncio.create_task(
            correlator.correlation_loop(), name="obs-correlation")
        # Poller REST (§9.2): snapshot periodici dai FortiGate con token API.
        if cfg.get("api_poll_s", 0) > 0:
            from observability.ingesters import api_poller
            app.state.obs_api_poller_task = asyncio.create_task(
                api_poller.poll_loop(cfg["api_poll_s"]), name="obs-api-poller")
    else:
        print("Observability: osservabilità disabilitata, nessun listener UDP "
              "in ascolto (abilitare con SENTINELNET_OBS_ENABLE=1 o "
              "\"observability.enabled\" in app_settings.json).")

    yield

    if retention_task:
        retention_task.cancel()
        for attr in ("obs_correlation_task", "obs_api_poller_task"):
            task = getattr(app.state, attr, None)
            if task:
                task.cancel()
    for handle in handles:
        await handle.stop()
    db.stop_writer()


app = FastAPI(title="SentinelNet API", version="0.2.0-beta.1", lifespan=lifespan)
from routers import ai as _ai_router
app.include_router(_ai_router.router)

from routers.ai import (  # noqa: F401  (compat: test_app_server_ai_profiles)
    _get_ai_profiles_raw,
    _mask_ai_profile,
    _find_ai_profile,
    _get_active_ai_profile,
)
from routers import analyzer as _analyzer_router
app.include_router(_analyzer_router.router)
from routers import arp as _arp_router
app.include_router(_arp_router.router)
from routers import mac as _mac_router
app.include_router(_mac_router.router)
from routers import backup as _backup_router
app.include_router(_backup_router.router)
from routers import commands as _commands_router
app.include_router(_commands_router.router)
from routers import triage as _triage_router
app.include_router(_triage_router.router)

from routers.mac import MacScanSchema

# =========================================================================
from routers import topology as _topology_router
app.include_router(_topology_router.router)
from routers import settings as _settings_router
app.include_router(_settings_router.router)
from routers import catalog as _catalog_router
app.include_router(_catalog_router.router)
from routers import inventory as _inventory_router
app.include_router(_inventory_router.router)

# Router modulari (fase 2.2/2.3/6.6): percorsi identici al monolite pre-refactor.
from routers import fortigate as _fortigate_router
from routers import wlc as _wlc_router
from routers import observability as _observability_router
from routers import auth as _auth_router
app.include_router(_fortigate_router.router)
app.include_router(_wlc_router.router)
app.include_router(_observability_router.router)
app.include_router(_auth_router.router)


# Abilita CORS. Le origini consentite sono configurabili via SENTINELNET_CORS_ORIGINS
# (lista separata da virgole). Default: solo localhost sulla porta dell'app.
# Nota: usare "*" insieme ad allow_credentials=True è invalido per spec ed è
# rifiutato dai browser, quindi le origini vengono sempre elencate esplicitamente.
_default_origins = f"http://localhost:{effective_port()},http://127.0.0.1:{effective_port()}"
ALLOWED_ORIGINS = [
    o.strip()
    for o in (os.environ.get("SENTINELNET_CORS_ORIGINS")
              or _app_adv_setting("cors_origins")
              or _default_origins).split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Header di sicurezza su ogni risposta (audit L-2). La CSP consente solo
# i CDN effettivamente usati da dashboard.html (fonts, font-awesome, vis-network, xterm).
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = _CSP
    return response

security_scheme = HTTPBearer(auto_error=False)

def get_resource_path(relative_path):
    """Restituisce il percorso assoluto della risorsa, funzionando sia in dev che bundled."""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# --- DIPENDENZE DI AUTENTICAZIONE (JWT) ---

# Autenticazione e scoping multi-gruppo: spostati in routers/deps.py (fase 2.1).
# Reimportati qui per compatibilità con il resto del monolite e con i test.
from routers.deps import (  # noqa: F401
    SESSION_COOKIE, CSRF_HEADER, get_current_user, require_role,
    require_admin, require_operator, user_group_scope,
    assert_group_allowed, assert_device_allowed, filter_map_to_scope,
)

# --- MODELLI DI VALIDAZIONE PYDANTIC ---












class SubnetScanRequest(BaseModel):
    network: str
    vendor: str = "cisco"
    group: str = "Generale"
    auto_add: bool = False
    use_default_creds: bool = True














class SwitchProvisionSchema(BaseModel):
    """Parametri del wizard 'Switch da Zero'. Vedi switch_provisioner.build_config
    per il significato di ciascun campo (tutti opzionali salvo hostname)."""
    hostname: str = "Switch"
    role: str = "access"                  # access | distribution
    domain: str = ""
    mgmt_vlan: Optional[int] = None
    mgmt_ip: str = ""
    mgmt_mask: str = ""
    mgmt_gw: str = ""
    admin_user: str = ""
    admin_password: str = ""
    enable_secret: str = ""
    ssh_only: bool = True
    banner: str = ""
    ntp_servers: List[str] = []
    syslog_server: str = ""
    snmpv3: dict = {}
    vlans: List[dict] = []
    vtp_mode: str = "transparent"
    stp_mode: str = "rapid-pvst"
    bpduguard: bool = True
    port_security: bool = False
    dhcp_snooping: bool = False
    dhcp_snooping_vlans: str = ""
    cdp_enabled: bool = True
    lldp_enabled: bool = True
    access_ports: List[str] = []
    access_vlan: Optional[int] = None
    trunk_ports: List[str] = []
    trunk_allowed_vlans: str = ""
    uplink_pc_id: Optional[int] = None
    login_block: bool = True
    storm_control: bool = False
    errdisable_recovery: bool = True
    no_vstack: bool = True
    svis: List[dict] = []
    enable_routing: bool = True
    default_route_gw: str = ""

class SwitchProvisionSSHSchema(SwitchProvisionSchema):
    ssh_host: str
    ssh_port: int = 22
    ssh_username: str
    ssh_password: str
    ssh_secret: str = ""
    save_after: bool = True

class SwitchProvisionSerialSchema(SwitchProvisionSchema):
    com_port: str
    baudrate: int = 9600

class FortiGateProvisionSchema(BaseModel):
    """Parametri del wizard ZTP FortiGate. Vedi fortigate_provisioner.build_config."""
    hostname: str = "FortiGate"
    timezone: str = "Europe/Rome"
    admin_user: str = ""
    admin_password: str = ""
    admin_timeout: int = 10
    lockout: bool = True
    strong_crypto: bool = True
    mgmt_interface: str = ""
    mgmt_ip: str = ""
    mgmt_mask: str = ""
    mgmt_allowaccess: str = "ping https ssh"
    wan_interface: str = ""
    wan_mode: str = "dhcp"
    wan_ip: str = ""
    wan_mask: str = ""
    wan_gw: str = ""
    lan_interface: str = ""
    lan_ip: str = ""
    lan_mask: str = ""
    dhcp_server: bool = False
    dhcp_start: str = ""
    dhcp_end: str = ""
    dns_primary: str = ""
    dns_secondary: str = ""
    ntp_servers: List[str] = []
    syslog_server: str = ""
    snmpv3: dict = {}
    lan_to_wan_policy: bool = True
    disable_wan_admin: bool = True
    banner: str = ""
    # Elementi ZTP (FortiOS 7.4 Admin Guide)
    api_user: dict = {}            # {name, accprofile, trusthosts: [..]}
    central_mgmt: dict = {}        # {type: fortiguard|fortimanager, fmg_ip}
    csf_group: str = ""
    netflow_collector: str = ""
    rest_api_logging: bool = True
    ha: dict = {}                  # {group_name, mode, password, hbdev, priority, mgmt_interface, mgmt_ip, mgmt_mask}

class FortiGateProvisionSSHSchema(FortiGateProvisionSchema):
    ssh_host: str
    ssh_port: int = 22
    ssh_username: str
    ssh_password: str

class FortiGateProvisionSerialSchema(FortiGateProvisionSchema):
    com_port: str
    baudrate: int = 9600
    console_user: str = "admin"
    console_password: str = ""

class McpSettingsSchema(BaseModel):
    disabled_tools: List[str] = []

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

# --- Modelli push agente (autenticazione per-sede, non JWT utente) ---

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

# --- STATO DEI JOB DI TRIAGE IN BACKGROUND CON LOCK ---

_scan_jobs: dict[str, dict] = {}
_scan_jobs_lock = threading.Lock()

# Job di invio comandi massivo (bulk) con polling, come per le scansioni.

# Comandi distruttivi vietati anche nell'invio massivo, indipendentemente dalla
# modalità: cancellano/riavviano l'apparato. NON si blocca 'conf t' né 'delete'
# (legittimi nel push di configurazione, p.es. in config mode o su Juniper).



triage_job = {
    "status": "idle",       # "idle", "running", "complete"
    "progress": 0,
    "total": 0,
    "current_device": "",
    "results": []
}


def _run_scan_job(job_id: str, req: SubnetScanRequest):
    credentials = {
        "username": core_engine.DEFAULT_USERNAME,
        "password": core_engine.DEFAULT_PASSWORD,
        "secret":   core_engine.DEFAULT_SECRET,
    }
    def _progress(done: int):
        with _scan_jobs_lock:
            if job_id in _scan_jobs:
                _scan_jobs[job_id]["progress"] = done

    try:
        results = scan_subnet(
            address=req.network,
            vendor_hint=req.vendor,
            credentials=credentials,
            progress_cb=_progress,
        )

        if req.auto_add:
            for r in results:
                if r["ssh_ok"] and not r["added"]:
                    try:
                        inventory_manager.add_or_update_device(
                            r["ip"], r["vendor"], "custom",
                            credentials["username"],
                            credentials["password"],
                            credentials["secret"],
                            req.group,
                        )
                        r["added"] = True
                    except Exception:
                        pass

        with _scan_jobs_lock:
            _scan_jobs[job_id]["status"]   = "done"
            _scan_jobs[job_id]["results"]  = results
            _scan_jobs[job_id]["progress"] = len(results)

    except Exception as exc:
        with _scan_jobs_lock:
            _scan_jobs[job_id]["status"] = "error"
            _scan_jobs[job_id]["error"]  = str(exc)


# --- ROTTE PRINCIPALI & INTERFACCIA WEB ---

@app.get("/")
def read_index():
    return FileResponse(get_resource_path(os.path.join("templates", "dashboard.html")))

# --- ROTTE DI AUTENTICAZIONE (JWT): spostate in routers/auth.py (fase 6.6) ---

# --- ROTTE DISPOSITIVI (INVENTARIO) ---

def get_devices_and_versions(current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    devices = inventory_manager.get_all_devices()
    versions = inventory_manager.get_detected_versions()
    groups = inventory_manager.get_all_groups()
    if scope is not None:
        devices = [d for d in devices if d.get('Group') in scope]
        allowed_ips = {d['IP'] for d in devices}
        versions = {ip: v for ip, v in versions.items() if ip in allowed_ips}
        groups = {g: v for g, v in groups.items() if g in scope}
    return {
        "devices": devices,
        "detected_versions": versions,
        "groups": groups
    }

def export_devices_csv(current_user = Depends(get_current_user)):
    import csv, io
    scope = user_group_scope(current_user)
    devices = inventory_manager.get_all_devices()
    if scope is not None:
        devices = [d for d in devices if d.get('Group') in scope]
    versions = inventory_manager.get_detected_versions()
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["Hostname", "IP", "Vendor", "Group", "Version", "Status"],
        extrasaction="ignore"
    )
    writer.writeheader()
    for d in devices:
        scan = versions.get(d["IP"], {})
        writer.writerow({
            "Hostname": d.get("Hostname") or d.get("IP"),
            "IP":       d["IP"],
            "Vendor":   d.get("Vendor", ""),
            "Group":    d.get("Group", ""),
            "Version":  scan.get("version", "Non Scansionato"),
            "Status":   scan.get("status", "unknown"),
        })
    content = output.getvalue()
    log_audit(f"Export CSV dispositivi richiesto dall'utente '{current_user.get('sub')}'.")
    from fastapi.responses import Response as FastResponse
    return FastResponse(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinelnet-devices.csv"}
    )

def add_device(device: DeviceSchema, current_user = Depends(require_operator)):
    assert_group_allowed(current_user, device.group)
    # Impedisce di modificare un dispositivo esistente in una sede non consentita
    existing = next((d for d in inventory_manager.get_all_devices() if d['IP'] == device.ip), None)
    if existing:
        assert_group_allowed(current_user, existing.get('Group', 'Generale'))
    try:
        inventory_manager.add_or_update_device(
            device.ip, device.vendor, device.profile,
            device.username, device.password, device.enable_secret, device.group,
            ssh_port=device.ssh_port, transports=device.transports
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    log_audit(f"Dispositivo '{device.ip}' (vendor: '{device.vendor}', gruppo: '{device.group}') aggiunto/aggiornato dall'utente '{current_user.get('sub')}'.")
    # §11.6: Telnet è in chiaro — traccia esplicitamente l'abilitazione.
    if device.transports and 'telnet' in device.transports:
        log_audit(f"ATTENZIONE: Telnet (trasmissione in chiaro) abilitato per il dispositivo '{device.ip}' dall'utente '{current_user.get('sub')}'.")
    return {"status": "success", "message": "Dispositivo salvato"}

def delete_device(payload: DeviceDelete, current_user = Depends(require_operator)):
    assert_device_allowed(current_user, payload.ip)
    inventory_manager.delete_device(payload.ip)
    log_audit(f"Dispositivo '{payload.ip}' eliminato dall'inventario dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}

def rename_device(payload: DeviceRenameSchema, current_user = Depends(require_operator)):
    """Rinomina un dispositivo gestito impostandone manualmente l'hostname (il
    nome mostrato in inventario e sulla mappa). admin/operator, con scoping."""
    assert_device_allowed(current_user, payload.ip)
    if not next((d for d in inventory_manager.get_all_devices() if d['IP'] == payload.ip), None):
        raise HTTPException(status_code=404, detail="Dispositivo non trovato in inventario.")
    hostname = payload.hostname.strip()
    inventory_manager.update_device_hostname(payload.ip, hostname)
    log_audit(f"Dispositivo '{payload.ip}' rinominato in '{hostname or '(vuoto)'}' dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}

def import_csv(payload: CSVImportRequest, current_user = Depends(require_operator)):
    lines = payload.csv_data.split('\n')
    import csv as csv_parser
    reader = csv_parser.DictReader(lines)
    
    results = {"imported": [], "failed": []}
    scope = user_group_scope(current_user)

    for i, row in enumerate(reader, start=2):  # start=2 perché riga 1 è l'header
        try:
            ip = row.get('IP')
            if not ip or not ip.strip():
                raise ValueError("IP mancante o vuoto")

            ip = ip.strip()

            # Se il campo Group è presente e non vuoto, chiama immediatamente inventory_manager.add_group(row['Group'])
            group_name = (row.get('Group') or '').strip() or 'Generale'
            # Scoping: un operatore limitato non può importare in sedi non consentite
            if scope is not None and group_name not in scope:
                raise ValueError(f"Sede '{group_name}' non consentita per il tuo profilo")
            if group_name != 'Generale':
                inventory_manager.add_group(group_name)

            username = (row.get('Username') or '').strip()
            password = (row.get('Password') or '').strip()
            enable_secret = (row.get('Enable Secret') or '').strip()
            
            # Il campo Hostname (nome switch) viene estratto ma attualmente ignorato nel salvataggio
            hostname = (row.get('Hostname') or '').strip()
            
            vendor = (row.get('Vendor') or '').strip() or 'cisco'
            
            # Rimozione Profile: passa forzatamente il valore "custom" come parametro profile
            inventory_manager.add_or_update_device(
                ip, vendor, "custom",
                username, password, enable_secret,
                group_name
            )
            results["imported"].append(ip)
        except Exception as e:
            results["failed"].append({
                "row": i,
                "ip": row.get('IP', '?'),
                "error": str(e)
            })
            
    log_audit(f"Importazione massiva da CSV completata dall'utente '{current_user.get('sub')}'. Importati: {len(results['imported'])}, Falliti: {len(results['failed'])}.")
    return results

# --- CRUD GESTIONE GRUPPI VIA WEB UI ---





# --- CRUD GESTIONE VENDOR ---




# --- CATEGORIE / CLASSIFICAZIONE DISPOSITIVI ---






def promote_device(payload: PromoteDeviceSchema, current_user = Depends(require_operator)):
    """Promuove un dispositivo scoperto (CDP/LLDP) a dispositivo gestito,
    aggiungendolo all'inventario così da poter essere sottoposto a triage.
    Le credenziali vanno completate dopo, nella pagina Inventario."""
    assert_group_allowed(current_user, payload.group)
    if payload.group not in inventory_manager.get_all_groups():
        raise HTTPException(status_code=400, detail=f"Sede '{payload.group}' inesistente.")
    existing = next((d for d in inventory_manager.get_all_devices() if d['IP'] == payload.ip), None)
    if existing:
        raise HTTPException(status_code=400, detail=f"Dispositivo {payload.ip} già in inventario.")
    inventory_manager.add_or_update_device(
        payload.ip, payload.vendor, "custom", "", "", "", payload.group
    )
    # Trasferisce l'eventuale classificazione manuale dal nodo scoperto all'IP.
    inventory_manager.migrate_assignment(payload.node_id, payload.ip)
    # Eredita ciò che è già stato scoperto via CDP/LLDP: categoria, modello,
    # versione e hostname, così il dispositivo promosso non riparte "vuoto".
    meta = {}
    if payload.device_type:
        meta["category"] = payload.device_type
    if payload.model:
        meta["model"] = payload.model
    # Eredita il nome scelto: sia come hostname CSV (tabella/triage) sia come
    # override 'name' (etichetta su mappa e tab Categorie), così resta coerente.
    if payload.hostname:
        meta["name"] = payload.hostname
    if meta:
        inventory_manager.set_device_meta(payload.ip, **meta)
    if payload.version:
        inventory_manager.update_version_inventory(
            payload.ip, payload.vendor, payload.version, "discovered"
        )
    if payload.hostname:
        inventory_manager.update_device_hostname(payload.ip, payload.hostname)
    log_audit(
        f"Dispositivo scoperto '{payload.node_id}' promosso a gestito "
        f"(IP {payload.ip}, vendor {payload.vendor}, sede {payload.group}) "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

# --- REGISTRO MODELLI (per vendor) ---




# --- IMPOSTAZIONI DI RETE (bind IP, solo amministratori) ---






# Impostazioni avanzate (sezione 'app' di app_settings.json): configurabili da
# GUI così l'exe non richiede variabili d'ambiente. Env > JSON > default.
_APP_ADV_ENV = {
    "port": "SENTINELNET_PORT",
    "ssl_certfile": "SENTINELNET_SSL_CERTFILE",
    "ssl_keyfile": "SENTINELNET_SSL_KEYFILE",
    "cors_origins": "SENTINELNET_CORS_ORIGINS",
    "no_browser": "SENTINELNET_NO_BROWSER",
    "retention_flows_days": "SENTINELNET_OBS_RETENTION_FLOWS_DAYS",
    "retention_syslog_days": "SENTINELNET_OBS_RETENTION_SYSLOG_DAYS",
    "retention_events_days": "SENTINELNET_OBS_RETENTION_EVENTS_DAYS",
}
_APP_ADV_INT_KEYS = {"port", "retention_flows_days", "retention_syslog_days",
                     "retention_events_days"}
_APP_ADV_DEFAULTS = {"port": PORT, "retention_flows_days": 30,
                     "retention_syslog_days": 7, "retention_events_days": 90}






# --- ENDPOINTS COSTRUZIONE MAPPA TOPOLOGICA ---









# --- ROTTE AUTOMAZIONE & DOWNLOAD ---




# Blacklist di comandi CLI pericolosi, distruttivi o bloccanti










def reassign_device(payload: DeviceReassignSchema, current_user = Depends(require_operator)):
    """Sposta un dispositivo in un gruppo diverso aggiornando solo il campo Group nel CSV."""
    devices = inventory_manager.get_all_devices()
    groups  = inventory_manager.get_all_groups()

    target = next((d for d in devices if d['IP'] == payload.ip), None)
    if not target:
        raise HTTPException(status_code=404, detail="Dispositivo non trovato in inventario.")
    if payload.new_group not in groups:
        raise HTTPException(
            status_code=400,
            detail=f"Gruppo '{payload.new_group}' non esiste. Crealo prima."
        )

    # Scoping: la sede di origine e quella di destinazione devono essere consentite
    assert_group_allowed(current_user, target.get('Group', 'Generale'))
    assert_group_allowed(current_user, payload.new_group)

    old_group = target.get('Group', 'Generale')
    target['Group'] = payload.new_group
    inventory_manager.safe_write_hosts_csv(devices)

    log_audit(
        f"Dispositivo '{payload.ip}' spostato dal gruppo '{old_group}' "
        f"al gruppo '{payload.new_group}' dall'utente '{current_user.get('sub')}'."
    )
    return {"status": "success", "message": f"Dispositivo spostato in '{payload.new_group}'"}



# Docker note: is_reachable() uses a TCP probe on port 22. Ensure the container
# has outbound TCP 22 allowed to the management VLAN in your docker-compose network policy.



# --- PROXY MIRATO VERSO ENISA EUVD (SOSTITUISCE IL CATCH-ALL PERICOLOSO) ---

# Parametri ammessi da /api/search come da documentazione EUVD: qualunque altro
# parametro viene scartato prima di inoltrare la richiesta al servizio ENISA.


# --- MAC ADDRESS TRACKER (storicizzazione + ricerca) ---



# --- Risoluzione origine/transito basata sulla topologia GLOBALE ---
# Il difetto storico: is_uplink veniva deciso per-switch al momento della
# raccolta, dal solo backup di quello switch. Se una porta di dorsale non aveva
# un vicino CDP/LLDP "vivo" in quell'istante, veniva scambiata per porta di
# accesso: lo stesso MAC compariva così come "posizione" su più switch.
#
# Qui la classificazione è rifatta a READ-TIME contro la mappa topologica
# globale (generate_network_map), che aggrega le adiacenze viste da TUTTI gli
# apparati e fa dedup + aggregazione port-channel. In più consideriamo dorsale
# SOLO una porta il cui vicino è infrastruttura (switch/router): una porta verso
# un server/PC/AP resta correttamente "accesso".

_MAC_INFRA_TYPES = {"switch", "router"}





















# --- Comandi ad-hoc per apparati non ordinari (es. C8000V bridge-domain) ---







# --- MAC <-> IP MATCHING (tabelle ARP dei gateway L3: switch SVI / firewall) ---






# --- CONFIG ANALYZER: analisi running-config dai backup ---





# --- AI ASSISTANT: provider pluggabili (Anthropic/OpenAI/Gemini/Ollama) ---
# La configurazione vive in app_settings.json sotto forma di PROFILI di
# connessione ("ai_profiles": lista di dict, "ai_active_profile": id del
# profilo attivo usato dalla chat). La API key di ogni profilo viene cifrata
# con lo stesso CIPHER_SUITE usato per le password degli apparati
# (crypto_vault), mai salvata in chiaro su disco e mai restituita in chiaro
# dalle GET (solo un flag booleano ``api_key_set``).
#
# Retrocompatibilità: se il vecchio formato a profilo singolo (chiave "ai")
# esiste ancora e "ai_profiles" non è mai stato inizializzato, viene
# migrato automaticamente in un profilo "Default" alla prima lettura.

_AI_PROVIDERS = {"anthropic", "openai", "gemini", "ollama"}




















# --- SWITCH PROVISIONER: config "da zero" (view/SSH/console-seriale) ---

def _provision_cfg(payload_dict: dict, materialized: bool, current_user, vendor: str) -> dict:
    """Prepara il payload del provisioner per la generazione testo (finding I-2):
    di default i segreti sono sostituiti da placeholder {{VAULT:...}}; la
    materializzazione completa richiede flag esplicito e viene auditata."""
    if not materialized:
        return provisioning_secrets.mask_secrets(payload_dict)
    log_audit(
        f"ATTENZIONE: config day-0 {vendor} generata MATERIALIZZATA (segreti in chiaro) "
        f"per '{payload_dict.get('hostname')}' da '{current_user.get('sub')}'."
    )
    return payload_dict

@app.post("/api/provisioner/generate")
def provisioner_generate(payload: SwitchProvisionSchema, materialized: bool = False,
                         current_user = Depends(require_operator)):
    """Genera la running-config e la restituisce come testo (view/copy nella UI).
    Di default i segreti sono placeholder; ``?materialized=true`` per il testo
    completo (auditato)."""
    cfg = _provision_cfg(payload.dict(), materialized, current_user, "switch")
    config_text = switch_provisioner.build_config(cfg)
    return {"status": "success", "config": config_text, "materialized": materialized}

@app.post("/api/provisioner/download")
def provisioner_download(payload: SwitchProvisionSchema, materialized: bool = False,
                         current_user = Depends(require_operator)):
    """Genera la running-config e la restituisce come file .txt scaricabile."""
    cfg = _provision_cfg(payload.dict(), materialized, current_user, "switch")
    config_text = switch_provisioner.build_config(cfg)
    from fastapi.responses import Response as FastResponse
    filename = f"{(payload.hostname or 'switch').strip()}-day0.txt"
    log_audit(f"Config day-0 generata (download) per '{payload.hostname}' da '{current_user.get('sub')}'.")
    return FastResponse(
        content=config_text,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.post("/api/provisioner/push-ssh")
def provisioner_push_ssh(payload: SwitchProvisionSSHSchema, current_user = Depends(require_operator)):
    """Genera la config e la applica via SSH (Netmiko) su un apparato raggiungibile."""
    config_text = switch_provisioner.build_config(payload.dict())
    result = switch_provisioner.push_via_ssh(
        host=payload.ssh_host,
        username=payload.ssh_username,
        password=payload.ssh_password,
        secret=payload.ssh_secret,
        config_text=config_text,
        port=payload.ssh_port,
        save=payload.save_after,
    )
    log_audit(
        f"Push SSH config day-0 su '{payload.ssh_host}' (hostname target: "
        f"'{payload.hostname}') da '{current_user.get('sub')}': {result.get('status')}."
    )
    # La config materializzata resta solo in memoria per il push: nella
    # risposta torna la versione con placeholder (finding I-2).
    result["config"] = switch_provisioner.build_config(provisioning_secrets.mask_secrets(payload.dict()))
    return result

@app.post("/api/provisioner/push-serial")
def provisioner_push_serial(payload: SwitchProvisionSerialSchema, current_user = Depends(require_operator)):
    """Genera la config e la applica via console/seriale (pyserial) per il
    provisioning day-0 senza connettivita' di rete."""
    config_text = switch_provisioner.build_config(payload.dict())
    result = switch_provisioner.push_via_serial(
        com_port=payload.com_port,
        config_text=config_text,
        baudrate=payload.baudrate,
    )
    log_audit(
        f"Push seriale ({payload.com_port}) config day-0 (hostname target: "
        f"'{payload.hostname}') da '{current_user.get('sub')}': {result.get('status')}."
    )
    result["config"] = switch_provisioner.build_config(provisioning_secrets.mask_secrets(payload.dict()))
    return result

@app.get("/api/provisioner/serial-ports")
def provisioner_serial_ports(current_user = Depends(require_operator)):
    """Elenca le porte COM/seriali disponibili sull'host del server."""
    return {"ports": switch_provisioner.list_serial_ports()}


# --- FORTIGATE PROVISIONER: ZTP firewall FortiGate (view/SSH/console-seriale) ---

@app.post("/api/provisioner/fgt/generate")
def fgt_provisioner_generate(payload: FortiGateProvisionSchema, materialized: bool = False,
                             current_user = Depends(require_operator)):
    """Genera la configurazione FortiOS day-0 e la restituisce come testo."""
    cfg = _provision_cfg(payload.dict(), materialized, current_user, "FortiGate")
    config_text = fortigate_provisioner.build_config(cfg)
    log_audit(f"Config FortiGate day-0 generata per '{payload.hostname}' da '{current_user.get('sub')}'.")
    return {"status": "success", "config": config_text, "materialized": materialized}

@app.post("/api/provisioner/fgt/download")
def fgt_provisioner_download(payload: FortiGateProvisionSchema, materialized: bool = False,
                             current_user = Depends(require_operator)):
    """Genera la configurazione FortiOS e la restituisce come file .txt."""
    cfg = _provision_cfg(payload.dict(), materialized, current_user, "FortiGate")
    config_text = fortigate_provisioner.build_config(cfg)
    from fastapi.responses import Response as FastResponse
    filename = f"{(payload.hostname or 'fortigate').strip()}-day0.txt"
    log_audit(f"Config FortiGate day-0 (download) per '{payload.hostname}' da '{current_user.get('sub')}'.")
    return FastResponse(
        content=config_text,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.post("/api/provisioner/fgt/push-ssh")
def fgt_provisioner_push_ssh(payload: FortiGateProvisionSSHSchema, current_user = Depends(require_operator)):
    """Genera la config FortiOS e la applica via SSH (Netmiko 'fortinet')."""
    config_text = fortigate_provisioner.build_config(payload.dict())
    result = fortigate_provisioner.push_via_ssh(
        host=payload.ssh_host,
        username=payload.ssh_username,
        password=payload.ssh_password,
        config_text=config_text,
        port=payload.ssh_port,
    )
    log_audit(
        f"Push SSH config FortiGate day-0 su '{payload.ssh_host}' (hostname target: "
        f"'{payload.hostname}') da '{current_user.get('sub')}': {result.get('status')}."
    )
    result["config"] = fortigate_provisioner.build_config(provisioning_secrets.mask_secrets(payload.dict()))
    return result

@app.post("/api/provisioner/fgt/push-serial")
def fgt_provisioner_push_serial(payload: FortiGateProvisionSerialSchema, current_user = Depends(require_operator)):
    """Genera la config FortiOS e la applica via console/seriale (day-0)."""
    config_text = fortigate_provisioner.build_config(payload.dict())
    result = fortigate_provisioner.push_via_serial(
        com_port=payload.com_port,
        config_text=config_text,
        baudrate=payload.baudrate,
        username=payload.console_user,
        password=payload.console_password,
    )
    log_audit(
        f"Push seriale ({payload.com_port}) config FortiGate day-0 (hostname target: "
        f"'{payload.hostname}') da '{current_user.get('sub')}': {result.get('status')}."
    )
    result["config"] = fortigate_provisioner.build_config(provisioning_secrets.mask_secrets(payload.dict()))
    return result


# --- FORTIGATE / WLC LIVE: estratti nei router modulari (fase 2.2/2.3) ---
# Vedi routers/fortigate.py e routers/wlc.py; inclusi in app più sotto.

# --- MCP SERVER: controllo dei tool esposti ai client LLM esterni ---
# Il catalogo dei tool vive in mcp_server.TOOLS (unica fonte); qui si gestisce
# solo l'elenco dei tool DISABILITATI, persistito in app_settings.json ("mcp").

# Tool disabilitati di default finché l'admin non salva una scelta esplicita
# (Decisione #7 pendente: i dati di flusso verso LLM esterni sono opt-in).
_MCP_DEFAULT_DISABLED = {"get_top_talkers", "get_anomalies"}


def _mcp_disabled_tools() -> list:
    mcp = get_app_settings().get("mcp")
    if mcp is None:
        # Nessuna configurazione salvata: vale il default (tool flussi spenti).
        return sorted(t for t in _MCP_DEFAULT_DISABLED if t in mcp_server.TOOLS)
    return [t for t in (mcp.get("disabled_tools") or []) if t in mcp_server.TOOLS]

@app.get("/api/mcp/settings")
def get_mcp_settings(current_user = Depends(require_admin)):
    """Catalogo dei tool MCP con descrizione + elenco dei tool disabilitati."""
    return {
        "tools": [{"name": name, "description": desc}
                  for name, (desc, _schema, _fn) in mcp_server.TOOLS.items()],
        "disabled_tools": _mcp_disabled_tools(),
    }

@app.post("/api/mcp/settings")
def set_mcp_settings(payload: McpSettingsSchema, current_user = Depends(require_admin)):
    unknown = [t for t in payload.disabled_tools if t not in mcp_server.TOOLS]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Tool sconosciuti: {', '.join(unknown)}")
    save_app_settings({"mcp": {"disabled_tools": payload.disabled_tools}})
    log_audit(f"Tool MCP disabilitati impostati a {payload.disabled_tools or '[]'} "
              f"da '{current_user.get('sub')}'.")
    return {"status": "success"}

@app.get("/api/mcp/tool-config")
def get_mcp_tool_config(current_user = Depends(get_current_user)):
    """Letto dal processo mcp_server.py (con l'account con cui si autentica)
    per sapere quali tool NON esporre al client LLM."""
    return {"disabled_tools": _mcp_disabled_tools()}


# --- SCANSIONE SUBNET IN BACKGROUND ---

@app.post("/api/scan-subnet")
def start_subnet_scan(
    payload: SubnetScanRequest,
    background_tasks: BackgroundTasks,
    current_user = Depends(require_operator),
):
    try:
        hosts = parse_network(payload.network)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    job_id = str(uuid.uuid4())
    with _scan_jobs_lock:
        _scan_jobs[job_id] = {
            "status":     "running",
            "results":    [],
            "progress":   0,
            "total":      len(hosts),
            "started_at": time.time(),
        }

    background_tasks.add_task(_run_scan_job, job_id, payload)

    log_audit(
        f"Scansione subnet '{payload.network}' avviata dall'utente "
        f"'{current_user.get('sub')}' (job_id: {job_id}, host totali: {len(hosts)})."
    )
    return {"job_id": job_id, "status": "started", "total_hosts": len(hosts)}


@app.get("/api/scan-subnet/{job_id}")
def get_subnet_scan_status(job_id: str, current_user = Depends(get_current_user)):
    with _scan_jobs_lock:
        # Elimina solo i job conclusi: una scansione lunga (es. /16) può
        # legittimamente restare "running" oltre i 10 minuti.
        stale = [k for k, v in _scan_jobs.items()
                 if v.get("status") != "running" and time.time() - v.get("started_at", 0) > 600]
        for k in stale:
            del _scan_jobs[k]
        job = _scan_jobs.get(job_id)

    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' non trovato.")

    log_audit(
        f"Stato job scansione '{job_id}' richiesto dall'utente '{current_user.get('sub')}'."
    )
    return {
        "status":   job["status"],
        "results":  job.get("results", []),
        "progress": job.get("progress", 0),
        "total":    job.get("total", 0),
    }


# --- GESTIONE SEDI MULTI-SITE (solo amministratori) ---

@app.get("/api/sites")
def list_sites_ep(current_user = Depends(require_admin)):
    return {"sites": site_manager.list_sites()}

@app.post("/api/sites")
def create_site_ep(payload: SiteSchema, current_user = Depends(require_admin)):
    try:
        site, token = site_manager.create_site(payload.name, payload.mode, payload.subnets)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    log_audit(f"Sede '{site['id']}' (mode: {payload.mode}) creata da '{current_user.get('sub')}'.")
    # Il token in chiaro è restituito UNA SOLA VOLTA (poi solo hash su disco).
    return {"status": "success", "site": site, "token": token}

@app.post("/api/sites/update")
def update_site_ep(payload: SiteUpdateSchema, current_user = Depends(require_admin)):
    try:
        ok = site_manager.update_site(payload.id, payload.name, payload.mode, payload.subnets)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    log_audit(f"Sede '{payload.id}' aggiornata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@app.post("/api/sites/delete")
def delete_site_ep(payload: SiteIdSchema, current_user = Depends(require_admin)):
    if not site_manager.delete_site(payload.id):
        raise HTTPException(status_code=400, detail="Sede non eliminabile o inesistente.")
    log_audit(f"Sede '{payload.id}' eliminata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@app.post("/api/sites/regenerate-token")
def regenerate_site_token_ep(payload: SiteIdSchema, current_user = Depends(require_admin)):
    token = site_manager.regenerate_token(payload.id)
    if token is None:
        raise HTTPException(status_code=400, detail="Sede inesistente o non in modalità agent.")
    log_audit(f"Token della sede '{payload.id}' rigenerato da '{current_user.get('sub')}'.")
    return {"status": "success", "token": token}

# --- Relay comandi CLI verso una sede agent (UI -> coda -> agente) ---

@app.post("/api/sites/{site_id}/command")
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

@app.get("/api/command-jobs/{job_id}")
def get_command_job_ep(job_id: str, current_user = Depends(require_operator)):
    job = site_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job non trovato.")
    return job

@app.get("/api/sites/{site_id}/command-jobs")
def list_site_command_jobs_ep(site_id: str, current_user = Depends(require_operator)):
    return {"jobs": site_manager.list_jobs(site_id)}


# --- ENDPOINT PER GLI AGENTI DI SEDE (auth per-sede, separata dal JWT utente) ---

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

@app.post("/api/agent/heartbeat")
def agent_heartbeat(site = Depends(get_agent_site)):
    return {"ok": True, "site_id": site["id"], "name": site["name"], "subnets": site.get("subnets", [])}

@app.post("/api/agent/inventory")
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

@app.post("/api/agent/mac")
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

@app.get("/api/agent/jobs")
def agent_poll_jobs(site = Depends(get_agent_site)):
    """L'agente preleva i job di comando pendenti (marcati 'running')."""
    return {"jobs": site_manager.claim_pending_jobs(site["id"])}

@app.post("/api/agent/jobs/{job_id}/result")
def agent_post_job_result(job_id: str, payload: AgentJobResultSchema,
                          site = Depends(get_agent_site)):
    if not site_manager.complete_job(job_id, site["id"], payload.status, payload.result):
        raise HTTPException(status_code=404, detail="Job non trovato per questa sede.")
    return {"status": "success"}


# --- AVVIO E BROWSER AUTOMATICO ---

def open_browser(scheme: str = "http"):
    time.sleep(1.5)
    webbrowser.open(f"{scheme}://localhost:{PORT}/")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SentinelNet Server")
    parser.add_argument("--mcp", action="store_true", help="Esegui il server MCP (Model Context Protocol) su stdio")
    args, _ = parser.parse_known_args()

    if args.mcp:
        import mcp_server
        mcp_server.main()
        return

    if not os.path.exists("templates"): 
        os.makedirs("templates")
        
    # Ordine di risoluzione: env SENTINELNET_HOST > app_settings.json > 127.0.0.1
    host = resolve_bind_host()
    port = effective_port()

    # Disabilita l'apertura automatica del browser in ambiente Docker/containerizzato
    _env_nb = os.environ.get("SENTINELNET_NO_BROWSER")
    _nb = _env_nb.lower() == "true" if _env_nb is not None else bool(_app_adv_setting("no_browser"))
    no_browser = _nb or host == "0.0.0.0"

    # TLS nativo opzionale (finding H-1): fail-closed su configurazione parziale.
    try:
        ssl_certfile, ssl_keyfile = data_config.resolve_tls_config()
    except data_config.TlsConfigError as e:
        print(f"ERRORE: {e}", file=sys.stderr)
        sys.exit(1)

    if not no_browser:
        scheme = "https" if ssl_certfile else "http"
        threading.Thread(target=open_browser, args=(scheme,), daemon=True).start()

    uvicorn.run(app, host=host, port=port, log_level="info",
                ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)

if __name__ == "__main__":
    main()
