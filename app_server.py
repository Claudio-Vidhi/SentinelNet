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
from typing import Optional, List
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, Security, Request, Response, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
from pydantic import BaseModel, Field

import uuid

import inventory_manager
import core_engine
import user_manager
from network_scanner import parse_network, scan_subnet
from security_manager import (
    create_access_token, verify_access_token, log_audit,
    is_locked_out, record_failed_attempt, reset_failed_attempts
)

PORT = 8765
BASE_URL = "https://euvdservices.enisa.europa.eu"

app = FastAPI(title="SentinelNet API", version="0.2.0-beta.1")

_ws_tokens: dict[str, tuple[str, float]] = {}  # otp -> (username, timestamp)

# Abilita CORS. Le origini consentite sono configurabili via SENTINELNET_CORS_ORIGINS
# (lista separata da virgole). Default: solo localhost sulla porta dell'app.
# Nota: usare "*" insieme ad allow_credentials=True è invalido per spec ed è
# rifiutato dai browser, quindi le origini vengono sempre elencate esplicitamente.
_default_origins = f"http://localhost:{PORT},http://127.0.0.1:{PORT}"
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("SENTINELNET_CORS_ORIGINS", _default_origins).split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security_scheme = HTTPBearer(auto_error=False)

def get_resource_path(relative_path):
    """Restituisce il percorso assoluto della risorsa, funzionando sia in dev che bundled."""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# --- DIPENDENZE DI AUTENTICAZIONE (JWT) ---

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme)):
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Autenticazione richiesta. Token mancante o non valido."
        )
    token = credentials.credentials
    payload = verify_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token non valido o scaduto."
        )
    sub = payload.get("sub")
    # L'utente deve esistere ancora (gestisce account eliminati con token valido)
    role = user_manager.get_role(sub)
    if role is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Utente non più valido.")
    # Lockout immediato degli account disabilitati anche con token ancora valido
    if user_manager.is_disabled(sub):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabilitato.")
    # Allinea sempre il ruolo allo stato corrente su disco.
    payload["role"] = role
    return payload

def require_role(*allowed):
    """Dipendenza FastAPI: consente l'accesso solo ai ruoli indicati."""
    def _dep(current_user = Depends(get_current_user)):
        if current_user.get("role") not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Privilegi insufficienti per questa operazione."
            )
        return current_user
    return _dep

require_admin = require_role("admin")              # solo amministratori
require_operator = require_role("admin", "operator")  # scritture/operazioni di rete

# --- SCOPING PER SEDE/GRUPPO ---
# Un utente operator/viewer può essere limitato dall'admin a un sottoinsieme di
# sedi (gruppi). L'admin non ha restrizioni. Lista vuota = tutte le sedi.

def user_group_scope(current_user):
    """Set dei gruppi consentiti, oppure None se l'utente vede/gestisce tutto."""
    if current_user.get("role") == "admin":
        return None
    groups = user_manager.get_user_groups(current_user.get("sub"))
    return set(groups) if groups else None

def assert_group_allowed(current_user, group):
    scope = user_group_scope(current_user)
    if scope is not None and group not in scope:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Sede '{group}' non consentita per il tuo profilo."
        )

def assert_device_allowed(current_user, ip):
    """Verifica che il dispositivo (per IP) appartenga a una sede consentita.
    Ritorna il device se trovato, None altrimenti (lascia gestire il 404 a valle)."""
    device = next((d for d in inventory_manager.get_all_devices() if d['IP'] == ip), None)
    if device is None:
        return None
    assert_group_allowed(current_user, device.get('Group', 'Generale'))
    return device

def filter_map_to_scope(data, scope):
    """Riduce nodi e link della mappa alle sole sedi consentite."""
    if scope is None:
        return data
    allowed_nodes = {n["id"] for n in data.get("nodes", []) if n.get("group") in scope}
    nodes = [n for n in data.get("nodes", []) if n["id"] in allowed_nodes]
    links = [l for l in data.get("links", [])
             if l["source"] in allowed_nodes and l["target"] in allowed_nodes]
    return {"nodes": nodes, "links": links}

# --- MODELLI DI VALIDAZIONE PYDANTIC ---

class DeviceSchema(BaseModel):
    ip: str = Field(..., pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    vendor: str
    profile: str
    username: str = "Admin"
    password: str = "admin"
    enable_secret: str = "admin"
    group: str = "Generale"

class GroupSchema(BaseModel):
    name: str
    description: str = ""

class GroupDeleteSchema(BaseModel):
    name: str

class UserSchema(BaseModel):
    username: str
    password: str

LoginRequest = UserSchema

class ChangePasswordSchema(BaseModel):
    old_password: str
    new_password: str

class UserCreateSchema(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    groups: List[str] = []

class UserDeleteSchema(BaseModel):
    username: str

class UserRoleSchema(BaseModel):
    username: str
    role: str

class UserGroupsSchema(BaseModel):
    username: str
    groups: List[str]

class UserDisableSchema(BaseModel):
    username: str
    disabled: bool

class DeviceDelete(BaseModel):
    ip: str

class CSVImportRequest(BaseModel):
    csv_data: str

class CommandRequest(BaseModel):
    ip: str
    command: str

class BulkCommandRequest(BaseModel):
    ips: List[str]
    commands: str
    mode: str = "exec"   # "exec" (show/operational) | "config" (configuration push)
    save: bool = False   # salva la config dopo l'invio (solo mode="config")

class DeviceReassignSchema(BaseModel):
    ip: str
    new_group: str

class PingCheckRequest(BaseModel):
    group: str = "all"

class TriageRunRequest(BaseModel):
    group: str = "all"

class SubnetScanRequest(BaseModel):
    network: str
    vendor: str = "cisco"
    group: str = "Generale"
    auto_add: bool = False
    use_default_creds: bool = True

class VendorSchema(BaseModel):
    name: str
    euvd_term: str
    driver: Optional[str] = None

class VendorDeleteSchema(BaseModel):
    name: str

class CategoryCreateSchema(BaseModel):
    key: str
    label: str = ""
    subcategory: str = ""

class CategoryDeleteSchema(BaseModel):
    key: str

class DeviceCategorySchema(BaseModel):
    node_id: str
    category: Optional[str] = None     # "" rimuove l'override (torna ad auto); None = invariato
    subcategory: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None

class ModelSchema(BaseModel):
    vendor: str
    model: str

# --- STATO DEI JOB DI TRIAGE IN BACKGROUND CON LOCK ---

_scan_jobs: dict[str, dict] = {}
_scan_jobs_lock = threading.Lock()

# Job di invio comandi massivo (bulk) con polling, come per le scansioni.
_bulk_jobs: dict[str, dict] = {}
_bulk_jobs_lock = threading.Lock()

# Comandi distruttivi vietati anche nell'invio massivo, indipendentemente dalla
# modalità: cancellano/riavviano l'apparato. NON si blocca 'conf t' né 'delete'
# (legittimi nel push di configurazione, p.es. in config mode o su Juniper).
BULK_DESTRUCTIVE_BLACKLIST = [
    r"\breload\b",
    r"\breboot\b",
    r"\berase\b",
    r"\bformat\b",
    r"\bwrite\s+erase\b",
]

def is_bulk_command_allowed(command: str) -> bool:
    cmd_clean = command.strip().lower()
    return not any(re.search(p, cmd_clean) for p in BULK_DESTRUCTIVE_BLACKLIST)

def _run_bulk_job(job_id: str, req: BulkCommandRequest):
    commands = [c for c in (line.strip() for line in req.commands.splitlines()) if c]
    config_mode = req.mode == "config"

    devices = inventory_manager.get_all_devices()
    by_ip = {d["IP"]: d for d in devices}
    targets = [by_ip[ip] for ip in req.ips if ip in by_ip]

    def worker(d):
        ip = d["IP"]
        try:
            res = core_engine.run_bulk_command(d, commands, config_mode, req.save)
        except Exception as e:
            res = {"status": "error", "message": str(e)}
        with _bulk_jobs_lock:
            job = _bulk_jobs.get(job_id)
            if job is not None:
                job["results"].append({
                    "ip": ip,
                    "hostname": d.get("Hostname") or ip,
                    "result": res,
                })
                job["progress"] += 1

    max_workers = min(10, len(targets)) if targets else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(worker, targets))

    with _bulk_jobs_lock:
        if job_id in _bulk_jobs:
            _bulk_jobs[job_id]["status"] = "done"

triage_lock = threading.Lock()
triage_job = {
    "status": "idle",       # "idle", "running", "complete"
    "progress": 0,
    "total": 0,
    "current_device": "",
    "results": []
}

def run_triage_background(allowed_groups=None):
    global triage_job
    devices = inventory_manager.get_all_devices()
    if allowed_groups is not None:
        devices = [d for d in devices if d.get('Group') in allowed_groups]
    with triage_lock:
        triage_job["status"] = "running"
        triage_job["total"] = len(devices)
        triage_job["progress"] = 0
        triage_job["results"] = []
        triage_job["current_device"] = "Inizializzazione..."
    
    active_ips = set()
    
    def triage_worker(d):
        ip = d['IP']
        with triage_lock:
            active_ips.add(ip)
            triage_job["current_device"] = ", ".join(sorted(active_ips))
            
        try:
            res = core_engine.run_backup_and_triage(d)
        except Exception as e:
            res = {"status": "error", "message": str(e)}
            
        with triage_lock:
            if ip in active_ips:
                active_ips.remove(ip)
            triage_job["current_device"] = ", ".join(sorted(active_ips))
            triage_job["results"].append({"ip": ip, "result": res})
            triage_job["progress"] += 1

    # Avvia ThreadPoolExecutor per gestire fino a 10 triage simultanei in parallelo
    max_workers = min(10, len(devices)) if devices else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Esegue la mappatura concorrente sui dispositivi
        list(executor.map(triage_worker, devices))
        
    with triage_lock:
        triage_job["status"] = "complete"
        triage_job["current_device"] = ""

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

# --- ROTTE DI AUTENTICAZIONE (JWT) ---

@app.get("/api/auth/status")
def setup_status():
    return {"has_users": user_manager.has_any_user()}

@app.post("/api/auth/register")
def setup_admin(payload: UserSchema):
    if user_manager.has_any_user():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Setup già completato. Registrazione non consentita."
        )
    success = user_manager.create_user(payload.username, payload.password, role="admin")
    if success:
        log_audit(f"Nuovo utente amministratore '{payload.username}' registrato con successo via Setup Wizard.")
        return {"status": "success", "message": "Primo account amministratore creato correttamente."}
    raise HTTPException(status_code=400, detail="Impossibile creare l'account.")

@app.post("/api/auth/login")
def login(payload: LoginRequest):
    if is_locked_out(payload.username):
        log_audit(f"Tentativo di login bloccato per lockout (username: '{payload.username}').")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Troppi tentativi di accesso falliti. Riprova più tardi."
        )
        
    if user_manager.verify_user(payload.username, payload.password):
        if user_manager.is_disabled(payload.username):
            log_audit(f"Login rifiutato per account disabilitato '{payload.username}'.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account disabilitato. Contatta un amministratore."
            )
        reset_failed_attempts(payload.username)
        role = user_manager.get_role(payload.username) or "viewer"
        access_token = create_access_token(data={"sub": payload.username, "role": role})
        log_audit(f"Utente '{payload.username}' (ruolo: {role}) loggato con successo.")
        return {"access_token": access_token, "token_type": "bearer", "role": role}
        
    record_failed_attempt(payload.username)
    log_audit(f"Tentativo di login fallito per l'utente '{payload.username}' (credenziali errate).")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Credenziali amministratore non valide o utente non registrato."
    )

@app.post("/api/auth/change-password")
def change_password(payload: ChangePasswordSchema,
                    current_user = Depends(get_current_user)):
    username = current_user.get("sub")
    success = user_manager.change_password(
        username, payload.old_password, payload.new_password
    )
    if not success:
        raise HTTPException(status_code=400, detail="Password attuale non corretta.")
    log_audit(f"Password cambiata per l'utente '{username}'.")
    return {"status": "success"}

@app.get("/api/auth/me")
def whoami(current_user = Depends(get_current_user)):
    return {"username": current_user.get("sub"), "role": current_user.get("role", "viewer")}

# --- GESTIONE UTENTI (solo amministratori) ---

@app.get("/api/users")
def list_users_ep(current_user = Depends(require_admin)):
    return user_manager.list_users()

@app.post("/api/users")
def create_user_ep(payload: UserCreateSchema, current_user = Depends(require_admin)):
    if payload.role not in user_manager.VALID_ROLES:
        raise HTTPException(status_code=400, detail="Ruolo non valido.")
    if not payload.username.strip() or not payload.password:
        raise HTTPException(status_code=400, detail="Username e password obbligatori.")
    valid_groups = set(inventory_manager.get_all_groups().keys())
    groups = [g for g in payload.groups if g in valid_groups]
    if not user_manager.create_user(payload.username.strip(), payload.password, payload.role, groups):
        raise HTTPException(status_code=400, detail="Utente già esistente.")
    log_audit(
        f"Utente '{payload.username}' (ruolo: {payload.role}, sedi: "
        f"{groups or 'tutte'}) creato da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

@app.post("/api/users/delete")
def delete_user_ep(payload: UserDeleteSchema, current_user = Depends(require_admin)):
    if payload.username == current_user.get("sub"):
        raise HTTPException(status_code=400, detail="Non puoi eliminare il tuo stesso account.")
    if user_manager.get_role(payload.username) == "admin" and user_manager.count_admins() <= 1:
        raise HTTPException(status_code=400, detail="Deve restare almeno un amministratore.")
    if not user_manager.delete_user(payload.username):
        raise HTTPException(status_code=404, detail="Utente non trovato.")
    log_audit(f"Utente '{payload.username}' eliminato da '{current_user.get('sub')}'.")
    return {"status": "success"}

@app.post("/api/users/role")
def set_user_role_ep(payload: UserRoleSchema, current_user = Depends(require_admin)):
    if payload.role not in user_manager.VALID_ROLES:
        raise HTTPException(status_code=400, detail="Ruolo non valido.")
    if (user_manager.get_role(payload.username) == "admin"
            and payload.role != "admin" and user_manager.count_admins() <= 1):
        raise HTTPException(status_code=400, detail="Deve restare almeno un amministratore.")
    if not user_manager.set_role(payload.username, payload.role):
        raise HTTPException(status_code=404, detail="Utente non trovato.")
    log_audit(f"Ruolo di '{payload.username}' impostato a '{payload.role}' da '{current_user.get('sub')}'.")
    return {"status": "success"}

@app.post("/api/users/disable")
def disable_user_ep(payload: UserDisableSchema, current_user = Depends(require_admin)):
    """Abilita/disabilita un utente. Un utente disabilitato non può autenticarsi."""
    if payload.disabled and payload.username == current_user.get("sub"):
        raise HTTPException(status_code=400, detail="Non puoi disabilitare il tuo stesso account.")
    if (payload.disabled and user_manager.get_role(payload.username) == "admin"
            and user_manager.count_active_admins() <= 1):
        raise HTTPException(status_code=400, detail="Deve restare almeno un amministratore attivo.")
    if not user_manager.set_disabled(payload.username, payload.disabled):
        raise HTTPException(status_code=404, detail="Utente non trovato.")
    log_audit(
        f"Utente '{payload.username}' {'disabilitato' if payload.disabled else 'riabilitato'} "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

@app.post("/api/users/groups")
def set_user_groups_ep(payload: UserGroupsSchema, current_user = Depends(require_admin)):
    """Assegna le sedi/gruppi visibili e gestibili da un utente (vuoto = tutte)."""
    valid_groups = set(inventory_manager.get_all_groups().keys())
    groups = [g for g in payload.groups if g in valid_groups]
    if not user_manager.set_groups(payload.username, groups):
        raise HTTPException(status_code=404, detail="Utente non trovato.")
    log_audit(
        f"Sedi di '{payload.username}' impostate a {groups or 'tutte'} "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

# --- ROTTE DISPOSITIVI (INVENTARIO) ---

@app.get("/api/local-devices")
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

@app.get("/api/export/devices")
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

@app.post("/api/add-device")
def add_device(device: DeviceSchema, current_user = Depends(require_operator)):
    assert_group_allowed(current_user, device.group)
    # Impedisce di modificare un dispositivo esistente in una sede non consentita
    existing = next((d for d in inventory_manager.get_all_devices() if d['IP'] == device.ip), None)
    if existing:
        assert_group_allowed(current_user, existing.get('Group', 'Generale'))
    inventory_manager.add_or_update_device(
        device.ip, device.vendor, device.profile,
        device.username, device.password, device.enable_secret, device.group
    )
    log_audit(f"Dispositivo '{device.ip}' (vendor: '{device.vendor}', gruppo: '{device.group}') aggiunto/aggiornato dall'utente '{current_user.get('sub')}'.")
    return {"status": "success", "message": "Dispositivo salvato"}

@app.post("/api/delete-device")
def delete_device(payload: DeviceDelete, current_user = Depends(require_operator)):
    assert_device_allowed(current_user, payload.ip)
    inventory_manager.delete_device(payload.ip)
    log_audit(f"Dispositivo '{payload.ip}' eliminato dall'inventario dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}

@app.post("/api/import-csv")
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

@app.get("/api/groups")
def list_groups(current_user = Depends(get_current_user)):
    groups = inventory_manager.get_all_groups()
    scope = user_group_scope(current_user)
    if scope is not None:
        groups = {g: v for g, v in groups.items() if g in scope}
    return groups

@app.post("/api/groups")
def create_group(group: GroupSchema, current_user = Depends(require_operator)):
    name = group.name
    if not name:
        raise HTTPException(status_code=400, detail="Il nome del gruppo è obbligatorio.")
    groups = inventory_manager.get_all_groups()
    groups[name] = {"description": group.description}
    inventory_manager.save_groups(groups)
    log_audit(f"Gruppo '{name}' (descrizione: '{group.description}') creato dall'utente '{current_user.get('sub')}'.")
    return {"status": "success", "message": "Gruppo creato"}

@app.post("/api/groups/delete")
def remove_group(payload: GroupDeleteSchema, current_user = Depends(require_operator)):
    group_name = payload.name
    assert_group_allowed(current_user, group_name)
    groups = inventory_manager.get_all_groups()
    if group_name in groups and group_name != "Generale":
        inventory_manager.delete_group(group_name)
        log_audit(f"Gruppo '{group_name}' eliminato dall'utente '{current_user.get('sub')}'. Tutti i relativi apparati sono riassegnati a 'Generale'.")
        return {"status": "success"}
    raise HTTPException(status_code=400, detail="Impossibile eliminare il gruppo")

# --- CRUD GESTIONE VENDOR ---

@app.get("/api/vendors")
def list_vendors(current_user = Depends(get_current_user)):
    return inventory_manager.get_all_vendors()

@app.post("/api/vendors")
def create_vendor(v: VendorSchema, current_user = Depends(require_operator)):
    vendors = inventory_manager.get_all_vendors()
    vendors[v.name.lower().strip()] = {"euvd_term": v.euvd_term, "driver": v.driver}
    inventory_manager.save_vendors(vendors)
    log_audit(f"Vendor '{v.name}' aggiunto/aggiornato da '{current_user.get('sub')}'.")
    return {"status": "success"}

@app.post("/api/vendors/delete")
def delete_vendor(v: VendorDeleteSchema, current_user = Depends(require_operator)):
    vendors = inventory_manager.get_all_vendors()
    if v.name.lower() in ("cisco", "hpe"):
        raise HTTPException(status_code=400, detail="Vendor di sistema non eliminabile.")
    vendors.pop(v.name.lower().strip(), None)
    inventory_manager.save_vendors(vendors)
    log_audit(f"Vendor '{v.name}' eliminato da '{current_user.get('sub')}'.")
    return {"status": "success"}

# --- CATEGORIE / CLASSIFICAZIONE DISPOSITIVI ---

@app.get("/api/device-classification")
def device_classification(current_user = Depends(get_current_user)):
    """Elenco completo dei dispositivi (inventariati + scoperti via CDP/LLDP) con
    categoria, sede e conteggi per categoria. Usato dal pannello Dispositivi."""
    scope = user_group_scope(current_user)
    data = core_engine.generate_network_map(group_filter="all")
    data = filter_map_to_scope(data, scope)

    cats = inventory_manager.get_device_categories()
    assignments = cats["assignments"]

    nodes = []
    counts_by_category: dict = {}
    counts_by_group: dict = {}
    for n in data["nodes"]:
        a = assignments.get(n["id"], {})
        dtype = n.get("device_type", "switch")
        group = n.get("group", "Generale")
        discovered = n.get("status") == "discovered"
        # IP mostrato in tabella: per i nodi scoperti l'IP annunciato (CDP/LLDP),
        # non l'id sintetico "discovered_<hostname>".
        display_ip = (n.get("reported_ip") or "") if discovered else n["id"]
        node = {
            "id": n["id"],
            "display_ip": display_ip,
            "label": n.get("label", n["id"]),
            "group": group,
            "status": n.get("status"),
            "device_type": dtype,
            "subcategory": a.get("subcategory", ""),
            "is_manual": bool(a.get("category")),
            "vendor": a.get("vendor") or n.get("vendor"),
            "model": a.get("model") or n.get("model") or "",
            "version": n.get("version"),
            "vtp_domain": n.get("vtp_domain"),
            "vtp_mode": n.get("vtp_mode"),
            "discovered": discovered,
        }
        nodes.append(node)
        counts_by_category[dtype] = counts_by_category.get(dtype, 0) + 1
        counts_by_group[group] = counts_by_group.get(group, 0) + 1

    return {
        "categories": cats["categories"],
        "nodes": nodes,
        "counts_by_category": counts_by_category,
        "counts_by_group": counts_by_group,
        "vendors": sorted(inventory_manager.get_all_vendors().keys()),
        "models": inventory_manager.get_models(),
        "total": len(nodes),
    }

@app.post("/api/device-categories")
def create_device_category(payload: CategoryCreateSchema, current_user = Depends(require_operator)):
    """Crea una categoria custom o aggiunge una sottocategoria (admin/operator)."""
    if not inventory_manager.add_category(payload.key, payload.label, payload.subcategory):
        raise HTTPException(status_code=400, detail="Chiave categoria non valida.")
    log_audit(
        f"Categoria '{payload.key}' (sub: '{payload.subcategory or '-'}') creata/aggiornata "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

@app.post("/api/device-categories/delete")
def delete_device_category(payload: CategoryDeleteSchema, current_user = Depends(require_operator)):
    if not inventory_manager.delete_category(payload.key):
        raise HTTPException(status_code=400, detail="Categoria di sistema o inesistente.")
    log_audit(f"Categoria '{payload.key}' eliminata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@app.post("/api/device-categories/assign")
def assign_device_category(payload: DeviceCategorySchema, current_user = Depends(require_operator)):
    """Aggiorna gli attributi manuali di un dispositivo: categoria, sottocategoria,
    vendor e/o modello (admin/operator). I campi non forniti restano invariati."""
    fields = {k: v for k, v in {
        "category": payload.category,
        "subcategory": payload.subcategory,
        "vendor": payload.vendor,
        "model": payload.model,
    }.items() if v is not None}
    if not inventory_manager.set_device_meta(payload.node_id, **fields):
        raise HTTPException(status_code=400, detail="Aggiornamento non valido.")
    # Se è stato indicato un nuovo modello con un vendor, lo si registra anche nel
    # catalogo modelli del vendor, così diventa riutilizzabile.
    if payload.model and payload.vendor:
        inventory_manager.add_model(payload.vendor, payload.model)
    log_audit(
        f"Attributi dispositivo '{payload.node_id}' aggiornati ({fields}) "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

# --- REGISTRO MODELLI (per vendor) ---

@app.get("/api/models")
def list_models(current_user = Depends(get_current_user)):
    return inventory_manager.get_models()

@app.post("/api/models")
def create_model(payload: ModelSchema, current_user = Depends(require_operator)):
    if not inventory_manager.add_model(payload.vendor, payload.model):
        raise HTTPException(status_code=400, detail="Vendor e modello obbligatori.")
    log_audit(f"Modello '{payload.model}' (vendor: {payload.vendor}) aggiunto da '{current_user.get('sub')}'.")
    return {"status": "success"}

@app.post("/api/models/delete")
def remove_model(payload: ModelSchema, current_user = Depends(require_operator)):
    if not inventory_manager.delete_model(payload.vendor, payload.model):
        raise HTTPException(status_code=404, detail="Modello non trovato.")
    log_audit(f"Modello '{payload.model}' (vendor: {payload.vendor}) eliminato da '{current_user.get('sub')}'.")
    return {"status": "success"}

# --- ENDPOINTS COSTRUZIONE MAPPA TOPOLOGICA ---

@app.get("/api/topology")
def get_topology_adjacency(group: str = "all", current_user = Depends(get_current_user)):
    """Restituisce la lista di adiacenza fisica per il triage testuale."""
    data = core_engine.generate_network_map(group_filter=group)
    return filter_map_to_scope(data, user_group_scope(current_user))

@app.get("/api/network-map")
def get_network_map(group: str = "all", current_user = Depends(get_current_user)):
    """Restituisce il grafo topologico strutturato per Vis.js."""
    data = core_engine.generate_network_map(group_filter=group)
    return filter_map_to_scope(data, user_group_scope(current_user))

@app.get("/api/portchannels")
def get_portchannels(group: str = "all", current_user = Depends(get_current_user)):
    """Report Port-channel per apparato (per il tab Adjacency List), filtrato per sede."""
    scope = user_group_scope(current_user)
    if group != "all" and scope is not None and group not in scope:
        raise HTTPException(status_code=403, detail="Sede non consentita.")
    report = core_engine.get_portchannel_report(group_filter=group)
    if scope is not None:
        report = [r for r in report if r["group"] in scope]
    return {"devices": report}

@app.post("/api/topology/reset")
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

# --- ROTTE AUTOMAZIONE & DOWNLOAD ---

@app.post("/api/run-triage")
def run_triage(payload: TriageRunRequest = TriageRunRequest(),
               current_user = Depends(require_operator)):
    global triage_job

    # Determina le sedi da sottoporre a triage, rispettando lo scope dell'utente.
    scope = user_group_scope(current_user)
    if payload.group and payload.group != "all":
        assert_group_allowed(current_user, payload.group)
        target_groups = {payload.group}
    else:
        target_groups = scope  # None = tutte le sedi

    with triage_lock:
        if triage_job["status"] == "running":
            return {"status": "running", "message": "Scansione già in corso"}

        triage_job["status"] = "running"
        triage_job["progress"] = 0
        triage_job["total"] = 0
        triage_job["current_device"] = "Inizializzazione..."

    log_audit(
        f"Triage avviato dall'utente '{current_user.get('sub')}' "
        f"(sede: {payload.group})."
    )
    thread = threading.Thread(target=run_triage_background,
                              args=(target_groups,), daemon=True)
    thread.start()
    return {"status": "running", "message": "Scansione avviata in background"}

@app.post("/api/triage/{ip}")
def triage_single_device(ip: str, current_user = Depends(require_operator)):
    import re
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        raise HTTPException(status_code=400, detail="IP non valido.")
    devices = inventory_manager.get_all_devices()
    device = next((d for d in devices if d["IP"] == ip), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Dispositivo {ip} non trovato in inventario.")
    assert_group_allowed(current_user, device.get('Group', 'Generale'))
    result = core_engine.run_backup_and_triage(device)
    log_audit(f"Triage singolo eseguito su '{ip}' dall'utente '{current_user.get('sub')}': {result.get('status')}.")
    return result

@app.get("/api/triage-status")
def get_triage_status(current_user = Depends(get_current_user)):
    with triage_lock:
        return dict(triage_job)

# Blacklist di comandi CLI pericolosi, distruttivi o bloccanti
COMMAND_BLACKLIST = [
    r"\breload\b",
    r"\berase\b",
    r"\bdelete\b",
    r"\bformat\b",
    r"\breboot\b",
    r"\bconf\s+t\b",
    r"\bconfigure\s+terminal\b",
    r"\bcopy\s+.*?startup-config\b"
]

def is_command_safe(command: str) -> bool:
    """Verifica se il comando contiene stringhe o pattern in blacklist per motivi di sicurezza."""
    cmd_clean = command.strip().lower()
    for pattern in COMMAND_BLACKLIST:
        if re.search(pattern, cmd_clean):
            return False
    return True

@app.post("/api/send-command")
def send_command(payload: CommandRequest, current_user = Depends(require_operator)):
    # Validazione blacklist di sicurezza dei comandi CLI
    if not is_command_safe(payload.command):
        log_audit(f"Tentativo bloccato di esecuzione comando non sicuro '{payload.command}' su '{payload.ip}' dall'utente '{current_user.get('sub')}'.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Comando non consentito per motivi di sicurezza (in blacklist)."
        )
        
    devices = inventory_manager.get_all_devices()
    target_device = next((d for d in devices if d['IP'] == payload.ip), None)
    if target_device:
        assert_group_allowed(current_user, target_device.get('Group', 'Generale'))
        log_audit(f"Comando CLI '{payload.command}' richiesto su dispositivo '{payload.ip}' dall'utente '{current_user.get('sub')}' (One-Shot API).")
        res = core_engine.send_custom_command(target_device, payload.command)
        return res
    raise HTTPException(status_code=404, detail="Dispositivo non presente in inventario")

@app.post("/api/bulk-command")
def start_bulk_command(payload: BulkCommandRequest, current_user = Depends(require_operator)):
    """Avvia l'invio degli stessi comandi a più dispositivi (in background)."""
    commands = [c for c in (line.strip() for line in payload.commands.splitlines()) if c]
    if not commands:
        raise HTTPException(status_code=400, detail="Nessun comando fornito.")
    if not payload.ips:
        raise HTTPException(status_code=400, detail="Nessun dispositivo selezionato.")

    # Guard di sicurezza: nessun comando distruttivo, in qualsiasi modalità.
    for c in commands:
        if not is_bulk_command_allowed(c):
            log_audit(
                f"Invio massivo bloccato: comando distruttivo '{c}' richiesto "
                f"dall'utente '{current_user.get('sub')}'."
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Comando non consentito per motivi di sicurezza: '{c}'."
            )

    for ip in payload.ips:
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            raise HTTPException(status_code=400, detail=f"IP non valido: {ip}")

    # Scoping: tutti i target devono appartenere a sedi consentite
    scope = user_group_scope(current_user)
    if scope is not None:
        by_ip = {d['IP']: d for d in inventory_manager.get_all_devices()}
        for ip in payload.ips:
            dev = by_ip.get(ip)
            if dev is not None and dev.get('Group', 'Generale') not in scope:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Dispositivo '{ip}' in una sede non consentita per il tuo profilo."
                )

    job_id = str(uuid.uuid4())
    with _bulk_jobs_lock:
        _bulk_jobs[job_id] = {
            "status":     "running",
            "results":    [],
            "progress":   0,
            "total":      len(payload.ips),
            "started_at": time.time(),
        }

    thread = threading.Thread(target=_run_bulk_job, args=(job_id, payload), daemon=True)
    thread.start()

    log_audit(
        f"Invio comandi massivo avviato dall'utente '{current_user.get('sub')}' "
        f"(mode={payload.mode}, save={payload.save}, {len(commands)} comandi su "
        f"{len(payload.ips)} dispositivi, job_id: {job_id})."
    )
    return {"job_id": job_id, "status": "started", "total": len(payload.ips)}


@app.get("/api/bulk-command/{job_id}")
def get_bulk_command_status(job_id: str, current_user = Depends(get_current_user)):
    with _bulk_jobs_lock:
        # Elimina solo i job conclusi e vecchi (oltre 10 minuti).
        stale = [k for k, v in _bulk_jobs.items()
                 if v.get("status") != "running" and time.time() - v.get("started_at", 0) > 600]
        for k in stale:
            del _bulk_jobs[k]
        job = _bulk_jobs.get(job_id)

    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' non trovato.")
    return {
        "status":   job["status"],
        "results":  job.get("results", []),
        "progress": job.get("progress", 0),
        "total":    job.get("total", 0),
    }


@app.post("/api/ws-token")
def get_ws_token(current_user = Depends(require_operator)):
    """Emette un token OTP monouso valido 30 secondi per aprire un WebSocket."""
    otp = _secrets.token_urlsafe(32)
    _ws_tokens[otp] = (current_user.get("sub"), time.time())
    return {"ws_token": otp}

@app.post("/api/reassign-device")
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


@app.post("/api/ping-check")
def ping_check(payload: PingCheckRequest, current_user = Depends(require_operator)):
    """
    Verifica la raggiungibilità SSH (porta 22) di tutti i dispositivi
    nel gruppo selezionato, in parallelo con ThreadPoolExecutor.
    """
    from core_engine import is_reachable

    scope = user_group_scope(current_user)
    if payload.group != "all":
        assert_group_allowed(current_user, payload.group)

    devices = inventory_manager.get_all_devices()
    if payload.group != "all":
        devices = [d for d in devices if d.get('Group') == payload.group]
    elif scope is not None:
        devices = [d for d in devices if d.get('Group') in scope]

    results: dict[str, bool] = {}

    def _ping(d):
        results[d['IP']] = is_reachable(d['IP'], timeout=3)

    max_workers = min(20, len(devices)) if devices else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(_ping, devices))

    # Aggiorna lo stato nel file detected_versions.json
    try:
        data = inventory_manager.get_detected_versions()
        for d in devices:
            ip = d['IP']
            alive = results.get(ip, False)
            vendor = d.get('Vendor', 'cisco')
            version = 'Non Rilevata'
            if ip in data:
                vendor = data[ip].get('vendor', vendor)
                version = data[ip].get('version', version)
            inventory_manager.update_version_inventory(ip, vendor, version, "online" if alive else "offline")
    except Exception:
        pass

    log_audit(
        f"Ping check completato su {len(devices)} dispositivi "
        f"(gruppo: '{payload.group}') dall'utente '{current_user.get('sub')}')."
    )
    return {"results": results, "group": payload.group, "total": len(devices)}

# Docker note: is_reachable() uses a TCP probe on port 22. Ensure the container
# has outbound TCP 22 allowed to the management VLAN in your docker-compose network policy.
@app.get("/api/ping/{ip}")
def ping_single(ip: str, current_user = Depends(require_operator)):
    from core_engine import is_reachable
    import re
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        raise HTTPException(status_code=400, detail="IP non valido.")
    # Scoping: se il dispositivo è in inventario, deve essere in una sede consentita
    _dev = next((d for d in inventory_manager.get_all_devices() if d['IP'] == ip), None)
    if _dev is not None:
        assert_group_allowed(current_user, _dev.get('Group', 'Generale'))
    alive = is_reachable(ip, timeout=3)

    # Aggiorna lo stato nel file detected_versions.json
    try:
        data = inventory_manager.get_detected_versions()
        vendor = "cisco"
        version = "Non Rilevata"
        if ip in data:
            vendor = data[ip].get("vendor", vendor)
            version = data[ip].get("version", version)
        else:
            devices = inventory_manager.get_all_devices()
            dev = next((d for d in devices if d["IP"] == ip), None)
            if dev:
                vendor = dev.get("Vendor", vendor)
        inventory_manager.update_version_inventory(ip, vendor, version, "online" if alive else "offline")
    except Exception:
        pass

    log_audit(f"Ping singolo verso '{ip}' eseguito dall'utente '{current_user.get('sub')}': {'raggiungibile' if alive else 'non raggiungibile'}.")
    return {"ip": ip, "reachable": alive}

@app.websocket("/api/ws-terminal/{ip}")
async def ws_terminal(websocket: WebSocket, ip: str):
    # Leggi l'OTP dal query param
    otp = websocket.query_params.get("token")
    now = time.time()
    
    # Pulisce vecchi token scaduti (più vecchi di 30 secondi) per evitare accumulo in memoria
    expired = [k for k, v in list(_ws_tokens.items()) if now - v[1] > 30]
    for k in expired:
        _ws_tokens.pop(k, None)
        
    if not otp or otp not in _ws_tokens:
        await websocket.accept()
        await websocket.send_text("[Errore Autenticazione] Token OTP non valido o scaduto. Connessione rifiutata.\r\n")
        await websocket.close(code=1008)
        return

    username_from_otp, timestamp = _ws_tokens.pop(otp)
    if now - timestamp > 30:
        await websocket.accept()
        await websocket.send_text("[Errore Autenticazione] Token OTP scaduto. Connessione rifiutata.\r\n")
        await websocket.close(code=1008)
        return

    await websocket.accept()
    await websocket.send_text(f"Inizializzazione sessione terminale...\r\n[Connessione SSH a {ip}...]\r\n")

    # 1. Recupero delle credenziali attuali
    devices = inventory_manager.get_all_devices()
    device = next((d for d in devices if d['IP'] == ip), None)
    if not device:
        await websocket.send_text("[Errore] Dispositivo non trovato in inventario.\r\n")
        await websocket.close()
        return

    # Scoping: l'utente del token OTP deve poter gestire la sede del dispositivo
    _role = user_manager.get_role(username_from_otp)
    if _role != "admin":
        _allowed = user_manager.get_user_groups(username_from_otp)
        if _allowed and device.get('Group', 'Generale') not in set(_allowed):
            await websocket.send_text("[Accesso Negato] Sede non consentita per il tuo profilo.\r\n")
            await websocket.close(code=1008)
            return

    username, password, _ = core_engine.get_device_credentials(device)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connected = False

    try:
        # 2. Primo tentativo di connessione invisibile
        client.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=10)
        connected = True
    except paramiko.AuthenticationException:
        # 3. L'autenticazione è fallita! Chiediamo la password manualmente nel terminale
        await websocket.send_text(f"\r\n[Errore Autenticazione] Credenziali non valide per l'utente '{username}'.\r\n")
        await websocket.send_text(f"Inserisci la password per {username}@{ip}: ")
        
        # Buffer temporaneo per leggere la digitazione dell'utente
        manual_password = ""
        while True:
            try:
                data = await websocket.receive_text()
                if data in ("\r", "\n"):
                    await websocket.send_text("\r\n[Ritentando connessione...]\r\n")
                    break
                elif data == "\x7f": # Gestione del tasto backspace
                    manual_password = manual_password[:-1]
                else:
                    manual_password += data
            except WebSocketDisconnect:
                return

        # 4. Secondo tentativo con la password appena digitata
        try:
            client.connect(ip, username=username, password=manual_password, look_for_keys=False, allow_agent=False, timeout=10)
            connected = True
        except Exception as e:
            await websocket.send_text(f"\r\n[Accesso Negato] {str(e)}\r\n")
            await websocket.close()
            return
            
    except Exception as e:
        await websocket.send_text(f"\r\n[Errore Connessione] {str(e)}\r\n")
        await websocket.close()
        return

    # 5. Connessione riuscita, apriamo la shell interattiva!
    if connected:
        chan = client.invoke_shell()
        chan.settimeout(0.0)

        # Task per inviare tasti dal Web allo Switch.
        # Applica la stessa blacklist di /api/send-command: i tasti vengono inoltrati
        # per l'echo, ma la riga digitata viene bufferizzata e, all'Invio, se contiene
        # un comando pericoloso, la riga viene annullata (Ctrl-U) invece di essere eseguita.
        async def ws_to_ssh():
            line_buf = ""
            try:
                while True:
                    data = await websocket.receive_text()
                    for ch in data:
                        if ch in ("\r", "\n"):
                            if line_buf.strip() and not is_command_safe(line_buf):
                                # Annulla la riga sullo switch (kill-line) e avvisa
                                chan.send("\x15")
                                await websocket.send_text(
                                    "\r\n[Comando bloccato] Operazione non consentita "
                                    "per motivi di sicurezza (in blacklist).\r\n"
                                )
                                log_audit(
                                    f"Comando da terminale bloccato per blacklist "
                                    f"('{line_buf.strip()}') su '{ip}' "
                                    f"dall'utente '{username_from_otp}'."
                                )
                                line_buf = ""
                                continue
                            line_buf = ""
                            chan.send(ch)
                        elif ch in ("\x7f", "\x08"):  # backspace
                            line_buf = line_buf[:-1]
                            chan.send(ch)
                        elif ch == "\x03":  # Ctrl-C annulla la riga corrente
                            line_buf = ""
                            chan.send(ch)
                        else:
                            line_buf += ch
                            chan.send(ch)
            except WebSocketDisconnect:
                pass
            except Exception:
                pass

        # Task per leggere lo schermo dello Switch verso il Web
        async def ssh_to_ws():
            try:
                while True:
                    if chan.recv_ready():
                        data = chan.recv(1024).decode('utf-8', errors='ignore')
                        await websocket.send_text(data)
                    await asyncio.sleep(0.01) # Previene il blocco del thread
            except Exception:
                pass

        # Avviamo i listener in parallelo
        task1 = asyncio.create_task(ws_to_ssh())
        task2 = asyncio.create_task(ssh_to_ws())
        
        # Aspettiamo che la connessione cada o il WebSocket venga chiuso
        done, pending = await asyncio.wait([task1, task2], return_when=asyncio.FIRST_COMPLETED)
        
        for task in pending:
            task.cancel()
        
        client.close()
        try:
            await websocket.close()
        except:
            pass

@app.get("/api/download-backup/{ip_or_filename}")
def download_backup(ip_or_filename: str, current_user = Depends(require_operator)):
    log_audit(f"Download del file di backup '{ip_or_filename}' richiesto dall'utente '{current_user.get('sub')}'.")

    # Scoping: ricava l'IP dal nome richiesto e verifica la sede del dispositivo.
    scope = user_group_scope(current_user)
    if scope is not None:
        ip_guess = ip_or_filename
        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ip_or_filename)
        if m:
            ip_guess = m.group(1)
        dev = next((d for d in inventory_manager.get_all_devices() if d['IP'] == ip_guess), None)
        if dev is None or dev.get('Group', 'Generale') not in scope:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Backup non consentito per il tuo profilo."
            )

    backup_dir = os.path.realpath("backup-config")
    requested = os.path.realpath(os.path.join(backup_dir, ip_or_filename))
    
    # Blocca qualsiasi path che esca dalla cartella backup-config
    if not requested.startswith(backup_dir + os.sep):
        raise HTTPException(status_code=400, detail="Path non consentito.")
    
    if os.path.exists(requested):
        return FileResponse(requested, media_type="application/octet-stream",
                            filename=os.path.basename(requested))
        
    ip = ip_or_filename
    if ip_or_filename.endswith(".txt"):
        for sep in ["_", "-"]:
            parts = ip_or_filename[:-4].split(sep)
            if len(parts) >= 2:
                ip = parts[-1]
                break

    # Ricerca ricorsiva: i backup sono organizzati in sottocartelle per gruppo/sede.
    if os.path.exists(backup_dir):
        for root, _dirs, files in os.walk(backup_dir):
            for f in files:
                if f.endswith(f"-{ip}.txt") or f.endswith(f"_{ip}.txt") or f == f"{ip}.txt" or f == ip_or_filename:
                    target_path = os.path.realpath(os.path.join(root, f))
                    if target_path.startswith(backup_dir + os.sep) and os.path.exists(target_path):
                        return FileResponse(target_path, media_type="application/octet-stream", filename=f)

    raise HTTPException(status_code=404, detail="File di backup non trovato per questo dispositivo.")

# --- PROXY MIRATO VERSO ENISA EUVD (SOSTITUISCE IL CATCH-ALL PERICOLOSO) ---

@app.get("/api/search")
async def proxy_enisa_search(request: Request, current_user = Depends(get_current_user)):
    from urllib.parse import parse_qs, urlencode
    target = f"{BASE_URL}/api/search"
    query = request.url.query
    if query:
        params = parse_qs(query, keep_blank_values=True)
        if "vendor" in params:
            original = params["vendor"][0]
            resolved = inventory_manager.resolve_euvd_term(original)
            if resolved != original:
                log_audit(f"EUVD vendor risolto: '{original}' → '{resolved}'")
            params["vendor"] = [resolved]
        target += f"?{urlencode(params, doseq=True)}"

    try:
        headers = {"User-Agent": "ThreatIntelDashboard/3.0"}
        from fastapi.concurrency import run_in_threadpool
        r = await run_in_threadpool(requests.get, target, headers=headers, timeout=15)
        
        return Response(
            content=r.content, 
            status_code=r.status_code, 
            headers={"Content-Type": r.headers.get("Content-Type", "application/json")}
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

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


# --- AVVIO E BROWSER AUTOMATICO ---

def open_browser():
    time.sleep(1.5)
    webbrowser.open(f"http://localhost:{PORT}/")

def main():
    if not os.path.exists("templates"): 
        os.makedirs("templates")
        
    host = os.environ.get("SENTINELNET_HOST", "127.0.0.1")
    port = int(os.environ.get("SENTINELNET_PORT", PORT))
    
    # Disabilita l'apertura automatica del browser in ambiente Docker/containerizzato
    no_browser = os.environ.get("SENTINELNET_NO_BROWSER", "false").lower() == "true" or host == "0.0.0.0"
    
    if not no_browser:
        threading.Thread(target=open_browser, daemon=True).start()
        
    uvicorn.run(app, host=host, port=port, log_level="info")

if __name__ == "__main__":
    main()
