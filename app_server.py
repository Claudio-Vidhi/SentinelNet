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

app = FastAPI(title="SentinelNet API", version="2.0.0")

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
    return payload

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

class DeviceDelete(BaseModel):
    ip: str

class CSVImportRequest(BaseModel):
    csv_data: str

class CommandRequest(BaseModel):
    ip: str
    command: str

class DeviceReassignSchema(BaseModel):
    ip: str
    new_group: str

class PingCheckRequest(BaseModel):
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
    driver: str = None

class VendorDeleteSchema(BaseModel):
    name: str

# --- STATO DEI JOB DI TRIAGE IN BACKGROUND CON LOCK ---

_scan_jobs: dict[str, dict] = {}
_scan_jobs_lock = threading.Lock()

triage_lock = threading.Lock()
triage_job = {
    "status": "idle",       # "idle", "running", "complete"
    "progress": 0,
    "total": 0,
    "current_device": "",
    "results": []
}

def run_triage_background():
    global triage_job
    devices = inventory_manager.get_all_devices()
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
    try:
        results = scan_subnet(
            address=req.network,
            vendor_hint=req.vendor,
            credentials=credentials,
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
    success = user_manager.create_user(payload.username, payload.password)
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
        reset_failed_attempts(payload.username)
        access_token = create_access_token(data={"sub": payload.username})
        log_audit(f"Utente '{payload.username}' loggato con successo.")
        return {"access_token": access_token, "token_type": "bearer"}
        
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

# --- ROTTE DISPOSITIVI (INVENTARIO) ---

@app.get("/api/local-devices")
def get_devices_and_versions(current_user = Depends(get_current_user)):
    return {
        "devices": inventory_manager.get_all_devices(),
        "detected_versions": inventory_manager.get_detected_versions(),
        "groups": inventory_manager.get_all_groups()
    }

@app.get("/api/export/devices")
def export_devices_csv(current_user = Depends(get_current_user)):
    import csv, io
    devices = inventory_manager.get_all_devices()
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
def add_device(device: DeviceSchema, current_user = Depends(get_current_user)):
    inventory_manager.add_or_update_device(
        device.ip, device.vendor, device.profile,
        device.username, device.password, device.enable_secret, device.group
    )
    log_audit(f"Dispositivo '{device.ip}' (vendor: '{device.vendor}', gruppo: '{device.group}') aggiunto/aggiornato dall'utente '{current_user.get('sub')}'.")
    return {"status": "success", "message": "Dispositivo salvato"}

@app.post("/api/delete-device")
def delete_device(payload: DeviceDelete, current_user = Depends(get_current_user)):
    inventory_manager.delete_device(payload.ip)
    log_audit(f"Dispositivo '{payload.ip}' eliminato dall'inventario dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}

@app.post("/api/import-csv")
def import_csv(payload: CSVImportRequest, current_user = Depends(get_current_user)):
    lines = payload.csv_data.split('\n')
    import csv as csv_parser
    reader = csv_parser.DictReader(lines)
    
    results = {"imported": [], "failed": []}
    
    for i, row in enumerate(reader, start=2):  # start=2 perché riga 1 è l'header
        try:
            ip = row.get('IP')
            if not ip or not ip.strip():
                raise ValueError("IP mancante o vuoto")
                
            ip = ip.strip()
            
            # Se il campo Group è presente e non vuoto, chiama immediatamente inventory_manager.add_group(row['Group'])
            group_name = (row.get('Group') or '').strip()
            if group_name:
                inventory_manager.add_group(group_name)
            else:
                group_name = 'Generale'
                
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
    return inventory_manager.get_all_groups()

@app.post("/api/groups")
def create_group(group: GroupSchema, current_user = Depends(get_current_user)):
    name = group.name
    if not name:
        raise HTTPException(status_code=400, detail="Il nome del gruppo è obbligatorio.")
    groups = inventory_manager.get_all_groups()
    groups[name] = {"description": group.description}
    inventory_manager.save_groups(groups)
    log_audit(f"Gruppo '{name}' (descrizione: '{group.description}') creato dall'utente '{current_user.get('sub')}'.")
    return {"status": "success", "message": "Gruppo creato"}

@app.post("/api/groups/delete")
def remove_group(payload: GroupDeleteSchema, current_user = Depends(get_current_user)):
    group_name = payload.name
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
def create_vendor(v: VendorSchema, current_user = Depends(get_current_user)):
    vendors = inventory_manager.get_all_vendors()
    vendors[v.name.lower().strip()] = {"euvd_term": v.euvd_term, "driver": v.driver}
    inventory_manager.save_vendors(vendors)
    log_audit(f"Vendor '{v.name}' aggiunto/aggiornato da '{current_user.get('sub')}'.")
    return {"status": "success"}

@app.post("/api/vendors/delete")
def delete_vendor(v: VendorDeleteSchema, current_user = Depends(get_current_user)):
    vendors = inventory_manager.get_all_vendors()
    if v.name.lower() in ("cisco", "hpe"):
        raise HTTPException(status_code=400, detail="Vendor di sistema non eliminabile.")
    vendors.pop(v.name.lower().strip(), None)
    inventory_manager.save_vendors(vendors)
    log_audit(f"Vendor '{v.name}' eliminato da '{current_user.get('sub')}'.")
    return {"status": "success"}

# --- ENDPOINTS COSTRUZIONE MAPPA TOPOLOGICA ---

@app.get("/api/topology")
def get_topology_adjacency(group: str = "all", current_user = Depends(get_current_user)):
    """Restituisce la lista di adiacenza fisica per il triage testuale."""
    return core_engine.generate_network_map(group_filter=group)

@app.get("/api/network-map")
def get_network_map(group: str = "all", current_user = Depends(get_current_user)):
    """Restituisce il grafo topologico strutturato per Vis.js."""
    return core_engine.generate_network_map(group_filter=group)

@app.post("/api/topology/reset")
def reset_topology(current_user = Depends(get_current_user)):
    backup_dir = "backup-config"
    deleted_count = 0
    if os.path.exists(backup_dir):
        for f in os.listdir(backup_dir):
            if f.endswith(".txt"):
                try:
                    os.remove(os.path.join(backup_dir, f))
                    deleted_count += 1
                except Exception:
                    pass
    
    # Svuota detected_versions.json
    inventory_manager.safe_json_write(inventory_manager.VERSION_DATA_FILE, {})
    
    log_audit(f"Topologia resettata dall'utente '{current_user.get('sub')}'. Eliminati {deleted_count} file cache.")
    return {"status": "success", "deleted": deleted_count}

# --- ROTTE AUTOMAZIONE & DOWNLOAD ---

@app.post("/api/run-triage")
def run_triage(current_user = Depends(get_current_user)):
    global triage_job
    with triage_lock:
        if triage_job["status"] == "running":
            return {"status": "running", "message": "Scansione già in corso"}
        
        triage_job["status"] = "running"
        triage_job["progress"] = 0
        triage_job["total"] = 0
        triage_job["current_device"] = "Inizializzazione..."
    
    log_audit(f"Triage globale in background avviato dall'utente '{current_user.get('sub')}'.")
    thread = threading.Thread(target=run_triage_background, daemon=True)
    thread.start()
    return {"status": "running", "message": "Scansione avviata in background"}

@app.post("/api/triage/{ip}")
def triage_single_device(ip: str, current_user = Depends(get_current_user)):
    import re
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        raise HTTPException(status_code=400, detail="IP non valido.")
    devices = inventory_manager.get_all_devices()
    device = next((d for d in devices if d["IP"] == ip), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Dispositivo {ip} non trovato in inventario.")
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
def send_command(payload: CommandRequest, current_user = Depends(get_current_user)):
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
        log_audit(f"Comando CLI '{payload.command}' richiesto su dispositivo '{payload.ip}' dall'utente '{current_user.get('sub')}' (One-Shot API).")
        res = core_engine.send_custom_command(target_device, payload.command)
        return res
    raise HTTPException(status_code=404, detail="Dispositivo non presente in inventario")

@app.post("/api/ws-token")
def get_ws_token(current_user = Depends(get_current_user)):
    """Emette un token OTP monouso valido 30 secondi per aprire un WebSocket."""
    otp = _secrets.token_urlsafe(32)
    _ws_tokens[otp] = (current_user.get("sub"), time.time())
    return {"ws_token": otp}

@app.post("/api/reassign-device")
def reassign_device(payload: DeviceReassignSchema, current_user = Depends(get_current_user)):
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

    old_group = target.get('Group', 'Generale')
    target['Group'] = payload.new_group
    inventory_manager.safe_write_hosts_csv(devices)

    log_audit(
        f"Dispositivo '{payload.ip}' spostato dal gruppo '{old_group}' "
        f"al gruppo '{payload.new_group}' dall'utente '{current_user.get('sub')}'."
    )
    return {"status": "success", "message": f"Dispositivo spostato in '{payload.new_group}'"}


@app.post("/api/ping-check")
def ping_check(payload: PingCheckRequest, current_user = Depends(get_current_user)):
    """
    Verifica la raggiungibilità SSH (porta 22) di tutti i dispositivi
    nel gruppo selezionato, in parallelo con ThreadPoolExecutor.
    """
    from core_engine import is_reachable

    devices = inventory_manager.get_all_devices()
    if payload.group != "all":
        devices = [d for d in devices if d.get('Group') == payload.group]

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
def ping_single(ip: str, current_user = Depends(get_current_user)):
    from core_engine import is_reachable
    import re
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        raise HTTPException(status_code=400, detail="IP non valido.")
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
def download_backup(ip_or_filename: str, current_user = Depends(get_current_user)):
    log_audit(f"Download del file di backup '{ip_or_filename}' richiesto dall'utente '{current_user.get('sub')}'.")
    
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

    if os.path.exists(backup_dir):
        for f in os.listdir(backup_dir):
            if f.endswith(f"-{ip}.txt") or f.endswith(f"_{ip}.txt") or f == f"{ip}.txt" or f == ip_or_filename:
                target_path = os.path.realpath(os.path.join(backup_dir, f))
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
    current_user = Depends(get_current_user),
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
        stale = [k for k, v in _scan_jobs.items() if time.time() - v.get("started_at", 0) > 600]
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
