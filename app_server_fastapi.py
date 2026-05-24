import os
import sys
import time
import json
import threading
import webbrowser
import requests
import re
from typing import Optional, List
from datetime import timedelta

from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, Security, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
from pydantic import BaseModel, Field

import inventory_manager
import core_engine
import topology_engine
from security_manager import create_access_token, verify_access_token

PORT = 8765
BASE_URL = "https://euvdservices.enisa.europa.eu"

app = FastAPI(title="Net Manager Alfa API", version="2.0.0")

# Abilita CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

class LoginRequest(BaseModel):
    username: str
    password: str

class DeviceDelete(BaseModel):
    ip: str

class CSVImportRequest(BaseModel):
    csv_data: str

class CommandRequest(BaseModel):
    ip: str
    command: str

# --- STATO DEI JOB DI TRIAGE IN BACKGROUND ---

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
    triage_job["status"] = "running"
    triage_job["total"] = len(devices)
    triage_job["progress"] = 0
    triage_job["results"] = []
    
    for d in devices:
        triage_job["current_device"] = d['IP']
        res = core_engine.run_backup_and_triage(d)
        triage_job["results"].append({"ip": d['IP'], "result": res})
        triage_job["progress"] += 1
        
    triage_job["status"] = "complete"
    triage_job["current_device"] = ""

# --- ROTTE PRINCIPALI & INTERFACCIA WEB ---

@app.get("/")
def read_index():
    return FileResponse(get_resource_path(os.path.join("templates", "dashboard.html")))

# --- ROTTE DI AUTENTICAZIONE (JWT) ---

@app.post("/api/auth/login")
def login(payload: LoginRequest):
    if payload.username == "admin" and payload.password == "admin":
        access_token = create_access_token(data={"sub": payload.username})
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Credenziali amministratore non valide."
    )

# --- ROTTE DISPOSITIVI (INVENTARIO) ---

@app.get("/api/local-devices")
def get_devices_and_versions(current_user = Depends(get_current_user)):
    return {
        "devices": inventory_manager.get_all_devices(),
        "detected_versions": inventory_manager.get_detected_versions(),
        "groups": inventory_manager.get_all_groups()
    }

@app.post("/api/add-device")
def add_device(device: DeviceSchema, current_user = Depends(get_current_user)):
    inventory_manager.add_or_update_device(
        device.ip, device.vendor, device.profile,
        device.username, device.password, device.enable_secret, device.group
    )
    return {"status": "success", "message": "Dispositivo salvato"}

@app.post("/api/delete-device")
def delete_device(payload: dict, current_user = Depends(get_current_user)):
    inventory_manager.delete_device(payload.get('ip'))
    return {"status": "success"}

@app.post("/api/import-csv")
def import_csv(payload: CSVImportRequest, current_user = Depends(get_current_user)):
    lines = payload.csv_data.split('\n')
    import csv as csv_parser
    reader = csv_parser.DictReader(lines)
    for row in reader:
        if row.get('IP'):
            inventory_manager.add_or_update_device(
                row['IP'], row.get('Vendor', 'cisco'), row.get('Profile', 'default'),
                row.get('Username', 'Admin'), row.get('Password', 'admin'), row.get('Enable Secret', 'admin'),
                row.get('Group', 'Generale')
            )
    return {"status": "success", "message": "CSV Importato"}

# --- CRUD GESTIONE GRUPPI VIA WEB UI ---

@app.get("/api/groups")
def list_groups(current_user = Depends(get_current_user)):
    return inventory_manager.get_all_groups()

@app.post("/api/groups")
def create_group(group: GroupSchema, current_user = Depends(get_current_user)):
    groups = inventory_manager.get_all_groups()
    groups[group.name] = {"description": group.description}
    inventory_manager.save_groups(groups)
    return {"status": "success", "message": "Gruppo creato"}

@app.post("/api/groups/delete")
def remove_group(payload: dict, current_user = Depends(get_current_user)):
    group_name = payload.get('name')
    groups = inventory_manager.get_all_groups()
    if group_name in groups and group_name != "Generale":
        del groups[group_name]
        inventory_manager.save_groups(groups)
        return {"status": "success"}
    raise HTTPException(status_code=400, detail="Impossibile eliminare il gruppo")

# --- ENDPOINTS COSTRUZIONE MAPPA TOPOLOGICA ---

@app.get("/api/topology")
@app.get("/api/network-map")
def get_network_topology(current_user = Depends(get_current_user)):
    topo = topology_engine.parse_topology_from_backups()
    
    devices = inventory_manager.get_all_devices()
    versions = inventory_manager.get_detected_versions()
    
    # Arricchisce i nodi con gruppi e stati reali dall'inventario
    for node in topo["nodes"]:
        node_id = node["id"]
        # Cerca un IP all'interno del node_id (es. SwitchA-10.0.0.1 -> 10.0.0.1)
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', node_id)
        ip = ip_match.group(1) if ip_match else None
        
        node["group"] = "Discovered"
        node["status"] = "discovered"
        
        if ip:
            device = next((d for d in devices if d['IP'] == ip), None)
            if device:
                node["group"] = device.get("Group", "Generale")
                scan = versions.get(ip, {"status": "offline"})
                node["status"] = scan.get("status", "offline")
                
    # Assicura le chiavi local_port e remote_port per la visualizzazione dei link nella UI
    for link in topo["links"]:
        if "local_port" not in link:
            link["local_port"] = "Vicino"
        if "remote_port" not in link:
            link["remote_port"] = "Vicino"
            
    return topo

# --- ROTTE AUTOMAZIONE & DOWNLOAD ---

@app.post("/api/run-triage")
def run_triage(background_tasks: BackgroundTasks, current_user = Depends(get_current_user)):
    global triage_job
    if triage_job["status"] == "running":
        return {"status": "running", "message": "Scansione già in corso"}
    
    triage_job["status"] = "running"
    triage_job["progress"] = 0
    triage_job["total"] = 0
    triage_job["current_device"] = "Inizializzazione..."
    
    background_tasks.add_task(run_triage_background)
    return {"status": "running", "message": "Scansione avviata in background"}

@app.get("/api/triage-status")
def get_triage_status(current_user = Depends(get_current_user)):
    return triage_job

@app.post("/api/send-command")
def send_command(payload: CommandRequest, current_user = Depends(get_current_user)):
    devices = inventory_manager.get_all_devices()
    target_device = next((d for d in devices if d['IP'] == payload.ip), None)
    if target_device:
        res = core_engine.send_custom_command(target_device, payload.command)
        return res
    raise HTTPException(status_code=404, detail="Dispositivo non presente in inventario")

@app.get("/api/download-backup/{ip_or_filename}")
def download_backup(ip_or_filename: str, current_user = Depends(get_current_user)):
    filepath = os.path.join("backup-config", ip_or_filename)
    if os.path.exists(filepath):
        return FileResponse(filepath, media_type="application/octet-stream", filename=ip_or_filename)
        
    ip = ip_or_filename
    if ip_or_filename.endswith(".txt"):
        for sep in ["_", "-"]:
            parts = ip_or_filename[:-4].split(sep)
            if len(parts) >= 2:
                ip = parts[-1]
                break

    if os.path.exists("backup-config"):
        for f in os.listdir("backup-config"):
            if f.endswith(f"-{ip}.txt") or f.endswith(f"_{ip}.txt") or f == f"{ip}.txt" or f == ip_or_filename:
                target_path = os.path.join("backup-config", f)
                return FileResponse(target_path, media_type="application/octet-stream", filename=f)
                
    raise HTTPException(status_code=404, detail="File di backup non trovato per questo dispositivo.")

# --- PROXY TRASPARENTE VERSO ENISA EUVD ---

@app.api_route("/api/{path:path}", methods=["GET", "POST", "OPTIONS"])
async def proxy_enisa(path: str, request: Request, current_user = Depends(get_current_user)):
    target = f"{BASE_URL}/api/{path}"
    query = request.url.query
    if query:
        target += f"?{query}"
        
    try:
        headers = {"User-Agent": "ThreatIntelDashboard/3.0"}
        method = request.method
        
        if method == "GET":
            from fastapi.concurrency import run_in_threadpool
            r = await run_in_threadpool(requests.get, target, headers=headers, timeout=15)
        elif method == "POST":
            body = await request.body()
            from fastapi.concurrency import run_in_threadpool
            r = await run_in_threadpool(requests.post, target, headers=headers, data=body, timeout=15)
        else:
            return Response(status_code=200)
            
        return Response(
            content=r.content, 
            status_code=r.status_code, 
            headers={"Content-Type": r.headers.get("Content-Type", "application/json")}
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

# --- AVVIO E BROWSER AUTOMATICO ---

def open_browser():
    time.sleep(1.5)
    webbrowser.open(f"http://localhost:{PORT}/")

def main():
    if not os.path.exists("templates"): 
        os.makedirs("templates")
        
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run("app_server_fastapi:app", host="127.0.0.1", port=PORT, log_level="info")

if __name__ == "__main__":
    main()
