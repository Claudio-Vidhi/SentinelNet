# -*- coding: utf-8 -*-
"""Router Commands. Estratto da app_server.py (fase 6.6)."""

import asyncio
import re
import threading
import time
import secrets as _secrets
import uuid
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks, status
from pydantic import BaseModel, Field
from typing import List, Optional

import paramiko
import inventory_manager
import user_manager
import site_manager
import core_engine
import crypto_vault
from security_manager import log_audit
from app_settings import get_app_settings
from routers.deps import get_current_user, require_operator, assert_device_allowed, assert_group_allowed, user_group_scope

router = APIRouter(tags=["Commands"])

_ws_tokens: dict[str, tuple[str, float]] = {}  # otp -> (username, timestamp)

_bulk_jobs: dict[str, dict] = {}

_bulk_jobs_lock = threading.Lock()

COMMAND_BLACKLIST = [
    r"\breload\b",
    r"\berase\b",
    r"\bdelete\b",
    r"\bformat\b",
    r"\breboot\b",
    r"\bconf\s+t\b",
    r"\bconfigure\s+terminal\b",
    r"\bcopy\s+.*?startup-config\b",
    # Hardening aggiuntivo (denylist): altri comandi distruttivi/di riavvio o di
    # scrittura config sui vari vendor. Restano fuori i comandi 'show/get/display'.
    r"\bwr\b",                       # 'wr', 'wr mem', 'wr erase'
    r"\bwrite\b",                    # 'write memory', 'write erase'
    r"\bboot\s+system\b",
    r"\bfactory[-\s]?reset\b",
    r"\brequest\s+system\b",         # Junos: reboot/halt/zeroize/software
    r"\brollback\b",
    r"\bhalt\b",
    r"\bzeroize\b",
    r"\bclear\s+config\b",
]

BULK_DESTRUCTIVE_BLACKLIST = [
    r"\breload\b",
    r"\breboot\b",
    r"\berase\b",
    r"\bformat\b",
    r"\bwrite\s+erase\b",
]

class CommandRequest(BaseModel):
    ip: str
    command: str

class BulkCommandRequest(BaseModel):
    ips: List[str]
    commands: str
    mode: str = "exec"   # "exec" (show/operational) | "config" (configuration push)
    save: bool = False   # salva la config dopo l'invio (solo mode="config")


# --- ENDPOINTS ---

def is_command_safe(command: str) -> bool:
    """Verifica se il comando contiene stringhe o pattern in blacklist per motivi di sicurezza."""
    cmd_clean = command.strip().lower()
    for pattern in COMMAND_BLACKLIST:
        if re.search(pattern, cmd_clean):
            return False
    return True

def command_allowed(command: str, current_user) -> bool:
    """Applica la blacklist CLI in base al ruolo (audit M-1): gli admin la
    bypassano sempre; gli operatori vi sono soggetti solo se l'impostazione
    'cli_blacklist_operators' è attiva (default: attiva)."""
    if current_user.get("role") == "admin":
        return True
    if not get_app_settings().get("cli_blacklist_operators", True):
        return True
    return is_command_safe(command)

def is_bulk_command_allowed(command: str) -> bool:
    cmd_clean = command.strip().lower()
    return not any(re.search(p, cmd_clean) for p in BULK_DESTRUCTIVE_BLACKLIST)

def _bypass_note(current_user) -> str:
    """Nota per l'audit log quando un comando in blacklist viene comunque consentito."""
    return ("(blacklist bypassata: admin)" if current_user.get("role") == "admin"
            else "(blacklist disattivata per gli operatori)")

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

@router.post("/api/send-command")
def send_command(payload: CommandRequest, current_user = Depends(require_operator)):
    # Validazione blacklist di sicurezza dei comandi CLI (admin: bypass; operatori: da impostazione)
    blacklist_bypass = not is_command_safe(payload.command)
    if not command_allowed(payload.command, current_user):
        log_audit(f"Tentativo bloccato di esecuzione comando non sicuro '{payload.command}' su '{payload.ip}' dall'utente '{current_user.get('sub')}'.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Comando non consentito per motivi di sicurezza (in blacklist)."
        )
    if blacklist_bypass:
        log_audit(f"Comando in blacklist '{payload.command}' consentito su '{payload.ip}' "
                  f"all'utente '{current_user.get('sub')}' {_bypass_note(current_user)}.")

    devices = inventory_manager.get_all_devices()
    target_device = next((d for d in devices if d['IP'] == payload.ip), None)
    if target_device:
        assert_group_allowed(current_user, target_device.get('Group', 'Generale'))
        log_audit(f"Comando CLI '{payload.command}' richiesto su dispositivo '{payload.ip}' dall'utente '{current_user.get('sub')}' (One-Shot API).")
        # Dispositivo di una sede agent: il centrale non lo raggiunge via SSH.
        # Il comando passa dalla coda di relay e si attende (breve) l'esito
        # dell'agente, restituendo la stessa forma della via diretta.
        site = site_manager.get_site(target_device.get('Site') or 'central')
        if site and site.get('mode') == 'agent':
            job = site_manager.enqueue_job(site['id'], payload.ip, payload.command,
                                           requested_by=current_user.get('sub'))
            deadline = time.time() + 90       # l'agente fa polling (default 60s)
            while time.time() < deadline:
                time.sleep(2)
                j = site_manager.get_job(job['id'])
                if j and j['status'] in ('done', 'error'):
                    if j['status'] == 'done':
                        return {"status": "success", "output": j.get('result', '')}
                    return {"status": "error", "message": j.get('result', 'errore agente')}
            return {"status": "queued", "job_id": job['id'],
                    "message": "Comando accodato per la sede agent; esito non ancora "
                               "disponibile (consulta /api/command-jobs/{job_id})."}
        res = core_engine.send_custom_command(target_device, payload.command,
                                              bypass_blacklist=blacklist_bypass)
        return res
    raise HTTPException(status_code=404, detail="Dispositivo non presente in inventario")

@router.post("/api/bulk-command")
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

@router.get("/api/bulk-command/{job_id}")
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

@router.post("/api/ws-token")
def get_ws_token(current_user = Depends(require_operator)):
    """Emette un token OTP monouso valido 30 secondi per aprire un WebSocket."""
    otp = _secrets.token_urlsafe(32)
    _ws_tokens[otp] = (current_user.get("sub"), time.time())
    return {"ws_token": otp}

@router.websocket("/api/ws-terminal/{ip}")
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
                            _cmd = line_buf.strip()
                            _ws_user = {"role": _role, "sub": username_from_otp}
                            if _cmd and not command_allowed(_cmd, _ws_user):
                                # Annulla la riga sullo switch (kill-line) e avvisa
                                chan.send("\x15")
                                await websocket.send_text(
                                    "\r\n[Comando bloccato] Operazione non consentita "
                                    "per motivi di sicurezza (in blacklist).\r\n"
                                )
                                log_audit(
                                    f"Comando da terminale bloccato per blacklist "
                                    f"('{_cmd}') su '{ip}' "
                                    f"dall'utente '{username_from_otp}'."
                                )
                                line_buf = ""
                                continue
                            if _cmd and not is_command_safe(_cmd):
                                log_audit(
                                    f"Comando da terminale in blacklist ('{_cmd}') "
                                    f"consentito su '{ip}' all'utente "
                                    f"'{username_from_otp}' {_bypass_note(_ws_user)}."
                                )
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

