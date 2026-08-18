# -*- coding: utf-8 -*-
"""Router Scan. Estratto da app_server.py (fase 6.6)."""

import ipaddress
import threading
import uuid
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Annotated, Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from security.security_manager import log_audit
from routers.deps import get_current_user, require_operator, user_group_scope
from collectors.network_scanner import parse_network, scan_subnet
from core import core_engine
from security import crypto_vault, identity_manager
from services import site_manager

router = APIRouter(tags=["Scan"])

class SubnetScanRequest(BaseModel):
    network: str
    # Ports are user input and each one costs len(hosts) TCP connects: cap the
    # list, or 254 x 65535 connects are one POST away. Empty = ping-only sweep.
    ports: List[Annotated[int, Field(ge=1, le=65535)]] = Field(
        default_factory=lambda: [22], max_length=16
    )

_scan_jobs: dict[str, dict] = {}

_scan_jobs_lock = threading.Lock()


def _site_for_network(hosts: list[str]):
    """Return the site whose declared subnet contains this scan's targets, or
    None. Uses the first host as a proxy for the whole requested range."""
    if not hosts:
        return None
    addr = ipaddress.ip_address(hosts[0])
    for site in site_manager.list_sites():
        for raw in site.get("subnets") or []:
            try:
                net = ipaddress.ip_network(str(raw).strip(), strict=False)
            except ValueError:
                continue
            if addr in net:
                return site
    return None

def _run_scan_job(job_id: str, req: SubnetScanRequest):
    def _progress(done: int, total: int):
        with _scan_jobs_lock:
            if job_id in _scan_jobs:
                _scan_jobs[job_id]["progress"] = done

    try:
        results = scan_subnet(
            address=req.network,
            ports=req.ports,
            progress_cb=_progress,
        )
        with _scan_jobs_lock:
            _scan_jobs[job_id]["status"]   = "done"
            _scan_jobs[job_id]["results"]  = results
            _scan_jobs[job_id]["progress"] = _scan_jobs[job_id]["total"]
    except Exception as exc:
        with _scan_jobs_lock:
            _scan_jobs[job_id]["status"] = "error"
            _scan_jobs[job_id]["error"]  = str(exc)

@router.post("/api/scan-subnet")
def start_subnet_scan(
    payload: SubnetScanRequest,
    current_user = Depends(require_operator),
):
    try:
        hosts = parse_network(payload.network)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    site = _site_for_network(hosts)
    if site and not site_manager.is_reachable_by_icmp(site["id"]):
        raise HTTPException(status_code=409,
                            detail="Sito jump: la scansione ICMP non e' possibile.")

    job_id = str(uuid.uuid4())
    with _scan_jobs_lock:
        _scan_jobs[job_id] = {
            "status":     "running",
            "results":    [],
            "progress":   0,
            "total":      len(hosts),
            "started_at": time.time(),
        }

    # Thread dedicato, non BackgroundTasks: Starlette esegue i task sincroni
    # nello stesso threadpool (~40 slot) di tutte le rotte sync, e una /24
    # tiene occupato uno slot per l'intera scansione. Stesso schema di
    # start_bulk_command in routers/commands.py.
    threading.Thread(target=_run_scan_job, args=(job_id, payload),
                     daemon=True).start()

    log_audit(
        f"Scansione subnet '{payload.network}' (porte: {payload.ports}) avviata "
        f"dall'utente '{current_user.get('sub')}' (job_id: {job_id}, host totali: {len(hosts)})."
    )
    return {"job_id": job_id, "status": "started", "total_hosts": len(hosts)}

class ScanVerifyRequest(BaseModel):
    # Same IP shape as DeviceSchema (routers/inventory.py:23): these strings are
    # handed to netmiko, they do not get to be arbitrary.
    ips: List[Annotated[str, Field(pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]] = Field(
        min_length=1, max_length=512
    )
    vendor: str
    identity_id: str


def _run_verify_job(job_id: str, req: ScanVerifyRequest, credentials: tuple):
    username, password, secret = credentials
    # probe_device -> get_device_credentials decrypts, so encrypt once here
    # instead of per host.
    enc_password = crypto_vault.encrypt_password(password)
    enc_secret   = crypto_vault.encrypt_password(secret)

    def _verify_one(ip: str) -> dict:
        device = {
            'IP':            ip,
            'Vendor':        req.vendor,
            'Profile':       'custom',
            'Username':      username,
            'Password':      enc_password,
            'Enable Secret': enc_secret,
            'Group':         'Discovered',
        }
        res = core_engine.probe_device(device)
        if res.get('status') != 'success':
            return {"ip": ip, "ok": False, "hostname": None,
                    "error": res.get('message')}
        return {"ip": ip, "ok": True, "hostname": res.get('hostname'), "error": None}

    try:
        rows: list[dict] = []
        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = [pool.submit(_verify_one, ip) for ip in req.ips]
            for fut in as_completed(futures):
                rows.append(fut.result())
                with _scan_jobs_lock:
                    if job_id in _scan_jobs:
                        _scan_jobs[job_id]["progress"] = len(rows)
        order = {ip: i for i, ip in enumerate(req.ips)}
        rows.sort(key=lambda r: order[r["ip"]])
        with _scan_jobs_lock:
            _scan_jobs[job_id]["status"]   = "done"
            _scan_jobs[job_id]["results"]  = rows
            _scan_jobs[job_id]["progress"] = _scan_jobs[job_id]["total"]
    except Exception as exc:
        with _scan_jobs_lock:
            _scan_jobs[job_id]["status"] = "error"
            _scan_jobs[job_id]["error"]  = str(exc)


@router.post("/api/scan-verify")
def start_scan_verify(
    payload: ScanVerifyRequest,
    current_user = Depends(require_operator),
):
    """The only part of a scan that authenticates, and only on the IPs the user
    selected with the identity the user picked."""
    # Visibility BEFORE decryption: without it an operator reads another site's
    # password by guessing an identity id. 404, not 403 — a 403 would confirm
    # that the identity exists.
    if not identity_manager.identity_visible_to(payload.identity_id,
                                                user_group_scope(current_user)):
        raise HTTPException(status_code=404, detail="Identita' non trovata.")

    credentials = identity_manager.get_identity_credentials(payload.identity_id)
    if credentials is None:
        raise HTTPException(status_code=404, detail="Identita' non trovata.")

    job_id = str(uuid.uuid4())
    with _scan_jobs_lock:
        _scan_jobs[job_id] = {
            "status":     "running",
            "results":    [],
            "progress":   0,
            "total":      len(payload.ips),
            "started_at": time.time(),
        }

    threading.Thread(target=_run_verify_job,
                     args=(job_id, payload, credentials), daemon=True).start()

    # This is the operation that generates authentication attempts on the
    # customer network: it gets an audit line.
    log_audit(
        f"Verifica credenziali su {len(payload.ips)} host avviata dall'utente "
        f"'{current_user.get('sub')}' (identita': {payload.identity_id}, "
        f"vendor: '{payload.vendor}', job_id: {job_id})."
    )
    return {"job_id": job_id, "status": "started", "total_hosts": len(payload.ips)}

@router.get("/api/scan-subnet/{job_id}")
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

