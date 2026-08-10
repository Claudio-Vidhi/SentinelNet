# -*- coding: utf-8 -*-
"""Router Scan. Estratto da app_server.py (fase 6.6)."""

import threading
import uuid
import time
from typing import Annotated, Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from security.security_manager import log_audit
from routers.deps import get_current_user, require_operator
from collectors.network_scanner import parse_network, scan_subnet

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

