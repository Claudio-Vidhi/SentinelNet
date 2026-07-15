# -*- coding: utf-8 -*-
"""Router Scan. Estratto da app_server.py (fase 6.6)."""

import threading
import uuid
import time
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel

from security_manager import log_audit
from routers.deps import get_current_user, require_operator, assert_group_allowed
from network_scanner import parse_network, scan_subnet
import core_engine
import inventory_manager

router = APIRouter(tags=["Scan"])

class SubnetScanRequest(BaseModel):
    network: str
    vendor: str = "cisco"
    group: str = "Generale"
    auto_add: bool = False
    use_default_creds: bool = True

_scan_jobs: dict[str, dict] = {}

_scan_jobs_lock = threading.Lock()

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

@router.post("/api/scan-subnet")
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

