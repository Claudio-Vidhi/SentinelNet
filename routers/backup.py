# -*- coding: utf-8 -*-
"""Router Backup. Estratto da app_server.py (fase 6.6)."""

import re
import os
import requests

from fastapi import APIRouter, Depends, HTTPException, Request, status, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel

import data_config
import inventory_manager
from security_manager import log_audit
from routers.deps import get_current_user, require_operator, assert_device_allowed, user_group_scope

router = APIRouter(tags=["Backup"])

BASE_URL = "https://euvdservices.enisa.europa.eu"

ENISA_SEARCH_PARAMS = {
    "fromScore", "toScore", "fromEpss", "toEpss",
    "fromDate", "toDate", "fromUpdatedDate", "toUpdatedDate",
    "product", "vendor", "assigner", "exploited", "text", "page", "size",
}


# --- ENDPOINTS ---

@router.get("/api/download-backup/{ip_or_filename}")
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

    # Radice ASSOLUTA dei backup (stessa usata da core_engine): un percorso
    # relativo alla CWD sarebbe fragile sotto exe/servizio e indebolirebbe il
    # guard anti-traversal.
    backup_dir = os.path.realpath(core_engine.BACKUP_FOLDER)
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

@router.get("/api/search")
async def proxy_enisa_search(request: Request, current_user = Depends(get_current_user)):
    from urllib.parse import parse_qs, urlencode
    raw = parse_qs(request.url.query, keep_blank_values=True)
    # Inoltra solo i parametri documentati dall'API EUVD.
    params = {k: v for k, v in raw.items() if k in ENISA_SEARCH_PARAMS}

    if params.get("vendor"):
        original = params["vendor"][0]
        resolved = inventory_manager.resolve_euvd_term(original)
        if resolved != original:
            log_audit(f"EUVD vendor risolto: '{original}' → '{resolved}'")
        params["vendor"] = [resolved]

    # 'size' è limitato a 100 dalla specifica API: lo vincoliamo a [1, 100].
    if params.get("size"):
        try:
            params["size"] = [str(max(1, min(100, int(params["size"][0]))))]
        except ValueError:
            params.pop("size", None)

    target = f"{BASE_URL}/api/search"
    if params:
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

