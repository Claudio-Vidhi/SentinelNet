# -*- coding: utf-8 -*-
"""Router Backup & Vulnerability Search Proxy (NVD NIST API v2.0)."""

import re
import os
import requests

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse, Response

from core import core_engine, data_config
from services import inventory_manager
from security.security_manager import log_audit
from routers.deps import get_current_user, require_operator, assert_device_allowed, user_group_scope

router = APIRouter(tags=["Backup"])

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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
async def proxy_nvd_search(request: Request, current_user = Depends(get_current_user)):
    from urllib.parse import parse_qs, urlencode
    raw = parse_qs(request.url.query, keep_blank_values=True)

    vendor_val = raw.get("vendor", [""])[0].strip()
    text_val = raw.get("text", [""])[0].strip()
    cve_id = raw.get("cveId", raw.get("cve", [""]))[0].strip()

    resolved_vendor = inventory_manager.resolve_euvd_term(vendor_val) if vendor_val else ""

    nvd_params = {}

    # Map query to NVD API v2.0 parameters
    if cve_id and cve_id.upper().startswith("CVE-"):
        nvd_params["cveId"] = cve_id.upper()
    else:
        keywords = []
        if resolved_vendor:
            keywords.append(resolved_vendor)
        if text_val:
            keywords.append(text_val)
        if keywords:
            nvd_params["keywordSearch"] = " ".join(keywords)

    results_per_page = 40
    if "size" in raw:
        try:
            results_per_page = max(1, min(2000, int(raw["size"][0])))
        except ValueError:
            pass
    nvd_params["resultsPerPage"] = str(results_per_page)

    start_index = 0
    if "page" in raw:
        try:
            page_num = max(1, int(raw["page"][0]))
            start_index = (page_num - 1) * results_per_page
        except ValueError:
            pass
    elif "startIndex" in raw:
        try:
            start_index = max(0, int(raw["startIndex"][0]))
        except ValueError:
            pass
    nvd_params["startIndex"] = str(start_index)

    if "fromScore" in raw:
        try:
            score_num = float(raw["fromScore"][0])
            if score_num >= 9.0:
                nvd_params["cvssV3Severity"] = "CRITICAL"
            elif score_num >= 7.0:
                nvd_params["cvssV3Severity"] = "HIGH"
            elif score_num >= 4.0:
                nvd_params["cvssV3Severity"] = "MEDIUM"
        except ValueError:
            pass

    target_url = f"{NVD_BASE_URL}?{urlencode(nvd_params)}"

    try:
        headers = {"User-Agent": "SentinelNet-NVD-Client/2.0"}
        from fastapi.concurrency import run_in_threadpool
        resp = await run_in_threadpool(requests.get, target_url, headers=headers, timeout=15)

        if resp.status_code != 200:
            return JSONResponse(
                status_code=resp.status_code,
                content={"detail": f"NVD API HTTP {resp.status_code}", "items": [], "total": 0}
            )

        data = resp.json()
        total = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])

        items = []
        for elem in vulnerabilities:
            cve = elem.get("cve", {})
            cid = cve.get("id", "CVE-Unknown")

            descriptions = cve.get("descriptions", [])
            desc_text = "Nessuna descrizione disponibile."
            for d in descriptions:
                if d.get("lang") == "en":
                    desc_text = d.get("value", "")
                    break
            if not desc_text and descriptions:
                desc_text = descriptions[0].get("value", "")

            metrics = cve.get("metrics", {})
            base_score = None
            severity = "MEDIUM"

            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])
            cvss_v40 = metrics.get("cvssMetricV40", [])
            cvss_v2 = metrics.get("cvssMetricV2", [])

            active_metric = cvss_v31 or cvss_v30 or cvss_v40 or cvss_v2
            if active_metric and isinstance(active_metric, list) and len(active_metric) > 0:
                m_obj = active_metric[0]
                cvss_data = m_obj.get("cvssData", {})
                base_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity") or m_obj.get("baseSeverity") or "MEDIUM"

            published = cve.get("published", "")
            cisa_k = bool(cve.get("cisaExploitAdd"))

            refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]

            items.append({
                "id": cid,
                "cve": cid,
                "cveId": cid,
                "euvd": cid,
                "vendor": resolved_vendor or vendor_val or "—",
                "product": text_val or "—",
                "description": desc_text,
                "summary": desc_text,
                "score": base_score,
                "baseScore": base_score,
                "severity": str(severity).upper(),
                "published": published,
                "date": published,
                "exploited": cisa_k,
                "references": refs
            })

        return {"items": items, "total": total}

    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Errore connessione NVD NIST: {str(e)}")
