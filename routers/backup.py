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
async def proxy_enisa_search(request: Request, current_user = Depends(get_current_user)):
    from urllib.parse import parse_qs, urlencode
    import datetime
    raw = parse_qs(request.url.query, keep_blank_values=True)

    vendor_val = raw.get("vendor", [""])[0].strip()
    text_val = raw.get("text", [""])[0].strip()
    cve_id = raw.get("cveId", raw.get("cve", [""]))[0].strip()
    cve_ids = raw.get("cveIds", [""])[0].strip()
    if not cve_id and text_val.upper().startswith("CVE-"):
        cve_id = text_val.upper()

    resolved_vendor = inventory_manager.resolve_euvd_term(vendor_val) if vendor_val else ""

    nvd_params = {}

    # NIST NVD v2.0 parameters
    if cve_ids:
        nvd_params["cveIds"] = cve_ids
    elif cve_id and cve_id.upper().startswith("CVE-"):
        nvd_params["cveId"] = cve_id.upper()
    elif "cpeName" in raw and raw["cpeName"][0].strip():
        nvd_params["cpeName"] = raw["cpeName"][0].strip()
        if "isVulnerable" in raw and raw["isVulnerable"][0].lower() in ("true", "1", ""):
            nvd_params["isVulnerable"] = ""
    elif "virtualMatchString" in raw and raw["virtualMatchString"][0].strip():
        nvd_params["virtualMatchString"] = raw["virtualMatchString"][0].strip()
    else:
        keywords = []
        if resolved_vendor:
            keywords.append(resolved_vendor)
        if text_val:
            clean_text = re.sub(r'[^\w\s\.\-]', ' ', text_val).strip()
            if clean_text:
                keywords.append(clean_text)
        if keywords:
            nvd_params["keywordSearch"] = " ".join(keywords)
            if "keywordExactMatch" in raw and raw["keywordExactMatch"][0].lower() in ("true", "1", ""):
                nvd_params["keywordExactMatch"] = ""

        # NVD 120-day date window for queries without specific identifiers
        now = datetime.datetime.now(datetime.timezone.utc)
        from_date_str = raw.get("fromDate", raw.get("pubStartDate", [""]))[0].strip()
        to_date_str = raw.get("toDate", raw.get("pubEndDate", [""]))[0].strip()

        start_dt = None
        end_dt = None

        if from_date_str:
            try:
                start_dt = datetime.datetime.fromisoformat(from_date_str).replace(tzinfo=datetime.timezone.utc)
                if to_date_str:
                    end_dt = datetime.datetime.fromisoformat(to_date_str).replace(tzinfo=datetime.timezone.utc)
                else:
                    end_dt = min(start_dt + datetime.timedelta(days=119), now)
            except Exception:
                start_dt = now - datetime.timedelta(days=119)
                end_dt = now
        elif to_date_str:
            try:
                end_dt = datetime.datetime.fromisoformat(to_date_str).replace(tzinfo=datetime.timezone.utc)
                start_dt = end_dt - datetime.timedelta(days=119)
            except Exception:
                start_dt = now - datetime.timedelta(days=119)
                end_dt = now
        else:
            start_dt = now - datetime.timedelta(days=119)
            end_dt = now

        if start_dt and end_dt:
            if (end_dt - start_dt).days > 120:
                end_dt = start_dt + datetime.timedelta(days=119)
            nvd_params["pubStartDate"] = start_dt.strftime("%Y-%m-%dT00:00:00.000")
            nvd_params["pubEndDate"] = end_dt.strftime("%Y-%m-%dT23:59:59.000")

    # Additional NVD v2.0 filter parameters
    if "cweId" in raw and raw["cweId"][0].strip():
        nvd_params["cweId"] = raw["cweId"][0].strip()

    if "vulnStatuses" in raw and raw["vulnStatuses"][0].strip():
        nvd_params["vulnStatuses"] = raw["vulnStatuses"][0].strip()

    if "cveTag" in raw and raw["cveTag"][0].strip():
        nvd_params["cveTag"] = raw["cveTag"][0].strip()

    if "noRejected" in raw and raw["noRejected"][0].lower() in ("true", "1", ""):
        nvd_params["noRejected"] = ""

    if "hasKev" in raw or (raw.get("exploited", [""])[0].lower() in ("true", "1")):
        nvd_params["hasKev"] = ""

    if "hasCertAlerts" in raw and raw["hasCertAlerts"][0].lower() in ("true", "1", ""):
        nvd_params["hasCertAlerts"] = ""

    if "hasCertNotes" in raw and raw["hasCertNotes"][0].lower() in ("true", "1", ""):
        nvd_params["hasCertNotes"] = ""

    # Severity ratings
    severity_param = raw.get("severity", raw.get("cvssV3Severity", [""]))[0].strip().upper()
    if severity_param in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        nvd_params["cvssV3Severity"] = severity_param
    elif "fromScore" in raw:
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

    if "cvssV4Severity" in raw and raw["cvssV4Severity"][0].strip().upper() in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        nvd_params["cvssV4Severity"] = raw["cvssV4Severity"][0].strip().upper()

    # Pagination
    results_per_page = 40
    if "size" in raw or "resultsPerPage" in raw:
        try:
            val_list = raw.get("resultsPerPage") or raw.get("size") or []
            if val_list:
                results_per_page = max(1, min(2000, int(val_list[0])))
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

    target_url = f"{NVD_BASE_URL}?{urlencode(nvd_params)}"

    try:
        headers = {"User-Agent": "SentinelNet-NVD-Client/2.0"}
        nvd_api_key = os.environ.get("NVD_API_KEY", "").strip()
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key

        from fastapi.concurrency import run_in_threadpool
        resp = await run_in_threadpool(requests.get, target_url, headers=headers, timeout=20)

        if resp.status_code != 200:
            return JSONResponse(
                status_code=resp.status_code,
                content={"detail": f"NVD API HTTP {resp.status_code}", "items": [], "total": 0}
            )

        data = resp.json()
        total = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])

        items = []
        cve_ids = []
        for elem in vulnerabilities:
            cve = elem.get("cve", {})
            cid = cve.get("id", "CVE-Unknown")
            cve_ids.append(cid)

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

            extracted_prods = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        crit = cpe_match.get("criteria", "")
                        parts = crit.split(":")
                        if len(parts) >= 5:
                            p = parts[4].replace("_", " ").title()
                            if p and p not in ("*", "-") and p not in extracted_prods:
                                extracted_prods.append(p)

            cwes = []
            for w in cve.get("weaknesses", []):
                for d in w.get("description", []):
                    v = d.get("value", "")
                    if v.startswith("CWE-") and v not in ("CWE-Other", "CWE-noinfo") and v not in cwes:
                        cwes.append(v)
            cwe_str = ", ".join(cwes[:2]) if cwes else ""

            prod_display = ", ".join(extracted_prods[:3]) if extracted_prods else (text_val or "—")

            items.append({
                "id": cid,
                "cve": cid,
                "cveId": cid,
                "euvd": cwe_str or "",
                "cwe": cwe_str or "",
                "vendor": resolved_vendor or vendor_val or "—",
                "product": prod_display,
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

        if cve_ids:
            try:
                epss_url = f"https://api.first.org/data/v1/epss?cve={','.join(cve_ids[:100])}"
                epss_resp = await run_in_threadpool(requests.get, epss_url, timeout=3)
                if epss_resp.status_code == 200:
                    epss_data = epss_resp.json().get("data", [])
                    epss_map = {entry.get("cve"): float(entry.get("epss", 0)) for entry in epss_data if "cve" in entry}
                    for it in items:
                        if it["cve"] in epss_map:
                            it["epss"] = epss_map[it["cve"]]
            except Exception:
                pass

        items.sort(key=lambda x: x.get("published", ""), reverse=True)

        return {"items": items, "total": total}

    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Errore connessione NVD NIST: {str(e)}")
