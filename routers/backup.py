# -*- coding: utf-8 -*-
"""Router Backup & Vulnerability Search Proxy (NVD NIST API v2.0)."""

import logging
import re
import os
import requests

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse, Response

from core import core_engine, data_config
from drivers.registry import model_matches
from services import inventory_manager
from security.security_manager import log_audit
from routers.deps import get_current_user, require_operator, assert_device_allowed, user_group_scope

router = APIRouter(tags=["Backup"])

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

log = logging.getLogger("sentinelnet.nvd")


def cpe_from_device(vendor: str, text: str) -> "str | None":
    """CPE match string for what the Threat Intel tab knows about a device.

    `text` is whatever the tab collected (an SNMP sysDescr, a model plus a
    version): the version is extracted from it, and a vendor with no CPE
    identity yields None so the caller keeps the keyword path.
    """
    from drivers.registry import cpe_match_string
    version = _version_of(text or "")
    if not vendor or not version:
        # Senza versione il CPE renderebbe OGNI CVE mai emesso per il prodotto:
        # per la Vulnerability Watch (che interroga per solo vendor) sarebbe un
        # peggioramento, non una correzione. In quel caso resta la keyword.
        return None
    return cpe_match_string(vendor, version, text or "")


def _version_of(text: str) -> "str | None":
    """Version to pin the CPE to.

    A parenthesised train comes first: core_engine.extract_version strips
    trailing punctuation, so NX-OS "9.3(5)" comes back as "9.3(5" and the
    CPE built from it matched 11 CVEs instead of 20. That helper is used
    across triage and inventory, so it is left alone and handled here.

    Then extract_version, then a bare dotted release: a model in front of
    the version ("WS-C2960X-24TS-L 15.2(4)E10") must not swallow it.
    """
    m = re.search(r"\b(\d+\.\d+\(\w[\w.]*\)[a-z0-9]*)",
                  text, re.IGNORECASE)
    if m:
        return m.group(1)
    found = core_engine.extract_version(text)
    if found:
        return found
    m = re.search(r"\b(\d+\.\d+(?:\.\d+)*[a-z0-9]*)", text, re.IGNORECASE)
    return m.group(1) if m else None


# --- ENDPOINTS ---

@router.get("/api/download-backup/{ip_or_filename}")
def download_backup(ip_or_filename: str, current_user = Depends(require_operator)):
    log_audit(f"Download del file di backup '{ip_or_filename}' richiesto dall'utente '{current_user.get('sub')}'.")

    # Scoping: ricava l'IP dal nome richiesto e verifica la sede del dispositivo.
    scope = user_group_scope(current_user)
    if scope is not None:
        # EVERY IP in the requested name must be in scope, not just the first.
        # The lookup below derives its own IP from the LAST '-'/'_' token, so
        # checking only the first let "<own-ip>-<their-ip>.txt" pass the check
        # on one device and fetch the backup of another.
        found = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip_or_filename)
        devices = inventory_manager.get_all_devices()
        for ip_guess in (found or [ip_or_filename]):
            dev = next((d for d in devices if d['IP'] == ip_guess), None)
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
    model_val = raw.get("model", [""])[0].strip()
    text_val = raw.get("text", [""])[0].strip()
    cve_id = raw.get("cveId", raw.get("cve", [""]))[0].strip()
    cve_ids = raw.get("cveIds", [""])[0].strip()
    if not cve_id and text_val.upper().startswith("CVE-"):
        cve_id = text_val.upper()

    resolved_vendor = inventory_manager.resolve_euvd_term(vendor_val) if vendor_val else ""

    nvd_params = {}
    cpe_window = False   # True quando la query e' un CPE dedotto dal dispositivo

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
    elif cpe_from_device(vendor_val, text_val):
        # CPE first. keywordSearch is an AND over the words of the CVE
        # DESCRIPTION, so every version token added to it removes results:
        # "cisco IOS" matches 1176 CVEs, "cisco IOS Version 15.2 4 E10"
        # matches zero. A device knows its vendor and its version, which is
        # exactly the match NVD answers version-aware, through the CPE API.
        # isVulnerable NON si usa qui: NVD lo accetta solo insieme a
        # cpeName, e con virtualMatchString risponde HTTP 404 — che il
        # chiamante leggerebbe come "nessuna vulnerabilita".
        match = cpe_from_device(vendor_val, text_val) or ""
        nvd_params["virtualMatchString"] = match
        # NVD non ordina: rende le prime N per id CVE. Chiedendone 3 si
        # ottengono le tre PIU' VECCHIE (CVE del 1999 per un apparato di
        # oggi). Si prende una finestra piu' ampia e si ordina qui sotto;
        # il totale vero resta quello dichiarato da NVD.
        cpe_window = True
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
    if cpe_window:
        results_per_page = max(results_per_page, 50)
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
    # The query IS the diagnosis when the matcher answers "nothing found":
    # without it there is no telling an unaffected device from a query that
    # could never have matched.
    log.info("NVD query: vendor=%r text=%r -> %s", vendor_val, text_val,
             nvd_params)

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

        # Zero CVE su una versione precisa ha due significati opposti: la
        # versione e' pulita, oppure NVD non la conosce (release nuova, treno
        # non catalogato, prodotto sbagliato). Senza distinguerli la scheda
        # direbbe "nessuna vulnerabilita" anche nel secondo caso, che e' il
        # modo peggiore di sbagliare per uno strumento di sicurezza.
        version_unknown = False
        if not total and cpe_window and ":" in nvd_params.get("virtualMatchString", ""):
            unversioned = nvd_params["virtualMatchString"].rsplit(":", 1)[0]
            probe = await run_in_threadpool(
                requests.get,
                f"{NVD_BASE_URL}?{urlencode({'virtualMatchString': unversioned, 'resultsPerPage': '1'})}",
                headers=headers, timeout=20)
            if probe.status_code == 200 and probe.json().get("totalResults", 0) > 0:
                version_unknown = True
                log.warning("NVD non conosce la versione richiesta: %s "
                            "(il prodotto esiste, la versione no)",
                            nvd_params["virtualMatchString"])

        # If date window produced fewer than 5 results and user didn't specify strict dates,
        # fetch the most recent slice across all time using startIndex
        if len(vulnerabilities) < 5 and "pubStartDate" in nvd_params and not raw.get("fromDate") and not raw.get("toDate"):
            fallback_params = dict(nvd_params)
            fallback_params.pop("pubStartDate", None)
            fallback_params.pop("pubEndDate", None)
            fallback_params["resultsPerPage"] = "1"
            fallback_params["startIndex"] = "0"
            r0_url = f"{NVD_BASE_URL}?{urlencode(fallback_params)}"
            r0_resp = await run_in_threadpool(requests.get, r0_url, headers=headers, timeout=20)
            if r0_resp.status_code == 200:
                tot_count = r0_resp.json().get("totalResults", 0)
                if tot_count > 0:
                    fallback_params["resultsPerPage"] = str(results_per_page)
                    fallback_params["startIndex"] = str(max(0, tot_count - results_per_page))
                    fb_url = f"{NVD_BASE_URL}?{urlencode(fallback_params)}"
                    fb_resp = await run_in_threadpool(requests.get, fb_url, headers=headers, timeout=20)
                    if fb_resp.status_code == 200:
                        fb_data = fb_resp.json()
                        total = fb_data.get("totalResults", 0)
                        vulnerabilities = fb_data.get("vulnerabilities", [])

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
                primary = next((m for m in active_metric if isinstance(m, dict) and m.get("type") == "Primary"), None)
                if primary:
                    m_obj = primary
                else:
                    m_obj = max(active_metric, key=lambda m: (m.get("cvssData", {}).get("baseScore", 0) or 0) if isinstance(m, dict) else 0)

                cvss_data = m_obj.get("cvssData", {}) if isinstance(m_obj, dict) else {}
                base_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity") or (m_obj.get("baseSeverity") if isinstance(m_obj, dict) else None) or "MEDIUM"

            published = cve.get("published", "")
            cisa_k = bool(cve.get("cisaExploitAdd"))

            refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]

            extracted_prods = []
            for aff in cve.get("affected", []):
                for ad in aff.get("affectedData", []):
                    p = ad.get("product")
                    if p and p not in extracted_prods:
                        extracted_prods.append(p)

            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        crit = cpe_match.get("criteria", "")
                        parts = crit.split(":")
                        if len(parts) >= 5:
                            p = parts[4].replace("_", " ").title()
                            if p and p not in ("*", "-") and p not in extracted_prods:
                                extracted_prods.append(p)

            # Modelli hardware citati dal CVE: 'cpe:2.3:h:cisco:catalyst_9200'.
            hw_models = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        crit = cpe_match.get("criteria", "")
                        if crit.startswith("cpe:2.3:h:"):
                            parts = crit.split(":")
                            if len(parts) >= 5 and parts[4] not in ("*", "-"):
                                hw_models.append(parts[4])

            # 'generic'  il CVE non nomina hardware: vale per ogni piattaforma
            # 'model'    nomina proprio questo apparato
            # 'other'    nomina altri modelli sullo stesso sistema operativo
            # Mai un filtro: l'elenco hardware di NVD e' incompleto, quindi
            # 'other' scende in fondo con un'etichetta, non viene nascosto.
            if not model_val or not hw_models:
                model_scope = "generic"
            elif any(model_matches(model_val, h) for h in hw_models):
                model_scope = "model"
            else:
                model_scope = "other"

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
                "modelScope": model_scope,
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

        # Chi apre la scheda di un apparato vuole sapere quanto e' esposto:
        # prima i CVE gia' sfruttati (CISA KEV), poi il punteggio, poi la data.
        # Prima l'ordine era solo per data e i primi tre erano i piu' vecchi.
        # Gravita' prima del modello, non dopo: l'elenco hardware di NVD e'
        # incompleto, e ordinando per modello un CVE 9.8 attribuito ad altre
        # piattaforme usciva dalle tre schede mostrate. Una euristica non deve
        # mai seppellire il ritrovamento piu' grave; il modello scioglie i
        # pari merito e l'etichetta "altro modello" lascia giudicare a chi legge.
        _scope_rank = {"model": 2, "generic": 1, "other": 0}
        items.sort(key=lambda x: (bool(x.get("exploited")),
                                  x.get("score") or 0,
                                  _scope_rank.get(x.get("modelScope"), 1),
                                  x.get("published") or ""), reverse=True)

        return {"items": items, "total": total,
                "query": nvd_params.get("virtualMatchString")
                         or nvd_params.get("keywordSearch"),
                "versionUnknown": version_unknown}

    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Errore connessione NVD NIST: {str(e)}")
