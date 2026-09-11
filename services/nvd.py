# -*- coding: utf-8 -*-
"""NVD access shared by the live proxy and the persisted CVE snapshot.

The per-CVE normalisation used to live inside the /api/search handler. The
snapshot (services/cve_intel.py) needs the very same fields — the severity
picked out of four metric families, the hardware CPEs, the model verdict — and
a second copy of that logic would be a second answer to "how severe is this
CVE", which is not a question a security tool may answer twice.
"""

import os

from drivers.registry import model_matches

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def headers() -> dict:
    out = {"User-Agent": "SentinelNet-NVD-Client/2.0"}
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        out["apiKey"] = api_key
    return out


def _description(cve: dict) -> str:
    descriptions = cve.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    if descriptions:
        return descriptions[0].get("value", "")
    return "Nessuna descrizione disponibile."


def _severity(cve: dict):
    """(base score, severity label) from whichever CVSS family NVD filled in."""
    metrics = cve.get("metrics", {})
    active_metric = (metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
                     or metrics.get("cvssMetricV40", []) or metrics.get("cvssMetricV2", []))
    if not (active_metric and isinstance(active_metric, list)):
        return None, "MEDIUM"

    primary = next((m for m in active_metric
                    if isinstance(m, dict) and m.get("type") == "Primary"), None)
    m_obj = primary or max(
        active_metric,
        key=lambda m: (m.get("cvssData", {}).get("baseScore", 0) or 0)
        if isinstance(m, dict) else 0)

    cvss_data = m_obj.get("cvssData", {}) if isinstance(m_obj, dict) else {}
    severity = (cvss_data.get("baseSeverity")
                or (m_obj.get("baseSeverity") if isinstance(m_obj, dict) else None)
                or "MEDIUM")
    return cvss_data.get("baseScore"), severity


def _cpe_criteria(cve: dict):
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                yield cpe_match.get("criteria", "")


def normalize_item(cve: dict, model: str = "", vendor_label: str = "",
                   text_label: str = "") -> dict:
    """One NVD vulnerability turned into the shape the UI and the snapshot use."""
    cid = cve.get("id", "CVE-Unknown")
    desc_text = _description(cve)
    base_score, severity = _severity(cve)

    extracted_prods = []
    for aff in cve.get("affected", []):
        for ad in aff.get("affectedData", []):
            p = ad.get("product")
            if p and p not in extracted_prods:
                extracted_prods.append(p)

    hw_models = []
    for crit in _cpe_criteria(cve):
        parts = crit.split(":")
        if len(parts) < 5 or parts[4] in ("*", "-"):
            continue
        p = parts[4].replace("_", " ").title()
        if p not in extracted_prods:
            extracted_prods.append(p)
        if crit.startswith("cpe:2.3:h:") and parts[4] not in hw_models:
            hw_models.append(parts[4])

    # 'generic'  il CVE non nomina hardware: vale per ogni piattaforma
    # 'model'    nomina proprio questo apparato
    # 'other'    nomina altri modelli sullo stesso sistema operativo
    # Mai un filtro: l'elenco hardware di NVD e' incompleto, quindi
    # 'other' scende in fondo con un'etichetta, non viene nascosto.
    if not model or not hw_models:
        model_scope = "generic"
    elif any(model_matches(model, h) for h in hw_models):
        model_scope = "model"
    else:
        model_scope = "other"

    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in ("CWE-Other", "CWE-noinfo") and v not in cwes:
                cwes.append(v)

    published = cve.get("published", "")
    prod_display = ", ".join(extracted_prods[:3]) if extracted_prods else (text_label or "—")

    return {
        "id": cid,
        "cve": cid,
        "cveId": cid,
        "cwe": ", ".join(cwes[:2]) if cwes else "",
        "vendor": vendor_label or "—",
        "product": prod_display,
        "description": desc_text,
        "summary": desc_text,
        "score": base_score,
        "baseScore": base_score,
        "severity": str(severity).upper(),
        "published": published,
        "date": published,
        "exploited": bool(cve.get("cisaExploitAdd")),
        "modelScope": model_scope,
        "cpeHardware": hw_models,
        "references": [r.get("url") for r in cve.get("references", []) if r.get("url")],
    }


def version_of(text: str) -> "str | None":
    """Version to pin the CPE to.

    A parenthesised train comes first: core_engine.extract_version strips
    trailing punctuation, so NX-OS "9.3(5)" comes back as "9.3(5" and the
    CPE built from it matched 11 CVEs instead of 20. That helper is used
    across triage and inventory, so it is left alone and handled here.

    Then extract_version, then a bare dotted release: a model in front of
    the version ("WS-C2960X-24TS-L 15.2(4)E10") must not swallow it.
    """
    import re
    from core import core_engine

    m = re.search(r"\b(\d+\.\d+\(\w[\w.]*\)[a-z0-9]*)", text, re.IGNORECASE)
    if m:
        return m.group(1)
    found = core_engine.extract_version(text)
    if found:
        return found
    m = re.search(r"\b(\d+\.\d+(?:\.\d+)*[a-z0-9]*)", text, re.IGNORECASE)
    return m.group(1) if m else None
