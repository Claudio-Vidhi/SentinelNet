# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""OT Vulnerability Intelligence, CISA KEV / ICS Advisories, and Air-Gap Mode.

Implements §4 of the SentinelNet OT expansion:
- Persistent local CISA KEV + CISA ICS Advisories catalog.
- Offline/air-gapped NVD query cache and outbound network kill-switch.
- Signed offline bundle export & verified import (Ed25519 + SHA-256) for
  air-gapped instances.
- Asset process criticality and planned maintenance window metadata.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core import app_settings, data_config

log = logging.getLogger("sentinelnet.ot_vuln")

# Public CISA feed endpoints (official paths).
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"  # check-site-name: ok
CISA_ICS_URL = "https://www.cisa.gov/sites/default/files/feeds/ics-advisories.json"  # check-site-name: ok

PROCESS_CRITICALITY_LEVELS = ("", "hot_patchable", "scheduled_shutdown", "mission_critical")
MAX_MAINTENANCE_WINDOW_LEN = 128

BUNDLE_FORMAT = "sentinelnet-ot-vuln-bundle"
BUNDLE_VERSION = 1
_SIGN_PREFIX = b"sentinelnet-ot-vuln-v1|"

_FEEDS_FILE = "ot_vuln_feeds.json"
_SIGNING_KEY_FILE = "ot_bundle_signing_key.pem"
_TRUSTED_KEYS_FILE = "ot_trusted_keys.json"

_lock = threading.RLock()
# In-process read cache keyed by (path, inode, mtime_ns, size)
_feeds_mem_cache: tuple[Optional[tuple[str, int, int, int]], dict] = (None, {})
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class BundleVerificationError(ValueError):
    """Raised when an offline bundle fails structural, hash, trust, or signature checks."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- Asset process criticality & maintenance windows -------------------------


def normalize_process_criticality(value: Any) -> str:
    """Validate and normalize asset process criticality level."""
    val = ("" if value is None else str(value)).strip().lower()
    if val not in PROCESS_CRITICALITY_LEVELS:
        raise ValueError(
            f"Criticita' processo non valida: '{value}'. "
            f"Valori ammessi: {', '.join(v or '(nessuna)' for v in PROCESS_CRITICALITY_LEVELS)}."
        )
    return val


def normalize_maintenance_window(value: Any) -> str:
    """Validate and normalize planned maintenance window label."""
    val = ("" if value is None else str(value)).strip()
    if len(val) > MAX_MAINTENANCE_WINDOW_LEN:
        raise ValueError(
            f"Finestra di manutenzione troppo lunga (max {MAX_MAINTENANCE_WINDOW_LEN} caratteri)."
        )
    return val


def asset_patch_posture(device: Optional[dict]) -> dict[str, Any]:
    """Return normalized patching posture for a device dictionary."""
    if not isinstance(device, dict):
        return {
            "process_criticality": "",
            "maintenance_window": "",
            "maintenance_deferrable": False,
            "patch_posture": "unset",
        }
    crit = (device.get("Process Criticality") or device.get("process_criticality") or "").strip().lower()
    if crit not in PROCESS_CRITICALITY_LEVELS:
        crit = ""
    window = (device.get("Maintenance Window") or device.get("maintenance_window") or "").strip()
    deferrable = crit in ("scheduled_shutdown", "mission_critical")
    if crit == "hot_patchable":
        posture = "hot_patchable"
    elif deferrable:
        posture = "defer_to_window"
    else:
        posture = "unset"
    return {
        "process_criticality": crit,
        "maintenance_window": window,
        "maintenance_deferrable": deferrable,
        "patch_posture": posture,
    }


# --- Air-gap mode ------------------------------------------------------------


def is_airgap_mode() -> bool:
    """True when outbound NVD/CISA/EPSS queries are disabled (air-gapped plant)."""
    env_val = os.environ.get("SENTINELNET_AIRGAP_MODE")
    if env_val is not None and env_val.strip() != "":
        return env_val.strip().lower() in ("1", "true", "yes", "on")
    settings = app_settings.get_app_settings()
    app_sec = settings.get("app") if isinstance(settings.get("app"), dict) else {}
    if "airgap_mode" in settings:
        return bool(settings.get("airgap_mode"))
    return bool(app_sec.get("airgap_mode", False))


def set_airgap_mode(enabled: bool) -> bool:
    """Persist air-gap mode toggle into app_settings.json."""
    val = bool(enabled)
    app_settings.save_app_settings({"airgap_mode": val})
    return val


# --- Feed store persistence --------------------------------------------------


def _empty_feeds() -> dict[str, Any]:
    return {
        "version": 1,
        "kev_updated_at": "",
        "kev": {},
        "ics_updated_at": "",
        "ics_advisories": [],
        "nvd_cache": {},
    }


def _feeds_path() -> str:
    return data_config.get_path(_FEEDS_FILE)


def _file_sig(path: str) -> Optional[tuple[str, int, int, int]]:
    try:
        st = os.stat(path)
        return (path, st.st_ino, st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def _read_feeds() -> dict[str, Any]:
    global _feeds_mem_cache
    path = _feeds_path()
    with _lock:
        sig = _file_sig(path)
        if sig is not None and _feeds_mem_cache[0] == sig:
            return _feeds_mem_cache[1]
        data = _empty_feeds()
        try:
            with open(path, encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                data["kev_updated_at"] = str(loaded.get("kev_updated_at") or "")
                if isinstance(loaded.get("kev"), dict):
                    data["kev"] = loaded["kev"]
                data["ics_updated_at"] = str(loaded.get("ics_updated_at") or "")
                if isinstance(loaded.get("ics_advisories"), list):
                    data["ics_advisories"] = loaded["ics_advisories"]
                if isinstance(loaded.get("nvd_cache"), dict):
                    data["nvd_cache"] = loaded["nvd_cache"]
        except (OSError, ValueError):
            pass
        _feeds_mem_cache = (sig, data)
        return data


def _write_feeds(data: dict[str, Any]) -> None:
    global _feeds_mem_cache
    path = _feeds_path()
    with _lock:
        data_config.atomic_write(path, data)
        _feeds_mem_cache = (_file_sig(path), data)


def invalidate_cache() -> None:
    """Clear in-process feed cache (mainly for tests switching DATA_DIR)."""
    global _feeds_mem_cache
    with _lock:
        _feeds_mem_cache = (None, {})


# --- CISA KEV & ICS Advisories ingestion & queries ---------------------------


def _parse_kev_payload(raw: Any) -> dict[str, dict[str, Any]]:
    if isinstance(raw, dict):
        items = raw.get("vulnerabilities")
        if items is None and all(isinstance(k, str) and k.upper().startswith("CVE-") for k in raw):
            items = list(raw.values())
    elif isinstance(raw, list):
        items = raw
    else:
        items = []

    out: dict[str, dict[str, Any]] = {}
    for entry in items or []:
        if not isinstance(entry, dict):
            continue
        cid = str(entry.get("cveID") or entry.get("cve_id") or entry.get("cve") or "").strip().upper()
        if not cid.startswith("CVE-"):
            continue
        out[cid] = {
            "cve_id": cid,
            "vendor": str(entry.get("vendorProject") or entry.get("vendor") or "").strip(),
            "product": str(entry.get("product") or "").strip(),
            "vulnerability_name": str(entry.get("vulnerabilityName") or entry.get("vulnerability_name") or "").strip(),
            "date_added": str(entry.get("dateAdded") or entry.get("date_added") or "").strip(),
            "due_date": str(entry.get("dueDate") or entry.get("due_date") or "").strip(),
            "required_action": str(entry.get("requiredAction") or entry.get("required_action") or "").strip(),
            "known_ransomware": str(
                entry.get("knownRansomwareCampaignUse") or entry.get("known_ransomware") or ""
            ).strip(),
        }
    return out


def _normalize_advisory(entry: dict[str, Any]) -> Optional[dict[str, Any]]:
    if not isinstance(entry, dict):
        return None
    # Support both normalized/CISA-JSON entries and CSAF document objects.
    doc = entry.get("document") if isinstance(entry.get("document"), dict) else None
    if doc:
        tracking = doc.get("tracking") if isinstance(doc.get("tracking"), dict) else {}
        adv_id = str(tracking.get("id") or entry.get("id") or "").strip()
        title = str(doc.get("title") or entry.get("title") or adv_id).strip()
        published = str(tracking.get("initial_release_date") or tracking.get("current_release_date") or "").strip()
        notes = doc.get("notes") if isinstance(doc.get("notes"), list) else []
        summary = " ".join(str(n.get("text") or "") for n in notes if isinstance(n, dict)).strip()
        cves = sorted({
            str(v.get("cve") or "").strip().upper()
            for v in (entry.get("vulnerabilities") or [])
            if isinstance(v, dict) and str(v.get("cve") or "").strip().upper().startswith("CVE-")
        })
        vendor = str(entry.get("vendor") or (doc.get("publisher") or {}).get("name") or "").strip()
        product = str(entry.get("product") or "").strip()
        url = str(entry.get("url") or "").strip()
        cvss = entry.get("cvss")
    else:
        adv_id = str(
            entry.get("id") or entry.get("advisory_id") or entry.get("icsa_id") or entry.get("code") or ""
        ).strip()
        title = str(entry.get("title") or entry.get("name") or adv_id).strip()
        vendor = str(entry.get("vendor") or entry.get("vendor_name") or "").strip()
        product = str(entry.get("product") or entry.get("products") or "").strip()
        published = str(entry.get("published") or entry.get("release_date") or entry.get("date") or "").strip()
        url = str(entry.get("url") or entry.get("link") or "").strip()
        summary = str(entry.get("summary") or entry.get("description") or "").strip()
        cvss = entry.get("cvss")
        raw_cves = entry.get("cves") or entry.get("cve") or []
        if isinstance(raw_cves, str):
            found = _CVE_RE.findall(raw_cves)
        elif isinstance(raw_cves, list):
            found = [str(c).strip().upper() for c in raw_cves if str(c).strip()]
        else:
            found = []
        if not found:
            found = _CVE_RE.findall(f"{title} {summary}")
        cves = sorted({c.upper() for c in found if c.upper().startswith("CVE-")})

    if not adv_id:
        return None
    try:
        cvss_num = float(cvss) if cvss not in (None, "") else None
    except (TypeError, ValueError):
        cvss_num = None
    return {
        "id": adv_id,
        "title": title[:300],
        "vendor": vendor[:120],
        "product": product[:200],
        "cves": cves,
        "published": published[:40],
        "cvss": cvss_num,
        "url": url[:500],
        "summary": summary[:1000],
    }


def _parse_ics_payload(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        if "document" in raw:
            items = [raw]
        else:
            items = raw.get("advisories") or raw.get("ics_advisories") or raw.get("items") or []
    elif isinstance(raw, list):
        items = raw
    else:
        items = []

    by_id: dict[str, dict[str, Any]] = {}
    for entry in items:
        norm = _normalize_advisory(entry)
        if norm:
            by_id[norm["id"]] = norm
    return sorted(by_id.values(), key=lambda a: (a.get("published") or "", a["id"]), reverse=True)


def ingest_kev_catalog(raw: Any, updated_at: Optional[str] = None) -> int:
    """Merge a parsed CISA KEV catalog into the local feed store."""
    parsed = _parse_kev_payload(raw)
    with _lock:
        data = dict(_read_feeds())
        kev = dict(data.get("kev") or {})
        kev.update(parsed)
        data["kev"] = kev
        data["kev_updated_at"] = updated_at or _now_iso()
        _write_feeds(data)
    return len(parsed)


def ingest_ics_advisories(raw: Any, updated_at: Optional[str] = None) -> int:
    """Merge CISA ICS advisories into the local feed store."""
    parsed = _parse_ics_payload(raw)
    with _lock:
        data = dict(_read_feeds())
        by_id = {
            str(a.get("id")): a
            for a in (data.get("ics_advisories") or [])
            if isinstance(a, dict) and a.get("id")
        }
        for adv in parsed:
            by_id[adv["id"]] = adv
        data["ics_advisories"] = sorted(
            by_id.values(),
            key=lambda a: (a.get("published") or "", a.get("id") or ""),
            reverse=True,
        )
        data["ics_updated_at"] = updated_at or _now_iso()
        _write_feeds(data)
    return len(parsed)


def sync_online_feeds(fetch_kev: bool = True, fetch_ics: bool = True, timeout: int = 20) -> dict[str, Any]:
    """Fetch CISA KEV and CISA ICS Advisories feeds when online."""
    if is_airgap_mode():
        raise RuntimeError("Modalita' air-gap attiva: sincronizzazione online disabilitata.")
    headers = {"User-Agent": "SentinelNet-OT-Intel/1.0"}
    kev_added = 0
    ics_added = 0
    if fetch_kev:
        r_kev = requests.get(CISA_KEV_URL, headers=headers, timeout=timeout)
        r_kev.raise_for_status()
        kev_added = ingest_kev_catalog(r_kev.json())
    if fetch_ics:
        r_ics = requests.get(CISA_ICS_URL, headers=headers, timeout=timeout)
        r_ics.raise_for_status()
        ics_added = ingest_ics_advisories(r_ics.json())
    feeds = _read_feeds()
    return {
        "kev_fetched": kev_added,
        "ics_fetched": ics_added,
        "kev_count": len(feeds.get("kev") or {}),
        "ics_count": len(feeds.get("ics_advisories") or []),
        "kev_updated_at": feeds.get("kev_updated_at") or "",
        "ics_updated_at": feeds.get("ics_updated_at") or "",
    }


def lookup_kev(cve_id: str) -> Optional[dict[str, Any]]:
    """Return CISA KEV entry for a CVE ID if present in local catalog."""
    cid = (cve_id or "").strip().upper()
    if not cid:
        return None
    kev = _read_feeds().get("kev") or {}
    entry = kev.get(cid)
    return dict(entry) if isinstance(entry, dict) else None


def advisories_for_cve(cve_id: str) -> list[dict[str, Any]]:
    """Return CISA ICS Advisories referencing a given CVE ID."""
    cid = (cve_id or "").strip().upper()
    if not cid:
        return []
    out: list[dict[str, Any]] = []
    for adv in _read_feeds().get("ics_advisories") or []:
        if not isinstance(adv, dict):
            continue
        if cid in (adv.get("cves") or []):
            out.append({
                "id": adv.get("id", ""),
                "title": adv.get("title", ""),
                "vendor": adv.get("vendor", ""),
                "product": adv.get("product", ""),
                "published": adv.get("published", ""),
                "cvss": adv.get("cvss"),
                "url": adv.get("url", ""),
            })
    return out


def advisories_for_device(
    device: dict,
    detected_entry: Optional[dict] = None,
    cve_ids: Optional[list[str]] = None,
) -> list[dict[str, Any]]:
    """Match ICS advisories relevant to an OT device by CVE or vendor/model."""
    from services import inventory_manager

    raw_vendor = str(device.get("Vendor") or "").strip().lower()
    mapped_vendor = (inventory_manager.resolve_euvd_term(raw_vendor) or raw_vendor).lower()
    vendor_terms = {t for t in (raw_vendor, mapped_vendor) if len(t) >= 3}

    entry = detected_entry if isinstance(detected_entry, dict) else {}
    model_str = str(device.get("Model") or entry.get("model") or "").strip().lower()
    ver_str = str(device.get("Version") or entry.get("version") or "").strip().lower()
    hay_tokens = {
        tok
        for tok in re.split(r"[^a-z0-9]+", f"{model_str} {ver_str}")
        if len(tok) >= 3 and tok not in ("non", "rilevato", "rilevata", "unknown", "scansionato")
    }
    cve_set = {str(c).strip().upper() for c in (cve_ids or []) if c}

    matched: list[dict[str, Any]] = []
    for adv in _read_feeds().get("ics_advisories") or []:
        if not isinstance(adv, dict):
            continue
        adv_cves = {str(c).upper() for c in (adv.get("cves") or [])}
        if cve_set and (adv_cves & cve_set):
            matched.append(adv)
            continue
        adv_hay = f"{adv.get('vendor', '')} {adv.get('product', '')} {adv.get('title', '')}".lower()
        if vendor_terms and any(vt in adv_hay for vt in vendor_terms):
            if not hay_tokens or any(ht in adv_hay for ht in hay_tokens):
                matched.append(adv)
    return matched


def list_ics_advisories(
    vendor: str = "",
    cve: str = "",
    q: str = "",
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Filter locally stored CISA ICS Advisories for API & Threat Intel UI."""
    v_q = (vendor or "").strip().lower()
    c_q = (cve or "").strip().upper()
    text_q = (q or "").strip().lower()
    cap = max(1, min(1000, int(limit)))
    out: list[dict[str, Any]] = []
    for adv in _read_feeds().get("ics_advisories") or []:
        if not isinstance(adv, dict):
            continue
        if v_q and v_q not in (adv.get("vendor") or "").lower() and v_q not in (adv.get("product") or "").lower():
            continue
        if c_q and c_q not in [str(x).upper() for x in (adv.get("cves") or [])]:
            continue
        if text_q:
            hay = f"{adv.get('id', '')} {adv.get('title', '')} {adv.get('vendor', '')} {adv.get('product', '')} {adv.get('summary', '')}".lower()
            if text_q not in hay:
                continue
        out.append(adv)
        if len(out) >= cap:
            break
    return out


# --- Persistent NVD offline cache --------------------------------------------


def _nvd_cache_key(params: dict) -> str:
    if not isinstance(params, dict):
        return ""
    for k in ("virtualMatchString", "keywordSearch", "cveId"):
        v = params.get(k)
        if v:
            return f"{k.lower()}={str(v).strip().lower()}"
    return ""


def record_nvd_response(params: dict, data: dict) -> None:
    """Persist an NVD 2.0 response into the local offline store for air-gap reuse."""
    key = _nvd_cache_key(params)
    if not key or not isinstance(data, dict):
        return
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return
    # Skip recording tiny resultsPerPage=1 metadata probes when they carry no CVEs unless empty total=0
    total = int(data.get("totalResults") or 0)
    if str(params.get("resultsPerPage", "")) == "1" and total > 1:
        return
    with _lock:
        feeds = dict(_read_feeds())
        cache = dict(feeds.get("nvd_cache") or {})
        raw_existing = cache.get(key)
        existing: dict[str, Any] = raw_existing if isinstance(raw_existing, dict) else {}
        raw_vulns = existing.get("vulnerabilities")
        existing_vulns = raw_vulns if isinstance(raw_vulns, list) else []
        by_cid: dict[str, dict] = {}
        for elem in existing_vulns + vulns:
            if not isinstance(elem, dict):
                continue
            cid = str((elem.get("cve") or {}).get("id") or "")
            if cid:
                by_cid[cid] = elem
        merged_list = list(by_cid.values())
        cache[key] = {
            "updated_at": _now_iso(),
            "totalResults": max(total, len(merged_list)),
            "vulnerabilities": merged_list,
        }
        feeds["nvd_cache"] = cache
        _write_feeds(feeds)


def _filter_cached_vulns(vulns: list[dict], params: dict) -> list[dict]:
    sev_v3 = str(params.get("cvssV3Severity") or "").strip().upper()
    sev_v4 = str(params.get("cvssV4Severity") or "").strip().upper()
    pub_start = str(params.get("pubStartDate") or "").strip()
    pub_end = str(params.get("pubEndDate") or "").strip()
    filtered: list[dict] = []
    for elem in vulns:
        if not isinstance(elem, dict):
            continue
        cve = elem.get("cve") or {}
        if pub_start or pub_end:
            pub = str(cve.get("published") or "")
            if pub_start and pub and pub < pub_start[:10]:
                continue
            if pub_end and pub and pub[:10] > pub_end[:10]:
                continue
        if sev_v3 or sev_v4:
            metrics = cve.get("metrics") or {}
            m_list = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
                      or metrics.get("cvssMetricV40") or [])
            sevs = {
                str((m.get("cvssData") or {}).get("baseSeverity") or m.get("baseSeverity") or "").upper()
                for m in m_list if isinstance(m, dict)
            }
            want = sev_v3 or sev_v4
            if want and sevs and want not in sevs:
                continue
        filtered.append(elem)
    return filtered


def lookup_nvd_response(params: dict) -> Optional[dict]:
    """Look up NVD results from the persistent offline cache."""
    key = _nvd_cache_key(params)
    if not key:
        return None
    cache = _read_feeds().get("nvd_cache") or {}
    entry = cache.get(key)
    # Fallback for unversioned CPE probe or prefix match in offline bundles
    if not isinstance(entry, dict) and key.startswith("virtualmatchstring="):
        target = key.split("=", 1)[1]
        for k, cand in cache.items():
            if not k.startswith("virtualmatchstring=") or not isinstance(cand, dict):
                continue
            cand_cpe = k.split("=", 1)[1]
            if cand_cpe.startswith(target + ":") or target.startswith(cand_cpe + ":"):
                entry = cand
                break
    if not isinstance(entry, dict):
        return None

    vulns = _filter_cached_vulns(entry.get("vulnerabilities") or [], params)
    total = max(int(entry.get("totalResults") or 0), len(vulns)) if (
        not params.get("cvssV3Severity") and not params.get("pubStartDate")
    ) else len(vulns)
    try:
        rpp = max(1, min(2000, int(params.get("resultsPerPage") or 200)))
    except (TypeError, ValueError):
        rpp = 200
    try:
        start = max(0, int(params.get("startIndex") or 0))
    except (TypeError, ValueError):
        start = 0
    return {
        "totalResults": total,
        "vulnerabilities": vulns[start:start + rpp],
        "offline": True,
    }


# --- Signed Air-Gap Bundle Export / Import (Ed25519 + SHA-256) ---------------


def _signing_key_path() -> str:
    return data_config.get_path(_SIGNING_KEY_FILE)


def _trusted_keys_path() -> str:
    return data_config.get_path(_TRUSTED_KEYS_FILE)


def key_id_for_public_pem(pem_text: str) -> str:
    """Short deterministic fingerprint (16 hex chars of SHA-256) of an Ed25519 public key."""
    pub = serialization.load_pem_public_key(pem_text.encode("utf-8"))
    if not isinstance(pub, Ed25519PublicKey):
        raise BundleVerificationError("Chiave pubblica non Ed25519.")
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def _load_or_create_signing_key() -> tuple[Ed25519PrivateKey, str, str]:
    path = _signing_key_path()
    with _lock:
        if os.path.exists(path):
            with open(path, "rb") as fh:
                loaded = serialization.load_pem_private_key(fh.read(), password=None)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise BundleVerificationError("Chiave privata di firma non valida.")
            priv = loaded
        else:
            priv = Ed25519PrivateKey.generate()
            pem_priv = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            data_config.atomic_write(path, pem_priv, restrict=True)
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        return priv, pub_pem, key_id_for_public_pem(pub_pem)


def get_signing_public_key() -> dict[str, str]:
    """Return this instance's public Ed25519 signing key and fingerprint."""
    _, pub_pem, kid = _load_or_create_signing_key()
    return {"key_id": kid, "public_key": pub_pem}


def _read_trusted_keys() -> dict[str, dict[str, str]]:
    path = _trusted_keys_path()
    with _lock:
        try:
            with open(path, encoding="utf-8") as fh:
                loaded = json.load(fh)
            return loaded if isinstance(loaded, dict) else {}
        except (OSError, ValueError):
            return {}


def _write_trusted_keys(keys: dict[str, dict[str, str]]) -> None:
    with _lock:
        data_config.atomic_write(_trusted_keys_path(), keys)


def list_trusted_keys() -> list[dict[str, str]]:
    """List Ed25519 public keys trusted to verify offline OT bundles."""
    keys = _read_trusted_keys()
    return [
        {"key_id": kid, "label": str(v.get("label") or ""), "added_at": str(v.get("added_at") or ""),
         "public_key": str(v.get("public_key") or "")}
        for kid, v in sorted(keys.items())
        if isinstance(v, dict)
    ]


def add_trusted_key(public_key_pem: str, label: str = "") -> dict[str, str]:
    """Validate and trust an Ed25519 public key PEM."""
    pem = (public_key_pem or "").strip()
    if not pem:
        raise BundleVerificationError("Chiave pubblica mancante.")
    try:
        kid = key_id_for_public_pem(pem)
    except BundleVerificationError:
        raise
    except Exception as exc:
        raise BundleVerificationError(f"Chiave pubblica non valida: {exc}") from exc
    with _lock:
        keys = _read_trusted_keys()
        entry = {"label": (label or "").strip()[:80], "public_key": pem, "added_at": _now_iso()}
        keys[kid] = entry
        _write_trusted_keys(keys)
    return {"key_id": kid, **entry}


def remove_trusted_key(key_id: str) -> bool:
    kid = (key_id or "").strip()
    with _lock:
        keys = _read_trusted_keys()
        if kid not in keys:
            return False
        keys.pop(kid)
        _write_trusted_keys(keys)
        return True


def _canonical_sha256(payload: Any) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def export_signed_bundle(include_nvd_cache: bool = True) -> dict[str, Any]:
    """Export current KEV, ICS Advisories, and NVD offline cache as an Ed25519-signed bundle."""
    feeds = _read_feeds()
    payload = {
        "kev_updated_at": feeds.get("kev_updated_at") or "",
        "kev": feeds.get("kev") or {},
        "ics_updated_at": feeds.get("ics_updated_at") or "",
        "ics_advisories": feeds.get("ics_advisories") or [],
        "nvd_entries": (feeds.get("nvd_cache") or {}) if include_nvd_cache else {},
    }
    digest = _canonical_sha256(payload)
    priv, pub_pem, kid = _load_or_create_signing_key()
    sig_bytes = priv.sign(_SIGN_PREFIX + digest.encode("ascii"))
    return {
        "format": BUNDLE_FORMAT,
        "version": BUNDLE_VERSION,
        "exported_at": _now_iso(),
        "key_id": kid,
        "public_key": pub_pem,
        "sha256": digest,
        "signature": base64.b64encode(sig_bytes).decode("ascii"),
        "payload": payload,
    }


def verify_and_import_bundle(bundle: dict[str, Any], trust_bundle_key: bool = False) -> dict[str, Any]:
    """Cryptographically verify and import a signed air-gapped vulnerability bundle."""
    if not isinstance(bundle, dict) or bundle.get("format") != BUNDLE_FORMAT:
        raise BundleVerificationError("Formato bundle non riconosciuto.")
    if bundle.get("version") != BUNDLE_VERSION:
        raise BundleVerificationError(f"Versione bundle non supportata: {bundle.get('version')}.")

    payload = bundle.get("payload")
    digest = str(bundle.get("sha256") or "").strip().lower()
    sig_b64 = str(bundle.get("signature") or "").strip()
    kid = str(bundle.get("key_id") or "").strip()
    if not isinstance(payload, dict) or not digest or not sig_b64 or not kid:
        raise BundleVerificationError("Bundle incompleto: payload, hash, chiave o firma mancanti.")

    actual_digest = _canonical_sha256(payload)
    if not hmac.compare_digest(actual_digest, digest):
        raise BundleVerificationError("Integrita' compromessa: SHA-256 del payload non corrisponde.")

    trusted = _read_trusted_keys()
    local_pub_pem: Optional[str] = None
    local_kid: Optional[str] = None
    if os.path.exists(_signing_key_path()):
        _, local_pub_pem, local_kid = _load_or_create_signing_key()

    verify_pem: Optional[str] = None
    if kid in trusted and isinstance(trusted[kid], dict):
        verify_pem = trusted[kid].get("public_key")
    elif local_kid and kid == local_kid and local_pub_pem:
        verify_pem = local_pub_pem
    elif trust_bundle_key:
        candidate_pem = str(bundle.get("public_key") or "").strip()
        if not candidate_pem:
            raise BundleVerificationError("Chiave pubblica assente nel bundle.")
        derived_kid = key_id_for_public_pem(candidate_pem)
        if not hmac.compare_digest(derived_kid, kid):
            raise BundleVerificationError("Key ID incoerente con la chiave pubblica allegata.")
        verify_pem = candidate_pem
    else:
        raise BundleVerificationError(
            f"Chiave di firma '{kid}' non attendibile. Registrare la chiave pubblica o abilitare trust esplicito."
        )

    if not verify_pem:
        raise BundleVerificationError("Chiave pubblica di verifica non valida.")

    try:
        pub_key = serialization.load_pem_public_key(verify_pem.encode("utf-8"))
        if not isinstance(pub_key, Ed25519PublicKey):
            raise BundleVerificationError("Chiave pubblica non Ed25519.")
        sig_bytes = base64.b64decode(sig_b64, validate=True)
        pub_key.verify(sig_bytes, _SIGN_PREFIX + digest.encode("ascii"))
    except InvalidSignature as exc:
        raise BundleVerificationError("Firma digitale Ed25519 non valida.") from exc
    except BundleVerificationError:
        raise
    except Exception as exc:
        raise BundleVerificationError(f"Errore verifica firma: {exc}") from exc

    if trust_bundle_key and kid not in trusted and not (local_kid and kid == local_kid):
        add_trusted_key(verify_pem, label=f"Bundle {str(bundle.get('exported_at') or '')[:10]}")

    kev_in = _parse_kev_payload(payload.get("kev") or {})
    ics_in = _parse_ics_payload(payload.get("ics_advisories") or [])
    nvd_in = payload.get("nvd_entries") if isinstance(payload.get("nvd_entries"), dict) else {}

    with _lock:
        feeds = dict(_read_feeds())
        kev = dict(feeds.get("kev") or {})
        kev.update(kev_in)
        feeds["kev"] = kev
        feeds["kev_updated_at"] = str(payload.get("kev_updated_at") or feeds.get("kev_updated_at") or _now_iso())

        by_adv = {
            str(a.get("id")): a
            for a in (feeds.get("ics_advisories") or [])
            if isinstance(a, dict) and a.get("id")
        }
        for adv in ics_in:
            by_adv[adv["id"]] = adv
        feeds["ics_advisories"] = sorted(
            by_adv.values(),
            key=lambda a: (a.get("published") or "", a.get("id") or ""),
            reverse=True,
        )
        feeds["ics_updated_at"] = str(payload.get("ics_updated_at") or feeds.get("ics_updated_at") or _now_iso())

        nvd_cache = dict(feeds.get("nvd_cache") or {})
        nvd_count = 0
        for qk, qval in nvd_in.items():
            if not isinstance(qk, str) or not isinstance(qval, dict):
                continue
            if not isinstance(qval.get("vulnerabilities"), list):
                continue
            nvd_cache[qk] = qval
            nvd_count += 1
        feeds["nvd_cache"] = nvd_cache
        _write_feeds(feeds)

    return {
        "status": "imported",
        "key_id": kid,
        "exported_at": str(bundle.get("exported_at") or ""),
        "kev_imported": len(kev_in),
        "ics_imported": len(ics_in),
        "nvd_imported": nvd_count,
    }


def feed_status() -> dict[str, Any]:
    """Summary of local OT vulnerability feeds and air-gap status."""
    feeds = _read_feeds()
    pub = get_signing_public_key()
    trusted = list_trusted_keys()
    return {
        "airgap_mode": is_airgap_mode(),
        "kev_count": len(feeds.get("kev") or {}),
        "kev_updated_at": feeds.get("kev_updated_at") or "",
        "ics_count": len(feeds.get("ics_advisories") or []),
        "ics_updated_at": feeds.get("ics_updated_at") or "",
        "nvd_cached_queries": len(feeds.get("nvd_cache") or {}),
        "signing_key_id": pub["key_id"],
        "signing_public_key": pub["public_key"],
        "trusted_keys_count": len(trusted),
        "ts": int(time.time()),
    }
