# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router Correlazione CVE: snapshot per apparato, vista prioritizzata,
resoconto per tenant.

Nessuna risposta di questo router puo' essere letta come "non impattato":
`not_evaluated` viaggia con ogni verdetto, e i punteggi riordinano senza mai
togliere un CVE dalla lista.
"""

import json
import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from routers.deps import (
    assert_device_allowed,
    devices_in_scope,
    get_current_user,
    require_admin,
    require_operator,
    require_tab,
)
from security.security_manager import log_audit
from services import cve_intel, ot_vuln_intel

router = APIRouter(tags=["CVE"])

log = logging.getLogger("sentinelnet.cve")


class AirgapModeSchema(BaseModel):
    enabled: bool


class TrustedKeySchema(BaseModel):
    public_key: str = Field(..., min_length=10, max_length=2048)
    label: str = Field("", max_length=80)


class BundleImportSchema(BaseModel):
    bundle: Dict[str, Any]
    trust_bundle_key: bool = False


class FeedSyncSchema(BaseModel):
    fetch_kev: bool = True
    fetch_ics: bool = True


def _device_or_404(current_user, ip: str) -> dict:
    device = assert_device_allowed(current_user, ip)
    if not device:
        raise HTTPException(status_code=404, detail=f"Apparato {ip} non trovato.")
    return device


def _device_view(device: dict) -> dict:
    snapshot = cve_intel.load(device)
    services = cve_intel.device_services(device)
    return {
        "device": device.get("IP"),
        "tenant": device.get("Group") or "",
        "fetched_at": snapshot.get("fetched_at", ""),
        "version_seen_at": snapshot.get("version_seen_at", ""),
        "query": snapshot.get("query") or {},
        "services": services,
        "posture": ot_vuln_intel.asset_patch_posture(device),
        "rows": cve_intel.score_rows(snapshot, services, device=device),
        "not_evaluated": cve_intel.not_evaluated_for(services),
    }


def _scoped_devices(current_user, tenant: str) -> list:
    """Gli apparati visibili al chiamante, ristretti al tenant richiesto.

    Il filtro si applica DOPO lo scope RBAC, mai al suo posto: un tenant scelto
    dal selettore e' una preferenza di vista, non un permesso.
    """
    devices = devices_in_scope(current_user)
    if tenant and tenant != "all":
        return [d for d in devices if (d.get("Group") or "") == tenant]
    return devices


# Static routes stay BEFORE /{ip} so FastAPI never matches them as an IP.
@router.get("/api/cve/summary", dependencies=[Depends(require_tab("tab-home", "tab-security"))])
def cve_summary(tenant: str = "", current_user=Depends(get_current_user)):
    """Una riga per tenant. Ogni conteggio con il suo denominatore."""
    return {"tenants": cve_intel.summary(_scoped_devices(current_user, tenant))}


@router.get("/api/cve/priority", dependencies=[Depends(require_tab("tab-security"))])
def cve_priority(tenant: str = "", limit: int = 200,
                 current_user=Depends(get_current_user)):
    """Cosa sistemare per primo: i CVE degli apparati in scope, per punteggio."""
    rows = []
    devices = _scoped_devices(current_user, tenant)

    not_evaluated = set(cve_intel.NOT_EVALUATED)
    for device in devices:
        snapshot = cve_intel.load(device)
        if not snapshot:
            continue
        services = cve_intel.device_services(device)
        if not services:
            not_evaluated.add("service_state")
        for row in cve_intel.score_rows(snapshot, services, device=device):
            row["tenant"] = device.get("Group") or ""
            rows.append(row)

    rows.sort(key=lambda r: r["score"], reverse=True)
    # `total` e' quanti ne esistono davvero: il taglio e' di presentazione, e
    # un elenco troncato in silenzio si legge come un elenco completo.
    return {"rows": rows[:max(1, limit)], "total": len(rows),
            "not_evaluated": sorted(not_evaluated)}


@router.get("/api/cve/ot/status", dependencies=[Depends(require_tab("tab-security"))])
def ot_vuln_status(current_user=Depends(get_current_user)):
    """Local CISA KEV / ICS Advisories counts, NVD cache state, and air-gap status."""
    status = ot_vuln_intel.feed_status()
    status["trusted_keys"] = ot_vuln_intel.list_trusted_keys()
    return status


@router.post("/api/cve/ot/airgap", dependencies=[Depends(require_tab("tab-security"))])
def ot_set_airgap(payload: AirgapModeSchema, current_user=Depends(require_admin)):
    """Enable or disable air-gapped offline vulnerability intelligence mode."""
    enabled = ot_vuln_intel.set_airgap_mode(payload.enabled)
    log_audit(
        f"Modalita' air-gap vulnerabilita' {'abilitata' if enabled else 'disabilitata'} "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success", "airgap_mode": enabled}


@router.post("/api/cve/ot/sync", dependencies=[Depends(require_tab("tab-security"))])
def ot_sync_feeds(payload: FeedSyncSchema = FeedSyncSchema(), current_user=Depends(require_operator)):
    """Fetch CISA KEV and CISA ICS Advisories catalogs when online."""
    if ot_vuln_intel.is_airgap_mode():
        raise HTTPException(
            status_code=409,
            detail="Modalita' air-gap attiva: usa l'importazione di un pacchetto firmato.",
        )
    try:
        res = ot_vuln_intel.sync_online_feeds(fetch_kev=payload.fetch_kev, fetch_ics=payload.fetch_ics)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Errore sincronizzazione feed CISA: {exc}")
    log_audit(
        f"Feed OT CISA sincronizzati da '{current_user.get('sub')}' "
        f"(KEV: {res['kev_count']}, ICS: {res['ics_count']})."
    )
    return res


@router.get("/api/cve/ot/ics-advisories", dependencies=[Depends(require_tab("tab-security"))])
def ot_list_ics_advisories(
    vendor: str = "",
    cve: str = "",
    q: str = "",
    ip: str = "",
    limit: int = 200,
    current_user=Depends(get_current_user),
):
    """Query locally cached CISA ICS Advisories (optionally scoped to one device)."""
    if ip:
        device = _device_or_404(current_user, ip)
        snap = cve_intel.load(device)
        cves = [str(c.get("id") or "") for c in (snap.get("cves") or []) if isinstance(c, dict)]
        from services import inventory_manager
        detected = inventory_manager.get_detected_versions().get(ip, {})
        items = ot_vuln_intel.advisories_for_device(device, detected, cves)[:max(1, min(1000, limit))]
    else:
        items = ot_vuln_intel.list_ics_advisories(vendor=vendor, cve=cve, q=q, limit=limit)
    return {"advisories": items, "total": len(items)}


@router.get("/api/cve/ot/bundle/export", dependencies=[Depends(require_tab("tab-security"))])
def ot_export_bundle(include_nvd: bool = True, current_user=Depends(require_operator)):
    """Export Ed25519-signed offline bundle for air-gapped SentinelNet instances."""
    bundle = ot_vuln_intel.export_signed_bundle(include_nvd_cache=include_nvd)
    log_audit(
        f"Pacchetto offline vulnerabilita' firmato (key_id={bundle['key_id']}) "
        f"esportato da '{current_user.get('sub')}'."
    )
    return Response(
        content=json.dumps(bundle, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="sentinelnet-ot-vuln-bundle.json"'},
    )


@router.post("/api/cve/ot/bundle/import", dependencies=[Depends(require_tab("tab-security"))])
def ot_import_bundle(payload: BundleImportSchema, current_user=Depends(require_operator)):
    """Verify Ed25519 signature + SHA-256 and import an offline vulnerability bundle."""
    if payload.trust_bundle_key and current_user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Solo gli amministratori possono registrare una nuova chiave di firma.",
        )
    try:
        result = ot_vuln_intel.verify_and_import_bundle(
            payload.bundle,
            trust_bundle_key=payload.trust_bundle_key,
        )
    except ot_vuln_intel.BundleVerificationError as exc:
        log_audit(f"Pacchetto offline rifiutato ({current_user.get('sub')}): {exc}")
        raise HTTPException(status_code=400, detail=str(exc))
    log_audit(
        f"Pacchetto offline importato da '{current_user.get('sub')}' "
        f"(key_id={result['key_id']}, KEV={result['kev_imported']}, "
        f"ICS={result['ics_imported']}, NVD={result['nvd_imported']})."
    )
    return result


@router.get("/api/cve/ot/trusted-keys", dependencies=[Depends(require_tab("tab-security"))])
def ot_list_trusted_keys(current_user=Depends(require_admin)):
    return {
        "local_signing_key": ot_vuln_intel.get_signing_public_key(),
        "trusted_keys": ot_vuln_intel.list_trusted_keys(),
    }


@router.post("/api/cve/ot/trusted-keys", dependencies=[Depends(require_tab("tab-security"))])
def ot_add_trusted_key(payload: TrustedKeySchema, current_user=Depends(require_admin)):
    try:
        added = ot_vuln_intel.add_trusted_key(payload.public_key, payload.label)
    except ot_vuln_intel.BundleVerificationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    log_audit(f"Chiave pubblica offline '{added['key_id']}' aggiunta da '{current_user.get('sub')}'.")
    return {"status": "success", "key": added}


@router.delete("/api/cve/ot/trusted-keys/{key_id}", dependencies=[Depends(require_tab("tab-security"))])
def ot_delete_trusted_key(key_id: str, current_user=Depends(require_admin)):
    if not ot_vuln_intel.remove_trusted_key(key_id):
        raise HTTPException(status_code=404, detail=f"Chiave '{key_id}' non trovata.")
    log_audit(f"Chiave pubblica offline '{key_id}' rimossa da '{current_user.get('sub')}'.")
    return {"status": "success"}


@router.get("/api/cve/{ip}", dependencies=[Depends(require_tab("tab-security"))])
def cve_device(ip: str, current_user=Depends(get_current_user)):
    return _device_view(_device_or_404(current_user, ip))


@router.post("/api/cve/{ip}/refresh", dependencies=[Depends(require_tab("tab-security"))])
def cve_refresh(ip: str, fresh: bool = True, current_user=Depends(require_operator)):
    """fresh=false lets "Analyze all" reuse the NVD answer of an identical firmware."""
    device = _device_or_404(current_user, ip)
    log_audit(f"Snapshot CVE di {ip} riscaricato dall'utente "
              f"'{current_user.get('sub')}'.")
    try:
        cve_intel.refresh(device, fresh=fresh)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Errore connessione NVD: {e}")
    return _device_view(device)
