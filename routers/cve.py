# -*- coding: utf-8 -*-
"""Router Correlazione CVE: snapshot per apparato, vista prioritizzata,
resoconto per tenant.

Nessuna risposta di questo router puo' essere letta come "non impattato":
`not_evaluated` viaggia con ogni verdetto, e i punteggi riordinano senza mai
togliere un CVE dalla lista.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException

from routers.deps import (require_operator, assert_device_allowed,
                          devices_in_scope)
from security.security_manager import log_audit
from services import cve_intel

router = APIRouter(tags=["CVE"])

log = logging.getLogger("sentinelnet.cve")


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
        "tenant": device.get("Group") or "Generale",
        "fetched_at": snapshot.get("fetched_at", ""),
        "version_seen_at": snapshot.get("version_seen_at", ""),
        "query": snapshot.get("query") or {},
        "services": services,
        "rows": cve_intel.score_rows(snapshot, services),
        "not_evaluated": cve_intel.not_evaluated_for(services),
    }


def _scoped_devices(current_user, tenant: str) -> list:
    """Gli apparati visibili al chiamante, ristretti al tenant richiesto.

    Il filtro si applica DOPO lo scope RBAC, mai al suo posto: un tenant scelto
    dal selettore e' una preferenza di vista, non un permesso.
    """
    devices = devices_in_scope(current_user)
    if tenant and tenant != "all":
        return [d for d in devices if (d.get("Group") or "Generale") == tenant]
    return devices


# /summary e /priority stanno PRIMA di /{ip}: altrimenti il path param se le
# mangia e "summary" viene cercato in inventario come se fosse un IP.
@router.get("/api/cve/summary")
def cve_summary(tenant: str = "", current_user=Depends(require_operator)):
    """Una riga per tenant. Ogni conteggio con il suo denominatore."""
    return {"tenants": cve_intel.summary(_scoped_devices(current_user, tenant))}


@router.get("/api/cve/priority")
def cve_priority(tenant: str = "", limit: int = 200,
                 current_user=Depends(require_operator)):
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
        for row in cve_intel.score_rows(snapshot, services):
            row["tenant"] = device.get("Group") or "Generale"
            rows.append(row)

    rows.sort(key=lambda r: r["score"], reverse=True)
    # `total` e' quanti ne esistono davvero: il taglio e' di presentazione, e
    # un elenco troncato in silenzio si legge come un elenco completo.
    return {"rows": rows[:max(1, limit)], "total": len(rows),
            "not_evaluated": sorted(not_evaluated)}


@router.get("/api/cve/{ip}")
def cve_device(ip: str, current_user=Depends(require_operator)):
    return _device_view(_device_or_404(current_user, ip))


@router.post("/api/cve/{ip}/refresh")
def cve_refresh(ip: str, current_user=Depends(require_operator)):
    device = _device_or_404(current_user, ip)
    log_audit(f"Snapshot CVE di {ip} riscaricato dall'utente "
              f"'{current_user.get('sub')}'.")
    try:
        cve_intel.refresh(device)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Errore connessione NVD: {e}")
    return _device_view(device)
