# -*- coding: utf-8 -*-
"""Router WLC LIVE: osservabilità wireless Cisco AireOS / Catalyst 9800 (SSH).
Estratto da app_server.py (fase 2.3): percorsi e risposte identici al
monolite. La logica resta in wlc_service.py."""

from fastapi import APIRouter, Depends, HTTPException

import wlc_service
from security_manager import log_audit
from routers.deps import get_current_user, assert_device_allowed

router = APIRouter(tags=["Wireless"])

_WLC_VENDORS = ("cisco_wlc", "cisco_9800", "cisco")


def _wlc_device(ip: str, current_user) -> dict:
    """Risolve un IP in un controller wireless Cisco dell'inventario, con
    verifica di scoping per sede. Vendor 'cisco' generico è ammesso e
    trattato come 9800/IOS-XE."""
    device = assert_device_allowed(current_user, ip)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device {ip} not found in inventory.")
    if (device.get('Vendor') or '').lower() not in _WLC_VENDORS:
        raise HTTPException(status_code=400,
                            detail=f"Device {ip} is not a Cisco WLC (vendor='{device.get('Vendor')}').")
    return device


def _wlc_query(ip, current_user, service, mac=None):
    device = _wlc_device(ip, current_user)
    try:
        return wlc_service.query(device, service, mac=mac)
    except wlc_service.WlcError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/api/wlc/{ip}/status")
def wlc_status(ip: str, current_user = Depends(get_current_user)):
    return _wlc_query(ip, current_user, "status")

@router.get("/api/wlc/{ip}/ap-summary")
def wlc_ap_summary(ip: str, current_user = Depends(get_current_user)):
    return _wlc_query(ip, current_user, "ap_summary")

@router.get("/api/wlc/{ip}/client-summary")
def wlc_client_summary(ip: str, current_user = Depends(get_current_user)):
    return _wlc_query(ip, current_user, "client_summary")

@router.get("/api/wlc/{ip}/client/{mac}")
def wlc_client_detail(ip: str, mac: str, current_user = Depends(get_current_user)):
    return _wlc_query(ip, current_user, "client_detail", mac=mac)

@router.get("/api/wlc/{ip}/wlan-summary")
def wlc_wlan_summary(ip: str, current_user = Depends(get_current_user)):
    return _wlc_query(ip, current_user, "wlan_summary")

@router.get("/api/wlc/{ip}/rogue-aps")
def wlc_rogue_aps(ip: str, current_user = Depends(get_current_user)):
    return _wlc_query(ip, current_user, "rogue_aps")

@router.get("/api/wlc/{ip}/interfaces")
def wlc_interfaces(ip: str, current_user = Depends(get_current_user)):
    return _wlc_query(ip, current_user, "interfaces")

@router.get("/api/wlc/{ip}/diagnose-client/{mac}")
def wlc_diagnose_client(ip: str, mac: str, current_user = Depends(get_current_user)):
    """Diagnosi aggregata di un client wireless (dettaglio client + AP +
    WLAN + rogue AP), sezioni best-effort."""
    device = _wlc_device(ip, current_user)
    log_audit(f"Diagnosi client WiFi '{mac}' su WLC '{ip}' da '{current_user.get('sub')}'.")
    return wlc_service.diagnose_wifi_client(device, mac)
