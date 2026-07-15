# -*- coding: utf-8 -*-
"""Router Analyzer. Estratto da app_server.py (fase 6.6)."""

from fastapi import APIRouter, Depends, HTTPException, status

import config_analyzer
import inventory_manager
from routers.deps import get_current_user, user_group_scope, assert_device_allowed

router = APIRouter(tags=["Analyzer"])


# --- ENDPOINTS ---

@router.get("/api/config-analyzer")
def config_analyzer_all(group: str = "all", current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    return config_analyzer.analyze_all(group_filter=group, allowed_groups=scope)

@router.get("/api/config-analyzer/{ip}")
def config_analyzer_device(ip: str, current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    device = next((d for d in inventory_manager.get_all_devices() if d.get('IP') == ip), None)
    if device is not None and scope is not None:
        if device.get('Group', 'Generale') not in scope:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Dispositivo non consentito per il tuo profilo.")
    result = config_analyzer.analyze_device(ip)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Nessun backup trovato per {ip}.")
    return result

