# -*- coding: utf-8 -*-
"""Router Analyzer. Estratto da app_server.py (fase 6.6)."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

import config_analyzer
import inventory_manager
from routers.deps import get_current_user, user_group_scope, assert_device_allowed

router = APIRouter(tags=["Analyzer"])


class ConvertSchema(BaseModel):
    """Corpo per il Config Converter: testo esplicito oppure IP di un
    dispositivo (in tal caso si usa il backup piu' recente)."""
    text: Optional[str] = None
    ip: Optional[str] = None
    source: str  # 'fortios' | 'panos'
    target: str  # 'fortios' | 'panos'


def _load_backup_text(ip: str, current_user) -> str:
    """Testo del backup piu' recente per l'IP, con scoping per sede.
    404 se il dispositivo non esiste o non ha backup."""
    device = assert_device_allowed(current_user, ip)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Dispositivo {ip} non trovato.")
    path, _tenant = config_analyzer._find_freshest_backup(ip)
    if not path:
        raise HTTPException(status_code=404, detail=f"Nessun backup trovato per {ip}.")
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        raise HTTPException(status_code=500, detail=f"Impossibile leggere il backup di {ip}.")
    return "\n".join(config_analyzer.running_config(content))


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


@router.post("/api/config-analyzer/convert")
def config_analyzer_convert(payload: ConvertSchema, current_user = Depends(get_current_user)):
    """Conversione deterministica (preview) FortiOS <-> PAN-OS. Accetta testo
    esplicito oppure {ip} -> backup piu' recente del dispositivo (scoped)."""
    text = payload.text
    from_ip = False
    if not text and payload.ip:
        text = _load_backup_text(payload.ip, current_user)
        from_ip = True
    if not text:
        raise HTTPException(status_code=400, detail="Fornire 'text' oppure 'ip'.")
    try:
        result = config_analyzer.convert_config(text, payload.source, payload.target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if from_ip:
        result["source_text"] = text
    return result

