# -*- coding: utf-8 -*-
"""Router Settings. Estratto da app_server.py (fase 6.6): percorsi, metodi,
parametri e risposte identici al monolite."""

import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app_settings import get_app_settings, save_app_settings, effective_port, list_local_ips
import core_engine
from security_manager import log_audit
from routers.deps import require_admin

router = APIRouter(tags=["Settings"])

class NetworkSettingsSchema(BaseModel):
    host: str

class CliBlacklistSchema(BaseModel):
    cli_blacklist_operators: bool


# --- ROTTE ---

@router.get("/api/settings/network")
def get_network_settings(current_user = Depends(require_admin)):
    """Stato attuale del bind IP: host configurato, host effettivo, eventuale
    override via env, porta e IP locali selezionabili."""
    env_host = os.environ.get("SENTINELNET_HOST")
    configured = get_app_settings().get("host")
    effective = env_host or configured or "127.0.0.1"
    return {
        "configured_host": configured,
        "effective_host": effective,
        "env_override": env_host is not None,
        "port": effective_port(),
        "local_ips": list_local_ips(),
    }

@router.post("/api/settings/network")
def set_network_settings(payload: NetworkSettingsSchema, current_user = Depends(require_admin)):
    """Imposta l'IP di bind (applicato al prossimo riavvio). Valida che l'host
    sia tra gli IP locali enumerati (o 0.0.0.0/127.0.0.1)."""
    host = payload.host.strip()
    valid = set(list_local_ips()) | {"0.0.0.0", "127.0.0.1"}
    if host not in valid:
        raise HTTPException(status_code=400, detail=f"Host '{host}' non valido o non disponibile sulla LAN.")
    save_app_settings({"host": host})
    log_audit(f"IP di bind impostato a '{host}' dall'utente '{current_user.get('sub')}' (applicato al riavvio).")
    return {"status": "success", "restart_required": True, "host": host}

@router.get("/api/settings/cli-blacklist")
def get_cli_blacklist_settings(current_user = Depends(require_admin)):
    """Stato dell'applicazione della blacklist CLI agli operatori (default: attiva)."""
    return {"cli_blacklist_operators": bool(get_app_settings().get("cli_blacklist_operators", True))}

@router.post("/api/settings/cli-blacklist")
def set_cli_blacklist_settings(payload: CliBlacklistSchema, current_user = Depends(require_admin)):
    save_app_settings({"cli_blacklist_operators": payload.cli_blacklist_operators})
    log_audit(f"Blacklist comandi CLI per gli operatori "
              f"{'attivata' if payload.cli_blacklist_operators else 'disattivata'} "
              f"dall'utente '{current_user.get('sub')}'.")
    return {"status": "success", "cli_blacklist_operators": payload.cli_blacklist_operators}

@router.get("/api/settings/app")
def get_app_advanced_settings(current_user = Depends(require_admin)):
    saved = get_app_settings().get("app", {}) or {}
    return {
        "settings": {k: saved.get(k) for k in _APP_ADV_ENV},
        "env_overrides": {k: env in os.environ for k, env in _APP_ADV_ENV.items()},
        "defaults": _APP_ADV_DEFAULTS,
        "data_dir": data_config.DATA_DIR,
    }

@router.post("/api/settings/app")
def set_app_advanced_settings(payload: dict, current_user = Depends(require_admin)):
    clean = {}
    for k, v in (payload or {}).items():
        if k not in _APP_ADV_ENV:
            raise HTTPException(status_code=400, detail=f"Invalid key: '{k}'.")
        if v in (None, ""):
            clean[k] = None  # torna al default
            continue
        if k in _APP_ADV_INT_KEYS:
            try:
                v = int(v)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"Invalid value for '{k}'.")
            if k == "port" and not (1 <= v <= 65535):
                raise HTTPException(status_code=400, detail="Invalid port (1-65535).")
            if k != "port" and v < 1:
                raise HTTPException(status_code=400, detail=f"Invalid value for '{k}'.")
        elif k == "no_browser":
            v = bool(v)
        else:
            v = str(v).strip()
        clean[k] = v
    saved = dict(get_app_settings().get("app", {}) or {})
    saved.update(clean)
    saved = {k: v for k, v in saved.items() if v is not None}
    # TLS: o entrambi i percorsi o nessuno (coerente con resolve_tls_config).
    if bool(saved.get("ssl_certfile")) != bool(saved.get("ssl_keyfile")):
        raise HTTPException(status_code=400,
                            detail="TLS: set both certificate and key paths, or neither.")
    save_app_settings({"app": saved})
    log_audit(f"Impostazioni applicazione aggiornate da '{current_user.get('sub')}' "
              f"(riavvio richiesto): {clean}.")
    return {"status": "success", "restart_required": True, "settings": saved}

