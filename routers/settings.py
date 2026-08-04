# -*- coding: utf-8 -*-
"""Router Settings. Estratto da app_server.py (fase 6.6): percorsi, metodi,
parametri e risposte identici al monolite."""

import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.app_settings import get_app_settings, save_app_settings, effective_port, list_local_ips, PORT
from core import core_engine
from security.security_manager import log_audit
from routers.deps import require_admin, get_current_user, user_group_scope
from core import data_config

_APP_ADV_ENV = {
    "port": "SENTINELNET_PORT",
    "ssl_certfile": "SENTINELNET_SSL_CERTFILE",
    "ssl_keyfile": "SENTINELNET_SSL_KEYFILE",
    "cors_origins": "SENTINELNET_CORS_ORIGINS",
    "no_browser": "SENTINELNET_NO_BROWSER",
    "retention_flows_days": "SENTINELNET_OBS_RETENTION_FLOWS_DAYS",
    "retention_syslog_days": "SENTINELNET_OBS_RETENTION_SYSLOG_DAYS",
    "retention_events_days": "SENTINELNET_OBS_RETENTION_EVENTS_DAYS",
}
_APP_ADV_INT_KEYS = {"port", "retention_flows_days", "retention_syslog_days",
                     "retention_events_days"}
_APP_ADV_DEFAULTS = {"port": PORT, "retention_flows_days": 30,
                     "retention_syslog_days": 7, "retention_events_days": 90}

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

# NetSec Audit, Incidenti, Flow SIEM e Fortigate Management non hanno piu' un
# flag di attivazione: le tab sono sempre presenti (restano gated dalla sola
# RBAC di nav). Le vecchie chiavi di app_settings.json per questi flag,
# eventualmente rimaste da installazioni precedenti, sono semplicemente
# ignorate: nessuna migrazione necessaria.


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


class SnmpDefaultSchema(BaseModel):
    tenant: str
    community: str = ""          # "" rimuove il default


@router.get("/api/settings/snmp-defaults")
def snmp_defaults_get(current_user = Depends(get_current_user)):
    """I tenant che hanno una community predefinita. SOLO i nomi.

    Il valore non esce da qui nemmeno cifrato: alla UI serve sapere SE il
    default c'e', non quale sia — stessa regola dei device in
    ``/api/local-devices`` e delle identita'.
    """
    from security.snmp_defaults import tenants_with_default
    scope = user_group_scope(current_user)
    names = tenants_with_default()
    if scope is not None:
        names = {t for t in names if t in scope}
    return {"tenants": sorted(names)}


@router.post("/api/settings/snmp-defaults")
def snmp_defaults_set(payload: SnmpDefaultSchema,
                      current_user = Depends(require_admin)):
    """Imposta o rimuove ("" rimuove) la community predefinita di un tenant.

    ``require_admin``: e' una credenziale che vale per OGNI apparato della
    sede, quindi non e' un'impostazione di comodo.
    """
    from security.snmp_defaults import set_tenant_community
    # Stesso vincolo di routers.deps.assert_group_allowed, ma sul nome
    # importato in QUESTO modulo: e' quello che i test mettono in patch.
    scope = user_group_scope(current_user)
    if scope is not None and payload.tenant not in scope:
        raise HTTPException(
            status_code=403,
            detail=f"Site '{payload.tenant}' is not allowed for your profile.")
    set_tenant_community(payload.tenant, payload.community)
    log_audit(f"Community SNMP predefinita del tenant '{payload.tenant}' "
              f"{'impostata' if payload.community else 'rimossa'} da "
              f"'{current_user.get('sub')}'.")
    return {"status": "success"}

