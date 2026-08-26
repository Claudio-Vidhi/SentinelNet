# -*- coding: utf-8 -*-
"""Router Settings. Estratto da app_server.py (fase 6.6): percorsi, metodi,
parametri e risposte identici al monolite."""

import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.app_settings import get_app_settings, save_app_settings, effective_port, list_local_ips, PORT
from core import core_engine
from security import crypto_vault
from security.security_manager import log_audit
from routers.deps import require_admin, get_current_user, user_group_scope
from core import data_config

_APP_ADV_ENV = {
    "port": "SENTINELNET_PORT",
    "ssl_certfile": "SENTINELNET_SSL_CERTFILE",
    "ssl_keyfile": "SENTINELNET_SSL_KEYFILE",
    "cors_origins": "SENTINELNET_CORS_ORIGINS",
    # Indirizzo pubblico usato nei link inviati per email (recupero password):
    # non si ricava mai dall'header Host della richiesta, che e' del chiamante.
    "app_base_url": "SENTINELNET_BASE_URL",
    "no_browser": "SENTINELNET_NO_BROWSER",
    "retention_flows_days": "SENTINELNET_OBS_RETENTION_FLOWS_DAYS",
    "retention_syslog_days": "SENTINELNET_OBS_RETENTION_SYSLOG_DAYS",
    "retention_events_days": "SENTINELNET_OBS_RETENTION_EVENTS_DAYS",
    "audit_history_days": "SENTINELNET_AUDIT_HISTORY_DAYS",
    "config_drift_keep_versions": "SENTINELNET_DRIFT_KEEP_VERSIONS",
}
_APP_ADV_INT_KEYS = {"port", "retention_flows_days", "retention_syslog_days",
                     "retention_events_days", "audit_history_days",
                     "config_drift_keep_versions"}
_APP_ADV_DEFAULTS = {"port": PORT, "retention_flows_days": 30,
                     "retention_syslog_days": 7, "retention_events_days": 90,
                     "audit_history_days": 365, "config_drift_keep_versions": 0}

router = APIRouter(tags=["Settings"])

class NetworkSettingsSchema(BaseModel):
    host: str

class CliBlacklistSchema(BaseModel):
    cli_blacklist_operators: bool

class UiVariantSchema(BaseModel):
    ui_variant: str = Field(default="default")

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

@router.get("/api/settings/ui-variant")
def get_ui_variant_settings(current_user = Depends(get_current_user)):
    """Restituisce la variante grafica UI selezionata (default, design-1, design-2, design-3)."""
    variant = get_app_settings().get("ui_variant", "default")
    return {"ui_variant": variant}

@router.post("/api/settings/ui-variant")
def set_ui_variant_settings(payload: UiVariantSchema, current_user = Depends(get_current_user)):
    """Imposta la variante grafica UI."""
    allowed = {"default", "design-1", "design-2", "design-3"}
    variant = payload.ui_variant.strip().lower()
    if variant not in allowed:
        raise HTTPException(status_code=400, detail=f"Variante UI non valida. Valori ammessi: {sorted(list(allowed))}")
    save_app_settings({"ui_variant": variant})
    log_audit(f"Variante UI impostata a '{variant}' dall'utente '{current_user.get('sub')}'.")
    return {"status": "success", "ui_variant": variant}

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
            if k in ("audit_history_days", "config_drift_keep_versions"):
                if v < 0:
                    raise HTTPException(status_code=400, detail=f"Invalid value for '{k}'.")
            elif k != "port" and v < 1:
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


class PingMonitorSchema(BaseModel):
    enabled: bool
    interval_seconds: int = Field(default=60, ge=5, le=86400)


@router.get("/api/settings/ping-monitor")
def get_ping_monitor_settings(current_user = Depends(require_admin)):
    """Configurazione corrente del monitor ping continuo."""
    from services import ping_monitor
    return ping_monitor.get_config()


@router.post("/api/settings/ping-monitor")
def set_ping_monitor_settings(payload: PingMonitorSchema,
                              current_user = Depends(require_admin)):
    """Attiva/disattiva il monitor ping continuo e ne imposta l'intervallo.
    Applicato subito, senza riavvio."""
    from services import ping_monitor
    cfg = ping_monitor.save_config(payload.enabled, payload.interval_seconds,
                                   current_user.get('sub'))
    return {"status": "success", **cfg}


@router.get("/api/ping-monitor/status")
def ping_monitor_status(current_user = Depends(get_current_user)):
    """Stato up/down di tutti i dispositivi monitorati, con scoping per tenant."""
    from services import ping_monitor, inventory_manager
    from routers.deps import user_group_scope
    status = ping_monitor.get_status()
    scope = user_group_scope(current_user)
    if scope is not None:
        ips_in_scope = {
            (d.get("IP") or "").strip()
            for d in inventory_manager.get_all_devices()
            if (d.get("Group") or "Generale") in scope
        }
        status["devices"] = [d for d in status["devices"] if d["ip"] in ips_in_scope]
        # Tri-state: "up" is None for a jump-site device (not measurable, see
        # services/ping_monitor.py), which must not be counted as "down".
        up_count = sum(1 for d in status["devices"] if d["up"] is True)
        down_count = sum(1 for d in status["devices"] if d["up"] is False)
        status["summary"] = {
            "total": len(status["devices"]),
            "up": up_count,
            "down": down_count,
            "unknown": len(status["devices"]) - up_count - down_count,
        }
    return status


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



class SmtpSettingsSchema(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = Field(default=587, ge=1, le=65535)
    username: str = ""
    # Vuota = mantieni la password gia' salvata: la UI non la riceve mai
    # indietro, quindi non puo' rimandarla a ogni salvataggio.
    password: str = ""
    from_email: str = ""
    tls_mode: str = Field(default="starttls")


class SmtpTestSchema(BaseModel):
    to: str


@router.get("/api/settings/smtp")
def get_smtp_settings(current_user = Depends(require_admin)):
    """Configurazione SMTP. La password non esce mai: solo se c'e' o no."""
    from services import mailer
    cfg = mailer.get_config()
    return {
        "enabled": cfg["enabled"],
        "host": cfg["host"],
        "port": cfg["port"],
        "username": cfg["username"],
        "has_password": bool(cfg["password_enc"]),
        "from_email": cfg["from_email"],
        "tls_mode": cfg["tls_mode"],
    }


@router.post("/api/settings/smtp")
def set_smtp_settings(payload: SmtpSettingsSchema,
                      current_user = Depends(require_admin)):
    from services import mailer
    if payload.tls_mode not in mailer.TLS_MODES:
        raise HTTPException(
            status_code=400,
            detail=f"Modalita' TLS non valida: {', '.join(mailer.TLS_MODES)}.")

    current = mailer.get_config()
    password_enc = current["password_enc"]
    if payload.password:
        password_enc = crypto_vault.encrypt_password(payload.password)

    mailer.save_config({
        "enabled": payload.enabled,
        "host": payload.host.strip(),
        "port": payload.port,
        "username": payload.username.strip(),
        "password_enc": password_enc,
        "from_email": payload.from_email.strip(),
        "tls_mode": payload.tls_mode,
    })
    log_audit(f"Impostazioni SMTP aggiornate da '{current_user.get('sub')}' "
              f"(host='{payload.host.strip()}', tls={payload.tls_mode}, "
              f"attivo={payload.enabled}).")
    return {"status": "success"}


@router.post("/api/settings/smtp/test")
def test_smtp_settings(payload: SmtpTestSchema,
                       current_user = Depends(require_admin)):
    """Invia un messaggio di prova con la configurazione SALVATA: prima si
    salva, poi si prova, altrimenti si collauda qualcosa che non resta."""
    from services import mailer
    try:
        mailer.send_test_email(payload.to.strip())
    except mailer.MailerError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    log_audit(f"Email di test SMTP inviata a '{payload.to.strip()}' "
              f"da '{current_user.get('sub')}'.")
    return {"status": "success"}


class SsoSettingsSchema(BaseModel):
    enabled: bool = False
    provider_name: str = "Single Sign-On"
    client_id: str = ""
    # Vuoto = mantieni il segreto gia' salvato (non torna mai dall'API).
    client_secret: str = ""
    issuer_url: str = ""
    default_role: str = "viewer"
    admin_group: str = ""
    operator_group: str = ""
    auto_provision: bool = False
    sync_roles: bool = False


@router.get("/api/settings/sso")
def get_sso_settings(current_user = Depends(require_admin)):
    from security import sso
    cfg = sso.get_config()
    return {
        "enabled": cfg["enabled"],
        "provider_name": cfg["provider_name"],
        "client_id": cfg["client_id"],
        "has_client_secret": bool(cfg["client_secret_enc"]),
        "issuer_url": cfg["issuer_url"],
        "default_role": cfg["default_role"],
        "admin_group": cfg["admin_group"],
        "operator_group": cfg["operator_group"],
        "auto_provision": cfg["auto_provision"],
        "sync_roles": cfg["sync_roles"],
    }


@router.post("/api/settings/sso")
def set_sso_settings(payload: SsoSettingsSchema, current_user = Depends(require_admin)):
    from security import sso, user_manager
    if payload.default_role not in user_manager.VALID_ROLES:
        raise HTTPException(status_code=400, detail="Ruolo predefinito non valido.")
    issuer = payload.issuer_url.strip().rstrip("/")
    # Il discovery e le chiavi di firma arrivano da questo URL: su HTTP
    # semplice chiunque sia sul percorso puo' sostituirli.
    if issuer and not issuer.startswith("https://"):
        raise HTTPException(status_code=400,
                            detail="L'URL dell'issuer deve usare HTTPS.")
    if payload.enabled and (not issuer or not payload.client_id.strip()):
        raise HTTPException(status_code=400,
                            detail="Per attivare il Single Sign-On servono issuer URL e client ID.")

    current = sso.get_config()
    secret_enc = current["client_secret_enc"]
    if payload.client_secret:
        secret_enc = crypto_vault.encrypt_password(payload.client_secret)

    sso.save_config({
        "enabled": payload.enabled,
        "provider_name": payload.provider_name.strip() or "Single Sign-On",
        "client_id": payload.client_id.strip(),
        "client_secret_enc": secret_enc,
        "issuer_url": issuer,
        "default_role": payload.default_role,
        "admin_group": payload.admin_group.strip(),
        "operator_group": payload.operator_group.strip(),
        "auto_provision": payload.auto_provision,
        "sync_roles": payload.sync_roles,
    })
    log_audit(f"Impostazioni SSO aggiornate da '{current_user.get('sub')}' "
              f"(issuer='{issuer}', attivo={payload.enabled}, "
              f"provisioning automatico={payload.auto_provision}).")
    return {"status": "success"}
