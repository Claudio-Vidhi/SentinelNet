# -*- coding: utf-8 -*-
"""Router Settings. Estratto da app_server.py (fase 6.6): percorsi, metodi,
parametri e risposte identici al monolite."""

import os
import re
import sys

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
            detail=f"Group '{payload.tenant}' is not allowed for your profile.")
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


def _install_kind() -> str:
    """Come gira questa istanza: da repo git, da exe PyInstaller, o da una
    copia dei sorgenti senza repo. La terza non e' un dettaglio: chi ha
    scaricato uno zip non puo' aggiornare con git piu' di quanto possa un exe."""
    if getattr(sys, "frozen", False):
        return "exe"
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return "git" if os.path.isdir(os.path.join(root, ".git")) else "source"


@router.get("/api/fleet/versions")
def get_fleet_versions(current_user = Depends(require_admin)):
    """Cosa sta girando in ogni pezzo della flotta: il centrale e ogni agente.

    Risponde senza SSH alla domanda "l'aggiornamento e' arrivato ovunque?"."""
    from core.version import __version__
    from services import site_manager
    kind = _install_kind()
    agents = []
    for s in site_manager.list_sites():
        if s.get("mode") != "agent":
            continue
        v = s.get("agent_version") or ""
        agents.append({
            "site_id": s["id"], "name": s.get("name", ""),
            "version": v, "commit": s.get("agent_commit", ""),
            "branch": s.get("agent_branch", ""),
            "dirty": bool(s.get("agent_dirty")),
            "last_seen": s.get("last_seen"),
            # Confronto grezzo di stringhe: una versione diversa da quella del
            # centrale e' esattamente cio' che l'operatore deve vedere, e non
            # serve un parser SemVer per dirlo.
            "behind": bool(v) and v != __version__,
        })
    return {"central": {"version": __version__, "install_kind": kind},
            "install_kind": kind, "agents": agents}


# Nome FISSO del servizio Windows. Non e' configurabile di proposito: e' il
# nome che finisce in una riga di comando, e un nome che arriva da fuori
# trasformerebbe questa rotta in una shell remota.
WINDOWS_SERVICE_NAME = "SentinelNet"


def _supervisor() -> str:
    """Chi rimettera' in piedi il processo dopo l'uscita: '' se nessuno.

    Su Linux: systemd esporta INVOCATION_ID a ogni unit che avvia, quindi la
    sua assenza significa che "riavvia" e' solo "termina".

    Su Windows non esiste una variabile equivalente -- un servizio non si
    distingue dall'esterno da un exe lanciato a mano -- quindi e' chi installa
    il servizio a dichiararlo con SENTINELNET_WINDOWS_SERVICE=1. Stessa
    logica del caso systemd: e' il supervisore a dire di esserci."""
    if os.environ.get("INVOCATION_ID"):
        return "systemd"
    if sys.platform == "win32" and os.environ.get("SENTINELNET_WINDOWS_SERVICE"):
        return "windows-service"
    # Un exe PyInstaller avviato a mano non ha nessuno che lo rialzi. Sotto un
    # servizio Windows invece e' normale che sia frozen, ed e' il ramo sopra
    # a coprirlo.
    return ""


def _is_supervised() -> bool:
    """Compatibilita': la rotta ragiona su _supervisor(), i test su questo."""
    return bool(_supervisor())


@router.post("/api/settings/restart")
def restart_application(current_user = Depends(require_admin)):
    """Riavvia l'applicazione delegando a un processo separato.

    L'app non si uccide MAI da sola: su Linux e' la unit oneshot
    sentinelnet-restart.service a riavviare sentinelnet.service, su Windows e'
    un powershell staccato a fare Restart-Service. Cosi' un riavvio fallito
    lascia in piedi il processo vecchio, invece di lasciare la macchina senza
    pannello.

    L'argv e' FISSO su entrambi i sistemi: nulla del corpo della richiesta lo
    raggiunge, altrimenti questa rotta sarebbe una shell remota sulla macchina
    che custodisce le credenziali di ogni sede."""
    kind = _supervisor()
    if not kind:
        raise HTTPException(
            status_code=409,
            detail="L'applicazione non e' gestita da un supervisore: un "
                   "riavvio la spegnerebbe soltanto. Riavviala da systemd o "
                   "dal gestore servizi di Windows.")
    _spawn_restart(kind)
    log_audit(f"Riavvio dell'applicazione richiesto da '{current_user.get('sub')}' "
              f"(supervisore: {kind}).")
    return {"status": "scheduled", "supervisor": kind}


def _spawn_restart(kind: str) -> None:
    """Fa partire il riavvio delegandolo a un processo separato.

    Estratta perche' ha due chiamanti: il pulsante di riavvio e
    l'aggiornamento, che deve riavviare per applicare il codice appena
    scaricato. Due copie di questa logica divergerebbero, e la copia
    sbagliata sarebbe quella che spegne il pannello."""
    import subprocess
    if kind == "windows-service":
        # Staccato, e senza aspettarlo: Restart-Service ferma QUESTO processo,
        # quindi un subprocess.run atteso non tornerebbe mai. Il prezzo e' che
        # l'esito non si conosce -- lo stesso prezzo di --no-block su Linux.
        try:
            subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Restart-Service", "-Name", WINDOWS_SERVICE_NAME],
                creationflags=getattr(subprocess, "DETACHED_PROCESS", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        except Exception as e:
            raise HTTPException(status_code=409,
                                detail=f"Riavvio non disponibile: {e}")
    else:
        try:
            proc = subprocess.run(
                ["sudo", "-n", "systemctl", "start", "--no-block",
                 "sentinelnet-restart.service"],
                capture_output=True, text=True, timeout=15)
        except Exception as e:
            raise HTTPException(status_code=409, detail=f"Riavvio non disponibile: {e}")
        if proc.returncode != 0:
            raise HTTPException(
                status_code=409,
                detail="sudo ha rifiutato il comando di riavvio: "
                       f"{(proc.stderr or proc.stdout or '').strip()}")


@router.post("/api/settings/update")
def update_application(current_user = Depends(require_admin)):
    """Aggiorna il centrale: git pull, dipendenze, riavvio. In quest'ordine.

    L'agente si aggiorna da solo dal 0.27.1; qui c'era ancora la sequenza a
    mano via SSH, cioe' la shell che questa tab esiste per evitare.

    Ogni argv e' FISSO: niente del corpo della richiesta lo raggiunge. Non
    esiste un parametro per il remote, il branch o il repository, perche' un
    parametro qui sarebbe esecuzione di codice arbitrario sulla macchina che
    custodisce le credenziali di ogni sede."""
    import subprocess
    kind = _install_kind()
    if kind != "git":
        raise HTTPException(
            status_code=409,
            detail=f"Installazione '{kind}': non c'e' un repository git da cui "
                   "aggiornare. Sostituisci l'eseguibile, o reinstalla da sorgenti.")
    supervisor = _supervisor()
    if not supervisor:
        # Scaricare il codice nuovo e non poterlo applicare lascia l'albero
        # avanti e il processo indietro: lo stato piu' confuso possibile.
        raise HTTPException(
            status_code=409,
            detail="L'applicazione non e' gestita da un supervisore: "
                   "l'aggiornamento non potrebbe essere applicato.")

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        pull = subprocess.run(["git", "pull"], cwd=root, capture_output=True,
                              text=True, timeout=120)
    except Exception as e:
        raise HTTPException(status_code=409, detail=f"git non disponibile: {e}")
    output = (pull.stdout or "") + (pull.stderr or "")
    if pull.returncode != 0:
        raise HTTPException(status_code=409,
                            detail=f"git pull fallito:\n{output.strip()[-2000:]}")
    if "Already up to date" in output:
        # Niente installazione e niente riavvio: interromperebbero le sessioni
        # aperte per applicare esattamente nulla.
        log_audit(f"Aggiornamento richiesto da '{current_user.get('sub')}': "
                  "gia' aggiornato.")
        return {"status": "up-to-date", "output": output.strip()}

    # Le dipendenze PRIMA del riavvio, con l'interprete che sta girando: un
    # aggiornamento che ne aggiunge una, riavviato senza installarla, non
    # riparte piu' e lascia la rete senza pannello.
    dep = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r",
         os.path.join(root, "requirements.txt")],
        cwd=root, capture_output=True, text=True, timeout=900)
    if dep.returncode != 0:
        raise HTTPException(
            status_code=409,
            detail="Dipendenze non installate, riavvio annullato (resta in "
                   "esecuzione la versione precedente, che funziona):\n"
                   f"{(dep.stderr or dep.stdout or '').strip()[-2000:]}")

    _spawn_restart(supervisor)
    log_audit(f"Aggiornamento dell'applicazione eseguito da "
              f"'{current_user.get('sub')}' (supervisore: {supervisor}).")
    return {"status": "updating", "supervisor": supervisor,
            "output": output.strip()}


class SelfSignedCertSchema(BaseModel):
    host: str


# Solo un IPv4 letterale o un nome DNS: e' cio' che un SAN puo' contenere, e
# un host fuori da queste due forme e' un errore di battitura, non un caso
# d'uso. La validazione resta anche ora che il certificato non passa piu' da
# una riga di comando.
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DNS_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                     r"(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


@router.post("/api/settings/tls/self-signed")
def generate_self_signed_cert(payload: SelfSignedCertSchema,
                              current_user = Depends(require_admin)):
    """Genera certificato e chiave self-signed per questo host.

    Il subjectAltName porta l'indirizzo con cui i client contattano davvero il
    pannello: senza, ogni client moderno rifiuta il certificato qualunque sia
    il CN.

    Il certificato e' costruito con `cryptography`, che e' gia' una dipendenza
    obbligatoria (la usa crypto_vault). Chiamare `openssl` costringeva a
    sperare che fosse nel PATH -- su Windows di norma non c'e' -- e la versione
    di macOS e' LibreSSL, che rifiuta -addext. Qui la funzione si comporta
    identica su ogni sistema operativo."""
    from datetime import datetime, timedelta, timezone
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    host = (payload.host or "").strip()
    is_ip = bool(_IPV4_RE.match(host))
    if is_ip:
        if any(int(o) > 255 for o in host.split(".")):
            raise HTTPException(status_code=400, detail="Indirizzo IPv4 non valido.")
    elif not (host and len(host) <= 253 and _DNS_RE.match(host)):
        raise HTTPException(
            status_code=400,
            detail="Host non valido: usare un indirizzo IPv4 o un nome DNS.")

    certs_dir = data_config.get_path("certs")
    os.makedirs(certs_dir, exist_ok=True)
    certfile = os.path.join(certs_dir, "server.crt")
    keyfile = os.path.join(certs_dir, "server.key")
    if os.path.exists(certfile) or os.path.exists(keyfile):
        raise HTTPException(
            status_code=409,
            detail="Un certificato esiste gia'. Rimuovi o archivia "
                   f"{certfile} e {keyfile} prima di generarne uno nuovo.")

    days = 825
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    san = x509.IPAddress(ipaddress.ip_address(host)) if is_ip else x509.DNSName(host)
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))

    # La chiave prima del certificato, e i permessi subito dopo averla scritta:
    # tra la creazione e restrict_permissions il file esiste con i permessi
    # ereditati dalla cartella, e quella finestra va tenuta corta.
    with open(keyfile, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
    # Non os.chmod: su Windows non restringe nulla e la chiave privata
    # resterebbe leggibile da chiunque erediti i permessi della cartella.
    # restrict_permissions usa icacls la' e chmod 600 su POSIX.
    data_config.restrict_permissions(keyfile)
    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    log_audit(f"Certificato self-signed generato per '{host}' da "
              f"'{current_user.get('sub')}'.")
    return {"certfile": certfile, "keyfile": keyfile, "days": days,
            "not_after": cert.not_valid_after_utc.isoformat()}
