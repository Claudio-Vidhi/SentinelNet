import os
import secrets as _secrets
import sys
import asyncio
import paramiko
import time
import json
import threading
import webbrowser
import requests
import re
from typing import Optional, List, Dict
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, Security, Request, Response, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
from pydantic import BaseModel, Field

import uuid

import data_config
import inventory_manager
import core_engine
import user_manager
import mac_history
import mac_collector
import arp_collector
import config_analyzer
import ai_assistant
import crypto_vault
import switch_provisioner
import fortigate_provisioner
import provisioning_secrets
import fortigate_service
import wlc_service
import site_manager
import mcp_server
import visio_export
from network_scanner import parse_network, scan_subnet
from security_manager import (
    create_access_token, verify_access_token, log_audit,
    is_locked_out, record_failed_attempt, reset_failed_attempts,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)


from app_settings import (  # noqa: F401
    PORT, _app_adv_setting, get_app_settings, save_app_settings,
    effective_port, list_local_ips, resolve_bind_host,
)

from contextlib import asynccontextmanager

import db


@asynccontextmanager
async def lifespan(app: "FastAPI"):
    """Avvio/arresto ordinato (fasi 2.4 + 3.6): (1) migrazione observability.db,
    (2) writer DB, (3) listener UDP e job di retention se abilitati; chiusura
    in ordine inverso con drain. Un errore in avvio fa terminare il processo
    (fail-closed) con messaggio in italiano."""
    try:
        db.start_writer()  # esegue anche migrate() con guardia di versione
    except db.SchemaTooNewError as e:
        print(f"ERRORE: {e}", file=sys.stderr)
        raise

    handles = []
    retention_task = None
    cfg = data_config.obs_config()
    if cfg["enabled"]:
        from observability import rollup
        from observability.ingesters import ipfix, sflow, syslog as syslog_parser
        from observability.ingesters.udp_server import start_udp_listener
        from routers import observability as _obs_router_mod
        listeners = (
            ("ipfix", cfg["ipfix"], ipfix.parse, "flow"),
            ("netflow", cfg["netflow"], ipfix.parse, "flow"),
            ("sflow", cfg["sflow"], sflow.parse, "flow"),
            ("syslog", cfg["syslog"], syslog_parser.parse, "syslog"),
        )
        for name, lcfg, parser, kind in listeners:
            if not lcfg["enabled"]:
                _obs_router_mod.listener_status[name] = {"active": False}
                continue
            try:
                handles.append(await start_udp_listener(
                    cfg["bind"], lcfg["port"], parser, kind, name))
                _obs_router_mod.listener_status[name] = {
                    "active": True, "bind": cfg["bind"], "port": lcfg["port"]}
                print(f"Observability: listener {name} attivo su "
                      f"{cfg['bind']}:{lcfg['port']} (UDP).")
            except OSError as e:
                from observability import metrics as _obs_metrics
                _obs_metrics.inc("listener_bind_failed", listener=name)
                _obs_router_mod.listener_status[name] = {
                    "active": False, "error": str(e)}
                print(f"ERRORE: bind del listener {name} su "
                      f"{cfg['bind']}:{lcfg['port']} fallito ({e}). "
                      "Listener saltato, l'applicazione resta attiva.",
                      file=sys.stderr)
        from observability import correlator
        retention_task = asyncio.create_task(rollup.retention_loop(),
                                             name="obs-retention")
        app.state.obs_correlation_task = asyncio.create_task(
            correlator.correlation_loop(), name="obs-correlation")
        # Poller REST (§9.2): snapshot periodici dai FortiGate con token API.
        if cfg.get("api_poll_s", 0) > 0:
            from observability.ingesters import api_poller
            app.state.obs_api_poller_task = asyncio.create_task(
                api_poller.poll_loop(cfg["api_poll_s"]), name="obs-api-poller")
    else:
        print("Observability: osservabilità disabilitata, nessun listener UDP "
              "in ascolto (abilitare con SENTINELNET_OBS_ENABLE=1 o "
              "\"observability.enabled\" in app_settings.json).")

    yield

    if retention_task:
        retention_task.cancel()
        for attr in ("obs_correlation_task", "obs_api_poller_task"):
            task = getattr(app.state, attr, None)
            if task:
                task.cancel()
    for handle in handles:
        await handle.stop()
    db.stop_writer()


app = FastAPI(title="SentinelNet API", version="0.2.0-beta.1", lifespan=lifespan)
from routers import agent as _agent_router
app.include_router(_agent_router.router)
from routers import sites as _sites_router
app.include_router(_sites_router.router)
from routers import scan as _scan_router
app.include_router(_scan_router.router)
from routers import mcp as _mcp_router
app.include_router(_mcp_router.router)
from routers import provisioner as _provisioner_router
app.include_router(_provisioner_router.router)
from routers import ai as _ai_router
app.include_router(_ai_router.router)

from routers.ai import (  # noqa: F401  (compat: test_app_server_ai_profiles)
    _get_ai_profiles_raw,
    _mask_ai_profile,
    _find_ai_profile,
    _get_active_ai_profile,
)
from routers import analyzer as _analyzer_router
app.include_router(_analyzer_router.router)
from routers import arp as _arp_router
app.include_router(_arp_router.router)
from routers import mac as _mac_router
app.include_router(_mac_router.router)
from routers import backup as _backup_router
app.include_router(_backup_router.router)
from routers import commands as _commands_router
app.include_router(_commands_router.router)
from routers import triage as _triage_router
app.include_router(_triage_router.router)

from routers.mac import MacScanSchema

# =========================================================================
from routers import topology as _topology_router
app.include_router(_topology_router.router)
from routers import settings as _settings_router
app.include_router(_settings_router.router)
from routers import catalog as _catalog_router
app.include_router(_catalog_router.router)
from routers import inventory as _inventory_router
app.include_router(_inventory_router.router)

# Router modulari (fase 2.2/2.3/6.6): percorsi identici al monolite pre-refactor.
from routers import fortigate as _fortigate_router
from routers import wlc as _wlc_router
from routers import observability as _observability_router
from routers import auth as _auth_router
app.include_router(_fortigate_router.router)
app.include_router(_wlc_router.router)
app.include_router(_observability_router.router)
app.include_router(_auth_router.router)


# Abilita CORS. Le origini consentite sono configurabili via SENTINELNET_CORS_ORIGINS
# (lista separata da virgole). Default: solo localhost sulla porta dell'app.
# Nota: usare "*" insieme ad allow_credentials=True è invalido per spec ed è
# rifiutato dai browser, quindi le origini vengono sempre elencate esplicitamente.
_default_origins = f"http://localhost:{effective_port()},http://127.0.0.1:{effective_port()}"
ALLOWED_ORIGINS = [
    o.strip()
    for o in (os.environ.get("SENTINELNET_CORS_ORIGINS")
              or _app_adv_setting("cors_origins")
              or _default_origins).split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Header di sicurezza su ogni risposta (audit L-2). La CSP consente solo
# i CDN effettivamente usati da dashboard.html (fonts, font-awesome, vis-network, xterm).
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = _CSP
    return response

security_scheme = HTTPBearer(auto_error=False)

def get_resource_path(relative_path):
    """Restituisce il percorso assoluto della risorsa, funzionando sia in dev che bundled."""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# --- DIPENDENZE DI AUTENTICAZIONE (JWT) ---

# Autenticazione e scoping multi-gruppo: spostati in routers/deps.py (fase 2.1).
# Reimportati qui per compatibilità con il resto del monolite e con i test.
from routers.deps import (  # noqa: F401
    SESSION_COOKIE, CSRF_HEADER, get_current_user, require_role,
    require_admin, require_operator, user_group_scope,
    assert_group_allowed, assert_device_allowed, filter_map_to_scope,
)

# --- MODELLI DI VALIDAZIONE PYDANTIC ---





































# --- Modelli push agente (autenticazione per-sede, non JWT utente) ---






# --- STATO DEI JOB DI TRIAGE IN BACKGROUND CON LOCK ---


# Job di invio comandi massivo (bulk) con polling, come per le scansioni.

# Comandi distruttivi vietati anche nell'invio massivo, indipendentemente dalla
# modalità: cancellano/riavviano l'apparato. NON si blocca 'conf t' né 'delete'
# (legittimi nel push di configurazione, p.es. in config mode o su Juniper).



triage_job = {
    "status": "idle",       # "idle", "running", "complete"
    "progress": 0,
    "total": 0,
    "current_device": "",
    "results": []
}




# --- ROTTE PRINCIPALI & INTERFACCIA WEB ---

@app.get("/")
def read_index():
    return FileResponse(get_resource_path(os.path.join("templates", "dashboard.html")))

# --- ROTTE DI AUTENTICAZIONE (JWT): spostate in routers/auth.py (fase 6.6) ---

# --- ROTTE DISPOSITIVI (INVENTARIO) ---

def get_devices_and_versions(current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    devices = inventory_manager.get_all_devices()
    versions = inventory_manager.get_detected_versions()
    groups = inventory_manager.get_all_groups()
    if scope is not None:
        devices = [d for d in devices if d.get('Group') in scope]
        allowed_ips = {d['IP'] for d in devices}
        versions = {ip: v for ip, v in versions.items() if ip in allowed_ips}
        groups = {g: v for g, v in groups.items() if g in scope}
    return {
        "devices": devices,
        "detected_versions": versions,
        "groups": groups
    }

def export_devices_csv(current_user = Depends(get_current_user)):
    import csv, io
    scope = user_group_scope(current_user)
    devices = inventory_manager.get_all_devices()
    if scope is not None:
        devices = [d for d in devices if d.get('Group') in scope]
    versions = inventory_manager.get_detected_versions()
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["Hostname", "IP", "Vendor", "Group", "Version", "Status"],
        extrasaction="ignore"
    )
    writer.writeheader()
    for d in devices:
        scan = versions.get(d["IP"], {})
        writer.writerow({
            "Hostname": d.get("Hostname") or d.get("IP"),
            "IP":       d["IP"],
            "Vendor":   d.get("Vendor", ""),
            "Group":    d.get("Group", ""),
            "Version":  scan.get("version", "Non Scansionato"),
            "Status":   scan.get("status", "unknown"),
        })
    content = output.getvalue()
    log_audit(f"Export CSV dispositivi richiesto dall'utente '{current_user.get('sub')}'.")
    from fastapi.responses import Response as FastResponse
    return FastResponse(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinelnet-devices.csv"}
    )

def add_device(device: DeviceSchema, current_user = Depends(require_operator)):
    assert_group_allowed(current_user, device.group)
    # Impedisce di modificare un dispositivo esistente in una sede non consentita
    existing = next((d for d in inventory_manager.get_all_devices() if d['IP'] == device.ip), None)
    if existing:
        assert_group_allowed(current_user, existing.get('Group', 'Generale'))
    try:
        inventory_manager.add_or_update_device(
            device.ip, device.vendor, device.profile,
            device.username, device.password, device.enable_secret, device.group,
            ssh_port=device.ssh_port, transports=device.transports
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    log_audit(f"Dispositivo '{device.ip}' (vendor: '{device.vendor}', gruppo: '{device.group}') aggiunto/aggiornato dall'utente '{current_user.get('sub')}'.")
    # §11.6: Telnet è in chiaro — traccia esplicitamente l'abilitazione.
    if device.transports and 'telnet' in device.transports:
        log_audit(f"ATTENZIONE: Telnet (trasmissione in chiaro) abilitato per il dispositivo '{device.ip}' dall'utente '{current_user.get('sub')}'.")
    return {"status": "success", "message": "Dispositivo salvato"}

def delete_device(payload: DeviceDelete, current_user = Depends(require_operator)):
    assert_device_allowed(current_user, payload.ip)
    inventory_manager.delete_device(payload.ip)
    log_audit(f"Dispositivo '{payload.ip}' eliminato dall'inventario dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}

def rename_device(payload: DeviceRenameSchema, current_user = Depends(require_operator)):
    """Rinomina un dispositivo gestito impostandone manualmente l'hostname (il
    nome mostrato in inventario e sulla mappa). admin/operator, con scoping."""
    assert_device_allowed(current_user, payload.ip)
    if not next((d for d in inventory_manager.get_all_devices() if d['IP'] == payload.ip), None):
        raise HTTPException(status_code=404, detail="Dispositivo non trovato in inventario.")
    hostname = payload.hostname.strip()
    inventory_manager.update_device_hostname(payload.ip, hostname)
    log_audit(f"Dispositivo '{payload.ip}' rinominato in '{hostname or '(vuoto)'}' dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}

def import_csv(payload: CSVImportRequest, current_user = Depends(require_operator)):
    lines = payload.csv_data.split('\n')
    import csv as csv_parser
    reader = csv_parser.DictReader(lines)
    
    results = {"imported": [], "failed": []}
    scope = user_group_scope(current_user)

    for i, row in enumerate(reader, start=2):  # start=2 perché riga 1 è l'header
        try:
            ip = row.get('IP')
            if not ip or not ip.strip():
                raise ValueError("IP mancante o vuoto")

            ip = ip.strip()

            # Se il campo Group è presente e non vuoto, chiama immediatamente inventory_manager.add_group(row['Group'])
            group_name = (row.get('Group') or '').strip() or 'Generale'
            # Scoping: un operatore limitato non può importare in sedi non consentite
            if scope is not None and group_name not in scope:
                raise ValueError(f"Sede '{group_name}' non consentita per il tuo profilo")
            if group_name != 'Generale':
                inventory_manager.add_group(group_name)

            username = (row.get('Username') or '').strip()
            password = (row.get('Password') or '').strip()
            enable_secret = (row.get('Enable Secret') or '').strip()
            
            # Il campo Hostname (nome switch) viene estratto ma attualmente ignorato nel salvataggio
            hostname = (row.get('Hostname') or '').strip()
            
            vendor = (row.get('Vendor') or '').strip() or 'cisco'
            
            # Rimozione Profile: passa forzatamente il valore "custom" come parametro profile
            inventory_manager.add_or_update_device(
                ip, vendor, "custom",
                username, password, enable_secret,
                group_name
            )
            results["imported"].append(ip)
        except Exception as e:
            results["failed"].append({
                "row": i,
                "ip": row.get('IP', '?'),
                "error": str(e)
            })
            
    log_audit(f"Importazione massiva da CSV completata dall'utente '{current_user.get('sub')}'. Importati: {len(results['imported'])}, Falliti: {len(results['failed'])}.")
    return results

# --- CRUD GESTIONE GRUPPI VIA WEB UI ---





# --- CRUD GESTIONE VENDOR ---




# --- CATEGORIE / CLASSIFICAZIONE DISPOSITIVI ---






def promote_device(payload: PromoteDeviceSchema, current_user = Depends(require_operator)):
    """Promuove un dispositivo scoperto (CDP/LLDP) a dispositivo gestito,
    aggiungendolo all'inventario così da poter essere sottoposto a triage.
    Le credenziali vanno completate dopo, nella pagina Inventario."""
    assert_group_allowed(current_user, payload.group)
    if payload.group not in inventory_manager.get_all_groups():
        raise HTTPException(status_code=400, detail=f"Sede '{payload.group}' inesistente.")
    existing = next((d for d in inventory_manager.get_all_devices() if d['IP'] == payload.ip), None)
    if existing:
        raise HTTPException(status_code=400, detail=f"Dispositivo {payload.ip} già in inventario.")
    inventory_manager.add_or_update_device(
        payload.ip, payload.vendor, "custom", "", "", "", payload.group
    )
    # Trasferisce l'eventuale classificazione manuale dal nodo scoperto all'IP.
    inventory_manager.migrate_assignment(payload.node_id, payload.ip)
    # Eredita ciò che è già stato scoperto via CDP/LLDP: categoria, modello,
    # versione e hostname, così il dispositivo promosso non riparte "vuoto".
    meta = {}
    if payload.device_type:
        meta["category"] = payload.device_type
    if payload.model:
        meta["model"] = payload.model
    # Eredita il nome scelto: sia come hostname CSV (tabella/triage) sia come
    # override 'name' (etichetta su mappa e tab Categorie), così resta coerente.
    if payload.hostname:
        meta["name"] = payload.hostname
    if meta:
        inventory_manager.set_device_meta(payload.ip, **meta)
    if payload.version:
        inventory_manager.update_version_inventory(
            payload.ip, payload.vendor, payload.version, "discovered"
        )
    if payload.hostname:
        inventory_manager.update_device_hostname(payload.ip, payload.hostname)
    log_audit(
        f"Dispositivo scoperto '{payload.node_id}' promosso a gestito "
        f"(IP {payload.ip}, vendor {payload.vendor}, sede {payload.group}) "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

# --- REGISTRO MODELLI (per vendor) ---




# --- IMPOSTAZIONI DI RETE (bind IP, solo amministratori) ---






# Impostazioni avanzate (sezione 'app' di app_settings.json): configurabili da
# GUI così l'exe non richiede variabili d'ambiente. Env > JSON > default.
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






# --- ENDPOINTS COSTRUZIONE MAPPA TOPOLOGICA ---









# --- ROTTE AUTOMAZIONE & DOWNLOAD ---




# Blacklist di comandi CLI pericolosi, distruttivi o bloccanti










def reassign_device(payload: DeviceReassignSchema, current_user = Depends(require_operator)):
    """Sposta un dispositivo in un gruppo diverso aggiornando solo il campo Group nel CSV."""
    devices = inventory_manager.get_all_devices()
    groups  = inventory_manager.get_all_groups()

    target = next((d for d in devices if d['IP'] == payload.ip), None)
    if not target:
        raise HTTPException(status_code=404, detail="Dispositivo non trovato in inventario.")
    if payload.new_group not in groups:
        raise HTTPException(
            status_code=400,
            detail=f"Gruppo '{payload.new_group}' non esiste. Crealo prima."
        )

    # Scoping: la sede di origine e quella di destinazione devono essere consentite
    assert_group_allowed(current_user, target.get('Group', 'Generale'))
    assert_group_allowed(current_user, payload.new_group)

    old_group = target.get('Group', 'Generale')
    target['Group'] = payload.new_group
    inventory_manager.safe_write_hosts_csv(devices)

    log_audit(
        f"Dispositivo '{payload.ip}' spostato dal gruppo '{old_group}' "
        f"al gruppo '{payload.new_group}' dall'utente '{current_user.get('sub')}'."
    )
    return {"status": "success", "message": f"Dispositivo spostato in '{payload.new_group}'"}



# Docker note: is_reachable() uses a TCP probe on port 22. Ensure the container
# has outbound TCP 22 allowed to the management VLAN in your docker-compose network policy.



# --- PROXY MIRATO VERSO ENISA EUVD (SOSTITUISCE IL CATCH-ALL PERICOLOSO) ---

# Parametri ammessi da /api/search come da documentazione EUVD: qualunque altro
# parametro viene scartato prima di inoltrare la richiesta al servizio ENISA.


# --- MAC ADDRESS TRACKER (storicizzazione + ricerca) ---



# --- Risoluzione origine/transito basata sulla topologia GLOBALE ---
# Il difetto storico: is_uplink veniva deciso per-switch al momento della
# raccolta, dal solo backup di quello switch. Se una porta di dorsale non aveva
# un vicino CDP/LLDP "vivo" in quell'istante, veniva scambiata per porta di
# accesso: lo stesso MAC compariva così come "posizione" su più switch.
#
# Qui la classificazione è rifatta a READ-TIME contro la mappa topologica
# globale (generate_network_map), che aggrega le adiacenze viste da TUTTI gli
# apparati e fa dedup + aggregazione port-channel. In più consideriamo dorsale
# SOLO una porta il cui vicino è infrastruttura (switch/router): una porta verso
# un server/PC/AP resta correttamente "accesso".

_MAC_INFRA_TYPES = {"switch", "router"}





















# --- Comandi ad-hoc per apparati non ordinari (es. C8000V bridge-domain) ---







# --- MAC <-> IP MATCHING (tabelle ARP dei gateway L3: switch SVI / firewall) ---






# --- CONFIG ANALYZER: analisi running-config dai backup ---





# --- AI ASSISTANT: provider pluggabili (Anthropic/OpenAI/Gemini/Ollama) ---
# La configurazione vive in app_settings.json sotto forma di PROFILI di
# connessione ("ai_profiles": lista di dict, "ai_active_profile": id del
# profilo attivo usato dalla chat). La API key di ogni profilo viene cifrata
# con lo stesso CIPHER_SUITE usato per le password degli apparati
# (crypto_vault), mai salvata in chiaro su disco e mai restituita in chiaro
# dalle GET (solo un flag booleano ``api_key_set``).
#
# Retrocompatibilità: se il vecchio formato a profilo singolo (chiave "ai")
# esiste ancora e "ai_profiles" non è mai stato inizializzato, viene
# migrato automaticamente in un profilo "Default" alla prima lettura.

_AI_PROVIDERS = {"anthropic", "openai", "gemini", "ollama"}




















# --- SWITCH PROVISIONER: config "da zero" (view/SSH/console-seriale) ---








# --- FORTIGATE PROVISIONER: ZTP firewall FortiGate (view/SSH/console-seriale) ---






# --- FORTIGATE / WLC LIVE: estratti nei router modulari (fase 2.2/2.3) ---
# Vedi routers/fortigate.py e routers/wlc.py; inclusi in app più sotto.

# --- MCP SERVER: controllo dei tool esposti ai client LLM esterni ---
# Il catalogo dei tool vive in mcp_server.TOOLS (unica fonte); qui si gestisce
# solo l'elenco dei tool DISABILITATI, persistito in app_settings.json ("mcp").

# Tool disabilitati di default finché l'admin non salva una scelta esplicita
# (Decisione #7 pendente: i dati di flusso verso LLM esterni sono opt-in).
_MCP_DEFAULT_DISABLED = {"get_top_talkers", "get_anomalies"}







# --- SCANSIONE SUBNET IN BACKGROUND ---





# --- GESTIONE SEDI MULTI-SITE (solo amministratori) ---






# --- Relay comandi CLI verso una sede agent (UI -> coda -> agente) ---





# --- ENDPOINT PER GLI AGENTI DI SEDE (auth per-sede, separata dal JWT utente) ---








# --- AVVIO E BROWSER AUTOMATICO ---

def open_browser(scheme: str = "http"):
    time.sleep(1.5)
    webbrowser.open(f"{scheme}://localhost:{PORT}/")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SentinelNet Server")
    parser.add_argument("--mcp", action="store_true", help="Esegui il server MCP (Model Context Protocol) su stdio")
    args, _ = parser.parse_known_args()

    if args.mcp:
        import mcp_server
        mcp_server.main()
        return

    if not os.path.exists("templates"): 
        os.makedirs("templates")
        
    # Ordine di risoluzione: env SENTINELNET_HOST > app_settings.json > 127.0.0.1
    host = resolve_bind_host()
    port = effective_port()

    # Disabilita l'apertura automatica del browser in ambiente Docker/containerizzato
    _env_nb = os.environ.get("SENTINELNET_NO_BROWSER")
    _nb = _env_nb.lower() == "true" if _env_nb is not None else bool(_app_adv_setting("no_browser"))
    no_browser = _nb or host == "0.0.0.0"

    # TLS nativo opzionale (finding H-1): fail-closed su configurazione parziale.
    try:
        ssl_certfile, ssl_keyfile = data_config.resolve_tls_config()
    except data_config.TlsConfigError as e:
        print(f"ERRORE: {e}", file=sys.stderr)
        sys.exit(1)

    if not no_browser:
        scheme = "https" if ssl_certfile else "http"
        threading.Thread(target=open_browser, args=(scheme,), daemon=True).start()

    uvicorn.run(app, host=host, port=port, log_level="info",
                ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)

if __name__ == "__main__":
    main()
