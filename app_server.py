# -*- coding: utf-8 -*-
import os
import sys
import asyncio
import socket
import threading
import time
import webbrowser

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from contextlib import asynccontextmanager

from core import data_config
from core import db
from security import crypto_vault  # compat for test_observability_ui.py

from core.app_settings import (  # noqa: F401
    PORT, _app_adv_setting, get_app_settings, save_app_settings,
    effective_port, list_local_ips, resolve_bind_host,
)

@asynccontextmanager
async def lifespan(app: "FastAPI"):
    try:
        db.start_writer()
    except db.SchemaTooNewError as e:
        print(f"ERRORE: {e}", file=sys.stderr)
        raise

    from observability import listener_manager
    cfg = data_config.obs_config()
    await listener_manager.apply_obs_config(cfg)
    if cfg["enabled"]:
        print("Observability: listener/task avviati da config.")
    else:
        print("Observability: osservabilità disabilitata, nessun listener UDP "
              "in ascolto.")

    from services import audit_checklist
    audit_checklist.seed_default_template()

    from services import ping_monitor
    ping_monitor.start()

    yield

    ping_monitor.stop()
    # Close the cached SSH transports to the jump-site bastions: they are real
    # long-lived sockets kept open for the process lifetime.
    from core import net_ssh
    net_ssh.close_all()
    await listener_manager.shutdown()
    db.stop_writer()

from core.version import __version__

app = FastAPI(title="SentinelNet API", version=__version__, lifespan=lifespan)

@app.get("/api/version")
def get_app_version():
    return {"app": "SentinelNet", "version": __version__}

from routers import deps as _deps_router  # not a router, but compat
from routers import fortigate as _fortigate_router
from routers import wlc as _wlc_router
from routers import observability as _observability_router
from routers import auth as _auth_router

from routers import inventory as _inventory_router
from routers import catalog as _catalog_router
from routers import settings as _settings_router
from routers import topology as _topology_router
from routers import triage as _triage_router
from routers import commands as _commands_router
from routers import backup as _backup_router
from routers import mac as _mac_router
from routers import arp as _arp_router
from routers import analyzer as _analyzer_router
from routers import ai as _ai_router
from routers import provisioner as _provisioner_router
from routers import mcp as _mcp_router
from routers import mcp_client as _mcp_client_router
from routers import scan as _scan_router
from routers import sites as _sites_router
from routers import agent as _agent_router
from routers import flow_siem as _flow_siem_router
from routers import audit_checklist as _audit_checklist_router
from routers import incidents as _incidents_router
from routers import diagnosis as _diagnosis_router
from routers import endpoint_inventory as _endpoint_inventory_router
from routers import policy_test as _policy_test_router
from routers import config_drift as _config_drift_router
from routers import cloud_backup as _cloud_backup_router
from redundancy import router as _redundancy_router

app.include_router(_fortigate_router.router)
app.include_router(_wlc_router.router)
app.include_router(_observability_router.router)
app.include_router(_auth_router.router)
app.include_router(_inventory_router.router)
app.include_router(_catalog_router.router)
app.include_router(_settings_router.router)
app.include_router(_topology_router.router)
app.include_router(_triage_router.router)
app.include_router(_commands_router.router)
app.include_router(_backup_router.router)
app.include_router(_mac_router.router)
app.include_router(_arp_router.router)
app.include_router(_analyzer_router.router)
app.include_router(_ai_router.router)
app.include_router(_provisioner_router.router)
app.include_router(_mcp_router.router)
app.include_router(_mcp_client_router.router)
app.include_router(_scan_router.router)
app.include_router(_sites_router.router)
app.include_router(_agent_router.router)
app.include_router(_flow_siem_router.router)
app.include_router(_audit_checklist_router.router)
app.include_router(_incidents_router.router)
app.include_router(_diagnosis_router.router)
app.include_router(_endpoint_inventory_router.router)
app.include_router(_redundancy_router.router)
app.include_router(_policy_test_router.router)
app.include_router(_config_drift_router.router)
app.include_router(_cloud_backup_router.router)

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

_CSP = (
    # No remote origin is allowed. Fonts, FontAwesome, vis.js and xterm.js all
    # live under static/: an isolated management LAN cannot resolve
    # cdnjs/unpkg/jsdelivr anyway, so those origins loaded nothing and only
    # widened the surface — with an XSS they are permitted destinations to
    # exfiltrate to, or to pull code from. Adding a CDN tag now fails
    # tests/test_csp.py, which is the point: decide about the isolated site
    # first.
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; "
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

# Vendor e font sono pinnati in static/ e cambiano solo di versione: un anno
# di cache e' sicuro. Il codice dell'app cambia a ogni release: TTL corto
# finche' non esiste il fingerprinting dei nomi file.
@app.middleware("http")
async def cache_control_middleware(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path.startswith("/static/vendor/") or path.startswith("/static/fonts/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=300"
    return response

# Ultimo middleware aggiunto = piu' esterno: comprime il corpo finale.
# I JS pesano (topology.js ~175KB) e la LAN di gestione spesso e' lenta.
app.add_middleware(GZipMiddleware, minimum_size=1024)

def get_resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# Mount the static assets (JS/CSS) extracted from dashboard.html
app.mount("/static", StaticFiles(directory=get_resource_path("static")), name="static")

@app.get("/")
def read_index():
    return FileResponse(get_resource_path(os.path.join("templates", "dashboard.html")))

from routers.deps import (  # noqa: F401
    SESSION_COOKIE, CSRF_HEADER, get_current_user, require_role,
    require_admin, require_operator, user_group_scope,
    assert_group_allowed, assert_device_allowed, filter_map_to_scope,
)

from routers.ai import (  # noqa: F401
    _get_ai_profiles_raw,
    _mask_ai_profile,
    _find_ai_profile,
    _get_active_ai_profile,
)

def open_browser(scheme: str = "http"):
    time.sleep(1.5)
    webbrowser.open(f"{scheme}://localhost:{PORT}/")


def _port_in_use(host: str, port: int) -> bool:
    """True when something already listens on host:port.

    The listening port is the single-instance lock: a second launch would die
    on "address already in use" anyway, so we detect it and hand the user over
    to the instance that is already running.
    """
    probe = "127.0.0.1" if host == "0.0.0.0" else host
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        # ponytail: cannot tell our own server from a foreign one on the same
        # port. Probe /api/version if that ever matters.
        return s.connect_ex((probe, port)) == 0


def reset_admin_cli(username=None) -> int:
    """Break-glass recovery of an administrator password from the CLI.

    The only way back in when the last admin is locked out or disabled. It
    needs local access to users.json, i.e. the same privilege that would allow
    editing that file by hand, so it adds no new trust assumption.
    """
    from getpass import getpass
    from security import user_manager
    from security.security_manager import log_audit

    if not user_manager.has_any_user():
        print("ERRORE: nessun utente registrato. Completare prima il setup iniziale.",
              file=sys.stderr)
        return 1

    if username:
        if user_manager.get_role(username) is None:
            print(f"ERRORE: l'utente '{username}' non esiste.", file=sys.stderr)
            return 1
    else:
        username = user_manager.first_admin_username()
        if not username:
            print("ERRORE: nessun amministratore trovato. Indicare l'account con --user.",
                  file=sys.stderr)
            return 1

    print(f"Reimpostazione password di emergenza (break-glass) per '{username}'.")
    if sys.stdin.isatty():
        new_password = getpass("Nuova password: ")
        if new_password != getpass("Conferma password: "):
            print("ERRORE: le password non coincidono.", file=sys.stderr)
            return 1
    else:
        new_password = sys.stdin.readline().rstrip("\n")

    pw_err = user_manager.password_error(new_password)
    if pw_err:
        print(f"ERRORE: {pw_err}", file=sys.stderr)
        return 1

    if not user_manager.reset_password_break_glass(username, new_password):
        print("ERRORE: aggiornamento dell'account non riuscito.", file=sys.stderr)
        return 1

    log_audit(f"Break-glass CLI: password reimpostata per l'utente '{username}'.")
    print(f"Password di '{username}' reimpostata. L'account e' abilitato e al primo "
          "accesso sara' obbligatorio impostare una nuova password.")
    return 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SentinelNet Server")
    parser.add_argument("--mcp", action="store_true", help="Esegui il server MCP su stdio")
    parser.add_argument("--no-browser", action="store_true", help="Non aprire il browser all'avvio")
    parser.add_argument("--reset-admin", action="store_true",
                        help="Reimposta da CLI la password di un amministratore (break-glass)")
    parser.add_argument("--user", help="Account da reimpostare con --reset-admin "
                                       "(default: primo amministratore)")
    args, _ = parser.parse_known_args()

    if args.mcp:
        from ai import mcp_server
        mcp_server.main()
        return

    if args.reset_admin:
        sys.exit(reset_admin_cli(args.user))

    if not os.path.exists("templates"): 
        os.makedirs("templates")
        
    host = resolve_bind_host()
    port = effective_port()

    _env_nb = os.environ.get("SENTINELNET_NO_BROWSER")
    _env_is_nb = _env_nb.lower() in ("true", "1", "yes") if _env_nb is not None else False
    _nb = args.no_browser or _env_is_nb or bool(_app_adv_setting("no_browser"))
    no_browser = _nb or host == "0.0.0.0"

    try:
        ssl_certfile, ssl_keyfile = data_config.resolve_tls_config()
    except data_config.TlsConfigError as e:
        print(f"ERRORE: {e}", file=sys.stderr)
        sys.exit(1)

    scheme = "https" if ssl_certfile else "http"

    # Istanza singola: un secondo avvio (doppio clic sul collegamento) apre
    # l'interfaccia di quella gia' in esecuzione invece di morire sulla porta
    # occupata.
    if _port_in_use(host, port):
        print(f"SentinelNet e' gia' in esecuzione su {host}:{port}: apro l'interfaccia.")
        if not no_browser:
            webbrowser.open(f"{scheme}://localhost:{port}/")
        return

    if not no_browser:
        threading.Thread(target=open_browser, args=(scheme,), daemon=True).start()

    uvicorn.run(app, host=host, port=port, log_level="info",
                ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)

if __name__ == "__main__":
    main()
