# -*- coding: utf-8 -*-
import os
import sys
import asyncio
import threading
import time
import webbrowser

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from contextlib import asynccontextmanager

from core import data_config
from core import db
from security import crypto_vault  # compat per test_observability_ui.py

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

    yield

    await listener_manager.shutdown()
    db.stop_writer()

app = FastAPI(title="SentinelNet API", version="0.2.0-beta.1", lifespan=lifespan)

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
app.include_router(_redundancy_router.router)

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

def get_resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# Monta gli asset statici (JS/CSS) estratti dal dashboard.html
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

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SentinelNet Server")
    parser.add_argument("--mcp", action="store_true", help="Esegui il server MCP su stdio")
    args, _ = parser.parse_known_args()

    if args.mcp:
        from ai import mcp_server
        mcp_server.main()
        return

    if not os.path.exists("templates"): 
        os.makedirs("templates")
        
    host = resolve_bind_host()
    port = effective_port()

    _env_nb = os.environ.get("SENTINELNET_NO_BROWSER")
    _nb = _env_nb.lower() == "true" if _env_nb is not None else bool(_app_adv_setting("no_browser"))
    no_browser = _nb or host == "0.0.0.0"

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
