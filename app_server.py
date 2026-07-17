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

import data_config
import db
import crypto_vault  # compat per test_observability_ui.py

from app_settings import (  # noqa: F401
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
        if cfg.get("api_poll_s", 0) > 0:
            from observability.ingesters import api_poller
            app.state.obs_api_poller_task = asyncio.create_task(
                api_poller.poll_loop(cfg["api_poll_s"]), name="obs-api-poller")
    else:
        print("Observability: osservabilità disabilitata, nessun listener UDP "
              "in ascolto.")

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
from routers import scan as _scan_router
from routers import sites as _sites_router
from routers import agent as _agent_router

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
app.include_router(_scan_router.router)
app.include_router(_sites_router.router)
app.include_router(_agent_router.router)

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
        import mcp_server
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
