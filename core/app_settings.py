# -*- coding: utf-8 -*-
"""Application settings and host/port resolution.

Moved here from app_server.py (phase 6.6) to be used by modular routers
and by main() without circular imports: routers/observability.py imported
get_app_settings/save_app_settings from app_server inside the function
precisely to avoid the cycle. app_server re-imports these names, so the
test patch points remain unchanged.

The app_settings.json file is tolerant to absence/corruption: in both
cases {} is read.
"""

import json
import os
import socket
import threading

from core import data_config

PORT = 8765


def _app_adv_setting(key, default=None):
    """Reads a key from the 'app' section of app_settings.json (advanced
    settings configurable from GUI). Also used at import-time, before
    get_app_settings is defined. Environment variables take precedence
    at each read point."""
    try:
        with open(data_config.get_path("app_settings.json"), encoding="utf-8") as fh:
            return ((json.load(fh) or {}).get("app") or {}).get(key, default)
    except Exception:
        return default


def effective_port() -> int:
    """Effective HTTP port: env SENTINELNET_PORT > app_settings 'app.port' > 8765."""
    try:
        return int(os.environ.get("SENTINELNET_PORT") or _app_adv_setting("port") or PORT)
    except (TypeError, ValueError):
        return PORT


_app_settings_lock = threading.Lock()

def get_app_settings() -> dict:
    """Reads app_settings.json. Returns {} if absent or corrupt."""
    path = data_config.get_path("app_settings.json")
    with _app_settings_lock:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

def save_app_settings(settings: dict) -> None:
    """Saves (merges) settings to app_settings.json."""
    path = data_config.get_path("app_settings.json")
    with _app_settings_lock:
        current = {}
        try:
            with open(path, encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                current = loaded
        except (OSError, ValueError):
            current = {}
        current.update(settings)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(current, fh, indent=2)

def list_local_ips() -> list:
    """Enumerates local IPs without additional dependencies. Always includes
    '0.0.0.0' (all interfaces) and '127.0.0.1'; excludes link-local 169.254.*."""
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    # UDP-connect trick: obtains the IP of the interface used toward the outside.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass
    ips = {ip for ip in ips if isinstance(ip, str) and not ip.startswith("169.254.")}
    ips.discard("0.0.0.0")
    ips.discard("127.0.0.1")
    return ["0.0.0.0", "127.0.0.1"] + sorted(ips)

def resolve_bind_host() -> str:
    """Bind host resolution order: env SENTINELNET_HOST >
    app_settings.json 'host' > '127.0.0.1'."""
    env = os.environ.get("SENTINELNET_HOST")
    if env:
        return env
    cfg = get_app_settings().get("host")
    if cfg:
        return cfg
    return "127.0.0.1"
