# -*- coding: utf-8 -*-
"""Impostazioni applicative e risoluzione host/porta.

Spostate qui da app_server.py (fase 6.6) per essere usate dai router modulari
e da main() senza import circolari: routers/observability.py importava
get_app_settings/save_app_settings da app_server dentro la funzione proprio
per evitare il ciclo. app_server reimporta questi nomi, quindi i punti di
patch dei test restano invariati.

Il file app_settings.json e' tollerante a mancanza/corruzione: in entrambi i
casi si legge {}.
"""

import json
import os
import socket
import threading

import data_config

PORT = 8765


def _app_adv_setting(key, default=None):
    """Legge una chiave dalla sezione 'app' di app_settings.json (impostazioni
    avanzate configurabili da GUI). Usata anche a import-time, prima che
    get_app_settings sia definita. Le variabili d'ambiente hanno la precedenza
    nei singoli punti di lettura."""
    try:
        with open(data_config.get_path("app_settings.json"), encoding="utf-8") as fh:
            return ((json.load(fh) or {}).get("app") or {}).get(key, default)
    except Exception:
        return default


def effective_port() -> int:
    """Porta HTTP effettiva: env SENTINELNET_PORT > app_settings 'app.port' > 8765."""
    try:
        return int(os.environ.get("SENTINELNET_PORT") or _app_adv_setting("port") or PORT)
    except (TypeError, ValueError):
        return PORT


_app_settings_lock = threading.Lock()

def get_app_settings() -> dict:
    """Legge app_settings.json. Ritorna {} se assente o corrotto."""
    path = data_config.get_path("app_settings.json")
    with _app_settings_lock:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

def save_app_settings(settings: dict) -> None:
    """Salva (merge) le impostazioni su app_settings.json."""
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
    """Enumera gli IP locali senza dipendenze aggiuntive. Include sempre
    '0.0.0.0' (tutte le interfacce) e '127.0.0.1'; esclude i link-local 169.254.*."""
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    # Trucco UDP-connect: ricava l'IP dell'interfaccia usata verso l'esterno.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass
    ips = {ip for ip in ips if not ip.startswith("169.254.")}
    ips.discard("0.0.0.0")
    ips.discard("127.0.0.1")
    return ["0.0.0.0", "127.0.0.1"] + sorted(ips)

def resolve_bind_host() -> str:
    """Ordine di risoluzione dell'host di bind: env SENTINELNET_HOST >
    app_settings.json 'host' > '127.0.0.1'."""
    env = os.environ.get("SENTINELNET_HOST")
    if env:
        return env
    cfg = get_app_settings().get("host")
    if cfg:
        return cfg
    return "127.0.0.1"
