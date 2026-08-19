# -*- coding: utf-8 -*-
"""Continuous ICMP monitor for inventory devices.

Enabled from Settings: a background thread pings every inventory device at a
user-defined interval and keeps per-device state (up/down, last check,
transitions) in memory.

Configuration stored in app_settings.json::

    {"ping_monitor": {"enabled": true, "interval_seconds": 60}}

The worker re-reads the configuration on every cycle, so enable/disable and
interval changes apply immediately without a restart.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from core.app_settings import get_app_settings, save_app_settings
from security.security_manager import log_audit

DEFAULT_INTERVAL = 60
MIN_INTERVAL = 5
MAX_INTERVAL = 86400

_lock = threading.Lock()
_state = {}          # ip -> {up, last_check, last_change, checks, fails}
_thread = None       # worker thread
_stop = threading.Event()
_cycle = threading.Event()   # wake the worker immediately on config change
_last_run = None     # timestamp of the last completed cycle


def get_config() -> dict:
    cfg = get_app_settings().get("ping_monitor") or {}
    enabled = bool(cfg.get("enabled", False))
    try:
        interval = int(cfg.get("interval_seconds") or DEFAULT_INTERVAL)
    except (TypeError, ValueError):
        interval = DEFAULT_INTERVAL
    interval = max(MIN_INTERVAL, min(MAX_INTERVAL, interval))
    return {"enabled": enabled, "interval_seconds": interval}


def save_config(enabled: bool, interval_seconds: int, username: str) -> dict:
    interval_seconds = max(MIN_INTERVAL, min(MAX_INTERVAL, int(interval_seconds)))
    save_app_settings({"ping_monitor": {
        "enabled": bool(enabled),
        "interval_seconds": interval_seconds,
    }})
    log_audit(f"Ping monitor {'enabled' if enabled else 'disabled'} "
              f"(interval {interval_seconds}s) by user '{username}'.")
    _cycle.set()  # worker re-reads the new configuration immediately
    return {"enabled": bool(enabled), "interval_seconds": interval_seconds}


def _ping_one(ip: str) -> tuple:
    from collectors.network_scanner import _ping as icmp_ping
    try:
        return ip, bool(icmp_ping(ip))
    except Exception:
        return ip, False


def _run_cycle() -> None:
    """One ping round over the full inventory."""
    global _last_run
    from services import inventory_manager, site_manager
    devices = inventory_manager.get_all_devices()
    # Map IP -> Site so a jump-site device can be excluded from ICMP without
    # losing its identity (a plain set of IPs would drop the Site column).
    ip_site = {}
    for d in devices:
        ip = (d.get("IP") or "").strip()
        if ip:
            ip_site[ip] = d.get("Site") or "central"
    if not ip_site:
        with _lock:
            _state.clear()
            _last_run = time.time()
        return

    # A jump site is reachable over SSH only: ICMP cannot cross the bastion
    # tunnel, so these devices are never pinged and are reported "unknown"
    # rather than a false "down".
    pingable_ips = sorted(ip for ip, site in ip_site.items()
                          if site_manager.has_direct_path(site))
    unknown_ips = sorted(ip for ip in ip_site if ip not in pingable_ips)

    results = {}
    if pingable_ips:
        # Same parallelism level as subnet scan: enough to avoid serializing
        # hundreds of pings, low enough not to saturate the network.
        with ThreadPoolExecutor(max_workers=min(50, max(4, len(pingable_ips)))) as pool:
            for ip, up in pool.map(_ping_one, pingable_ips):
                results[ip] = up

    now = time.time()
    with _lock:
        for ip, up in results.items():
            prev = _state.get(ip)
            if prev is None:
                _state[ip] = {
                    "up": up, "status": "up" if up else "down",
                    "last_check": now, "last_change": now,
                    "checks": 1, "fails": 0 if up else 1,
                }
            else:
                if prev["up"] != up:
                    prev["last_change"] = now
                prev["up"] = up
                prev["status"] = "up" if up else "down"
                prev["last_check"] = now
                prev["checks"] += 1
                if not up:
                    prev["fails"] += 1
        for ip in unknown_ips:
            # No history to carry forward: a jump-site device has nothing to
            # transition from/to, it is simply not measurable.
            _state[ip] = {
                "up": None, "status": "unknown",
                "last_check": now, "last_change": now,
                "checks": 0, "fails": 0,
            }
        # Devices removed from inventory drop out of the state.
        for ip in list(_state.keys()):
            if ip not in ip_site:
                del _state[ip]
        _last_run = now


def _worker() -> None:
    while not _stop.is_set():
        cfg = get_config()
        if not cfg["enabled"]:
            # Disabled: idle wait; _cycle.set() wakes the worker immediately
            # when an admin re-enables the monitor.
            _cycle.wait(timeout=2.0)
            _cycle.clear()
            continue
        try:
            _run_cycle()
        except Exception as e:
            print(f"[ping-monitor] cycle failed: {e}")
        # Sleep for the configured interval, but wake immediately if the
        # configuration changes (disable or new interval).
        _cycle.wait(timeout=cfg["interval_seconds"])
        _cycle.clear()


def start() -> None:
    """Start the worker (idempotent). Called from the app lifespan."""
    global _thread
    with _lock:
        if _thread is not None and _thread.is_alive():
            return
        _stop.clear()
        _thread = threading.Thread(target=_worker, name="ping-monitor", daemon=True)
        _thread.start()


def stop() -> None:
    """Stop the worker. Called on app shutdown."""
    global _thread
    _stop.set()
    _cycle.set()
    with _lock:
        t = _thread
        _thread = None
    if t is not None:
        t.join(timeout=5)


def get_status() -> dict:
    """Current state for the UI/API. Includes ALL devices; tenant scoping is
    applied by the router, as everywhere else."""
    cfg = get_config()
    with _lock:
        devices = [
            {"ip": ip, **st}
            for ip, st in sorted(_state.items())
        ]
        last_run = _last_run
    up_count = sum(1 for d in devices if d["up"] is True)
    down_count = sum(1 for d in devices if d["up"] is False)
    unknown_count = len(devices) - up_count - down_count
    return {
        "enabled": cfg["enabled"],
        "interval_seconds": cfg["interval_seconds"],
        "last_run": last_run,
        "devices": devices,
        "summary": {"total": len(devices), "up": up_count, "down": down_count,
                    "unknown": unknown_count},
    }