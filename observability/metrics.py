# -*- coding: utf-8 -*-
"""Registro metriche in-process della pipeline di osservabilità (fase 3.8).

Contatori e gauge semplici, thread-safe, senza dipendenze esterne (export
Prometheus rimandato — Decisione #14). Snapshot esposto da
GET /api/observability/health (solo admin)."""

import threading
import time
from collections import defaultdict

_lock = threading.Lock()
_counters = defaultdict(int)
_gauges = {}

# WARN rate-limited: al massimo un log per chiave ogni intervallo.
_warn_last = {}
WARN_INTERVAL_S = 60


def inc(name: str, amount: int = 1, **labels):
    key = _key(name, labels)
    with _lock:
        _counters[key] += amount


def set_gauge(name: str, value, **labels):
    key = _key(name, labels)
    with _lock:
        _gauges[key] = value


def _key(name, labels):
    if not labels:
        return name
    lbl = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
    return f"{name}{{{lbl}}}"


def should_warn(key: str) -> bool:
    """True se è passato l'intervallo dall'ultimo WARN per questa chiave
    (per non inondare i log a ogni pacchetto scartato)."""
    now = time.monotonic()
    with _lock:
        last = _warn_last.get(key, 0.0)
        if now - last >= WARN_INTERVAL_S:
            _warn_last[key] = now
            return True
        return False


def snapshot() -> dict:
    """Snapshot corrente di contatori e gauge (per l'endpoint di health)."""
    with _lock:
        return {"counters": dict(_counters), "gauges": dict(_gauges)}


def reset():
    """Solo per i test."""
    with _lock:
        _counters.clear()
        _gauges.clear()
        _warn_last.clear()
