# -*- coding: utf-8 -*-
"""Router observability: endpoint dati scoped multi-tenant (/top, /anomalies,
fase 4.1) e diagnostica operativa della pipeline (health, fase 3.8).

REGOLA DI SCOPE (CONTRIBUTING.md §4): ogni query filtra
``WHERE tenant IN (…placeholders…)`` con parametri bound — mai interpolazione
di stringhe, mai un gruppo scalare. Scope None (admin o utente non limitato)
= nessun filtro tenant."""

import os
import re

from fastapi import APIRouter, Depends, HTTPException, Query

import db
import data_config
from observability import metrics
from observability.ingesters import ipfix
from routers.deps import (get_current_user, require_admin, require_operator,
                          user_group_scope)

router = APIRouter(tags=["Observability"])

# Popolato dal lifespan con lo stato dei listener attivi.
listener_status: dict = {}

_WINDOW_RE = re.compile(r"^(\d{1,4})([mhd])$")
_WINDOW_UNIT_S = {"m": 60, "h": 3600, "d": 86400}
MAX_WINDOW_S = 7 * 86400
MAX_LIMIT = 500


def _parse_window(window: str) -> int:
    """'15m' | '24h' | '7d' → secondi, validato e con tetto massimo."""
    m = _WINDOW_RE.match((window or "").strip())
    if not m:
        raise HTTPException(status_code=400,
                            detail="Invalid window: use e.g. 15m, 24h, 7d.")
    seconds = int(m.group(1)) * _WINDOW_UNIT_S[m.group(2)]
    if seconds <= 0 or seconds > MAX_WINDOW_S:
        raise HTTPException(status_code=400,
                            detail="Window out of bounds (max 7d).")
    return seconds


def _tenant_filter(current_user):
    """Ritorna (clausola_sql, params) per lo scope multi-gruppo dell'utente.
    Scope None = nessuna restrizione (admin / utente non limitato)."""
    scope = user_group_scope(current_user)
    if scope is None:
        return "", ()
    groups = sorted(scope)
    placeholders = ",".join("?" * len(groups))
    return f" AND tenant IN ({placeholders})", tuple(groups)


@router.get("/api/observability/top")
async def obs_top_talkers(
    window: str = Query("15m"),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    metric: str = Query("bytes", pattern="^(bytes|packets)$"),
    current_user = Depends(get_current_user),
):
    """Top talker aggregati sulla finestra richiesta, scoped per tenant."""
    import time as _time
    seconds = _parse_window(window)
    cutoff = int(_time.time()) - seconds
    order_col = "total_bytes" if metric == "bytes" else "total_packets"
    clause, params = _tenant_filter(current_user)
    rows = await db.read(
        f"""SELECT tenant, src_ip, dst_ip, protocol, dst_port,
                   SUM(total_bytes) AS total_bytes,
                   SUM(total_packets) AS total_packets,
                   SUM(flow_count) AS flow_count
            FROM flow_aggregates
            WHERE window_start >= ?{clause}
            GROUP BY tenant, src_ip, dst_ip, protocol, dst_port
            ORDER BY SUM({order_col}) DESC
            LIMIT ?""",
        (cutoff, *params, limit))
    return {"window": window, "metric": metric,
            "flows": [dict(r) for r in rows]}


@router.get("/api/observability/anomalies")
async def obs_anomalies(
    status: str = Query("new", pattern="^(new|ack|resolved|all)$"),
    window: str = Query("24h"),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    page: int = Query(0, ge=0),
    current_user = Depends(get_current_user),
):
    """Eventi correlati (fase 4.2), scoped per tenant, paginati."""
    import time as _time
    seconds = _parse_window(window)
    cutoff = int(_time.time()) - seconds
    clause, params = _tenant_filter(current_user)
    status_clause = "" if status == "all" else " AND status = ?"
    status_params = () if status == "all" else (status,)
    rows = await db.read(
        f"""SELECT id, created_ts, tenant, kind, src_ip, dst_ip, switch_port,
                   severity, status, evidence_json
            FROM correlated_events
            WHERE created_ts >= ?{clause}{status_clause}
            ORDER BY created_ts DESC
            LIMIT ? OFFSET ?""",
        (cutoff, *params, *status_params, limit, page * limit))
    return {"window": window, "status": status, "page": page,
            "anomalies": [dict(r) for r in rows]}


_ALLOWED_TRANSITIONS = {("new", "ack"), ("new", "resolved"), ("ack", "resolved")}


@router.post("/api/observability/anomalies/{event_id}/status")
async def obs_anomaly_status(
    event_id: int,
    payload: dict,
    current_user = Depends(require_operator),
):
    """Transizione di stato di un evento correlato (5.5): new→ack,
    new→resolved, ack→resolved. Concorrenza ottimistica: la transizione
    avviene solo se lo stato corrente è ancora quello di partenza."""
    new_status = (payload or {}).get("status")
    from_status = (payload or {}).get("from_status")
    if (from_status, new_status) not in _ALLOWED_TRANSITIONS:
        raise HTTPException(
            status_code=409,
            detail=f"Status transition not allowed: "
                   f"'{from_status}' → '{new_status}'.")

    scope = user_group_scope(current_user)

    def _transition():
        conn = db.get_observability_connection()
        try:
            row = conn.execute(
                "SELECT tenant, status FROM correlated_events WHERE id = ?",
                (event_id,)).fetchone()
            # Fuori scope o inesistente → 404 identico (non confermare l'esistenza).
            if row is None or (scope is not None and row["tenant"] not in scope):
                return "not_found"
            cur = conn.execute(
                "UPDATE correlated_events SET status = ? WHERE id = ? AND status = ?",
                (new_status, event_id, from_status))
            conn.commit()
            return "ok" if cur.rowcount == 1 else "stale"
        finally:
            conn.close()

    import asyncio as _asyncio
    result = await _asyncio.to_thread(_transition)
    if result == "not_found":
        raise HTTPException(status_code=404, detail="Event not found.")
    if result == "stale":
        raise HTTPException(
            status_code=409,
            detail="The event status changed in the meantime: reload the list.")
    from security_manager import log_audit
    log_audit(f"Anomalia observability #{event_id}: stato '{from_status}' → "
              f"'{new_status}' da '{current_user.get('sub')}'.")
    return {"status": "success", "id": event_id, "new_status": new_status}


@router.get("/api/observability/config")
def obs_get_config(current_user = Depends(require_admin)):
    """Config effettiva dei listener (settings + eventuali override da env).
    I listener partono all'avvio: le modifiche richiedono riavvio."""
    return data_config.obs_config()


@router.post("/api/observability/config")
def obs_set_config(payload: dict, current_user = Depends(require_admin)):
    """Salva la sezione 'observability' in app_settings.json (§9.5).
    Chiavi ammesse: enabled, bind, {ipfix,sflow,syslog,netflow}_{enabled,port},
    api_poll_s. Richiede riavvio per avere effetto."""
    allowed = {"enabled", "bind", "api_poll_s"} | {
        f"{l}_{k}" for l in ("ipfix", "sflow", "syslog", "netflow")
        for k in ("enabled", "port")}
    clean = {}
    for k, v in (payload or {}).items():
        if k not in allowed:
            raise HTTPException(status_code=400, detail=f"Invalid key: '{k}'.")
        if k.endswith("_port") or k == "api_poll_s":
            if k.endswith("_port") and v in (None, "") \
                    and not (payload or {}).get(f"{k[:-5]}_enabled"):
                continue  # listener disabilitato senza porta: mantieni il valore salvato
            try:
                v = int(v)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"Invalid value for '{k}'.")
            if k.endswith("_port") and not (1 <= v <= 65535):
                raise HTTPException(status_code=400, detail=f"Invalid port for '{k}'.")
        clean[k] = v
    from app_server import get_app_settings, save_app_settings
    saved = dict(get_app_settings().get("observability", {}) or {})
    saved.update(clean)
    save_app_settings({"observability": saved})
    from security_manager import log_audit
    log_audit(f"Config observability aggiornata da '{current_user.get('sub')}' "
              f"(riavvio richiesto): {clean}.")
    return {"status": "success", "restart_required": True,
            "effective": data_config.obs_config()}


@router.get("/api/observability/api-context")
async def obs_api_context(
    device_ip: str = Query(...),
    current_user = Depends(get_current_user),
):
    """Ultimi snapshot REST (api_observations, §9.2) per un dispositivo,
    scoped per tenant: una riga per kind (la più recente)."""
    clause, params = _tenant_filter(current_user)
    rows = await db.read(
        f"""SELECT ts, tenant, device_ip, kind, summary_json
            FROM api_observations
            WHERE device_ip = ?{clause}
              AND id IN (SELECT MAX(id) FROM api_observations
                         WHERE device_ip = ? GROUP BY kind)
            ORDER BY kind""",
        (device_ip, *params, device_ip))
    return {"device_ip": device_ip, "observations": [dict(r) for r in rows]}


@router.post("/api/observability/api-poll")
async def obs_api_poll_now(current_user = Depends(require_operator)):
    """Polling REST one-shot ("Aggiorna ora"): esegue subito un giro del
    poller API su tutti i FortiGate con token configurato."""
    import asyncio as _asyncio
    from observability.ingesters import api_poller
    n = await _asyncio.to_thread(api_poller.poll_once)
    return {"status": "success", "snapshots": n}


@router.get("/api/observability/health")
def obs_health(current_user = Depends(require_admin)):
    """Stato pipeline: listener attivi, metriche, dimensione DB, versione
    schema. Diagnostica operativa primaria dell'intero modulo (solo admin)."""
    db_path = db.get_db_path()
    try:
        db_size = os.path.getsize(db_path)
    except OSError:
        db_size = 0
    snap = metrics.snapshot()
    snap["counters"].update({f"db_{k}": v for k, v in db.metrics.items()})
    return {
        "enabled": data_config.obs_config()["enabled"],
        "listeners": listener_status,
        "metrics": snap,
        "template_cache_size": ipfix.template_cache_size(),
        "db_size_bytes": db_size,
        "schema_version": db.SCHEMA_VERSION,
    }
