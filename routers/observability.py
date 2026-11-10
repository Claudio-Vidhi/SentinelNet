# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router observability: endpoint dati scoped multi-tenant (/top, /anomalies,
fase 4.1) e diagnostica operativa della pipeline (health, fase 3.8).

REGOLA DI SCOPE (CONTRIBUTING.md §4): ogni query filtra
``WHERE tenant IN (…placeholders…)`` con parametri bound — mai interpolazione
di stringhe, mai un gruppo scalare. Scope None (admin o utente non limitato)
= nessun filtro tenant."""

import ipaddress
import os
import re

from fastapi import APIRouter, Depends, HTTPException, Query
from routers.deps import require_tab

from core import db
from core import data_config
from core.app_settings import get_app_settings, save_app_settings
from observability import metrics
from observability.ingesters import ipfix
from routers.deps import (get_current_user, require_unscoped_admin, require_operator,
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


def _telemetry_filter(exclude: bool):
    """Ritorna (clausola_sql, params) per escludere i flussi diretti ai
    collector di telemetria.

    Gli apparati esportano verso i nostri listener, e quel traffico rientra
    poi come flusso: nei top talker sono conversazioni vere ma sono rumore di
    misura, non traffico di rete. Le porte arrivano da ``obs_config()``, non
    da costanti: se l'utente sposta un listener il filtro lo segue.
    161/162 sono SNMP, che qui non ha un listener ma genera lo stesso rumore.
    """
    if not exclude:
        return "", ()
    cfg = data_config.obs_config()
    ports = sorted({int(cfg[k]["port"])
                    for k in ("ipfix", "sflow", "syslog", "netflow")} | {161, 162})
    placeholders = ",".join("?" * len(ports))
    return (f" AND (dst_port IS NULL OR dst_port NOT IN ({placeholders}))",
            tuple(ports))


@router.get("/api/observability/top", dependencies=[Depends(require_tab("tab-flows"))])
async def obs_top_talkers(
    window: str = Query("15m"),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    metric: str = Query("bytes", pattern="^(bytes|packets)$"),
    source: str = Query("all", pattern="^(all|ipfix|netflow|sflow)$"),
    exclude_telemetry: bool = Query(False),
    current_user = Depends(get_current_user),
):
    """Top talker aggregati sulla finestra richiesta, scoped per tenant.
    ``source`` filtra per listener di origine (le righe legacy senza source
    compaiono solo con 'all'); ``exclude_telemetry`` toglie i flussi diretti
    ai collector (vedi ``_telemetry_filter``)."""
    import time as _time
    seconds = _parse_window(window)
    cutoff = int(_time.time()) - seconds
    order_col = "total_bytes" if metric == "bytes" else "total_packets"
    clause, params = _tenant_filter(current_user)
    source_clause = "" if source == "all" else " AND source = ?"
    source_params = () if source == "all" else (source,)
    tele_clause, tele_params = _telemetry_filter(exclude_telemetry)
    rows = await db.read(
        f"""SELECT tenant, src_ip, dst_ip, protocol, dst_port, source,
                   SUM(total_bytes) AS total_bytes,
                   SUM(total_packets) AS total_packets,
                   SUM(flow_count) AS flow_count
            FROM flow_aggregates
            WHERE window_start >= ?{clause}{source_clause}{tele_clause}
            GROUP BY tenant, src_ip, dst_ip, protocol, dst_port, source
            ORDER BY SUM({order_col}) DESC
            LIMIT ?""",
        (cutoff, *params, *source_params, *tele_params, limit))
    return {"window": window, "metric": metric, "source": source,
            "exclude_telemetry": exclude_telemetry,
            "flows": [dict(r) for r in rows]}


@router.get("/api/observability/syslog", dependencies=[Depends(require_tab("tab-flows"))])
async def obs_syslog(
    window: str = Query("15m"),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    current_user = Depends(get_current_user),
):
    """Ultimi eventi syslog normalizzati sulla finestra, scoped per tenant."""
    import time as _time
    seconds = _parse_window(window)
    cutoff = int(_time.time()) - seconds
    clause, params = _tenant_filter(current_user)
    rows = await db.read(
        f"""SELECT ts, tenant, device_ip, severity, action, message, exporter_ip
            FROM syslog_events
            WHERE ts >= ?{clause}
            ORDER BY ts DESC
            LIMIT ?""",
        (cutoff, *params, limit))
    return {"window": window, "events": [dict(r) for r in rows]}


# Superficie pubblica deliberata: nessun chiamante in-tree (la UI legge le
# tabelle specifiche), esiste per i consumatori esterni CLI/MCP/automazione.
@router.get("/api/observability/events", dependencies=[Depends(require_tab("tab-flows"))])
async def obs_events(
    window: str = Query("15m"),
    event_type: str = Query("all"),
    entity_id: str = Query(""),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    page: int = Query(0, ge=0),
    current_user = Depends(get_current_user),
):
    """Feed del modello eventi unificato: la stessa forma per NetFlow, syslog e
    snapshot REST. È il livello su cui lavorano correlazione e ragionamento, ed
    è esposto perché ogni consumatore (CLI, AI, automazione) possa partire da
    qui invece che dalle tabelle grezze di ogni sorgente."""
    import time as _time
    seconds = _parse_window(window)
    cutoff = int(_time.time()) - seconds
    clause, params = _tenant_filter(current_user)
    type_clause = "" if event_type == "all" else " AND event_type = ?"
    type_params = () if event_type == "all" else (event_type,)
    entity_clause = " AND entity_id = ?" if entity_id else ""
    entity_params = (entity_id,) if entity_id else ()
    rows = await db.read(
        f"""SELECT id, ts, tenant, source, source_id, event_type, entity_type,
                   entity_id, severity, device_ip, interface, src_ip, dst_ip,
                   dst_port, protocol, metrics_json, attrs_json
            FROM events
            WHERE ts >= ?{clause}{type_clause}{entity_clause}
            ORDER BY ts DESC
            LIMIT ? OFFSET ?""",
        (cutoff, *params, *type_params, *entity_params, limit, page * limit))
    # Classificazione DERIVATA in lettura, mai salvata dentro l'evento: quando
    # la Endpoint KB impara un ruolo nuovo, migliora anche il passato.
    from observability import endpoints
    events = []
    for r in rows:
        row = dict(r)
        row["src_info"] = endpoints.classify(row.get("src_ip"))
        row["dst_info"] = endpoints.classify(row.get("dst_ip"))
        row["direction"] = endpoints.traffic_direction(row.get("src_ip"),
                                                       row.get("dst_ip"))
        events.append(row)
    return {"window": window, "event_type": event_type, "page": page,
            "events": events}


@router.get("/api/observability/anomalies", dependencies=[Depends(require_tab("tab-home", "tab-flows"))])
async def obs_anomalies(
    status: str = Query("new", pattern="^(new|ack|resolved|all)$"),
    window: str = Query("24h"),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    page: int = Query(0, ge=0),
    current_user = Depends(get_current_user),
):
    """Anomalie correlate, scoped per tenant, paginate.

    Dalla v7 la riga è un INCIDENTE, non più un singolo evento correlato: la
    stessa anomalia ripetuta 27 volte era 27 righe da chiudere a mano. La forma
    della risposta resta quella storica (``kind``, ``src_ip``, ``switch_port``,
    ``status``) perché la consumano il tab Flussi e il tool MCP ``get_anomalies``;
    il dettaglio completo con ruoli e timeline sta in ``/api/incidents/{id}``.
    """
    import time as _time
    seconds = _parse_window(window)
    cutoff = int(_time.time()) - seconds
    clause, params = _tenant_filter(current_user)
    status_clause = "" if status == "all" else " AND i.status = ?"
    status_params = () if status == "all" else (status,)
    rows = await db.read(
        f"""SELECT i.id, i.opened_ts AS created_ts, i.tenant,
                   i.cause_kind AS kind, i.title, i.severity, i.status,
                   i.confidence, i.event_count, i.entity_key,
                   (SELECT src_ip FROM evidence e WHERE e.incident_id = i.id
                      AND e.src_ip IS NOT NULL ORDER BY e.ts LIMIT 1) AS src_ip,
                   (SELECT dst_ip FROM evidence e WHERE e.incident_id = i.id
                      AND e.dst_ip IS NOT NULL ORDER BY e.ts LIMIT 1) AS dst_ip,
                   (SELECT switch_port FROM evidence e WHERE e.incident_id = i.id
                      AND e.switch_port IS NOT NULL ORDER BY e.ts LIMIT 1) AS switch_port,
                   i.reasoning_json AS evidence_json
            FROM incidents i
            WHERE i.last_event_ts >= ?{clause}{status_clause}
            ORDER BY i.last_event_ts DESC
            LIMIT ? OFFSET ?""",
        (cutoff, *params, *status_params, limit, page * limit))
    return {"window": window, "status": status, "page": page,
            "anomalies": [dict(r) for r in rows]}


@router.post("/api/observability/anomalies/{event_id}/status", deprecated=True, dependencies=[Depends(require_tab("tab-flows"))])
async def obs_anomaly_status(
    event_id: int,
    payload: dict,
    current_user = Depends(require_operator),
):
    """DEPRECATA: usare ``POST /api/incidents/{id}/status``.

    Dalla v7 ``event_id`` è l'id dell'INCIDENTE (vedi ``obs_anomalies``), e
    questa rotta scriveva la stessa tabella con una seconda copia della
    transizione: due implementazioni dello stesso controllo di scope, libere
    di divergere. Ora delega a quella degli incidenti — l'URL resta in piedi
    per i client esterni che lo chiamano ancora.

    L'import è locale perché ``routers.incidents`` importa questo modulo."""
    from routers.incidents import set_incident_status
    return await set_incident_status(event_id, payload, current_user)


@router.get("/api/observability/config", dependencies=[Depends(require_tab("tab-settings"))])
def obs_get_config(current_user = Depends(require_unscoped_admin)):
    """Config effettiva dei listener (settings + eventuali override da env).
    Le modifiche via POST vengono applicate a caldo, senza riavvio."""
    return data_config.obs_config()


@router.post("/api/observability/config", dependencies=[Depends(require_tab("tab-settings"))])
async def obs_set_config(payload: dict, current_user = Depends(require_unscoped_admin)):
    """Salva la sezione 'observability' in app_settings.json (§9.5) e applica
    subito la nuova config ai listener UDP e ai task di background (nessun
    riavvio del processo necessario).
    Chiavi ammesse: enabled, bind, {ipfix,sflow,syslog,netflow}_{enabled,port},
    api_poll_s, snmp_poll_s, linux_poll_s."""
    allowed = {"enabled", "bind", "api_poll_s", "snmp_poll_s", "linux_poll_s"} | {
        f"{l}_{k}" for l in ("ipfix", "sflow", "syslog", "netflow")
        for k in ("enabled", "port")}
    clean = {}
    for k, v in (payload or {}).items():
        if k not in allowed:
            raise HTTPException(status_code=400, detail=f"Invalid key: '{k}'.")
        if k.endswith("_port") or k in ("api_poll_s", "snmp_poll_s", "linux_poll_s"):
            if k.endswith("_port") and v in (None, "") \
                    and not (payload or {}).get(f"{k[:-5]}_enabled"):
                continue  # listener disabilitato senza porta: mantieni il valore salvato
            try:
                v = int(v)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"Invalid value for '{k}'.")
            if k.endswith("_port") and not (1 <= v <= 65535):
                raise HTTPException(status_code=400, detail=f"Invalid port for '{k}'.")
        elif k == "bind":
            # Stored and then fed to every listener: a non-address here broke
            # obs_config() on each later read (security review 2026-10-12, L3).
            try:
                v = str(ipaddress.ip_address(str(v).strip()))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid value for 'bind'.")
        clean[k] = v
    saved = dict(get_app_settings().get("observability", {}) or {})
    saved.update(clean)
    save_app_settings({"observability": saved})
    effective = data_config.obs_config()
    from observability import listener_manager
    await listener_manager.apply_obs_config(effective)
    from security.security_manager import log_audit
    log_audit(f"Config observability aggiornata da '{current_user.get('sub')}': "
              f"{clean} (applicata a caldo, nessun riavvio).")
    return {"status": "success", "restart_required": False,
            "effective": effective, "listeners": listener_status}


@router.get("/api/observability/api-context", dependencies=[Depends(require_tab("tab-flows"))])
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
                         WHERE device_ip = ?{clause} GROUP BY kind)
            ORDER BY kind""",
        (device_ip, *params, device_ip, *params))
    return {"device_ip": device_ip, "observations": [dict(r) for r in rows]}


@router.post("/api/observability/api-poll", dependencies=[Depends(require_tab("tab-flows"))])
async def obs_api_poll_now(current_user = Depends(require_operator)):
    """Polling REST one-shot ("Aggiorna ora"): esegue subito un giro del
    poller API su tutti i FortiGate con token configurato."""
    import asyncio as _asyncio
    from observability.ingesters import api_poller
    n = await _asyncio.to_thread(api_poller.poll_once)
    return {"status": "success", "snapshots": n}


@router.get("/api/observability/health", dependencies=[Depends(require_tab("tab-flows", "tab-settings"))])
def obs_health(current_user = Depends(require_unscoped_admin)):
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
        # WP7: writer loss is a STATE the operator reads, not just counters:
        # "degraded" is true on any drop or a dead writer since startup.
        "db_health": db.health_state(),
        "template_cache_size": ipfix.template_cache_size(),
        "db_size_bytes": db_size,
        "schema_version": db.SCHEMA_VERSION,
    }


from pydantic import BaseModel
import time

class PruneLogsSchema(BaseModel):
    days: int = 30


@router.post("/api/observability/prune-logs", dependencies=[Depends(require_tab("tab-settings"))])
async def obs_prune_logs(payload: PruneLogsSchema, current_user = Depends(require_unscoped_admin)):
    """Elimina i log di osservabilità più vecchi del limite in giorni."""
    cutoff = int(time.time()) - (payload.days * 86400)
    db.enqueue_write("DELETE FROM syslog_events WHERE ts < ?", (cutoff,))
    db.enqueue_write("DELETE FROM flow_aggregates WHERE ts < ?", (cutoff,))
    return {"status": "success", "days_retained": payload.days, "cutoff_timestamp": cutoff}
