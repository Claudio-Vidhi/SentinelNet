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

from core import db
from core import data_config
from core.app_settings import get_app_settings, save_app_settings
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
    source: str = Query("all", pattern="^(all|ipfix|netflow|sflow)$"),
    current_user = Depends(get_current_user),
):
    """Top talker aggregati sulla finestra richiesta, scoped per tenant.
    ``source`` filtra per listener di origine (le righe legacy senza source
    compaiono solo con 'all')."""
    import time as _time
    seconds = _parse_window(window)
    cutoff = int(_time.time()) - seconds
    order_col = "total_bytes" if metric == "bytes" else "total_packets"
    clause, params = _tenant_filter(current_user)
    source_clause = "" if source == "all" else " AND source = ?"
    source_params = () if source == "all" else (source,)
    rows = await db.read(
        f"""SELECT tenant, src_ip, dst_ip, protocol, dst_port, source,
                   SUM(total_bytes) AS total_bytes,
                   SUM(total_packets) AS total_packets,
                   SUM(flow_count) AS flow_count
            FROM flow_aggregates
            WHERE window_start >= ?{clause}{source_clause}
            GROUP BY tenant, src_ip, dst_ip, protocol, dst_port, source
            ORDER BY SUM({order_col}) DESC
            LIMIT ?""",
        (cutoff, *params, *source_params, limit))
    return {"window": window, "metric": metric, "source": source,
            "flows": [dict(r) for r in rows]}


@router.get("/api/observability/syslog")
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
    from security.security_manager import log_audit
    log_audit(f"Anomalia observability #{event_id}: stato '{from_status}' → "
              f"'{new_status}' da '{current_user.get('sub')}'.")
    return {"status": "success", "id": event_id, "new_status": new_status}


def _synthetic_vlan(tenant: str) -> int:
    """VLAN sintetico deterministico dal tenant, usato SOLO come fallback
    quando non esiste un binding ARP noto per l'IP (vedi ``vlans_for_ips``
    più sotto). Deterministico tra restart/worker: ``hash()`` di builtin è
    salato per processo (PYTHONHASHSEED random di default), quindi qui si usa
    sha1 troncato — stabile ovunque per lo stesso input."""
    import hashlib
    digest = hashlib.sha1(tenant.encode("utf-8")).digest()
    return 100 + (int.from_bytes(digest[:2], "big") % 900)


@router.get("/api/observability/flowgraph")
async def obs_flowgraph(
    window: str = Query("5m"),
    current_user = Depends(get_current_user),
):
    """Grafo dei flussi aggregato (Task 3, Live Flows): nodi/archi con tassi,
    KPI di sintesi, riepilogo del tenant corrente e breakdown protocolli.
    Riusa le stesse query di ``obs_top_talkers``/``obs_anomalies``, scoped
    per tenant via ``_tenant_filter``. Nodi/archi limitati ai top 50 per rate.

    VLAN: quando esiste un binding ARP noto per l'IP (tabella ``arp_entries``
    di Client Map, popolata dai gateway L3) si usa la VLAN reale 802.1Q;
    altrimenti si ricade su ``_synthetic_vlan(tenant)`` e il nodo/arco viene
    marcato ``vlan_real: false`` così la UI può segnalarlo (non è un fake
    silenzioso)."""
    import time as _time
    seconds = _parse_window(window)
    cutoff = int(_time.time()) - seconds
    clause, params = _tenant_filter(current_user)

    flow_rows = await db.read(
        f"""SELECT tenant, src_ip, dst_ip, protocol, dst_port,
                   SUM(total_bytes) AS total_bytes,
                   SUM(total_packets) AS total_packets
            FROM flow_aggregates
            WHERE window_start >= ?{clause}
            GROUP BY tenant, src_ip, dst_ip, protocol, dst_port
            ORDER BY SUM(total_bytes) DESC
            LIMIT 50""",
        (cutoff, *params))

    spike_rows = await db.read(
        f"""SELECT COUNT(*) AS n FROM correlated_events
            WHERE created_ts >= ?{clause} AND status = 'new'""",
        (cutoff, *params))
    spikes = spike_rows[0]["n"] if spike_rows else 0

    _PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp"}
    edges = []
    node_bytes: dict = {}
    node_tenant: dict = {}
    proto_totals: dict = {}
    tenants_seen: set = set()

    for r in flow_rows:
        tenant = r["tenant"]
        src, dst = r["src_ip"], r["dst_ip"]
        nbytes = r["total_bytes"] or 0
        rate_bps = (nbytes * 8) / seconds if seconds else 0
        proto = _PROTO_NAMES.get(r["protocol"], str(r["protocol"] or "?"))
        tenants_seen.add(tenant)

        # Bytes del nodo = somma del traffico in cui compare, sia come
        # sorgente che come destinazione, così un host solo-destinazione
        # (es. un server interno mai visto come src) non resta a 0 e non
        # viene ingiustamente scartato dal cap top-50.
        node_bytes[src] = node_bytes.get(src, 0) + nbytes
        node_bytes[dst] = node_bytes.get(dst, 0) + nbytes
        node_tenant.setdefault(src, tenant)
        node_tenant.setdefault(dst, tenant)

        edges.append({"src": src, "dst": dst, "rate_bps": rate_bps,
                      "proto": proto, "tenant": tenant})

        proto_key = (proto, r["dst_port"])
        pt = proto_totals.setdefault(proto_key, {"proto": proto,
                                                  "port": r["dst_port"],
                                                  "rate_bps": 0.0})
        pt["rate_bps"] += rate_bps

    # Top 50 nodi per bytes totali (src+dst).
    top_ids = [ip for ip, _ in sorted(node_bytes.items(), key=lambda kv: kv[1],
                                      reverse=True)[:50]]
    kept_ids = set(top_ids)

    # VLAN reale (arp_entries) se nota, altrimenti sintetica dal tenant.
    import asyncio as _asyncio
    from collectors import mac_history
    real_vlans = await _asyncio.to_thread(mac_history.vlans_for_ips, top_ids)

    def _vlan_for(ip):
        raw = real_vlans.get(ip)
        if raw:
            try:
                return int(raw), True
            except (TypeError, ValueError):
                pass
        return _synthetic_vlan(node_tenant.get(ip, "")), False

    node_vlan = {ip: _vlan_for(ip) for ip in top_ids}
    node_list = [{"id": ip, "bytes": node_bytes[ip],
                 "vlan": node_vlan[ip][0], "vlan_real": node_vlan[ip][1]}
                for ip in top_ids]

    edges = [e for e in edges if e["src"] in kept_ids and e["dst"] in kept_ids]
    edges.sort(key=lambda e: e["rate_bps"], reverse=True)
    edges = edges[:50]
    for e in edges:
        vlan, vlan_real = node_vlan.get(e["src"], (None, False))
        e["vlan"] = vlan
        e["vlan_real"] = vlan_real

    throughput_bps = sum(e["rate_bps"] for e in edges)
    top_edge = max(edges, key=lambda e: e["rate_bps"], default=None)
    top_path = ({"src": top_edge["src"], "dst": top_edge["dst"],
                "pct": round(100 * top_edge["rate_bps"] / throughput_bps, 1)
                if throughput_bps else 0} if top_edge else
               {"src": None, "dst": None, "pct": 0})
    talkers = len({e["src"] for e in edges} | {e["dst"] for e in edges})

    kpi = {"throughput_bps": throughput_bps, "top_path": top_path,
          "talkers": talkers, "spikes": spikes}

    protocols = sorted(proto_totals.values(), key=lambda p: p["rate_bps"],
                       reverse=True)

    scope = user_group_scope(current_user)
    tenant_name = sorted(scope)[0] if scope else (
        sorted(tenants_seen)[0] if tenants_seen else None)
    tenant_edges = [e for e in edges if e.get("tenant") == tenant_name] \
        if tenant_name else edges
    top_talker_edge = max(tenant_edges, key=lambda e: e["rate_bps"],
                          default=None)
    tenant_node_ids = [ip for ip in top_ids
                       if node_tenant.get(ip) == tenant_name] \
        if tenant_name else top_ids
    tenant_vlans = sorted({node_vlan[ip][0] for ip in tenant_node_ids}) \
        if tenant_node_ids else \
        ([_synthetic_vlan(tenant_name)] if tenant_name else [])
    tenant_summary = {
        "name": tenant_name,
        "vlans": tenant_vlans,
        "flows_shown": len(tenant_edges),
        "top_talker": ({"src": top_talker_edge["src"],
                        "dst": top_talker_edge["dst"],
                        "rate_bps": top_talker_edge["rate_bps"]}
                       if top_talker_edge else None),
    }

    for e in edges:
        e.pop("tenant", None)

    return {"window": window, "nodes": node_list, "edges": edges, "kpi": kpi,
            "tenant": tenant_summary, "protocols": protocols}


@router.get("/api/observability/config")
def obs_get_config(current_user = Depends(require_admin)):
    """Config effettiva dei listener (settings + eventuali override da env).
    Le modifiche via POST vengono applicate a caldo, senza riavvio."""
    return data_config.obs_config()


@router.post("/api/observability/config")
async def obs_set_config(payload: dict, current_user = Depends(require_admin)):
    """Salva la sezione 'observability' in app_settings.json (§9.5) e applica
    subito la nuova config ai listener UDP e ai task di background (nessun
    riavvio del processo necessario).
    Chiavi ammesse: enabled, bind, {ipfix,sflow,syslog,netflow}_{enabled,port},
    api_poll_s."""
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
