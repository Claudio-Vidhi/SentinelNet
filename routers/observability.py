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


@router.get("/api/observability/top")
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


@router.get("/api/observability/protocol-distribution")
async def obs_protocol_distribution(
    window: str = Query("15m"),
    exclude_telemetry: bool = Query(False),
    current_user = Depends(get_current_user),
):
    """Ripartizione traffico e volumi per protocollo (NetFlow, IPFIX, sFlow, Syslog)
    sulla finestra temporale, scoped per tenant."""
    import time as _time
    seconds = _parse_window(window)
    now = int(_time.time())
    cutoff = now - seconds
    clause, params = _tenant_filter(current_user)
    # Solo i flussi: il conteggio syslog non ha una dst_port ed e' il payload
    # della telemetria, non il rumore che genera nei flussi.
    tele_clause, tele_params = _telemetry_filter(exclude_telemetry)

    # 1. Flow aggregates per source (netflow, ipfix, sflow)
    flow_rows = await db.read(
        f"""SELECT COALESCE(source, 'netflow') AS source,
                   SUM(total_bytes) AS total_bytes,
                   SUM(total_packets) AS total_packets,
                   SUM(flow_count) AS flow_count
            FROM flow_aggregates
            WHERE window_start >= ?{clause}{tele_clause}
            GROUP BY COALESCE(source, 'netflow')""",
        (cutoff, *params, *tele_params))

    # 2. Syslog events count
    syslog_rows = await db.read(
        f"""SELECT COUNT(*) AS total_events
            FROM syslog_events
            WHERE ts >= ?{clause}""",
        (cutoff, *params))

    # 3. Time-series buckets for trend chart (bucket size dynamically scaled)
    bucket_size = 60 if seconds <= 900 else (300 if seconds <= 3600 else (3600 if seconds <= 86400 else 86400))

    trend_flow_rows = await db.read(
        f"""SELECT (window_start / ?) * ? AS bucket_ts,
                   COALESCE(source, 'netflow') AS source,
                   SUM(total_bytes) AS total_bytes,
                   SUM(total_packets) AS total_packets,
                   SUM(flow_count) AS flow_count
            FROM flow_aggregates
            WHERE window_start >= ?{clause}{tele_clause}
            GROUP BY bucket_ts, COALESCE(source, 'netflow')
            ORDER BY bucket_ts ASC""",
        (bucket_size, bucket_size, cutoff, *params, *tele_params))

    trend_syslog_rows = await db.read(
        f"""SELECT (ts / ?) * ? AS bucket_ts,
                   COUNT(*) AS total_events
            FROM syslog_events
            WHERE ts >= ?{clause}
            GROUP BY bucket_ts
            ORDER BY bucket_ts ASC""",
        (bucket_size, bucket_size, cutoff, *params))

    totals = {
        "netflow": {"bytes": 0, "packets": 0, "flows": 0, "events": 0},
        "ipfix":   {"bytes": 0, "packets": 0, "flows": 0, "events": 0},
        "sflow":   {"bytes": 0, "packets": 0, "flows": 0, "events": 0},
        "syslog":  {"bytes": 0, "packets": 0, "flows": 0, "events": 0},
    }

    for r in flow_rows:
        src = (r["source"] or "netflow").lower()
        if src not in totals:
            totals[src] = {"bytes": 0, "packets": 0, "flows": 0, "events": 0}
        totals[src]["bytes"] = r["total_bytes"] or 0
        totals[src]["packets"] = r["total_packets"] or 0
        totals[src]["flows"] = r["flow_count"] or 0

    if syslog_rows:
        totals["syslog"]["events"] = syslog_rows[0]["total_events"] or 0

    # Build trend timeline
    timeline = {}
    for r in trend_flow_rows:
        bts = r["bucket_ts"]
        src = (r["source"] or "netflow").lower()
        if bts not in timeline:
            timeline[bts] = {"ts": bts, "netflow": 0, "ipfix": 0, "sflow": 0, "syslog": 0}
        timeline[bts][src] = r["total_bytes"] or 0

    for r in trend_syslog_rows:
        bts = r["bucket_ts"]
        if bts not in timeline:
            timeline[bts] = {"ts": bts, "netflow": 0, "ipfix": 0, "sflow": 0, "syslog": 0}
        timeline[bts]["syslog"] = r["total_events"] or 0

    trend_series = [timeline[k] for k in sorted(timeline.keys())]

    # 4. Detailed Drill-down Breakdown for Inspection Modal
    syslog_sev_rows = await db.read(
        f"""SELECT severity, COUNT(*) AS count
            FROM syslog_events
            WHERE ts >= ?{clause}
            GROUP BY severity""",
        (cutoff, *params))

    syslog_act_rows = await db.read(
        f"""SELECT COALESCE(action, 'unknown') AS action, COUNT(*) AS count
            FROM syslog_events
            WHERE ts >= ?{clause}
            GROUP BY action""",
        (cutoff, *params))

    syslog_dev_rows = await db.read(
        f"""SELECT COALESCE(device_ip, exporter_ip, 'unknown') AS device_ip, COUNT(*) AS count
            FROM syslog_events
            WHERE ts >= ?{clause}
            GROUP BY device_ip
            ORDER BY count DESC LIMIT 5""",
        (cutoff, *params))

    flow_l4_rows = await db.read(
        f"""SELECT COALESCE(source, 'netflow') AS source,
                   protocol,
                   dst_port,
                   SUM(total_bytes) AS total_bytes
            FROM flow_aggregates
            WHERE window_start >= ?{clause}
            GROUP BY COALESCE(source, 'netflow'), protocol, dst_port
            ORDER BY SUM(total_bytes) DESC""",
        (cutoff, *params))

    breakdown = {
        "syslog": {
            "severity": {str(r["severity"] if r["severity"] is not None else 6): r["count"] for r in syslog_sev_rows},
            "actions": {r["action"]: r["count"] for r in syslog_act_rows},
            "devices": {r["device_ip"]: r["count"] for r in syslog_dev_rows},
        },
        "netflow": {"l4": {}, "ports": {}},
        "ipfix":   {"l4": {}, "ports": {}},
        "sflow":   {"l4": {}, "ports": {}},
    }

    _PROTO_MAP = {6: "TCP", 17: "UDP", 1: "ICMP"}
    for r in flow_l4_rows:
        src = (r["source"] or "netflow").lower()
        if src not in breakdown:
            breakdown[src] = {"l4": {}, "ports": {}}
        l4_name = _PROTO_MAP.get(r["protocol"], f"Proto {r['protocol']}")
        port_name = f"Port {r['dst_port']}" if r["dst_port"] else "—"
        b = r["total_bytes"] or 0
        breakdown[src]["l4"][l4_name] = breakdown[src]["l4"].get(l4_name, 0) + b
        breakdown[src]["ports"][port_name] = breakdown[src]["ports"].get(port_name, 0) + b

    return {
        "window": window,
        "bucket_size": bucket_size,
        "totals": totals,
        "trend": trend_series,
        "breakdown": breakdown,
    }


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


@router.get("/api/observability/events")
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


@router.get("/api/observability/anomalies")
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


@router.post("/api/observability/anomalies/{event_id}/status", deprecated=True)
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
    exclude_telemetry: bool = Query(False),
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
    tele_clause, tele_params = _telemetry_filter(exclude_telemetry)

    flow_rows = await db.read(
        f"""SELECT tenant, src_ip, dst_ip, protocol, dst_port,
                   SUM(total_bytes) AS total_bytes,
                   SUM(total_packets) AS total_packets
            FROM flow_aggregates
            WHERE window_start >= ?{clause}{tele_clause}
            GROUP BY tenant, src_ip, dst_ip, protocol, dst_port
            ORDER BY SUM(total_bytes) DESC
            LIMIT 50""",
        (cutoff, *params, *tele_params))

    spike_rows = await db.read(
        f"""SELECT COUNT(*) AS n FROM incidents
            WHERE last_event_ts >= ?{clause} AND status = 'new'""",
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
                      "proto": proto, "port": r["dst_port"], "tenant": tenant})

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
    ip_tenant_map = {ip: node_tenant.get(ip, "") for ip in top_ids}
    real_vlans = await _asyncio.to_thread(mac_history.vlans_for_ips, ip_tenant_map)

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

    throughput_bps = sum(float(e.get("rate_bps", 0) or 0) for e in edges)
    top_edge = max(edges, key=lambda e: e["rate_bps"], default=None)
    top_path = ({"src": top_edge["src"], "dst": top_edge["dst"],
                "pct": round(100 * float(top_edge.get("rate_bps", 0) or 0) / throughput_bps, 1)
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
    tenant_vlans = sorted({node_vlan[ip][0] for ip in tenant_node_ids
                           if node_vlan[ip][1] is True}) \
        if tenant_node_ids else []
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


from pydantic import BaseModel
import time

class PruneLogsSchema(BaseModel):
    days: int = 30


@router.post("/api/observability/prune-logs")
async def obs_prune_logs(payload: PruneLogsSchema, current_user = Depends(require_admin)):
    """Elimina i log di osservabilità più vecchi del limite in giorni."""
    cutoff = int(time.time()) - (payload.days * 86400)
    db.enqueue_write("DELETE FROM syslog_events WHERE ts < ?", (cutoff,))
    db.enqueue_write("DELETE FROM flow_aggregates WHERE ts < ?", (cutoff,))
    return {"status": "success", "days_retained": payload.days, "cutoff_timestamp": cutoff}
