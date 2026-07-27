# -*- coding: utf-8 -*-
"""Adapter di normalizzazione: dalle tabelle grezze al modello eventi unico.

Ogni sorgente conserva il proprio formato di ingestione (i listener UDP, il
poller REST e gli agent non cambiano); qui gli eventi vengono PROIETTATI nella
tabella ``events`` con lo stesso vocabolario. Da lì in poi correlazione,
ragionamento, baseline e knowledge base leggono una forma sola.

Adapter attivi (solo sorgenti già raccolte oggi):
- ``flow_aggregates``  → ``flow.aggregate``   (entità flow)
- ``syslog_events``    → ``log.security`` / ``log.event``   (entità device)
- ``api_observations`` → ``device.state`` + ``device.change`` (entità device)

Avanzamento: ``normalize_cursors`` tiene la posizione per sorgente. Il rientro
è comunque idempotente grazie a ``dedup_key`` UNIQUE, quindi un cursore
riavvolto non duplica: al più riscrive le stesse righe.

I bucket di flusso vengono aggiornati in place dall'ingestione (UPSERT al
minuto): l'adapter li rilegge finché la finestra non è chiusa e aggiorna le
metriche sul conflitto, invece di ignorarle.
"""

import json
import logging
import time
from typing import Optional

from core import db
from observability import fieldmap, metrics

logger = logging.getLogger("sentinelnet.obs")

LOOKBACK_S = 3600         # quanto indietro guardare al primo giro / dopo un fermo
MAX_ROWS_PER_SOURCE = 2000
MAX_CHANGES_PER_SNAPSHOT = 20

# Campi che cambiano a ogni poll per costruzione (contatori, uptime, sessioni):
# confrontarli produrrebbe un "cambiamento" ogni 5 minuti su ogni apparato.
# ponytail: filtro per sottostringa, sufficiente sui payload FortiGate visti;
# se servisse più precisione, la strada è una allowlist per vendor negli adapter.
_VOLATILE_HINTS = ("byte", "packet", "uptime", "time", "count", "session",
                   "error", "drop", "collision", "rate", "usage", "seconds",
                   "timestamp", "last_", "current_")

_INSERT_SQL = """
INSERT INTO events
    (ts, ingested_ts, tenant, source, source_id, event_type, entity_type,
     entity_id, severity, device_ip, interface, src_ip, dst_ip, dst_port,
     protocol, metrics_json, attrs_json, dedup_key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(dedup_key) DO UPDATE SET
    metrics_json = excluded.metrics_json,
    ingested_ts  = excluded.ingested_ts
"""


def _cursor(conn, source: str) -> dict:
    row = conn.execute(
        "SELECT last_id, last_ts FROM normalize_cursors WHERE source = ?",
        (source,)).fetchone()
    if row is None:
        return {"last_id": 0, "last_ts": 0}
    return {"last_id": row["last_id"], "last_ts": row["last_ts"]}


def _save_cursor(conn, source: str, last_id: int, last_ts: int) -> None:
    conn.execute(
        """INSERT INTO normalize_cursors (source, last_id, last_ts)
           VALUES (?, ?, ?)
           ON CONFLICT(source) DO UPDATE SET last_id = ?, last_ts = ?""",
        (source, last_id, last_ts, last_id, last_ts))


def _emit(conn, **row) -> None:
    conn.execute(_INSERT_SQL, (
        row["ts"], row["ingested_ts"], row["tenant"], row["source"],
        row.get("source_id"), row["event_type"], row["entity_type"],
        row["entity_id"], row.get("severity"), row.get("device_ip"),
        row.get("interface"), row.get("src_ip"), row.get("dst_ip"),
        row.get("dst_port"), row.get("protocol"),
        json.dumps(row.get("metrics") or {}, ensure_ascii=False),
        json.dumps(row.get("attrs") or {}, ensure_ascii=False),
        row["dedup_key"]))


# --- ADAPTER: FLUSSI ---------------------------------------------------------

def _from_flows(conn, now: int) -> int:
    # Il cursore riparte DALLO STESSO bucket in cui si era fermato (>=, non >):
    # l'ingestione aggiorna in place il bucket ancora aperto, e il rientro ne
    # aggiorna le metriche via ON CONFLICT invece di perderle. Nessun ritardo di
    # assestamento: la correlazione deve poter vedere il minuto corrente.
    cur = _cursor(conn, "flow")
    start = cur["last_ts"] or (now - LOOKBACK_S)
    rows = conn.execute(
        """SELECT window_start, tenant, src_ip, dst_ip, protocol, dst_port,
                  total_bytes, total_packets, flow_count, exporter_ip, source
           FROM flow_aggregates
           WHERE window_start >= ?
           ORDER BY window_start ASC LIMIT ?""",
        (start, MAX_ROWS_PER_SOURCE)).fetchall()
    last_ts = cur["last_ts"]
    for r in rows:
        proto = str(r["protocol"]) if r["protocol"] is not None else ""
        _emit(conn,
              ts=r["window_start"], ingested_ts=now, tenant=r["tenant"],
              source=r["source"] or "netflow", event_type="flow.aggregate",
              entity_type="flow",
              entity_id=f"{r['src_ip']}>{r['dst_ip']}",
              src_ip=r["src_ip"], dst_ip=r["dst_ip"], dst_port=r["dst_port"],
              protocol=fieldmap.PROTO_NUM.get(proto, proto) or None,
              device_ip=r["exporter_ip"],
              metrics={"bytes": r["total_bytes"], "packets": r["total_packets"],
                       "flows": r["flow_count"]},
              dedup_key=f"flow:{r['window_start']}:{r['tenant']}:{r['src_ip']}:"
                        f"{r['dst_ip']}:{r['protocol']}:{r['dst_port']}")
        last_ts = max(last_ts, r["window_start"])
    if rows:
        # Il bucket più recente può ancora ricevere UPSERT: si riparte da lì.
        _save_cursor(conn, "flow", 0, last_ts)
    return len(rows)


# --- ADAPTER: SYSLOG ---------------------------------------------------------

def _from_syslog(conn, now: int) -> int:
    # Primo giro: si guarda solo LOOKBACK_S indietro (niente backfill dello
    # storico). Dopo, il cursore sull'id monotono basta da solo.
    cur = _cursor(conn, "syslog")
    min_ts = (now - LOOKBACK_S) if cur["last_id"] == 0 else 0
    rows = conn.execute(
        """SELECT id, ts, tenant, device_ip, severity, action, message, exporter_ip
           FROM syslog_events
           WHERE id > ? AND ts >= ?
           ORDER BY id ASC LIMIT ?""",
        (cur["last_id"], min_ts, MAX_ROWS_PER_SOURCE)).fetchall()
    last_id = cur["last_id"]
    for r in rows:
        fields = fieldmap.extract(r["message"])
        action = r["action"] or fields["action"]
        security = fieldmap.is_security_action(action)
        _emit(conn,
              ts=r["ts"], ingested_ts=now, tenant=r["tenant"], source="syslog",
              source_id=r["id"],
              event_type="log.security" if security else "log.event",
              entity_type="device",
              entity_id=r["device_ip"] or (fields["src_ip"] or "sconosciuto"),
              severity=r["severity"], device_ip=r["device_ip"],
              src_ip=fields["src_ip"], dst_ip=fields["dst_ip"],
              dst_port=fields["dst_port"], protocol=fields["protocol"],
              metrics={"bytes": fields["bytes"]} if fields["bytes"] else {},
              attrs={"action": action, "message": (r["message"] or "")[:1024],
                     "src_port": fields["src_port"],
                     "exporter_ip": r["exporter_ip"]},
              dedup_key=f"syslog:{r['id']}")
        last_id = max(last_id, r["id"])
    if rows:
        _save_cursor(conn, "syslog", last_id, now)
    return len(rows)


# --- ADAPTER: SNAPSHOT REST (stato apparato + variazioni) --------------------

def _flatten(obj, prefix: str = "", out: Optional[dict] = None, depth: int = 0) -> dict:
    """Appiattisce un payload JSON in percorsi 'a.b.c' → valore scalare.
    Vendor-agnostico: nessuna conoscenza della forma FortiGate."""
    if out is None:
        out = {}
    if depth > 4 or len(out) > 400:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten(v, f"{prefix}.{k}" if prefix else str(k), out, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            _flatten(v, f"{prefix}[{i}]", out, depth + 1)
    else:
        out[prefix] = obj
    return out


def _stable_fields(payload: str) -> dict:
    """Campi confrontabili di uno snapshot: esclude i contatori volatili.
    Payload troncato/illeggibile → dict vuoto (nessun cambiamento inventato)."""
    try:
        data = json.loads(payload or "{}")
    except (ValueError, TypeError):
        return {}
    flat = _flatten(data)
    return {k: v for k, v in flat.items()
            if not any(h in k.lower() for h in _VOLATILE_HINTS)}


def _from_api_observations(conn, now: int) -> int:
    cur = _cursor(conn, "api")
    rows = conn.execute(
        """SELECT id, ts, tenant, device_ip, kind, summary_json
           FROM api_observations
           WHERE id > ?
           ORDER BY id ASC LIMIT ?""",
        (cur["last_id"], MAX_ROWS_PER_SOURCE)).fetchall()
    last_id = cur["last_id"]
    for r in rows:
        _emit(conn,
              ts=r["ts"], ingested_ts=now, tenant=r["tenant"],
              source="fortigate_api", source_id=r["id"],
              event_type="device.state", entity_type="device",
              entity_id=r["device_ip"], device_ip=r["device_ip"],
              attrs={"kind": r["kind"]},
              dedup_key=f"api:{r['id']}")

        # Variazione di configurazione/stato: confronto con lo snapshot
        # precedente dello stesso apparato e della stessa natura.
        prev = conn.execute(
            """SELECT summary_json FROM api_observations
               WHERE device_ip = ? AND kind = ? AND id < ?
               ORDER BY id DESC LIMIT 1""",
            (r["device_ip"], r["kind"], r["id"])).fetchone()
        if prev is not None:
            before = _stable_fields(prev["summary_json"])
            after = _stable_fields(r["summary_json"])
            changed = [k for k in after
                       if k in before and before[k] != after[k]][:MAX_CHANGES_PER_SNAPSHOT]
            for field in changed:
                _emit(conn,
                      ts=r["ts"], ingested_ts=now, tenant=r["tenant"],
                      source="fortigate_api", source_id=r["id"],
                      event_type="device.change", entity_type="device",
                      entity_id=r["device_ip"], device_ip=r["device_ip"],
                      severity=5,
                      attrs={"kind": r["kind"], "field": field,
                             "before": before[field], "after": after[field]},
                      dedup_key=f"api-change:{r['id']}:{field}")
        last_id = max(last_id, r["id"])
    if rows:
        _save_cursor(conn, "api", last_id, now)
    return len(rows)


# --- CICLO -------------------------------------------------------------------

def normalize_once(now: Optional[int] = None) -> dict:
    """Un giro di normalizzazione. Ritorna {sorgente: righe lette}."""
    now = now or int(time.time())
    conn = db.get_observability_connection()
    try:
        counts = {
            "flow": _from_flows(conn, now),
            "syslog": _from_syslog(conn, now),
            "api": _from_api_observations(conn, now),
        }
        conn.commit()
        metrics.set_gauge("last_normalize_ts", now)
        metrics.inc("events_normalized", sum(counts.values()))
        return counts
    finally:
        conn.close()
