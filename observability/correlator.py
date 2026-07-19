# -*- coding: utf-8 -*-
"""Motore di correlazione (fase 4.2): eventi di sicurezza syslog × flussi ×
posizione fisica (MAC history) → ``correlated_events``.

Criteri (Decisione #9, default precision-over-recall):
- si parte dagli eventi syslog di sicurezza (action in _SECURITY_ACTIONS)
  degli ultimi LOOKBACK_S secondi;
- src/dst/porta vengono estratti dal messaggio (kv FortiGate: srcip/dstip/
  dstport; Palo Alto: coppie IP nel CSV);
- serve EVIDENZA DI FLUSSO corroborante: un bucket in ``flow_aggregates``
  stesso tenant, stessi src/dst, entro ±MATCH_DELTA_S dall'evento — senza
  flusso non si emette nulla;
- arricchimento switch/porta best-effort via mac_history.client_map (uplink
  già esclusi); assente → switch_port NULL;
- MAI correlazione cross-tenant (tutte le query filtrano per tenant);
- dedup_key deterministico sha256(tenant|kind|syslog_id|flow_tuple):
  INSERT OR IGNORE sull'UNIQUE — le ri-esecuzioni non duplicano.

Gira come task periodico (lifespan): letture su thread dedicato, scritture
via il writer batch di db.py.
"""

import asyncio
import hashlib
import json
import logging
import re
import time

from core import db
from observability import metrics

logger = logging.getLogger("sentinelnet.obs")

INTERVAL_S = 300          # un ciclo ogni 5 minuti
LOOKBACK_S = 900          # eventi syslog degli ultimi 15 minuti
MATCH_DELTA_S = 120       # ±120s fra evento e bucket di flusso (Decisione #9)
MAX_EVENTS_PER_CYCLE = 500
HIGH_SEVERITY_MAX = 3     # sev syslog 0-3 (emerg..error): emerge anche senza flusso

_SECURITY_ACTIONS = ("deny", "denied", "blocked", "block", "drop",
                     "reset-both", "reset-client", "reset-server", "sinkhole")

_KV_RE = re.compile(r'(srcip|dstip|dstport)=(?:"([^"]*)"|(\S+))')
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

_SEVERITY_KIND = {0: "critico", 1: "critico", 2: "critico", 3: "alto",
                  4: "medio", 5: "medio", 6: "informativo", 7: "informativo"}

_INSERT_SQL = """
INSERT OR IGNORE INTO correlated_events
    (created_ts, tenant, kind, src_ip, dst_ip, switch_port, severity,
     status, dedup_key, evidence_json)
VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)
"""

_running = False


def _extract_endpoints(message: str):
    """Estrae (src_ip, dst_ip, dst_port) dal messaggio syslog normalizzato."""
    kv = {k: (v1 or v2) for k, v1, v2 in _KV_RE.findall(message or "")}
    if kv.get("srcip") and kv.get("dstip"):
        try:
            port = int(kv["dstport"]) if kv.get("dstport") else None
        except ValueError:
            port = None
        return kv["srcip"], kv["dstip"], port
    # Palo Alto / generico: prime due IP distinte nel messaggio
    ips = list(dict.fromkeys(_IP_RE.findall(message or "")))
    if len(ips) >= 2:
        return ips[0], ips[1], None
    return None, None, None


def _switch_port_for(src_ip: str, tenant: str):
    """Posizione fisica best-effort del client (switch/porta), stesso tenant."""
    try:
        from collectors import mac_history
        entries = mac_history.client_map(ip=src_ip, tenants=[tenant], limit=1)
        if entries and entries[0].get("switch_port"):
            e = entries[0]
            return f"{e.get('switch_name') or e.get('switch_ip')}:{e['switch_port']}"
    except Exception:
        pass
    return None


def correlate_once(now: int = None) -> int:
    """Un ciclo di correlazione. Ritorna il numero di eventi emessi (accodati)."""
    now = now or int(time.time())
    conn = db.get_observability_connection()
    try:
        placeholders = ",".join("?" * len(_SECURITY_ACTIONS))
        # Candidati: azioni di sicurezza (regola precision-over-recall con
        # evidenza di flusso) OPPURE alta severità (<= HIGH_SEVERITY_MAX), che
        # emerge comunque, anche senza flusso e senza endpoint nel messaggio.
        events = conn.execute(
            f"""SELECT id, ts, tenant, severity, action, message
                FROM syslog_events
                WHERE ts >= ? AND (lower(coalesce(action,'')) IN ({placeholders})
                                   OR severity <= ?)
                ORDER BY ts DESC LIMIT ?""",
            (now - LOOKBACK_S, *_SECURITY_ACTIONS, HIGH_SEVERITY_MAX,
             MAX_EVENTS_PER_CYCLE)).fetchall()

        emitted = 0
        for ev in events:
            severity = ev["severity"] if ev["severity"] is not None else 4
            src, dst, dport = _extract_endpoints(ev["message"])
            flow = None
            if src and dst:
                # Evidenza di flusso corroborante: STESSO tenant, stessi endpoint,
                # bucket entro ±MATCH_DELTA_S (bucket = 60s, quindi il confronto
                # è sull'inizio finestra).
                flow = conn.execute(
                    """SELECT window_start, protocol, dst_port, total_bytes,
                              total_packets
                       FROM flow_aggregates
                       WHERE tenant = ? AND src_ip = ? AND dst_ip = ?
                         AND window_start BETWEEN ? AND ?
                       ORDER BY window_start DESC LIMIT 1""",
                    (ev["tenant"], src, dst,
                     ev["ts"] - MATCH_DELTA_S - 60, ev["ts"] + MATCH_DELTA_S)).fetchone()

            if flow is not None:
                kind = f"traffico_bloccato_{_SEVERITY_KIND.get(severity, 'medio')}"
                flow_tuple = (flow["window_start"], flow["protocol"], flow["dst_port"])
                dedup_key = hashlib.sha256(
                    f"{ev['tenant']}|{kind}|{ev['id']}|{src}|{dst}|{flow_tuple}"
                    .encode()).hexdigest()
                evidence = json.dumps({
                    "syslog_id": ev["id"], "syslog_ts": ev["ts"],
                    "action": ev["action"],
                    "flow": {"window_start": flow["window_start"],
                             "protocol": flow["protocol"],
                             "dst_port": flow["dst_port"],
                             "bytes": flow["total_bytes"],
                             "packets": flow["total_packets"]},
                }, ensure_ascii=False)
            elif severity <= HIGH_SEVERITY_MAX:
                # Alta severità senza flusso corroborante: evento standalone,
                # dedup sul solo id syslog (un evento per riga).
                kind = f"syslog_{_SEVERITY_KIND.get(severity, 'alto')}"
                dedup_key = hashlib.sha256(
                    f"{ev['tenant']}|{kind}|{ev['id']}".encode()).hexdigest()
                evidence = json.dumps({
                    "syslog_id": ev["id"], "syslog_ts": ev["ts"],
                    "action": ev["action"], "message": ev["message"],
                }, ensure_ascii=False)
            else:
                continue  # precision over recall: niente flusso, niente evento

            switch_port = _switch_port_for(src, ev["tenant"]) if src else None
            db.enqueue_write(_INSERT_SQL, (
                now, ev["tenant"], kind, src, dst, switch_port,
                severity, dedup_key, evidence))
            emitted += 1
        metrics.set_gauge("last_correlation_ts", now)
        metrics.inc("correlated_events_emitted", emitted)
        return emitted
    finally:
        conn.close()


async def correlation_loop():
    """Task periodico avviato dal lifespan."""
    global _running
    while True:
        await asyncio.sleep(INTERVAL_S)
        try:
            if _running:
                continue
            _running = True
            try:
                emitted = await asyncio.to_thread(correlate_once)
                if emitted:
                    logger.info("Correlazione: %d eventi emessi.", emitted)
            finally:
                _running = False
        except Exception as e:
            logger.warning("Errore nel ciclo di correlazione: %s", e)
