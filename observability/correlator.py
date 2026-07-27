# -*- coding: utf-8 -*-
"""Motore di correlazione (fase 4.2): eventi di sicurezza × flussi ×
posizione fisica (MAC history) → ``correlated_events``.

Legge SOLO il modello eventi unificato (``events``): ogni ciclo proietta prima
le sorgenti grezze con ``normalize.normalize_once()`` e poi correla. Le tabelle
di ingestione restano la provenienza, non il contratto — così una sorgente
nuova entra nella correlazione scrivendo un adapter, senza toccare questo file.

Criteri (Decisione #9, default precision-over-recall):
- si parte dagli eventi ``log.security`` degli ultimi LOOKBACK_S secondi;
- src/dst/porta arrivano già estratti dal normalizzatore (observability/
  fieldmap.py: kv FortiGate, fallback sulle prime due IP);
- serve EVIDENZA DI FLUSSO corroborante: un evento ``flow.aggregate`` stesso
  tenant, stessi src/dst, entro ±MATCH_DELTA_S — senza flusso non si emette
  nulla;
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
from typing import Optional
import logging
import time

from core import db
from observability import fieldmap, metrics

logger = logging.getLogger("sentinelnet.obs")

INTERVAL_S = 300          # un ciclo ogni 5 minuti
LOOKBACK_S = 900          # eventi syslog degli ultimi 15 minuti
MATCH_DELTA_S = 120       # ±120s fra evento e bucket di flusso (Decisione #9)
MAX_EVENTS_PER_CYCLE = 500
HIGH_SEVERITY_MAX = 3     # sev syslog 0-3 (emerg..error): emerge anche senza flusso

_SECURITY_ACTIONS = fieldmap.SECURITY_ACTIONS

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
    fields = fieldmap.extract(message)
    return fields["src_ip"], fields["dst_ip"], fields["dst_port"]


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


def correlate_once(now: Optional[int] = None) -> int:
    """Un ciclo di correlazione. Ritorna il numero di eventi emessi (accodati)."""
    now = now or int(time.time())
    # Il correlatore consuma SOLO il modello normalizzato: prima si proietta
    # ciò che le sorgenti hanno prodotto, poi si correla.
    from observability import normalize
    normalize.normalize_once(now)

    conn = db.get_observability_connection()
    try:
        # Candidati: eventi di sicurezza normalizzati (regola precision-over-
        # recall, servono le evidenze di flusso) OPPURE alta severità
        # (<= HIGH_SEVERITY_MAX), che emerge comunque, anche senza flusso e
        # senza endpoint nel messaggio.
        events = conn.execute(
            """SELECT source_id, ts, tenant, severity, src_ip, dst_ip,
                      attrs_json
               FROM events
               WHERE ts >= ? AND source = 'syslog'
                 AND (event_type = 'log.security' OR severity <= ?)
               ORDER BY ts DESC LIMIT ?""",
            (now - LOOKBACK_S, HIGH_SEVERITY_MAX,
             MAX_EVENTS_PER_CYCLE)).fetchall()

        emitted = 0
        for ev in events:
            severity = ev["severity"] if ev["severity"] is not None else 4
            attrs = json.loads(ev["attrs_json"] or "{}")
            src, dst = ev["src_ip"], ev["dst_ip"]
            flow = None
            if src and dst:
                # Evidenza di flusso corroborante: STESSO tenant, stessi endpoint,
                # bucket entro ±MATCH_DELTA_S (bucket = 60s, quindi il confronto
                # è sull'inizio finestra).
                flow = conn.execute(
                    """SELECT ts, protocol, dst_port, metrics_json
                       FROM events
                       WHERE event_type = 'flow.aggregate'
                         AND tenant = ? AND src_ip = ? AND dst_ip = ?
                         AND ts BETWEEN ? AND ?
                       ORDER BY ts DESC LIMIT 1""",
                    (ev["tenant"], src, dst,
                     ev["ts"] - MATCH_DELTA_S - 60, ev["ts"] + MATCH_DELTA_S)).fetchone()

            if flow is not None:
                measures = json.loads(flow["metrics_json"] or "{}")
                kind = f"traffico_bloccato_{_SEVERITY_KIND.get(severity, 'medio')}"
                flow_tuple = (flow["ts"], flow["protocol"], flow["dst_port"])
                dedup_key = hashlib.sha256(
                    f"{ev['tenant']}|{kind}|{ev['source_id']}|{src}|{dst}|{flow_tuple}"
                    .encode()).hexdigest()
                evidence = json.dumps({
                    "syslog_id": ev["source_id"], "syslog_ts": ev["ts"],
                    "action": attrs.get("action"),
                    "flow": {"window_start": flow["ts"],
                             "protocol": flow["protocol"],
                             "dst_port": flow["dst_port"],
                             "bytes": measures.get("bytes"),
                             "packets": measures.get("packets")},
                }, ensure_ascii=False)
            elif severity <= HIGH_SEVERITY_MAX:
                # Alta severità senza flusso corroborante: evento standalone,
                # dedup sul solo id syslog (un evento per riga).
                kind = f"syslog_{_SEVERITY_KIND.get(severity, 'alto')}"
                dedup_key = hashlib.sha256(
                    f"{ev['tenant']}|{kind}|{ev['source_id']}".encode()).hexdigest()
                evidence = json.dumps({
                    "syslog_id": ev["source_id"], "syslog_ts": ev["ts"],
                    "action": attrs.get("action"),
                    "message": attrs.get("message"),
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
                # Gli eventi appena emessi sono ancora in coda al writer: il
                # raggruppamento li prenderà al ciclo successivo (l'anti-join su
                # incident_events lo rende idempotente).
                from observability import incidents
                linked = await asyncio.to_thread(incidents.group_once)
                closed = await asyncio.to_thread(incidents.close_stale)
                if linked or closed:
                    logger.info("Incidenti: %d eventi associati, %d chiusi.",
                                linked, closed)
            finally:
                _running = False
        except Exception as e:
            logger.warning("Errore nel ciclo di correlazione: %s", e)
