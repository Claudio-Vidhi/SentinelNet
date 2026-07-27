# -*- coding: utf-8 -*-
"""Correlation Engine: dal modello eventi unificato alle EVIDENZE.

Pipeline:

    collectors → events (normalize) → REGOLE → evidence → incidents

Questo modulo non produce più incidenti. Produce evidenze, ciascuna con un
ruolo causale dichiarato dalla regola che l'ha prodotta e con la provenienza
(``rule_id``, ``rule_version``, soglie effettive). L'incidente è la vista
derivata, costruita da ``observability/incidents.py``.

Il vantaggio della separazione: lo stesso insieme di evidenze alimenta motore
incidenti, baseline, assistente AI e knowledge base senza duplicare la logica
di correlazione.

Legge SOLO ``events``: non sa più cosa sia un syslog, un flusso o uno snapshot
REST. Una sorgente nuova entra scrivendo un adapter in ``normalize.py``.

Gira come task periodico (lifespan), su thread dedicato con connessione propria.
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Optional

from core import db
from observability import metrics, normalize, rules

logger = logging.getLogger("sentinelnet.obs")

INTERVAL_S = 300          # un ciclo ogni 5 minuti
LOOKBACK_S = 900          # eventi normalizzati degli ultimi 15 minuti
MAX_EVENTS_PER_CYCLE = 2000

_INSERT_SQL = """
INSERT OR IGNORE INTO evidence
    (created_ts, ts, tenant, event_id, entity_key, role, rule_id, rule_version,
     params_json, weight, severity, src_ip, dst_ip, switch_port, summary,
     attrs_json, dedup_key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
"""

_running = False


def _switch_port_for(src_ip: str, tenant: str) -> Optional[str]:
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


def _insert_finding(conn, now, rule_id, version, params, f):
    """Registra un'evidenza. Ritorna (id, quante_righe_nuove)."""
    # La versione entra nella chiave: una regola nuova è una conclusione nuova,
    # e deve poter riemettere la propria evidenza accanto a quella vecchia
    # invece di essere scambiata per un doppione.
    dedup_key = hashlib.sha256(
        f"{rule_id}|{version}|{f.event_id}|{f.role}|{f.entity_key}"
        .encode()).hexdigest()
    switch_port = f.switch_port
    if switch_port is None and f.role == "trigger" and f.src_ip:
        switch_port = _switch_port_for(f.src_ip, f.tenant)
    cur = conn.execute(_INSERT_SQL, (
        now, f.ts, f.tenant, f.event_id, f.entity_key, f.role,
        rule_id, version, json.dumps(params, ensure_ascii=False),
        f.severity, f.src_ip, f.dst_ip, switch_port, f.summary,
        json.dumps(f.attrs, ensure_ascii=False), dedup_key))
    if cur.rowcount:
        assert cur.lastrowid is not None   # garantito da sqlite3 dopo INSERT
        return cur.lastrowid, 1
    existing = conn.execute("SELECT id FROM evidence WHERE dedup_key = ?",
                            (dedup_key,)).fetchone()
    return (existing["id"] if existing else None), 0


def _apply_retraction(conn, now, rule_id, version, params, r) -> int:
    """Invalida le evidenze bersaglio ancora attive, registrando PRIMA il fatto
    che giustifica la ritrattazione: senza il testimone la ritrattazione non
    sarebbe spiegabile."""
    targets = conn.execute(
        """SELECT id FROM evidence
           WHERE tenant = ? AND entity_key = ? AND rule_id = ?
             AND status = 'active' AND ts >= ?""",
        (r.tenant, r.entity_key, r.target_rule_id,
         r.witness.ts - r.window_s)).fetchall()
    if not targets:
        return 0

    witness_id, created = _insert_finding(conn, now, rule_id, version, params,
                                          r.witness)
    conn.execute(
        f"""UPDATE evidence
               SET status = 'retracted', retracted_by_evidence_id = ?,
                   retracted_by_rule_id = ?, retracted_at = ?,
                   retracted_reason = ?
             WHERE id IN ({",".join("?" * len(targets))})""",
        (witness_id, rule_id, now, r.reason, *[t["id"] for t in targets]))
    logger.info("Regola %s ha ritrattato %d evidenze di %s (%s).",
                rule_id, len(targets), r.target_rule_id, r.reason)
    return created


def correlate_once(now: Optional[int] = None) -> int:
    """Un ciclo di correlazione. Ritorna il numero di evidenze emesse."""
    now = now or int(time.time())
    # Prima si proietta ciò che le sorgenti hanno prodotto, poi si correla:
    # le regole vedono un vocabolario solo.
    normalize.normalize_once(now)

    conn = db.get_observability_connection()
    try:
        events = [dict(r) for r in conn.execute(
            """SELECT id, ts, tenant, source, source_id, event_type, entity_type,
                      entity_id, severity, device_ip, interface, src_ip, dst_ip,
                      dst_port, protocol, metrics_json, attrs_json
               FROM events
               WHERE ts >= ?
               ORDER BY ts ASC LIMIT ?""",
            (now - LOOKBACK_S, MAX_EVENTS_PER_CYCLE)).fetchall()]

        emitted = 0
        for rule_id, version, params, item in rules.evaluate(events):
            if isinstance(item, rules.Retraction):
                emitted += _apply_retraction(conn, now, rule_id, version,
                                             params, item)
                continue
            emitted += _insert_finding(conn, now, rule_id, version, params,
                                       item)[1]
        conn.commit()
        metrics.set_gauge("last_correlation_ts", now)
        metrics.inc("evidence_emitted", emitted)
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
                    logger.info("Correlazione: %d evidenze emesse.", emitted)
                from observability import incidents
                linked = await asyncio.to_thread(incidents.group_once)
                closed = await asyncio.to_thread(incidents.close_stale)
                if linked or closed:
                    logger.info("Incidenti: %d evidenze assegnate, %d chiusi.",
                                linked, closed)
            finally:
                _running = False
        except Exception as e:
            logger.warning("Errore nel ciclo di correlazione: %s", e)
