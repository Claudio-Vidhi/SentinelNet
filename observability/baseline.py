# -*- coding: utf-8 -*-
"""Baseline Engine: adapter che misura quanto il presente si discosta dal
comportamento abituale, e scrive la misura come FATTO nel modello unificato.

Non produce incidenti e non ritratta nulla: emette eventi ``flow.baseline``
con osservato, atteso e scostamento. Sono le regole a decidere se quello
scostamento è un picco (``BASELINE_SPIKE_001``) o la conferma che tutto rientra
nella norma (``BASELINE_NORMAL_RETRACT_001``). La banda di normalità vive
quindi nel catalogo regole, dov'è tarabile e tracciata nella provenienza,
invece che cablata qui dentro.

Confronto (principio del documento: mai solo "contro ieri"):
1. stesso giorno della settimana, stessa ora, fino a WEEKS_BACK settimane —
   cattura la stagionalità settimanale (il lunedì non somiglia alla domenica);
2. se i campioni non bastano, stessa ora dei giorni precedenti (media mobile);
3. se non bastano ancora, NON si emette nulla. Una baseline inventata su due
   punti è peggio di nessuna baseline: il documento chiede di non generare
   allarmi da picchi temporanei, e senza storia ogni picco lo è.

Un'ora storica conta come campione solo se in quell'ora il collettore stava
raccogliendo (c'era traffico per quel tenant): altrimenti un fermo
dell'ingestione verrebbe letto come "traffico zero" e gonfierebbe ogni
scostamento successivo.

ponytail: l'atteso è la mediana dei campioni, senza misura di dispersione. Con
4-7 campioni una MAD sarebbe rumore. Percorso di crescita, quando la retention
dei flussi sarà più lunga: mediana + MAD e banda proporzionale alla
variabilità del singolo talker, invece di una percentuale unica.
"""

import json
import logging
import statistics
import time
from typing import Optional

from core import db
from observability import metrics

logger = logging.getLogger("sentinelnet.obs")

HOUR_S = 3600
WEEKS_BACK = 4            # quante settimane indietro per lo stesso giorno/ora
DAYS_BACK = 7             # ripiego: stessa ora dei giorni precedenti
MIN_SAMPLES = 2           # sotto questa soglia non si emette nulla
MAX_ENTITIES_PER_HOUR = 200   # i talker più rilevanti, non tutta la rete
MAX_HOURS_PER_RUN = 6     # recupero dopo un fermo, senza bloccare il ciclo


def _hour_start(ts: int) -> int:
    return ts - (ts % HOUR_S)


def _hourly_totals(conn, hours: list) -> dict:
    """{(hour_start, tenant, src_ip): byte} per le ore richieste."""
    if not hours:
        return {}
    clauses = " OR ".join(
        ["(window_start >= ? AND window_start < ?)"] * len(hours))
    params: list = []
    for h in hours:
        params += [h, h + HOUR_S]
    rows = conn.execute(
        f"""SELECT (window_start / {HOUR_S}) * {HOUR_S} AS h, tenant, src_ip,
                   SUM(total_bytes) AS total
            FROM flow_aggregates
            WHERE {clauses}
            GROUP BY h, tenant, src_ip""", params).fetchall()
    return {(r["h"], r["tenant"], r["src_ip"]): r["total"] or 0 for r in rows}


def _reference_hours(hour: int) -> tuple:
    """(ore stagionali, ore di ripiego) per l'ora in esame."""
    seasonal = [hour - 7 * 86400 * k for k in range(1, WEEKS_BACK + 1)]
    rolling = [hour - 86400 * k for k in range(1, DAYS_BACK + 1)]
    return seasonal, rolling


def compute_hour(conn, hour: int, now: int) -> int:
    """Misura lo scostamento per un'ora conclusa. Ritorna gli eventi emessi."""
    seasonal, rolling = _reference_hours(hour)
    totals = _hourly_totals(conn, [hour] + seasonal + rolling)

    # Ore in cui il collettore stava effettivamente raccogliendo, per tenant.
    alive = {(h, tenant) for (h, tenant, _ip) in totals}

    observed = {(tenant, ip): value
                for (h, tenant, ip), value in totals.items() if h == hour}
    if not observed:
        return 0
    top = sorted(observed.items(), key=lambda kv: kv[1],
                 reverse=True)[:MAX_ENTITIES_PER_HOUR]

    emitted = 0
    for (tenant, src_ip), value in top:
        for reference, method in ((seasonal, "stesso_giorno_stessa_ora"),
                                  (rolling, "media_mobile_stessa_ora")):
            samples = [totals.get((h, tenant, src_ip), 0)
                       for h in reference if (h, tenant) in alive]
            if len(samples) >= MIN_SAMPLES:
                break
        else:
            continue   # storia insufficiente: nessuna baseline inventata

        expected = statistics.median(samples)
        if expected <= 0:
            # Talker nuovo: non è uno scostamento da un'abitudine, è una cosa
            # che prima non c'era. Fatto diverso, non lo si spaccia per questo.
            continue

        deviation_pct = round((value - expected) / expected * 100, 1)
        conn.execute(
            """INSERT INTO events
                   (ts, ingested_ts, tenant, source, event_type, entity_type,
                    entity_id, src_ip, metrics_json, attrs_json, dedup_key)
               VALUES (?, ?, ?, 'baseline', 'flow.baseline', 'flow', ?, ?, ?, ?, ?)
               ON CONFLICT(dedup_key) DO UPDATE SET
                   metrics_json = excluded.metrics_json,
                   ingested_ts  = excluded.ingested_ts""",
            (hour, now, tenant, src_ip, src_ip,
             json.dumps({"observed": value, "expected": expected,
                         "deviation_pct": deviation_pct,
                         "samples": len(samples)}, ensure_ascii=False),
             json.dumps({"method": method, "window": "1h"}, ensure_ascii=False),
             f"baseline:{tenant}:{src_ip}:{hour}"))
        emitted += 1
    return emitted


def compute_once(conn, now: Optional[int] = None) -> int:
    """Misura le ore concluse non ancora elaborate. Ritorna gli eventi emessi.

    Solo ore CHIUSE: l'ora corrente è ancora in corso e il suo totale
    crescerebbe fino allo scoccare della successiva, producendo uno
    scostamento negativo che non significa niente.
    """
    now = now or int(time.time())
    last_closed = _hour_start(now) - HOUR_S
    row = conn.execute(
        "SELECT last_ts FROM normalize_cursors WHERE source = 'baseline'"
    ).fetchone()
    start = (row["last_ts"] + HOUR_S) if row and row["last_ts"] else last_closed
    hours = [h for h in range(start, last_closed + HOUR_S, HOUR_S)][-MAX_HOURS_PER_RUN:]
    if not hours:
        return 0

    emitted = 0
    for hour in hours:
        emitted += compute_hour(conn, hour, now)
    conn.execute(
        """INSERT INTO normalize_cursors (source, last_id, last_ts)
           VALUES ('baseline', 0, ?)
           ON CONFLICT(source) DO UPDATE SET last_ts = ?""",
        (hours[-1], hours[-1]))
    metrics.inc("baseline_events_emitted", emitted)
    return emitted
