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

# --- QUALITÀ DELLA MISURA ----------------------------------------------------
# Quattro campioni e centottanta non valgono lo stesso, e una soglia binaria su
# ``samples`` fingeva il contrario. La qualità è SPIEGABILE: accanto al numero
# viaggiano i fattori che l'hanno prodotto, così fra sei mesi la domanda
# "perché quality è 0.41?" ha già la risposta nei dati.
SAMPLES_FOR_FULL = 8      # campioni oltre i quali la numerosità non aggiunge
_METHOD_WEIGHT = {"stesso_giorno_stessa_ora": 1.0,   # coglie la stagionalità
                  "media_mobile_stessa_ora": 0.7}    # ripiego, ignora il giorno


def _quality(samples: int, method: str) -> tuple:
    """(valore 0-1, etichetta, fattori). Nessuna magia: prodotto fra peso del
    metodo e saturazione sulla numerosità.

    ponytail: con la retention flussi a 30 giorni il massimo raggiungibile è
    ~0.5 (4 campioni stagionali). Non è un difetto della formula, è il tetto
    reale dei dati disponibili, ed è giusto che si veda. Allungando la
    retention la qualità sale da sola.
    """
    sample_score = min(1.0, samples / SAMPLES_FOR_FULL)
    method_weight = _METHOD_WEIGHT.get(method, 0.5)
    value = round(method_weight * sample_score, 2)
    label = "HIGH" if value >= 0.7 else ("MEDIUM" if value >= 0.4 else "LOW")
    return value, label, {"samples": samples, "method": method,
                          "sample_score": round(sample_score, 2),
                          "method_weight": method_weight,
                          "samples_for_full": SAMPLES_FOR_FULL}


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
        quality, quality_label, quality_reason = _quality(len(samples), method)
        # metrics = numerico e misurato; attrs = descrittivo. Contratto che
        # qualunque futura osservazione statistica (cpu, latenza, errori di
        # interfaccia) dovrà rispettare: {observed, expected, deviation_pct,
        # samples, quality} in metrics, il resto in attrs.
        conn.execute(
            """INSERT INTO events
                   (ts, ingested_ts, tenant, source, event_type, entity_type,
                    entity_id, src_ip, metrics_json, attrs_json, dedup_key)
               VALUES (?, ?, ?, 'baseline', 'flow.baseline', 'flow', ?, ?, ?, ?, ?)
               ON CONFLICT(dedup_key) DO UPDATE SET
                   metrics_json = excluded.metrics_json""",
            (hour, now, tenant, src_ip, src_ip,
             json.dumps({"observed": value, "expected": expected,
                         "deviation_pct": deviation_pct,
                         "samples": len(samples), "quality": quality},
                        ensure_ascii=False),
             json.dumps({"method": method, "window": "1h",
                         "quality_label": quality_label,
                         "quality_reason": quality_reason},
                        ensure_ascii=False),
             f"baseline:{tenant}:{src_ip}:{hour}"))
        emitted += 1
    return emitted


MIN_HISTORY_S = 86400     # storia minima prima di poter dire "mai visto"


def detect_emergence(conn, hour: int, now: int) -> int:
    """Talker mai visti prima: fenomeno DIVERSO dallo scostamento.

    Un host che compare dal nulla non si discosta da un'abitudine, non ne ha
    una. La domanda giusta non è "quanto ha trasmesso in quest'ora nelle
    settimane scorse" — con quella, un host che parla ogni giorno alle 09:00 ma
    mai alle 14:00 risulterebbe nuovo ogni pomeriggio — ma "ha MAI trasmesso,
    in tutta la finestra conservata, prima di adesso".

    Guardia obbligatoria: senza abbastanza storia alle spalle tutto sembra
    nuovo. A installazione fresca non si emette nulla.
    """
    rows = conn.execute(
        f"""SELECT tenant, src_ip, SUM(total_bytes) AS total
            FROM flow_aggregates
            WHERE window_start >= ? AND window_start < ?
            GROUP BY tenant, src_ip
            ORDER BY total DESC LIMIT {MAX_ENTITIES_PER_HOUR}""",
        (hour, hour + HOUR_S)).fetchall()
    if not rows:
        return 0

    emitted = 0
    by_tenant: dict = {}
    for r in rows:
        by_tenant.setdefault(r["tenant"], []).append((r["src_ip"], r["total"]))

    for tenant, entities in by_tenant.items():
        oldest = conn.execute(
            "SELECT MIN(window_start) AS m FROM flow_aggregates WHERE tenant = ?",
            (tenant,)).fetchone()["m"]
        if oldest is None or oldest > hour - MIN_HISTORY_S:
            continue   # storia troppo corta: qui è nuovo tutto, e non vuol dire nulla

        ips = [ip for ip, _ in entities]
        placeholders = ",".join("?" * len(ips))
        seen = {r["src_ip"] for r in conn.execute(
            f"""SELECT DISTINCT src_ip FROM flow_aggregates
                WHERE tenant = ? AND window_start < ? AND src_ip IN ({placeholders})""",
            (tenant, hour, *ips)).fetchall()}

        for src_ip, total in entities:
            if src_ip in seen:
                continue
            conn.execute(
                """INSERT INTO events
                       (ts, ingested_ts, tenant, source, event_type, entity_type,
                        entity_id, src_ip, metrics_json, attrs_json, dedup_key)
                   VALUES (?, ?, ?, 'baseline', 'flow.emergence', 'flow', ?, ?, ?, ?, ?)
                   ON CONFLICT(dedup_key) DO NOTHING""",
                (hour, now, tenant, src_ip, src_ip,
                 json.dumps({"observed": total}, ensure_ascii=False),
                 json.dumps({"history_since": oldest, "window": "1h"},
                            ensure_ascii=False),
                 f"emergence:{tenant}:{src_ip}:{hour}"))
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
        emitted += detect_emergence(conn, hour, now)
    conn.execute(
        """INSERT INTO normalize_cursors (source, last_id, last_ts)
           VALUES ('baseline', 0, ?)
           ON CONFLICT(source) DO UPDATE SET last_ts = ?""",
        (hours[-1], hours[-1]))
    metrics.inc("baseline_events_emitted", emitted)
    return emitted
