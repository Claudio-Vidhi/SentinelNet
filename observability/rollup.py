# -*- coding: utf-8 -*-
"""Job periodico di retention/pruning (fase 3.7) — misura tecnica GDPR
(piano §6.7): elimina le righe STRETTAMENTE più vecchie della finestra
configurata, per tabella. Gli eventi correlati non risolti (status new/ack)
non vengono MAI eliminati automaticamente.

I DELETE sono batchati (BATCH_ROWS righe per transazione, via rowid) per non
tenere lock lunghi. Il prune gira su un thread dedicato (asyncio.to_thread)
con una propria connessione breve: il busy_timeout gestisce la contesa con il
writer; i batch piccoli tengono i lock nell'ordine dei millisecondi.
Sovrapposizioni impedite (skip se il run precedente è ancora attivo).
"""

import asyncio
import logging
import time

from core import data_config
from core import db
from observability import metrics

logger = logging.getLogger("sentinelnet.obs")

BATCH_ROWS = 5000
INTERVAL_S = 3600  # un run all'ora

_TABLES = {
    # tabella -> (colonna ts, filtro extra)
    "flow_aggregates": ("window_start", ""),
    "syslog_events": ("ts", ""),
    "correlated_events": ("created_ts", " AND status = 'resolved'"),
}

_running = False


def prune_once(retention_days: dict) -> dict:
    """Esegue un ciclo di pruning. Ritorna {tabella: righe eliminate}."""
    deleted = {}
    conn = db.get_observability_connection()
    try:
        now = int(time.time())
        for table, (col, extra) in _TABLES.items():
            days = retention_days.get(table)
            if not days or days <= 0:
                continue
            cutoff = now - days * 86400
            total = 0
            while True:
                cur = conn.execute(
                    f"DELETE FROM {table} WHERE rowid IN ("
                    f"SELECT rowid FROM {table} WHERE {col} < ?{extra} LIMIT ?)",
                    (cutoff, BATCH_ROWS))
                conn.commit()
                total += cur.rowcount
                if cur.rowcount < BATCH_ROWS:
                    break
            deleted[table] = total
        metrics.set_gauge("last_prune_ts", now)
    finally:
        conn.close()
    return deleted


async def retention_loop():
    """Task periodico avviato dal lifespan."""
    global _running
    while True:
        try:
            if _running:
                logger.warning("Pruning ancora in corso: run saltato.")
            else:
                _running = True
                try:
                    cfg = data_config.obs_config()
                    deleted = await asyncio.to_thread(prune_once, cfg["retention_days"])
                    if any(deleted.values()):
                        logger.info("Retention: eliminate righe %s.", deleted)
                finally:
                    _running = False
        except Exception as e:
            logger.warning("Errore nel job di retention: %s", e)
        await asyncio.sleep(INTERVAL_S)
