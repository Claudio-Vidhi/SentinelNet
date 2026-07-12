# -*- coding: utf-8 -*-
"""Strato di accesso async-safe a observability.db (SQLite, WAL).

Regole (vedi docs/MASTER-IMPLEMENTATION-PLAN.md §1.2 e CONTRIBUTING.md):
- UNICA connessione in scrittura, posseduta dal thread writer dedicato.
- Le scritture NON si fanno mai direttamente: si accodano con
  ``enqueue_write()`` (coda bounded, non bloccante; se piena il payload viene
  scartato e conteggiato in ``metrics``).
- Le letture dagli endpoint async passano da ``read()`` (off-load su thread,
  connessione read-only per chiamata: WAL consente letture concorrenti).
- ``get_observability_connection()`` è SOLO per migrazioni e test: vietata
  nei percorsi async (gate di CI via grep).

Il writer esegue commit BATCH: consuma fino a ``BATCH_SIZE`` payload o quanto
disponibile, esegue, un solo commit. Crash del writer → riavvio automatico
con tentativi limitati; oltre il limite le scritture vengono scartate con
metrica (l'app resta viva, §2.7 del piano).
"""

import asyncio
import logging
import os
import queue
import sqlite3
import sys
import threading
import time

import data_config

logger = logging.getLogger("sentinelnet.db")

SCHEMA_VERSION = 2          # versione schema supportata da questo codice (v2: api_observations)
QUEUE_MAX = 10_000          # payload massimi in coda scritture
BATCH_SIZE = 500            # payload massimi per singolo commit
MAX_WRITER_RESTARTS = 5     # riavvii writer consentiti prima del fail-open
CLOCK_SKEW_MAX_S = 300      # tolleranza timestamp exporter (±300s, §1.4)

metrics = {
    "writes_ok": 0,
    "writes_dropped_queue_full": 0,
    "writes_dropped_error": 0,
    "writer_restarts": 0,
    "clock_skew_fallback": 0,
}

_write_queue: "queue.Queue[tuple[str, tuple]]" = queue.Queue(maxsize=QUEUE_MAX)
_writer_thread: threading.Thread | None = None
_stop_event = threading.Event()


def get_db_path() -> str:
    return data_config.get_path("observability.db")


def _schema_path() -> str:
    """Percorso di schema.sql, funzionante da sorgente, exe bundled e Docker."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "observability", "storage", "schema.sql")


def _configure(conn: sqlite3.Connection) -> sqlite3.Connection:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_observability_connection() -> sqlite3.Connection:
    """SOLO per migrazioni e test. Mai nei percorsi async (vedi CONTRIBUTING.md)."""
    return _configure(sqlite3.connect(get_db_path()))


class SchemaTooNewError(RuntimeError):
    """Il DB è stato scritto da una versione più recente del codice."""
    pass


def migrate() -> None:
    """Applica lo schema (idempotente, forward-only) e registra la versione.

    Guardia di downgrade: se il DB dichiara una versione più nuova di quella
    supportata dal codice, l'osservabilità rifiuta di partire (l'app di
    gestione resta su) — contratto di rollback del piano (§6.3).
    """
    conn = get_observability_connection()
    try:
        row = None
        try:
            row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
        except sqlite3.OperationalError:
            pass  # DB nuovo: schema_version non esiste ancora
        current = row["v"] if row and row["v"] is not None else 0
        if current > SCHEMA_VERSION:
            raise SchemaTooNewError(
                f"observability.db ha schema versione {current}, ma questo codice "
                f"supporta al massimo la {SCHEMA_VERSION}. Aggiornare SentinelNet "
                "oppure ripristinare il database precedente."
            )
        with open(_schema_path(), encoding="utf-8") as f:
            conn.executescript(f.read())
        if current < SCHEMA_VERSION:
            conn.execute("DELETE FROM schema_version")
            conn.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
        conn.commit()
    finally:
        conn.close()


# --- LETTURE (async, executor-offloaded) ------------------------------------

async def read(sql: str, params: tuple = ()) -> list:
    """Esegue una SELECT su un thread (mai nel loop) e ritorna le righe."""
    def _run():
        conn = _configure(sqlite3.connect(get_db_path()))
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()
    return await asyncio.to_thread(_run)


# --- SCRITTURE (coda bounded + writer dedicato) ------------------------------

def enqueue_write(sql: str, params: tuple = ()) -> bool:
    """Accoda una scrittura. Non blocca mai: se la coda è piena il payload è
    scartato (metrica ``writes_dropped_queue_full``) e ritorna False."""
    try:
        _write_queue.put_nowait((sql, params))
        return True
    except queue.Full:
        metrics["writes_dropped_queue_full"] += 1
        return False


def flow_window_start(export_ts, receive_ts=None) -> int:
    """Bucket al minuto per un flusso (§1.4): usa il timestamp dell'exporter
    se entro ±300s dalla ricezione, altrimenti il tempo di ricezione
    (metrica ``clock_skew_fallback``)."""
    now = int(receive_ts if receive_ts is not None else time.time())
    try:
        ts = int(export_ts)
    except (TypeError, ValueError):
        ts = None
    if ts is None or abs(ts - now) > CLOCK_SKEW_MAX_S:
        if ts is not None:
            metrics["clock_skew_fallback"] += 1
        ts = now
    return ts - (ts % 60)


FLOW_UPSERT_SQL = """
INSERT INTO flow_aggregates
    (window_start, tenant, src_ip, dst_ip, protocol, dst_port,
     total_bytes, total_packets, flow_count, exporter_ip)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
ON CONFLICT(window_start, tenant, src_ip, dst_ip, protocol, dst_port)
DO UPDATE SET
    total_bytes   = total_bytes   + excluded.total_bytes,
    total_packets = total_packets + excluded.total_packets,
    flow_count    = flow_count    + 1,
    exporter_ip   = excluded.exporter_ip
"""


def enqueue_flow(tenant: str, src_ip: str, dst_ip: str, protocol, dst_port,
                 total_bytes: int, total_packets: int, exporter_ip: str,
                 export_ts=None, receive_ts=None) -> bool:
    """Accoda l'UPSERT di aggregazione al minuto per un flusso (§1.4)."""
    return enqueue_write(FLOW_UPSERT_SQL, (
        flow_window_start(export_ts, receive_ts), tenant, src_ip, dst_ip,
        protocol, dst_port, int(total_bytes or 0), int(total_packets or 0),
        exporter_ip,
    ))


def _writer_loop():
    """Loop del thread writer: unica connessione in scrittura, commit batch."""
    conn = get_observability_connection()
    try:
        while not _stop_event.is_set() or not _write_queue.empty():
            try:
                item = _write_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            batch = [item]
            while len(batch) < BATCH_SIZE:
                try:
                    batch.append(_write_queue.get_nowait())
                except queue.Empty:
                    break
            try:
                for sql, params in batch:
                    conn.execute(sql, params)
                conn.commit()
                metrics["writes_ok"] += len(batch)
            except sqlite3.Error:
                # Un payload difettoso non deve far perdere l'intero batch:
                # rollback e riesecuzione item-per-item, scartando solo i
                # payload che falliscono (l'app resta viva, §2.7).
                conn.rollback()
                for sql, params in batch:
                    try:
                        conn.execute(sql, params)
                        conn.commit()
                        metrics["writes_ok"] += 1
                    except sqlite3.Error as e:
                        conn.rollback()
                        metrics["writes_dropped_error"] += 1
                        logger.warning("Scrittura observability scartata: %s", e)
    finally:
        conn.close()


def _writer_supervisor():
    """Supervisiona il writer: riavvio su crash, con tentativi limitati."""
    restarts = 0
    while not _stop_event.is_set():
        try:
            _writer_loop()
            return  # uscita pulita (stop richiesto)
        except Exception as e:
            restarts += 1
            metrics["writer_restarts"] = restarts
            if restarts > MAX_WRITER_RESTARTS:
                logger.error(
                    "Writer observability terminato definitivamente dopo %d riavvii: %s. "
                    "Le nuove scritture verranno scartate; l'app resta operativa.",
                    restarts, e,
                )
                return
            logger.warning("Writer observability crashato (%s), riavvio %d/%d.",
                           e, restarts, MAX_WRITER_RESTARTS)
            time.sleep(min(2 ** restarts, 30))


def start_writer() -> None:
    """Avvia migrazione + thread writer (chiamato dal lifespan dell'app)."""
    global _writer_thread
    if _writer_thread and _writer_thread.is_alive():
        return
    migrate()
    _stop_event.clear()
    _writer_thread = threading.Thread(
        target=_writer_supervisor, name="obs-db-writer", daemon=True)
    _writer_thread.start()


def stop_writer(drain_timeout: float = 10.0) -> None:
    """Ferma il writer drenando la coda (best-effort entro il timeout)."""
    global _writer_thread
    if not _writer_thread:
        return
    _stop_event.set()
    _writer_thread.join(timeout=drain_timeout)
    _writer_thread = None
