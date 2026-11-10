# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Async-safe access layer to observability.db (SQLite, WAL).

Rules (see CONTRIBUTING.md §3 and docs/adr/0004-single-process-sqlite-writer.md):
- SINGLE write connection, owned by the dedicated writer thread.
- Writes are NEVER done directly: they are enqueued via
  ``enqueue_write()`` (bounded, non-blocking queue; if full the payload is
  dropped and counted in ``metrics``).
- Reads from async endpoints go through ``read()`` (off-loaded to a thread,
  read-only connection per call: WAL allows concurrent reads).
- ``get_observability_connection()`` is a blocking connection: never on the
  event loop. Migrations, tests, background worker threads and helpers handed
  to ``asyncio.to_thread`` may use it (short transactional read-modify-write;
  busy_timeout covers contention with the writer). Enforced by
  tests/test_no_sync_db_on_event_loop.py.

The writer performs BATCH commits: consumes up to ``BATCH_SIZE`` payloads or
whatever is available, executes, a single commit. Writer crash → automatic restart
with limited attempts; beyond the limit writes are dropped with a metric
(the app stays alive, §2.7 of the plan).
"""

import asyncio
import logging
import os
import queue
import sqlite3
import sys
import threading
import time

from core import data_config

logger = logging.getLogger("sentinelnet.db")

SCHEMA_VERSION = 15         # schema version supported by this code (v15: audit_engagements.location_id)
QUEUE_MAX = 10_000          # max payloads in the write queue
BATCH_SIZE = 500            # max payloads per single commit
MAX_WRITER_RESTARTS = 5     # writer restarts allowed before fail-open

metrics = {
    "writes_ok": 0,
    "writes_dropped_queue_full": 0,
    "writes_dropped_error": 0,
    "writer_restarts": 0,
    "writer_dead": 0,
}

_write_queue: "queue.Queue[tuple[str, tuple]]" = queue.Queue(maxsize=QUEUE_MAX)
_writer_thread: threading.Thread | None = None
_stop_event = threading.Event()

# Drop announcements are rate-limited: a burst must not flood the log, but
# the first drop and its recurrence must be visible (WP7: loss stays loud).
DROP_LOG_INTERVAL_S = 60.0
_drop_last_log_ts = 0.0


def _log_queue_full_drops(total_dropped: int) -> bool:
    """Logs a queue-full drop at most once per DROP_LOG_INTERVAL_S.
    Returns True when a line was actually emitted (test hook)."""
    global _drop_last_log_ts
    now = time.monotonic()
    if now - _drop_last_log_ts >= DROP_LOG_INTERVAL_S:
        _drop_last_log_ts = now
        logger.warning("Coda scritture observability piena: payload scartato "
                       "(totale scartati dall'avvio: %d).", total_dropped)
        return True
    return False


def health_state() -> dict:
    """Writer health for the /api/observability/health endpoint: data loss
    must surface as a state the operator can read, not just a counter."""
    dropped = metrics.get("writes_dropped_queue_full", 0)
    dead = bool(metrics.get("writer_dead"))
    return {
        "writer_dead": dead,
        "writes_dropped_queue_full": dropped,
        "writes_dropped_error": metrics.get("writes_dropped_error", 0),
        "writer_restarts": metrics.get("writer_restarts", 0),
        "queue_depth": _write_queue.qsize(),
        "degraded": dead or dropped > 0,
    }


def get_db_path() -> str:
    return data_config.get_path("observability.db")


def _schema_path() -> str:
    """Path to schema.sql, working from source, bundled exe, and Docker."""
    # In source this module lives in core/, so the repo root is one
    # level up; in the bundled exe (_MEIPASS) instead it stays the root itself.
    src_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    base = getattr(sys, "_MEIPASS", src_root)
    return os.path.join(base, "observability", "storage", "schema.sql")


def _configure(conn: sqlite3.Connection) -> sqlite3.Connection:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_observability_connection() -> sqlite3.Connection:
    """Blocking connection: never on the event loop (see CONTRIBUTING.md §3)."""
    return _configure(sqlite3.connect(get_db_path()))


class SchemaTooNewError(RuntimeError):
    """The DB was written by a newer version of the code."""
    pass


def migrate() -> None:
    """Applies the schema (idempotent, forward-only) and records the version.

    Downgrade guard: if the DB declares a newer version than the one
    supported by the code, observability refuses to start (the management
    app stays up) — rollback contract of the plan (§6.3).
    """
    conn = get_observability_connection()
    try:
        row = None
        try:
            row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
        except sqlite3.OperationalError:
            pass  # New DB: schema_version does not exist yet
        current = row["v"] if row and row["v"] is not None else 0
        if current > SCHEMA_VERSION:
            raise SchemaTooNewError(
                f"observability.db ha schema versione {current}, ma questo codice "
                f"supporta al massimo la {SCHEMA_VERSION}. Aggiornare SentinelNet "
                "oppure ripristinare il database precedente."
            )
        with open(_schema_path(), encoding="utf-8") as f:
            conn.executescript(f.read())
        # run_name arrived after netsec_audit_runs shipped (CREATE TABLE IF NOT
        # EXISTS does not touch already-created tables).
        ar_cols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(netsec_audit_runs)").fetchall()}
        if ar_cols and "run_name" not in ar_cols:
            conn.execute("ALTER TABLE netsec_audit_runs ADD COLUMN run_name TEXT")
        # v15: an engagement's place is a location, not a probe.
        ae_cols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(audit_engagements)").fetchall()}
        if "site_id" in ae_cols:  # check-site-name: ok
            conn.execute("ALTER TABLE audit_engagements "
                         "RENAME COLUMN site_id TO location_id")  # check-site-name: ok
        if current < SCHEMA_VERSION:
            conn.execute("DELETE FROM schema_version")
            conn.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
        conn.commit()
    finally:
        conn.close()


# --- READS (async, executor-offloaded) ------------------------------------

async def read(sql: str, params: tuple = ()) -> list:
    """Runs a SELECT on a thread (never in the loop) and returns the rows."""
    def _run():
        conn = _configure(sqlite3.connect(get_db_path()))
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()
    return await asyncio.to_thread(_run)


# --- WRITES (bounded queue + dedicated writer) ------------------------------

def enqueue_write(sql: str, params: tuple = ()) -> bool:
    """Enqueues a write. Never blocks: if the queue is full the payload is
    dropped (metric ``writes_dropped_queue_full``) and returns False."""
    try:
        _write_queue.put_nowait((sql, params))
        return True
    except queue.Full:
        metrics["writes_dropped_queue_full"] += 1
        _log_queue_full_drops(metrics["writes_dropped_queue_full"])
        return False


def _writer_loop():
    """Writer thread loop: single write connection, batch commit."""
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
                # A faulty payload must not lose the whole batch:
                # rollback and re-execution item-per-item, dropping only the
                # payloads that fail (the app stays alive, §2.7).
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
    """Supervises the writer: restart on crash, with limited attempts."""
    restarts = 0
    while not _stop_event.is_set():
        try:
            _writer_loop()
            return  # clean exit (stop requested)
        except Exception as e:
            restarts += 1
            metrics["writer_restarts"] = restarts
            if restarts > MAX_WRITER_RESTARTS:
                metrics["writer_dead"] = 1
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
    """Starts migration + writer thread (called by the app lifespan)."""
    global _writer_thread
    if _writer_thread and _writer_thread.is_alive():
        return
    migrate()
    metrics["writer_dead"] = 0
    _stop_event.clear()
    _writer_thread = threading.Thread(
        target=_writer_supervisor, name="obs-db-writer", daemon=True)
    _writer_thread.start()


def stop_writer(drain_timeout: float = 10.0) -> None:
    """Stops the writer draining the queue (best-effort within the timeout)."""
    global _writer_thread
    if not _writer_thread:
        return
    _stop_event.set()
    _writer_thread.join(timeout=drain_timeout)
    _writer_thread = None
