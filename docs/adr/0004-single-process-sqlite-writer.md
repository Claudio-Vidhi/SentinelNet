# ADR-0004 — SQLite with one writer thread, single process

**Status:** Accepted
**Date:** 2026-07-27

## Context

Observability ingests UDP bursts (flows, syslog) while the same process serves
the API and a WebSocket SSH terminal. The first implementation opened a
`sqlite3` connection inside the async datagram handler and committed per packet.
Under load that blocked the event loop: the terminal froze and API calls timed
out.

The product is self-hosted and must ship as a single Windows exe and a single
Docker container. A separate database server is not an option.

## Decision

One SQLite file in WAL mode with **exactly one writer**: a dedicated thread
owning its own connection, draining a bounded queue and committing in batches of
up to 500.

Binding rules ([CONTRIBUTING.md](../../CONTRIBUTING.md) §3):

- writes go through `db.enqueue_write()` / `db.enqueue_flow()` — bounded, never
  blocking;
- reads from async endpoints go through `await db.read()`
  (`asyncio.to_thread`, read-only connection per call; WAL allows concurrent
  readers);
- `db.get_observability_connection()` is for migrations and tests only, enforced
  by a grep gate in review.

Writer resilience: if one payload in a batch fails, roll back and re-run the
batch item by item, dropping only the bad payloads (`writes_dropped_error`). If
the writer thread crashes, restart with exponential backoff up to 5 attempts;
past that, writes are dropped but **the app stays alive**.

## Consequences

- The event loop stays responsive under ingest bursts. That was the whole point.
- Batch commits turn per-packet fsync cost into per-batch cost.
- **Observability does not scale horizontally.** `--workers > 1` with
  observability enabled corrupts the assumption — two processes, two writers.
  This is stated in operations and in CONTRIBUTING; it is not a bug report.
- Backups must account for WAL: copying the `.db` without the `-wal` of a live
  process yields a stale file, silently.
- The async-DB rule applies to *all* code, not just ingestion. It is the single
  most common way to make the app slow, so it gets a grep gate.

## Alternatives rejected

**A real database server (PostgreSQL/TimescaleDB).** Correct for the workload,
wrong for the product: a self-hosted tool that must run from one exe cannot
require an operator to install and maintain a database.

**A connection per writer with WAL handling contention.** WAL allows concurrent
readers, not concurrent writers — this trades event-loop blocking for
`SQLITE_BUSY` retries and lock contention.

**Writing from the async handler with `aiosqlite`.** Moves the blocking without
removing it, and doesn't give batch commits.

## When to revisit

If a single site's ingest rate saturates one writer thread (watch
`dropped_queue_full`), or if horizontal scaling becomes a requirement. Either
signal means the storage engine choice is back on the table — not the queue
depth.
