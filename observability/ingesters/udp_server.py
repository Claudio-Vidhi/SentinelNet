# -*- coding: utf-8 -*-
"""Listener UDP asincroni per l'ingest IPFIX/sFlow/syslog (fasi 3.1 + 3.5).

Architettura loop-safe (corregge il difetto #1 della guida originale):
- ``datagram_received`` fa SOLO ``put_nowait`` di (data, addr, recv_ts) su una
  coda asyncio bounded: nessun task per pacchetto, nessun parsing, nessun DB;
  coda piena → scarto + metrica ``dropped_queue_full``.
- Un singolo task consumer per listener estrae dalla coda, parsa (CPU-bound
  ma per-datagramma, quindi breve), attribuisce il tenant e accoda le
  scritture al writer batch di db.py (thread separato).

Attribuzione tenant (fase 3.5, difetto #4): l'IP sorgente del datagramma
viene risolto in un device dell'inventario (inventory_manager.get_device_by_ip,
cache invalidata a ogni modifica inventario). Exporter sconosciuto →
record SCARTATI, upsert in ``quarantined_exporters``, UNA voce di audit
rate-limited per exporter/ora, metrica ``dropped_unknown_exporter``.
Nessun record viene mai scritto con tenant 'default'.
"""

import asyncio
import logging
import time

import db
import inventory_manager
from observability import metrics
from security_manager import log_audit

logger = logging.getLogger("sentinelnet.obs")

INGEST_QUEUE_MAX = 20_000
_AUDIT_INTERVAL_S = 3600  # una voce di audit per exporter sconosciuto all'ora

_SYSLOG_INSERT = """
INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message, exporter_ip)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""

_QUARANTINE_UPSERT = """
INSERT INTO quarantined_exporters (exporter_ip, first_seen, last_seen, packet_count)
VALUES (?, ?, ?, 1)
ON CONFLICT(exporter_ip) DO UPDATE SET
    last_seen = excluded.last_seen,
    packet_count = packet_count + 1
"""

_unknown_audit_last: dict = {}


class _IngestProtocol(asyncio.DatagramProtocol):
    """Handler minimo: accoda e basta (mai bloccare il loop)."""

    def __init__(self, queue: asyncio.Queue, name: str):
        self._queue = queue
        self._name = name

    def datagram_received(self, data: bytes, addr):
        metrics.inc("datagrams_received", listener=self._name)
        try:
            self._queue.put_nowait((data, addr[0], time.time()))
        except asyncio.QueueFull:
            metrics.inc("dropped_queue_full", listener=self._name)

    def error_received(self, exc):
        metrics.inc("parse_errors", proto=self._name)


def _resolve_tenant(exporter_ip: str, recv_ts: float):
    """IP exporter → tenant. None se sconosciuto/collisione (già gestito)."""
    device = inventory_manager.get_device_by_ip(exporter_ip)
    now = time.monotonic()
    if device is None or device.get("collision"):
        metrics.inc("dropped_unknown_exporter")
        db.enqueue_write(_QUARANTINE_UPSERT,
                         (exporter_ip, int(recv_ts), int(recv_ts)))
        last = _unknown_audit_last.get(exporter_ip, 0.0)
        if now - last >= _AUDIT_INTERVAL_S:
            _unknown_audit_last[exporter_ip] = now
            if device is None:
                log_audit(f"Observability: datagrammi da exporter sconosciuto "
                          f"'{exporter_ip}' scartati e messi in quarantena.")
            else:
                log_audit(f"Observability: ANOMALIA — più device in inventario "
                          f"condividono l'IP '{exporter_ip}'; attribuzione rifiutata.")
        return None
    return device["tenant"]


def _handle_records(records, kind: str, recv_ts: float):
    for rec in records:
        tenant = _resolve_tenant(rec["exporter_ip"], recv_ts)
        if tenant is None:
            continue
        if kind == "syslog":
            db.enqueue_write(_SYSLOG_INSERT, (
                rec["ts"], tenant, rec["device_ip"], rec["severity"],
                rec["action"], rec["message"], rec["exporter_ip"]))
        else:
            db.enqueue_flow(
                tenant, rec["src_ip"], rec["dst_ip"], rec["protocol"],
                rec["dst_port"], rec["bytes"], rec["packets"],
                rec["exporter_ip"], export_ts=rec.get("flow_end_ts"),
                receive_ts=recv_ts)


async def _consumer(queue: asyncio.Queue, parser, kind: str, name: str):
    processed = 0
    while True:
        data, src_ip, recv_ts = await queue.get()
        try:
            records = parser(data, src_ip)
            _handle_records(records, kind, recv_ts)
        except Exception as e:
            metrics.inc("parse_errors", proto=name)
            if metrics.should_warn(f"consumer_{name}"):
                logger.warning("Errore nel consumer %s: %s", name, e)
        finally:
            processed += 1
            if processed % 20 == 0:
                metrics.set_gauge("queue_depth", queue.qsize(), listener=name)
                # Con coda piena queue.get() ritorna senza sospendere: senza
                # questo yield periodico il consumer affamerebbe l'event loop
                # (terminale WS, API) durante i burst.
                await asyncio.sleep(0)


# --- Event loop dedicato all'ingest -------------------------------------------
# I listener UDP girano su un loop asyncio SEPARATO in un thread dedicato:
# anche un burst di decine di migliaia di datagrammi non tocca mai il loop
# principale (terminale WS, API restano reattivi). È la correzione strutturale
# del difetto #1 della guida originale.

import threading

_ingest_loop: asyncio.AbstractEventLoop | None = None
_ingest_thread: threading.Thread | None = None
_ingest_lock = threading.Lock()


def _get_ingest_loop() -> asyncio.AbstractEventLoop:
    global _ingest_loop, _ingest_thread
    with _ingest_lock:
        if _ingest_loop and _ingest_thread and _ingest_thread.is_alive():
            return _ingest_loop
        loop = asyncio.new_event_loop()
        # Con l'ingest attivo il thread di parsing è CPU-bound a burst: il
        # default del GIL switch interval (5ms) farebbe attendere il loop
        # principale decine di ms sotto carico. 1ms mantiene reattivi
        # terminale/API con un costo di throughput trascurabile.
        import sys as _sys
        if _sys.getswitchinterval() > 0.001:
            _sys.setswitchinterval(0.001)

        def run():
            asyncio.set_event_loop(loop)
            loop.run_forever()

        thread = threading.Thread(target=run, name="obs-ingest-loop", daemon=True)
        thread.start()
        _ingest_loop, _ingest_thread = loop, thread
        return loop


class ListenerHandle:
    def __init__(self, name, transport, task, queue, loop):
        self.name = name
        self._transport = transport
        self._task = task
        self._queue = queue
        self._loop = loop

    def bound_port(self) -> int:
        return self._transport.get_extra_info("sockname")[1]

    async def stop(self):
        """Chiude il listener (invocabile da qualunque loop/thread)."""
        fut = asyncio.run_coroutine_threadsafe(self._stop_on_ingest_loop(), self._loop)
        await asyncio.wrap_future(fut)

    async def _stop_on_ingest_loop(self):
        self._transport.close()
        # drena la coda residua (best-effort, max 2s)
        deadline = time.monotonic() + 2.0
        while not self._queue.empty() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass


async def _create_listener(host, port, parser, kind, name, loop):
    queue: asyncio.Queue = asyncio.Queue(maxsize=INGEST_QUEUE_MAX)
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: _IngestProtocol(queue, name), local_addr=(host, port))
    task = asyncio.create_task(_consumer(queue, parser, kind, name),
                               name=f"obs-consumer-{name}")
    logger.info("Listener %s in ascolto su %s:%d (UDP).", name, host, port)
    return ListenerHandle(name, transport, task, queue, loop)


async def start_udp_listener(host: str, port: int, parser, kind: str,
                             name: str) -> ListenerHandle:
    """Avvia un listener UDP sul loop di ingest dedicato. ``kind``: 'flow' |
    'syslog'. Solleva OSError se il bind fallisce (gestito dal chiamante)."""
    loop = _get_ingest_loop()
    fut = asyncio.run_coroutine_threadsafe(
        _create_listener(host, port, parser, kind, name, loop), loop)
    return await asyncio.wrap_future(fut)
