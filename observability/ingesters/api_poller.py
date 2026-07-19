# -*- coding: utf-8 -*-
"""Poller REST (§9.2): interroga periodicamente i FortiGate con token API
configurato e accoda snapshot compatti in api_observations, così GUI e AI
leggono dal DB invece di colpire i dispositivi a ogni vista.

Le chiamate REST sono bloccanti (requests): vengono off-loadate su thread
per non bloccare il loop asyncio. Fallimenti per-device sono best-effort:
si logga e si passa al successivo.
"""

import asyncio
import json
import logging
import time

logger = logging.getLogger("sentinelnet.obs.api_poller")

# kind -> funzione di fortigate_service (risolte lazy per evitare cicli import)
_KINDS = ("system_status", "interfaces")

_MAX_SUMMARY = 20_000  # caratteri massimi per snapshot (cap contesto)


def _poll_device(device: dict) -> list:
    """Sincrona: raccoglie gli snapshot per un device. Ritorna [(kind, json)]."""
    from services import fortigate_service
    getters = {
        "system_status": fortigate_service.get_system_status,
        "interfaces": fortigate_service.get_interfaces,
    }
    out = []
    for kind in _KINDS:
        getter = getters.get(kind)
        if getter is None:
            continue
        try:
            res = getter(device)
            summary = json.dumps(res.get("data"), ensure_ascii=False, default=str)
            if len(summary) > _MAX_SUMMARY:
                summary = summary[:_MAX_SUMMARY]
            out.append((kind, summary))
        except Exception as e:
            logger.debug("Poll API %s/%s fallito: %s", device.get("IP"), kind, e)
    return out


def poll_once() -> int:
    """Sincrona: un giro di polling su tutti i FortiGate con token API.
    Ritorna il numero di snapshot accodati."""
    from core import db
    from services import fortigate_service
    from services import inventory_manager

    tokened = set(fortigate_service.token_status().keys())
    if not tokened:
        return 0
    n = 0
    ts = int(time.time())
    for device in inventory_manager.get_all_devices():
        ip = device.get("IP")
        if ip not in tokened:
            continue
        tenant = device.get("Group") or "Generale"
        for kind, summary in _poll_device(device):
            db.enqueue_write(
                "INSERT INTO api_observations(ts, tenant, device_ip, kind, summary_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (ts, tenant, ip, kind, summary),
            )
            n += 1
    return n


async def poll_loop(interval_s: int):
    """Loop asincrono avviato dal lifespan (cancellato allo shutdown)."""
    while True:
        try:
            n = await asyncio.to_thread(poll_once)
            if n:
                logger.info("Poller API: %d snapshot accodati.", n)
        except Exception as e:
            logger.warning("Poller API: giro fallito (%s), riprovo al prossimo intervallo.", e)
        await asyncio.sleep(interval_s)
