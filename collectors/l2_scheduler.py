# -*- coding: utf-8 -*-
"""L2 discovery scheduler (WP9, docs/app-review-fix-plan.md).

ARP/MAC collection was on-demand only: the endpoint knowledge base aged
silently between manual scans, and mac_history pruning ran merely as a side
effect of a scan. This module gives both a clock.

Default OFF (``l2_poll_s = 0`` in obs_config): the cycle opens SSH sessions
with device credentials, exactly like the SNMP and Linux pollers, so it must
be enabled deliberately, not switch on by itself with observability.
"""

import asyncio
import logging

from core.ssh_pool import run_ssh

logger = logging.getLogger("sentinelnet.obs")


def _collect_once() -> dict:
    """One scheduled cycle: MAC (already pooled), ARP, then prune.

    Each phase is isolated: one collector failing must not stop the others,
    and prune runs even when no collection succeeded."""
    from collectors import arp_collector, mac_collector, mac_history
    from services import inventory_manager

    results: dict = {"mac": None, "arp": None, "pruned": False}
    devices = inventory_manager.get_all_devices()
    if devices:
        try:
            results["mac"] = mac_collector.collect_all(devices)
        except Exception as e:
            logger.warning("Raccolta MAC schedulata fallita: %s", e)
        try:
            results["arp"] = arp_collector.collect_all(devices)
        except Exception as e:
            logger.warning("Raccolta ARP schedulata fallita: %s", e)
    try:
        mac_history.prune()
        results["pruned"] = True
    except Exception as e:
        logger.warning("Prune schedulato di mac_history fallito: %s", e)
    return results


async def poll_loop(interval_s: int):
    """Un ciclo ogni ``interval_s``; la raccolta (bloccante, SSH) gira sul
    pool ``device-ssh`` (WP11) e non sul threadpool condiviso, altrimenti il
    lavoro SSH piu' lungo dell'app siederebbe proprio dove la web surface
    prende i suoi worker. I cicli non si accavallano mai: se una raccolta
    dura più dell'intervallo, il ciclo successivo parte dopo.

    I collector interni tengono i loro pool (8 worker, bounded): il ciclo
    occupa uno slot del pool SSH e ne attende un altro, quindi nessun
    annidamento sullo stesso executor."""
    while True:
        try:
            await run_ssh(_collect_once)
        except Exception as e:
            logger.warning("Ciclo schedulato L2 fallito: %s", e)
        await asyncio.sleep(interval_s)
