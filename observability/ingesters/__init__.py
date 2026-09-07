# -*- coding: utf-8 -*-
"""Ingester dei dati di osservabilita' (poller e listener)."""
import asyncio
import logging

logger = logging.getLogger(__name__)


async def run_poll_loop(label: str, poll_once, interval_s: int):
    """Loop di polling avviato dal lifespan (cancellato allo shutdown).

    ``poll_once`` e' una coroutine che ritorna quanti snapshot ha accodato. Un
    giro fallito viene registrato e basta: il poller successivo riprova, mentre
    lasciar propagare l'eccezione ucciderebbe il task per sempre.

    I tre poller (API, Linux, SNMP) avevano tre copie identiche di queste dieci
    righe, quindi un cambio di backoff andava fatto tre volte o divergevano.
    """
    while True:
        try:
            n = await poll_once()
            if n:
                logger.info("Poller %s: %d snapshot accodati.", label, n)
        except Exception as e:
            logger.warning("Poller %s: giro fallito (%s), riprovo al prossimo "
                           "intervallo.", label, e)
        await asyncio.sleep(interval_s)
