# -*- coding: utf-8 -*-
"""Gestore centrale dei listener/task di observability (fase 3.9): applica
una config desiderata (da ``data_config.obs_config()``) allo stato live
dell'app, sia all'avvio (lifespan) sia a runtime (POST /api/observability/config),
senza mai richiedere il riavvio del processo.

Stato tenuto a livello di modulo (non su ``app.state``) così l'endpoint può
richiamare ``apply_obs_config`` senza bisogno di un riferimento a ``FastAPI``.

Listener UDP (ipfix/netflow/sflow/syslog): diff fra handle attivi e config
desiderata — ferma quelli rimossi/cambiati (bind o porta), poi avvia quelli
mancanti. Lo stop precede sempre lo start per lo stesso nome (rebind pulito
su Windows, che non permette il doppio bind della stessa porta).

Task di background (retention, correlazione, poller API): partono alla prima
attivazione del master switch "enabled" e restano attivi (sono idle/no-op se
non c'è nulla da fare); il poller API viene riavviato se cambia l'intervallo.
"""

import asyncio
import logging

logger = logging.getLogger("sentinelnet.obs")

# name -> ListenerHandle
_handles: dict = {}
# name -> (bind, port) effettivamente attivi, per il diff
_current: dict = {}

_retention_task: "asyncio.Task | None" = None
_correlation_task: "asyncio.Task | None" = None
_api_poller_task: "asyncio.Task | None" = None
_api_poller_interval: int = 0


def _listener_specs(cfg):
    """(name, listener_cfg, parser, kind) per i quattro protocolli supportati."""
    from observability.ingesters import ipfix, sflow, syslog as syslog_parser
    return (
        ("ipfix", cfg["ipfix"], ipfix.parse, "flow"),
        ("netflow", cfg["netflow"], ipfix.parse, "flow"),
        ("sflow", cfg["sflow"], sflow.parse, "flow"),
        ("syslog", cfg["syslog"], syslog_parser.parse, "syslog"),
    )


async def _apply_listeners(cfg):
    from observability.ingesters.udp_server import start_udp_listener
    from routers import observability as _obs_router_mod

    specs = _listener_specs(cfg)
    desired = {}
    for name, lcfg, parser, kind in specs:
        if cfg["enabled"] and lcfg["enabled"]:
            desired[name] = (cfg["bind"], lcfg["port"], parser, kind)

    # 1. Ferma i listener rimossi o con bind/porta cambiati (stop-before-start).
    for name in list(_handles):
        want = desired.get(name)
        have = _current.get(name)
        if want is None or (want[0], want[1]) != have:
            handle = _handles.pop(name)
            _current.pop(name, None)
            try:
                await handle.stop()
            except Exception as e:
                logger.warning("Errore fermando il listener %s: %s", name, e)
            if want is None:
                _obs_router_mod.listener_status[name] = {"active": False}

    # 2. Avvia i listener mancanti (nuovi o appena riconfigurati).
    for name, (bind, port, parser, kind) in desired.items():
        if name in _handles:
            continue
        try:
            handle = await start_udp_listener(bind, port, parser, kind, name)
            _handles[name] = handle
            _current[name] = (bind, port)
            _obs_router_mod.listener_status[name] = {
                "active": True, "bind": bind, "port": port}
            logger.info("Observability: listener %s attivo su %s:%d (UDP).",
                       name, bind, port)
        except OSError as e:
            from observability import metrics as _obs_metrics
            _obs_metrics.inc("listener_bind_failed", listener=name)
            _obs_router_mod.listener_status[name] = {
                "active": False, "error": str(e)}
            logger.error("Bind del listener %s su %s:%d fallito (%s). "
                        "Listener saltato, l'applicazione resta attiva.",
                        name, bind, port, e)

    # 3. Segna esplicitamente disattivi i listener mai attivati (config
    # disabilitata sin dall'inizio: nessun handle da fermare).
    for name, lcfg, parser, kind in specs:
        if name not in desired and name not in _obs_router_mod.listener_status:
            _obs_router_mod.listener_status[name] = {"active": False}


async def apply_obs_config(cfg):
    """Applica la config observability allo stato live: listener UDP + task
    di background. Idempotente — richiamabile sia al boot (lifespan) sia a
    ogni salvataggio di config (endpoint), senza restart del processo."""
    global _retention_task, _correlation_task, _api_poller_task, _api_poller_interval

    await _apply_listeners(cfg)

    if cfg["enabled"]:
        if _retention_task is None:
            from observability import rollup
            _retention_task = asyncio.create_task(rollup.retention_loop(),
                                                   name="obs-retention")
        if _correlation_task is None:
            from observability import correlator
            _correlation_task = asyncio.create_task(correlator.correlation_loop(),
                                                     name="obs-correlation")
        desired_interval = int(cfg.get("api_poll_s", 0) or 0)
    else:
        desired_interval = 0

    if desired_interval != _api_poller_interval or \
            (desired_interval > 0 and _api_poller_task is None):
        if _api_poller_task is not None:
            _api_poller_task.cancel()
            _api_poller_task = None
        if desired_interval > 0:
            from observability.ingesters import api_poller
            _api_poller_task = asyncio.create_task(
                api_poller.poll_loop(desired_interval), name="obs-api-poller")
        _api_poller_interval = desired_interval


async def shutdown():
    """Ferma tutti i listener e i task di background (spegnimento app)."""
    global _retention_task, _correlation_task, _api_poller_task, _api_poller_interval
    for task in (_retention_task, _correlation_task, _api_poller_task):
        if task is not None:
            task.cancel()
    _retention_task = None
    _correlation_task = None
    _api_poller_task = None
    _api_poller_interval = 0

    for name in list(_handles):
        handle = _handles.pop(name)
        _current.pop(name, None)
        try:
            await handle.stop()
        except Exception as e:
            logger.warning("Errore fermando il listener %s: %s", name, e)
