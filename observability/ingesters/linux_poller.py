# -*- coding: utf-8 -*-
"""Poller di salute per gli host Linux gestiti.

Un server Linux non espone né una REST come il FortiGate né, di norma, un
agente SNMP: senza questo poller resterebbe un device che si può interrogare a
mano ma che non contribuisce nulla al ragionamento sugli incidenti.

DOVE FINISCONO I DATI: negli stessi ``api_observations`` degli altri poller,
con ``kind='linux_health'``. Non è riuso furbo — è che a valle non deve
cambiare niente: lo snapshot viene già proiettato in ``device.state`` da
``normalize._from_api_observations``, e ``DEVICE_LOAD_001`` legge
``cpu_pct``/``memory_pct``/``disk_pct`` da ``events.metrics_json`` senza sapere
da dove arrivano.

FORMA DELLO SNAPSHOT: ``{"results": {...stato...}, "metrics": {...misure...}}``.
La separazione non è cosmetica: ``metrics`` è escluso dal rilevamento delle
variazioni (``normalize._stable_fields``), altrimenti una CPU che oscilla
sembrerebbe un cambiamento di configurazione a ogni giro.

NIENTE SUDO: ogni metrica qui è leggibile da un account non privilegiato,
quindi la sessione non chiama mai ``enable()``. Il tier privilegiato esiste
solo nel triage, dove l'operatore ha dichiarato la password sudo.

SOLO SEDI CENTRALI: il processo centrale non apre sessioni SSH verso i device
di una sede in ``mode == 'agent'`` (routers/commands.py). Gli host Linux dietro
un site agent non vengono interrogati; supportarli significa aggiungere il giro
a ``services/site_agent.py``.
"""

import asyncio
import json
import logging
import re
import time

logger = logging.getLogger("sentinelnet.obs.linux_poller")

_MAX_SUMMARY = 20_000

# Un solo comando per sessione: i marcatori separano le sezioni come nel backup.
# Le due letture di /proc/stat a un secondo di distanza servono perché la CPU si
# misura come DELTA fra due campioni — il contenuto grezzo è un contatore da
# boot, e leggerlo una volta sola darebbe la media dall'accensione.
PROBE_COMMAND = (
    'echo "--- CPU ---"; grep "^cpu " /proc/stat; sleep 1; grep "^cpu " /proc/stat; '
    'echo "--- MEM ---"; free -b; '
    'echo "--- DISK ---"; df -P /; '
    'echo "--- UPTIME ---"; cat /proc/uptime; '
    'echo "--- KERNEL ---"; uname -r; '
    'echo "--- FAILED ---"; systemctl --failed --no-legend --plain 2>/dev/null'
)


def _section(output: str, tag: str) -> list:
    """Righe non vuote della sezione ``--- <tag> ---``, [] se assente."""
    m = re.search(rf'--- {tag} ---\s*\n(.*?)(?=\n--- |\Z)', output or "",
                  re.DOTALL)
    if not m:
        return []
    return [l.strip() for l in m.group(1).splitlines() if l.strip()]


def _cpu_pct(output: str):
    """Percentuale di CPU occupata fra i due campioni di /proc/stat.

    Assente ≠ zero: se manca uno dei due campioni non si restituisce nulla,
    perché una regola a soglia che legge zero tacerebbe proprio dove non sta
    guardando.
    """
    samples = []
    for line in _section(output, "CPU"):
        fields = [int(f) for f in line.split()[1:] if f.isdigit()]
        if len(fields) >= 5:
            # user nice system idle iowait ...: inattivo = idle + iowait.
            samples.append((sum(fields), fields[3] + fields[4]))
    if len(samples) < 2:
        return None
    total = samples[-1][0] - samples[0][0]
    idle = samples[-1][1] - samples[0][1]
    if total <= 0:
        return None
    return round((total - idle) * 100.0 / total, 1)


def _memory_pct(output: str):
    """Memoria occupata dalla riga ``Mem:`` di ``free -b``.

    Si usa ``available``, non ``used``: buffer e page cache sono memoria
    riutilizzabile su richiesta, e contarli come occupati farebbe sembrare
    saturo qualunque host che abbia letto un file grosso.
    """
    for line in _section(output, "MEM"):
        if not line.lower().startswith("mem:"):
            continue
        fields = [int(f) for f in line.split()[1:] if f.isdigit()]
        if len(fields) >= 6 and fields[0] > 0:
            return round((fields[0] - fields[5]) * 100.0 / fields[0], 1)
        if len(fields) >= 2 and fields[0] > 0:      # free senza colonna available
            return round(fields[1] * 100.0 / fields[0], 1)
    return None


def _disk_pct(output: str):
    """Percentuale d'uso della radice dall'ultima riga di ``df -P /``."""
    for line in reversed(_section(output, "DISK")):
        m = re.search(r'(\d+)%', line)
        if m:
            return int(m.group(1))
    return None


def parse_health(output: str) -> tuple:
    """(results, metrics) dallo snapshot grezzo di ``PROBE_COMMAND``."""
    uptime = _section(output, "UPTIME")
    kernel = _section(output, "KERNEL")
    results = {"failed_units": len(_section(output, "FAILED"))}
    if uptime:
        try:
            results["uptime_s"] = int(float(uptime[0].split()[0]))
        except (ValueError, IndexError):
            pass
    if kernel:
        results["kernel"] = kernel[0]

    metrics = {}
    for field, value in (("cpu_pct", _cpu_pct(output)),
                         ("memory_pct", _memory_pct(output)),
                         ("disk_pct", _disk_pct(output))):
        if value is not None:
            metrics[field] = value
    return results, metrics


def _linux_devices() -> list:
    """Host dell'inventario il cui vendor normalizza a ``linux``."""
    from services import inventory_manager
    out = []
    for device in inventory_manager.get_all_devices():
        if inventory_manager.normalize_vendor(device.get("Vendor")) != "linux":
            continue
        out.append({"ip": device.get("IP"),
                    "tenant": device.get("Group") or "Generale",
                    "device": device})
    return out


def _poll_device(device: dict) -> list:
    """[(kind, summary_json)] per un host. Lista vuota se non risponde."""
    from netmiko import ConnectHandler
    from core import core_engine
    from drivers.linux import sanitize_session

    ip = str(device.get("IP") or "")
    cli_kind, port = core_engine.get_cli_transport(device)
    if not core_engine.is_reachable(ip, port):
        return []
    username, password, _ = core_engine.get_device_credentials(device)
    try:
        with ConnectHandler(device_type=core_engine._cli_device_type("linux", cli_kind),
                            host=ip, port=port, username=username,
                            password=password, timeout=15, auth_timeout=10,
                            banner_timeout=10) as conn:
            sanitize_session(conn)
            output = conn.send_command(PROBE_COMMAND, read_timeout=30)
    except Exception as e:
        logger.debug("Linux %s: giro fallito (%s)", ip, e)
        return []

    results, metrics = parse_health(output if isinstance(output, str)
                                    else str(output or ""))
    if not results and not metrics:
        return []
    text = json.dumps({"results": results, "metrics": metrics},
                      ensure_ascii=False, default=str)
    return [("linux_health", text[:_MAX_SUMMARY])]


async def poll_once() -> int:
    """Un giro su tutti gli host Linux. Ritorna gli snapshot accodati.

    Un host che non risponde non ferma gli altri: un server spento o dietro una
    ACL è il caso comune, non un'eccezione.
    """
    from core import db
    devices = await asyncio.to_thread(_linux_devices)
    if not devices:
        return 0
    n = 0
    ts = int(time.time())
    for entry in devices:
        for kind, summary in await asyncio.to_thread(_poll_device,
                                                     entry["device"]):
            db.enqueue_write(
                "INSERT INTO api_observations(ts, tenant, device_ip, kind, summary_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (ts, entry["tenant"], entry["ip"], kind, summary))
            n += 1
    return n


async def poll_loop(interval_s: int):
    """Loop asincrono avviato dal lifespan (cancellato allo shutdown)."""
    while True:
        try:
            n = await poll_once()
            if n:
                logger.info("Poller Linux: %d snapshot accodati.", n)
        except Exception as e:
            logger.warning("Poller Linux: giro fallito (%s), riprovo al "
                           "prossimo intervallo.", e)
        await asyncio.sleep(interval_s)
