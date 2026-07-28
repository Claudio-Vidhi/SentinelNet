# -*- coding: utf-8 -*-
"""Poller SNMP: sorgente di stato per gli apparati senza API REST.

Il documento chiede correlazione multi-sorgente: oggi lo stato per apparato
arriva solo dai FortiGate col token REST, quindi gli switch — che sono la
maggioranza di una rete — non contribuiscono nulla al ragionamento. SNMP
riempie quel vuoto in modo vendor-agnostico: si interrogano OID standard
(IF-MIB, RFC1213), non comandi CLI da riconoscere per vendore.

DOVE FINISCONO I DATI: negli stessi ``api_observations`` del poller REST, con
``kind`` ``snmp_system`` / ``snmp_interfaces``. Non è un riuso furbo — è che a
valle non deve cambiare niente: gli snapshot vengono già proiettati in
``device.state``, ``interface.state`` e ``interface.change`` da
``normalize._from_api_observations``, quindi regole, evidenze, incidenti e
timeline funzionano da subito. Il trasporto cambia, il fatto no.

FORMA DELLO SNAPSHOT: ``{"results": {"<ifName>": {campo: valore}}}``, la stessa
che espone la REST FortiGate, perché è quella che l'adapter sa già leggere per
attribuire un cambiamento alla singola interfaccia.

Solo LETTURA e solo v2c: nessuna SET, quindi una community compromessa non
consente di modificare un apparato. La community viaggia comunque in chiaro —
è un limite del protocollo, non dell'implementazione: va usato su rete di
management, e la nota è nella scheda del dispositivo.
"""

import asyncio
import json
import logging
import time

logger = logging.getLogger("sentinelnet.obs.snmp_poller")

MAX_INTERFACES = 200      # tetto per apparato: uno chassis grosso non deve
                          # bloccare il giro degli altri
TIMEOUT_S = 2
RETRIES = 1
_MAX_SUMMARY = 20_000

# OID scalari di sistema (RFC1213). Nessuna risoluzione MIB: numerici, così il
# poller non dipende dai file MIB e PyInstaller non deve imbarcarli.
_SYSTEM_OIDS = {
    "1.3.6.1.2.1.1.1.0": "descr",
    "1.3.6.1.2.1.1.3.0": "uptime_ticks",
    "1.3.6.1.2.1.1.5.0": "name",
    "1.3.6.1.2.1.1.6.0": "location",
}

# Colonne IF-MIB da percorrere. ifName è la chiave: è il nome che l'ingegnere
# vede sull'apparato, mentre ifIndex cambia fra i riavvii su diversi vendor.
_IF_COLUMNS = {
    "1.3.6.1.2.1.31.1.1.1.1": "name",        # ifName
    "1.3.6.1.2.1.2.2.1.7": "admin_status",   # ifAdminStatus
    "1.3.6.1.2.1.2.2.1.8": "link",           # ifOperStatus
    "1.3.6.1.2.1.31.1.1.1.6": "in_octets",   # ifHCInOctets
    "1.3.6.1.2.1.31.1.1.1.10": "out_octets",  # ifHCOutOctets
    "1.3.6.1.2.1.2.2.1.14": "in_errors",     # ifInErrors
    "1.3.6.1.2.1.2.2.1.20": "out_errors",    # ifOutErrors
    "1.3.6.1.2.1.31.1.1.1.15": "speed_mbps",  # ifHighSpeed
}

# ifAdminStatus/ifOperStatus sono interi: tradotti in parole perché le regole
# confrontano 'up'/'down' (IFACE_DOWN_001) e un 2 nel summary non spiega nulla.
_IF_STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown",
              5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}


def _scalar(value):
    """Valore pysnmp → tipo Python semplice, adatto a json.dumps."""
    from pysnmp.proto.rfc1905 import NoSuchInstance, NoSuchObject, EndOfMibView
    if isinstance(value, (NoSuchInstance, NoSuchObject, EndOfMibView)):
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return str(value)


async def _walk_column(engine, auth, target, context, oid: str) -> dict:
    """{ifIndex: valore} per una colonna IF-MIB, fermandosi appena si esce
    dal sottoalbero richiesto."""
    from pysnmp.hlapi.v3arch.asyncio import ObjectIdentity, ObjectType, bulk_walk_cmd
    out: dict = {}
    prefix = oid + "."
    async for error, status, index, var_binds in bulk_walk_cmd(
            engine, auth, target, context, 0, 25,
            ObjectType(ObjectIdentity(oid)), lexicographicMode=False):
        if error or status:
            break
        for name, value in var_binds:
            key = str(name)
            if not key.startswith(prefix):
                return out
            out[key[len(prefix):]] = _scalar(value)
            if len(out) >= MAX_INTERFACES:
                return out
    return out


def _interfaces(columns: dict) -> dict:
    """{ifName: {campo: valore}} dalle colonne percorse.

    ifName è la chiave, non ifIndex: l'indice numerico non è confrontabile fra
    un giro e l'altro (diversi vendor lo rinumerano al riavvio), e usarlo
    farebbe sembrare ogni riavvio un cambio di stato su tutte le porte.
    """
    interfaces = {}
    for if_index, name in (columns.get("name") or {}).items():
        if not name:
            continue
        fields = {}
        for field, values in columns.items():
            if field == "name":
                continue
            value = values.get(if_index)
            if value is None:
                continue
            if field in ("link", "admin_status"):
                value = _IF_STATUS.get(value, str(value))
            fields[field] = value
        fields["ifindex"] = int(if_index)
        interfaces[str(name)] = fields
    return interfaces


async def _poll_device(ip: str, community: str, port: int = 161) -> list:
    """[(kind, summary_json)] per un apparato. Lista vuota se non risponde."""
    from pysnmp.hlapi.v3arch.asyncio import (CommunityData, ContextData,
                                             ObjectIdentity, ObjectType,
                                             SnmpEngine, UdpTransportTarget,
                                             get_cmd)
    engine = SnmpEngine()
    auth = CommunityData(community, mpModel=1)          # mpModel=1 = SNMPv2c
    context = ContextData()
    try:
        target = await UdpTransportTarget.create((ip, port), timeout=TIMEOUT_S,
                                                 retries=RETRIES)

        error, status, _, var_binds = await get_cmd(
            engine, auth, target, context,
            *[ObjectType(ObjectIdentity(oid)) for oid in _SYSTEM_OIDS])
        if error or status:
            logger.debug("SNMP %s: sistema non leggibile (%s)", ip, error or status)
            return []
        system = {}
        for name, value in var_binds:
            field = _SYSTEM_OIDS.get(str(name))
            if field:
                system[field] = _scalar(value)

        columns = {}
        for oid, field in _IF_COLUMNS.items():
            columns[field] = await _walk_column(engine, auth, target, context, oid)

        interfaces = _interfaces(columns)
    except Exception as e:
        logger.debug("SNMP %s: giro fallito (%s)", ip, e)
        return []
    finally:
        engine.close_dispatcher()

    def dump(payload):
        text = json.dumps(payload, ensure_ascii=False, default=str)
        return text[:_MAX_SUMMARY]

    return [("snmp_system", dump({"results": system})),
            ("snmp_interfaces", dump({"results": interfaces}))]


def _snmp_devices() -> list:
    """Apparati con una community configurata. La community è cifrata nel
    vault come le altre credenziali: qui viene decifrata solo in memoria."""
    from security.crypto_vault import decrypt_password
    from services import inventory_manager
    out = []
    for device in inventory_manager.get_all_devices():
        community = decrypt_password(device.get("SNMP Community") or "")
        if not community:
            continue
        out.append({"ip": device.get("IP"),
                    "tenant": device.get("Group") or "Generale",
                    "community": community})
    return out


async def poll_once() -> int:
    """Un giro su tutti gli apparati con community. Ritorna gli snapshot scritti.

    Un apparato che non risponde non ferma gli altri: SNMP su UDP tace anche
    solo perché una ACL non contempla il collector, e sarebbe il caso più
    comune, non un'eccezione.
    """
    from core import db
    devices = await asyncio.to_thread(_snmp_devices)
    if not devices:
        return 0
    n = 0
    ts = int(time.time())
    for device in devices:
        for kind, summary in await _poll_device(device["ip"], device["community"]):
            db.enqueue_write(
                "INSERT INTO api_observations(ts, tenant, device_ip, kind, summary_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (ts, device["tenant"], device["ip"], kind, summary))
            n += 1
    return n


async def poll_loop(interval_s: int):
    """Loop asincrono avviato dal lifespan (cancellato allo shutdown)."""
    while True:
        try:
            n = await poll_once()
            if n:
                logger.info("Poller SNMP: %d snapshot accodati.", n)
        except Exception as e:
            logger.warning("Poller SNMP: giro fallito (%s), riprovo al prossimo "
                           "intervallo.", e)
        await asyncio.sleep(interval_s)
