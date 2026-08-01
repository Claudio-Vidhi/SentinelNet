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

# VLAN di accesso della porta. NON esiste in IF-MIB, ed è il motivo per cui
# cambiare VLAN a una porta di accesso non produceva alcun evento: lo snapshot
# non conteneva la VLAN, quindi non poteva cambiare, quindi CFG_CHANGE_001 —
# che scatta su ``interface.change`` — non aveva nulla da vedere. Una porta su
# nella VLAN sbagliata è indistinguibile da una porta su, e per chi la usa è
# esattamente un guasto.
#
# Due sorgenti, stessa logica dei CPU OID sopra: vince chi risponde.
#   - vmVlan (CISCO-VLAN-MEMBERSHIP-MIB): indicizzata per ifIndex, è quella
#     che gli switch Cisco popolano davvero per le porte di accesso;
#   - dot1qPvid (Q-BRIDGE): standard e multi-vendor, ma indicizzata per
#     dot1dBasePort — va ricondotta a ifIndex con dot1dBasePortIfIndex, che è
#     il motivo della terza query.
_VLAN_OID_CISCO = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"     # vmVlan (per ifIndex)
_VLAN_OID_QBRIDGE = "1.3.6.1.2.1.17.7.1.4.5.1.1"     # dot1qPvid (per dot1dBasePort)
_BRIDGE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"      # dot1dBasePortIfIndex

# ifAdminStatus/ifOperStatus sono interi: tradotti in parole perché le regole
# confrontano 'up'/'down' (IFACE_DOWN_001) e un 2 nel summary non spiega nulla.
_IF_STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown",
              5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}

# Carico dell'apparato. Non c'è un OID unico che vada bene ovunque: si provano
# entrambi e vince chi risponde. Determinare prima il vendor da sysObjectID
# costerebbe una tabella di mappatura da mantenere per risparmiare una query.
_CPU_OIDS = (
    "1.3.6.1.4.1.9.9.109.1.1.1.1.8",   # CISCO-PROCESS-MIB cpmCPUTotal5minRev
    "1.3.6.1.2.1.25.3.3.1.2",          # HOST-RESOURCES-MIB hrProcessorLoad
    # OLD-CISCO-CPU-MIB avgBusy5: deprecata da vent'anni, ma è l'unica che
    # rispondono gli IOL/IOSv di CML e la espone ancora qualunque IOS reale.
    # Ultima della lista proprio perché è la meno precisa: si usa solo se le
    # altre due tacciono.
    "1.3.6.1.4.1.9.2.1.58",
)
# CISCO-MEMORY-POOL-MIB: usata e libera per pool. La percentuale si calcola,
# non si legge — nessun OID standard la espone già fatta.
_MEM_USED_OID = "1.3.6.1.4.1.9.9.48.1.1.1.5"
_MEM_FREE_OID = "1.3.6.1.4.1.9.9.48.1.1.1.6"


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


async def _load(engine, auth, target, context) -> dict:
    """{cpu_pct, memory_pct} — solo le misure effettivamente ottenute.

    Un apparato che non espone il carico non deve comparire con uno zero: zero
    e "non lo so" sono cose diverse, e una regola a soglia che le confonde
    tacerebbe proprio dove non sta guardando.

    Della CPU si prende il valore PIÙ ALTO fra i core: su uno chassis la media
    nasconde il processo che sta saturando una scheda.
    """
    out: dict = {}
    for oid in _CPU_OIDS:
        values = [v for v in (await _walk_column(engine, auth, target, context,
                                                 oid)).values()
                  if isinstance(v, int)]
        if values:
            out["cpu_pct"] = max(values)
            break

    used = [v for v in (await _walk_column(engine, auth, target, context,
                                           _MEM_USED_OID)).values()
            if isinstance(v, int)]
    free = [v for v in (await _walk_column(engine, auth, target, context,
                                           _MEM_FREE_OID)).values()
            if isinstance(v, int)]
    total = sum(used) + sum(free)
    if used and total > 0:
        out["memory_pct"] = round(sum(used) * 100.0 / total, 1)
    return out


async def _port_vlans(engine, auth, target, context) -> dict:
    """{ifIndex: vlan} — VLAN di accesso per porta, keyed come le altre colonne.

    Un apparato che non è uno switch (router, firewall) non risponde a nessuna
    delle due: si ritorna vuoto e la porta semplicemente non porta il campo,
    invece di scrivere uno zero che poi sembrerebbe una VLAN vera.
    """
    vlans = await _walk_column(engine, auth, target, context, _VLAN_OID_CISCO)
    if vlans:
        return vlans

    pvid = await _walk_column(engine, auth, target, context, _VLAN_OID_QBRIDGE)
    if not pvid:
        return {}
    # dot1qPvid è indicizzata per dot1dBasePort: senza questa traduzione le
    # VLAN finirebbero appiccicate alle porte sbagliate, che è peggio di non
    # averle.
    bridge_to_if = await _walk_column(engine, auth, target, context,
                                      _BRIDGE_PORT_IFINDEX)
    return {str(bridge_to_if[bp]): vlan
            for bp, vlan in pvid.items() if bp in bridge_to_if}


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

        load = await _load(engine, auth, target, context)

        columns = {}
        for oid, field in _IF_COLUMNS.items():
            columns[field] = await _walk_column(engine, auth, target, context, oid)
        columns["port_vlan"] = await _port_vlans(engine, auth, target, context)

        interfaces = _interfaces(columns)
    except Exception as e:
        logger.debug("SNMP %s: giro fallito (%s)", ip, e)
        return []
    finally:
        engine.close_dispatcher()

    def dump(payload):
        text = json.dumps(payload, ensure_ascii=False, default=str)
        return text[:_MAX_SUMMARY]

    # ``metrics`` accanto a ``results``: valori MISURATI, separati dai campi di
    # stato. L'adapter li copia in ``events.metrics_json``, dove le regole a
    # soglia possono leggerli — nei ``results`` sarebbero solo testo da
    # confrontare, e finirebbero per generare un "cambiamento" a ogni giro.
    return [("snmp_system", dump({"results": system, "metrics": load})),
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
