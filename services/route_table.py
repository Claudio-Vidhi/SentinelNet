# -*- coding: utf-8 -*-
"""One routing table out of the devices that already publish theirs.

The FortiGate tab has shown a per-device route list since it shipped: pick a
firewall, read its RIB. The question an engineer actually asks is the other
one — "who has a route to this network, and does it agree with the neighbour"
— and answering it meant opening the tab once per device and comparing by eye.

Nothing new is collected here. This calls the same
``fortigate_service.get_routes`` (REST ``monitor/router/ipv4``, SSH fallback)
across the devices in the caller's scope and normalises the answers into one
shape. Devices that only answer over SSH return CLI text rather than rows;
they are reported as such instead of being parsed, because a routing-table
parser is a collector and this is not one.
"""
import logging
import re

from services import fortigate_service, inventory_manager

logger = logging.getLogger("sentinelnet.route_table")

# Tipi di rotta normalizzati. FortiOS scrive 'connect'/'static'/'ospf'/'bgp',
# a volte maiuscolo: la UI raggruppa su questi, non sulle stringhe grezze.
_TYPE_ALIASES = {
    "connect": "connected", "connected": "connected", "direct": "connected",
    # IOS distingue la rete connessa (C) dal /32 dell'interfaccia (L). Restano
    # due tipi: una tabella in cui ogni SVI compare due volte come "connected"
    # si legge come un errore di raccolta.
    "local": "local",
    "static": "static",
    "ospf": "ospf", "ospf-inter-area": "ospf", "ospf-external": "ospf",
    "bgp": "bgp", "rip": "rip", "isis": "isis", "eigrp": "eigrp",
}


def normalize_type(raw) -> str:
    """Il tipo di rotta in una delle famiglie che la vista raggruppa.

    Sconosciuto resta sconosciuto ('other'): inventare 'static' per una rotta
    che il firewall ha chiamato in un altro modo e' esattamente il genere di
    dettaglio che poi si legge come un fatto."""
    key = str(raw or "").strip().lower()
    return _TYPE_ALIASES.get(key, "other" if key else "unknown")


# --- Cisco IOS: `show ip route` -----------------------------------------------
#
# I FortiGate rispondono in REST; gli switch no, e la loro RIB esiste solo come
# testo. Le lettere in prima colonna sono la classificazione che l'apparato fa
# gia' della propria tabella: mapparle e' tradurre, non indovinare.
_IOS_CODE_TYPES = {
    "C": "connected", "L": "local", "S": "static", "R": "rip",
    "B": "bgp", "O": "ospf", "D": "eigrp", "i": "isis", "M": "other",
}

# Riga di rotta: codice, rete, e il resto. Il codice puo' portare un
# qualificatore (O IA, O E2, D EX, i L1) che NON cambia la famiglia.
_IOS_ROUTE = re.compile(
    r"^(?P<code>[A-Za-z])(?P<star>\*)?(?:\s+(?:IA|EX|E1|E2|N1|N2|L1|L2|su))?"
    r"\s+(?P<net>\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\s+(?P<rest>.*)$")

# Next-hop aggiuntivo della rotta precedente: nessun codice, nessuna rete.
_IOS_EXTRA_HOP = re.compile(
    r"^\s+\[(?P<dist>\d+)/(?P<metric>\d+)\]\s+via\s+"
    r"(?P<gw>\d{1,3}(?:\.\d{1,3}){3})(?P<tail>.*)$")

_IOS_VIA = re.compile(
    r"\[(?P<dist>\d+)/(?P<metric>\d+)\]\s+via\s+"
    r"(?P<gw>\d{1,3}(?:\.\d{1,3}){3})(?P<tail>.*)$")

_IOS_CONNECTED = re.compile(r"is\s+directly\s+connected,\s*(?P<intf>\S+)")


def _ios_interface(tail: str) -> str:
    """L'interfaccia in coda a una riga `via`, quando c'e'.

    IOS scrive `via 10.0.0.2, 00:05:23, Vlan10` ma anche `via 10.0.0.2` e
    basta: l'ultimo campo e' un'interfaccia solo se non e' un tempo."""
    parts = [x.strip() for x in (tail or "").split(",") if x.strip()]
    if not parts:
        return ""
    last = parts[-1]
    # 00:05:23, 1d02h, 3w4d, never: eta', non interfacce.
    if re.fullmatch(r"[\d:]+|\d+[dwyhm]\d*[dwyhm]?|never", last):
        return ""
    return last


def parse_ios_routes(output: str) -> list:
    """`show ip route` di IOS in righe {network, gateway, interface, type,
    distance, metric}.

    Si ignorano le intestazioni (`Codes:`, `Gateway of last resort`) e le righe
    `is variably subnetted`, che annunciano un gruppo e non sono rotte: contarle
    gonfierebbe ogni conteggio di una riga per blocco.
    """
    rows: list = []
    for raw in (output or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        low = line.strip().lower()
        if (low.startswith(("codes:", "gateway of last resort"))
                or "subnetted" in low or low.startswith("%")):
            continue

        extra = _IOS_EXTRA_HOP.match(line)
        if extra and rows:
            # Rotta a piu' next-hop: stessa rete, stesso tipo, altro gateway.
            prev = rows[-1]
            rows.append({**prev, "gateway": extra.group("gw"),
                         "interface": _ios_interface(extra.group("tail")),
                         "distance": int(extra.group("dist")),
                         "metric": int(extra.group("metric"))})
            continue

        m = _IOS_ROUTE.match(line.strip())
        if not m:
            continue
        route_type = _IOS_CODE_TYPES.get(m.group("code"))
        if route_type is None:
            continue
        rest = m.group("rest")

        conn = _IOS_CONNECTED.search(rest)
        if conn:
            rows.append({"network": m.group("net"), "gateway": "",
                         "interface": conn.group("intf"), "type": route_type,
                         "distance": 0, "metric": 0})
            continue

        via = _IOS_VIA.search(rest)
        if via:
            rows.append({"network": m.group("net"), "gateway": via.group("gw"),
                         "interface": _ios_interface(via.group("tail")),
                         "type": route_type,
                         "distance": int(via.group("dist")),
                         "metric": int(via.group("metric"))})
    return rows


def _row(device, entry: dict) -> dict:
    return {
        "device": device.get("Hostname") or device.get("IP"),
        "device_ip": device.get("IP"),
        "site": device.get("Site") or "central",
        "group": device.get("Group") or "Generale",
        "vendor": (device.get("Vendor") or "").lower(),
        "network": entry.get("ip_mask") or entry.get("network") or "",
        "source_kind": route_source(device),
        "gateway": entry.get("gateway") or "",
        "interface": entry.get("interface") or "",
        "type": normalize_type(entry.get("type")),
        "raw_type": entry.get("type") or "",
        "distance": entry.get("distance"),
        "metric": entry.get("metric"),
        # Una riga letta dal backup non e' una riga letta dall'apparato: e'
        # quello che era CONFIGURATO l'ultima volta che il backup e' stato
        # preso. La vista la marca, perche' altrimenti una configurazione
        # vecchia di un mese si legge come la tabella di adesso.
        "from_backup": bool(entry.get("from_backup")),
    }


# Vendor da cui questa vista sa leggere una tabella di routing, e come.
# Cisco soltanto per il ramo CLI: il parser e' scritto sul formato di IOS, e
# Aruba o ProCurve rispondono a `show ip route` con un'altra impaginazione.
# Aggiungerli significa scrivere il loro parser, non allargare questa riga.
ROUTE_SOURCES = {"fortinet": "rest", "cisco": "ios-cli"}


def route_source(device) -> str:
    """'rest', 'ios-cli' o '' se l'apparato non pubblica la sua tabella."""
    return ROUTE_SOURCES.get((device.get("Vendor") or "").lower(), "")


def routable_devices(devices) -> list:
    """Gli apparati che sanno rispondere con una tabella di routing."""
    return [d for d in devices if route_source(d) and d.get("IP")]


def _is_agent_site(site_id: str) -> bool:
    """La sede e' gestita da un agente: il centrale non apre SSH verso i suoi
    apparati, li raggiunge solo attraverso la coda dei job."""
    from services import site_manager
    site = site_manager.get_site(site_id or "central")
    return bool(site and site.get("mode") == "agent")


# --- Ripiego sul backup ------------------------------------------------------
#
# Un apparato che non risponde lascia la vista senza le sue rotte, ed e' quasi
# sempre il momento in cui servono. Il backup di configurazione che il prodotto
# gia' conserva ne contiene una parte: le rotte STATICHE configurate.
#
# Una parte, non la tabella. Dal backup non escono le rotte apprese (OSPF, BGP,
# RIP), non escono le connesse, e nulla dice se una statica fosse attiva: la
# next-hop poteva essere gia' irraggiungibile. Per questo ogni riga porta
# from_backup e la risposta dichiara la data: "rotte statiche del 3 settembre"
# e' un'informazione utile, "la tabella di routing" sarebbe una bugia.

def _hop(value: str) -> tuple:
    """(gateway, interfaccia) da una next-hop che puo' essere l'uno o l'altra.

    IOS accetta sia `ip route 10.0.0.0 255.0.0.0 192.0.2.254` sia la stessa
    riga con un'interfaccia al posto dell'indirizzo."""
    text = (value or "").strip()
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
        return text, ""
    return "", text


def routes_from_backup(device) -> "dict | None":
    """Le rotte statiche dell'ultimo backup, o None se backup non ce n'e'.

    Nessuna sessione verso l'apparato: si rilegge un file che il prodotto ha
    gia'. L'analisi (IOS o FortiOS a seconda del contenuto) e' la stessa che
    usa la tab Analisi Configurazione, non un secondo parser che le puo'
    divergere accanto."""
    from ai import config_analyzer
    analysis = config_analyzer.analyze_device(device.get("IP"))
    if not analysis:
        return None
    entries = []
    for r in (analysis.get("routing") or {}).get("static") or []:
        # Le rotte di una VRF non hanno una colonna in cui dire di quale VRF
        # sono: mostrarle accanto alle altre le farebbe leggere come rotte
        # della tabella globale.
        if r.get("vrf"):
            continue
        gateway, interface = _hop(r.get("next_hop") or "")
        distance = r.get("distance") or r.get("ad")
        entries.append({
            "network": r.get("prefix") or "",
            "gateway": gateway,
            "interface": interface or (r.get("device") or ""),
            "type": "static",
            "distance": int(distance) if str(distance or "").isdigit() else None,
            "from_backup": True,
        })
    if not entries:
        return None
    return {"device_ip": device.get("IP"), "source": "backup",
            "backup_ts": analysis.get("backup_ts"),
            "rows": [_row(device, e) for e in entries]}


def collect_for(device) -> dict:
    """Rotte di UN apparato: ``{"rows": [...]}`` oppure ``{"error": ...}``.

    Non solleva: un apparato irraggiungibile e' una riga di errore accanto
    agli altri, non una tabella vuota per tutti. Se pero' un backup c'e', le
    sue statiche arrivano lo stesso, marcate, con l'errore che resta accanto:
    dire perche' l'apparato non ha risposto conta quanto mostrare le righe."""
    answer = _collect_live(device)
    if answer.get("rows"):
        return answer
    fallback = routes_from_backup(device)
    if not fallback:
        return answer
    fallback["error"] = answer.get("error") or ""
    return fallback


def _collect_live(device) -> dict:
    """L'apparato, interrogato davvero."""
    ip = device.get("IP")
    if _is_agent_site(device.get("Site") or "central"):
        # Provarci finirebbe in timeout: il centrale non ha una rotta verso
        # gli apparati di una sede agent, e fingere di interrogarli
        # allungherebbe ogni refresh di un minuto per niente.
        return {"device_ip": ip,
                "error": "sede in modalita' agent: il centrale non raggiunge "
                         "questo apparato"}
    if route_source(device) == "ios-cli":
        return _collect_ios(device)
    try:
        answer = fortigate_service.get_routes(device)
    except fortigate_service.FortiGateError as e:
        return {"device_ip": ip, "error": str(e)}
    data = answer.get("data")
    if not isinstance(data, list):
        # Fallback SSH: `get router info routing-table all` torna testo. Si
        # dichiara, non si finge di averlo capito.
        return {"device_ip": ip, "source": answer.get("source"),
                "error": "solo testo CLI: la tabella per questo apparato e' "
                         "leggibile nella tab FortiGate"}
    return {"device_ip": ip, "source": answer.get("source"),
            "rows": [_row(device, e) for e in data if isinstance(e, dict)]}


def _collect_ios(device) -> dict:
    """`show ip route` su uno switch, letto dal parser IOS.

    Il comando e' FISSO e non arriva da nessuna richiesta: questa vista non e'
    una shell. bypass_blacklist=True perche' e' un comando di sola lettura
    scelto qui, non digitato da un utente."""
    from core import core_engine
    ip = device.get("IP")
    answer = core_engine.send_custom_command(device, "show ip route",
                                             bypass_blacklist=True)
    if answer.get("status") != "success":
        return {"device_ip": ip, "error": answer.get("message") or "SSH fallito"}
    output = answer.get("output")
    parsed = parse_ios_routes(output if isinstance(output, str) else "")
    if not parsed:
        # Sessione riuscita e zero rotte: quasi sempre uno switch L2, che una
        # tabella di routing non ce l'ha. Dirlo evita che l'assenza si legga
        # come un parser rotto.
        return {"device_ip": ip, "source": "ssh",
                "error": "nessuna rotta nella risposta: switch senza routing, "
                         "oppure output in un formato non riconosciuto"}
    return {"device_ip": ip, "source": "ssh",
            "rows": [_row(device, e) for e in parsed]}


def group_counts(rows) -> dict:
    """{device: {tipo: quante rotte}} — quello che il grafico disegna.

    Il conteggio e non un volume di traffico: nessun apparato espone i pacchetti
    per rotta, e una barra che dicesse pkt/s sarebbe un numero inventato."""
    out: dict = {}
    for r in rows:
        out.setdefault(r["device"], {})
        key = r["type"]
        out[r["device"]][key] = out[r["device"]].get(key, 0) + 1
    return out
