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

from services import fortigate_service, inventory_manager

logger = logging.getLogger("sentinelnet.route_table")

# Tipi di rotta normalizzati. FortiOS scrive 'connect'/'static'/'ospf'/'bgp',
# a volte maiuscolo: la UI raggruppa su questi, non sulle stringhe grezze.
_TYPE_ALIASES = {
    "connect": "connected", "connected": "connected", "direct": "connected",
    "static": "static",
    "ospf": "ospf", "ospf-inter-area": "ospf", "ospf-external": "ospf",
    "bgp": "bgp", "rip": "rip", "isis": "isis",
}


def normalize_type(raw) -> str:
    """Il tipo di rotta in una delle famiglie che la vista raggruppa.

    Sconosciuto resta sconosciuto ('other'): inventare 'static' per una rotta
    che il firewall ha chiamato in un altro modo e' esattamente il genere di
    dettaglio che poi si legge come un fatto."""
    key = str(raw or "").strip().lower()
    return _TYPE_ALIASES.get(key, "other" if key else "unknown")


def _row(device, entry: dict) -> dict:
    return {
        "device": device.get("Hostname") or device.get("IP"),
        "device_ip": device.get("IP"),
        "site": device.get("Site") or "central",
        "group": device.get("Group") or "Generale",
        "vendor": (device.get("Vendor") or "").lower(),
        "network": entry.get("ip_mask") or entry.get("network") or "",
        "gateway": entry.get("gateway") or "",
        "interface": entry.get("interface") or "",
        "type": normalize_type(entry.get("type")),
        "raw_type": entry.get("type") or "",
        "distance": entry.get("distance"),
        "metric": entry.get("metric"),
    }


def routable_devices(devices) -> list:
    """Gli apparati che sanno rispondere con una tabella di routing.

    Oggi solo i FortiGate: e' l'unico vendor per cui esiste gia' un servizio
    che la legge. Uno switch IOS la espone eccome, ma servirebbe un parser di
    `show ip route` — cioe' un collector nuovo, che non appartiene a questa
    vista."""
    return [d for d in devices
            if (d.get("Vendor") or "").lower() == "fortinet" and d.get("IP")]


def collect_for(device) -> dict:
    """Rotte di UN apparato: ``{"rows": [...]}`` oppure ``{"error": ...}``.

    Non solleva: un firewall irraggiungibile e' una riga di errore accanto
    agli altri, non una tabella vuota per tutti."""
    try:
        answer = fortigate_service.get_routes(device)
    except fortigate_service.FortiGateError as e:
        return {"device_ip": device.get("IP"), "error": str(e)}
    data = answer.get("data")
    if not isinstance(data, list):
        # Fallback SSH: `get router info routing-table all` torna testo. Si
        # dichiara, non si finge di averlo capito.
        return {"device_ip": device.get("IP"), "source": answer.get("source"),
                "error": "solo testo CLI: la tabella per questo apparato e' "
                         "leggibile nella tab FortiGate"}
    return {"device_ip": device.get("IP"), "source": answer.get("source"),
            "rows": [_row(device, e) for e in data if isinstance(e, dict)]}


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
