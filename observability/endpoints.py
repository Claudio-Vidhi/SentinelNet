# -*- coding: utf-8 -*-
"""Endpoint Knowledge Base: cosa È un indirizzo, non cosa significa.

Arricchimento puramente descrittivo. Non cambia la semantica di nessun evento e
non decide niente: dice che 224.0.0.5 è multicast link-local con ruolo
``ospf_allspfrouters``. Sono le regole a decidere cosa farci.

Perché esiste: senza, la conoscenza dei range finirebbe sparsa dentro le regole
(``if ip.startswith("224.")`` in otto punti che divergono). Qui sta in un posto
solo, come già fatto per l'estrazione syslog in ``fieldmap.py``.

DERIVATA, MAI COPIATA. La classificazione si calcola al momento della lettura e
non viene salvata dentro gli eventi: il giorno in cui questa tabella impara un
ruolo nuovo, migliora anche tutto ciò che è già stato scritto. L'unica forma
persistita è il TESTO leggibile dentro ``evidence.summary``, perché quello è il
contesto storico di una decisione presa allora e deve restare com'era.

Copertura: **solo IPv4**. Non è una scelta di questo modulo — l'estrazione a
monte (``fieldmap._IP_RE``, i decoder di flusso) riconosce solo IPv4, quindi
``family`` sarà ``ipv4`` per tutto finché quella non cambia.
"""

import ipaddress
from functools import lru_cache
from typing import Optional

# Indirizzi con un significato assegnato: statici, da RFC, nessun feed esterno
# da tenere aggiornato. address → (ruolo, etichetta leggibile).
_WELL_KNOWN = {
    "0.0.0.0": ("unspecified", "Indirizzo non specificato"),
    "255.255.255.255": ("broadcast_limited", "Broadcast limitato"),
    "224.0.0.1": ("all_hosts", "All Hosts"),
    "224.0.0.2": ("all_routers", "All Routers"),
    "224.0.0.4": ("dvmrp", "DVMRP Routers"),
    "224.0.0.5": ("ospf_allspfrouters", "OSPF AllSPFRouters"),
    "224.0.0.6": ("ospf_alldrouters", "OSPF AllDRouters"),
    "224.0.0.9": ("rip2", "RIPv2 Routers"),
    "224.0.0.10": ("eigrp", "EIGRP Routers"),
    "224.0.0.13": ("pim", "PIM Routers"),
    "224.0.0.18": ("vrrp", "VRRP"),
    "224.0.0.22": ("igmpv3", "IGMPv3 Reports"),
    "224.0.0.102": ("hsrpv2_glbp", "HSRPv2 / GLBP"),
    "224.0.0.251": ("mdns", "mDNS"),
    "224.0.0.252": ("llmnr", "LLMNR"),
    "224.0.1.1": ("ntp", "NTP Multicast"),
    "224.0.1.39": ("cisco_rp_announce", "Cisco RP Announce"),
    "224.0.1.40": ("cisco_rp_discovery", "Cisco RP Discovery"),
    "239.255.255.250": ("ssdp", "SSDP / UPnP"),
}

# Range con una categoria propria che ``ipaddress`` non distingue: per la
# stdlib sono tutti "non globali", ma per un ingegnere di rete non sono la
# stessa cosa. Ordine significativo: si prende il primo che contiene.
_SPECIAL_NETWORKS = (
    ("100.64.0.0/10", "cgnat", "site"),
    ("192.0.2.0/24", "documentation", "global"),
    ("198.51.100.0/24", "documentation", "global"),
    ("203.0.113.0/24", "documentation", "global"),
    ("198.18.0.0/15", "benchmark", "global"),
    ("192.88.99.0/24", "6to4_relay", "global"),
    ("240.0.0.0/4", "reserved", "global"),
)
_SPECIAL = tuple((ipaddress.ip_network(cidr), category, scope)
                 for cidr, category, scope in _SPECIAL_NETWORKS)

_LINK_LOCAL_MCAST = ipaddress.ip_network("224.0.0.0/24")


@lru_cache(maxsize=4096)
def classify(address: Optional[str]) -> Optional[dict]:
    """{address, family, category, role, scope, label} oppure None.

    None significa "non è un indirizzo interpretabile", non "sconosciuto": un
    indirizzo valido ma senza ruolo noto torna comunque con categoria e ambito.
    """
    if not address:
        return None
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return None

    role, label = _WELL_KNOWN.get(str(ip), (None, None))

    if ip.is_unspecified:
        category, scope = "unspecified", "host"
    elif ip.is_loopback:
        category, scope = "loopback", "host"
    elif ip.is_link_local:
        category, scope = "link_local", "link-local"
    elif str(ip) == "255.255.255.255":
        category, scope = "broadcast", "link-local"
    elif ip.is_multicast:
        category = "multicast"
        scope = "link-local" if ip in _LINK_LOCAL_MCAST else "global"
    else:
        for network, special_category, special_scope in _SPECIAL:
            if ip in network:
                category, scope = special_category, special_scope
                break
        else:
            if ip.is_private:
                category, scope = "private", "site"
            else:
                category, scope = "public", "global"

    return {"address": str(ip), "family": f"ipv{ip.version}",
            "category": category, "role": role, "scope": scope,
            "label": label}


def describe(address: Optional[str]) -> str:
    """'OSPF AllSPFRouters (224.0.0.5)' quando il ruolo è noto, altrimenti
    l'indirizzo nudo. Usata per i testi che vengono PERSISTITI (i summary delle
    evidenze) e per quelli mostrati."""
    info = classify(address)
    if info and info["label"]:
        return f"{info['label']} ({info['address']})"
    return address or "?"


def is_endpoint(address: Optional[str]) -> bool:
    """Vero se l'indirizzo può appartenere a un host reale della rete.

    Multicast, broadcast, loopback e "non specificato" non sono endpoint: non
    hanno una porta di switch, non hanno un'abitudine di traffico e non
    possono "comparire per la prima volta". Chiederglielo produce solo lookup
    a vuoto e falsi positivi.
    """
    info = classify(address)
    return bool(info) and info["category"] not in (
        "multicast", "broadcast", "loopback", "unspecified", "reserved")
