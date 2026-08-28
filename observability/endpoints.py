# -*- coding: utf-8 -*-
"""Endpoint Knowledge Base: cosa È un indirizzo (IP o MAC), non cosa significa.

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

Per i MAC la classificazione sta nei bit del primo byte, non in un database di
produttori: vedi ``classify_mac``.
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


# Categorie che stanno DENTRO il perimetro. Link-local incluso: un 169.254 è un
# DHCP fallito, non un host su Internet.
_INTERNAL = ("private", "cgnat", "link_local")


def traffic_direction(src: Optional[str], dst: Optional[str]) -> Optional[str]:
    """Che genere di conversazione è, dai soli metadati degli endpoint.

    - ``east_west``     interno ↔ interno: due host della rete che si parlano;
    - ``north_south``   interno ↔ esterno: traffico che attraversa il perimetro;
    - ``control_plane`` destinazione multicast o broadcast: protocolli di
      scoperta e di routing (mDNS, SSDP, OSPF, ARP). È traffico reale, ma non è
      una conversazione fra due host, e confonderlo con una lo è cambia il
      significato di qualunque conteggio;
    - ``local``         loopback, "non specificato", range riservati.

    ``None`` quando uno dei due indirizzi non è interpretabile.
    """
    source, target = classify(src), classify(dst)
    if source is None or target is None:
        return None
    if target["category"] in ("multicast", "broadcast"):
        return "control_plane"
    if not is_endpoint(src) or not is_endpoint(dst):
        return "local"
    if source["category"] in _INTERNAL and target["category"] in _INTERNAL:
        return "east_west"
    return "north_south"


# --- MAC ---------------------------------------------------------------------
# OUI di virtualizzazione: gli unici prefissi che vale la pena tenere in
# tabella, perché dicono qualcosa di STRUTTURALE (questo non è un apparato
# fisico) e sono una manciata stabile. Un database OUI completo direbbe solo il
# produttore della scheda ed è un feed da mantenere: non è questo il posto.
_VIRTUAL_OUI = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:05:69": "VMware",
    "00:1c:14": "VMware",
    "00:15:5d": "Hyper-V",
    "00:03:ff": "Hyper-V",
    "08:00:27": "VirtualBox",
    "0a:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:16:3e": "Xen",
    "00:1c:42": "Parallels",
}

_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    """'AA-BB-CC-80-01-00' | 'aabb.cc80.0100' → 'aa:bb:cc:80:01:00'."""
    if not mac:
        return None
    hexes = "".join(c for c in str(mac).lower() if c in "0123456789abcdef")
    if len(hexes) != 12:
        return None
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2))


@lru_cache(maxsize=4096)
def classify_mac(mac: Optional[str]) -> Optional[dict]:
    """{mac, oui, category, administration, vendor_kind, label} oppure None.

    Le due informazioni che contano stanno nel primo byte, non in un database di
    produttori: il bit I/G distingue unicast da multicast, il bit U/L distingue
    un indirizzo assegnato dal costruttore da uno *amministrato localmente*.

    Il secondo è quello utile davvero. Un MAC localmente amministrato può essere
    una VM, una porta configurata a mano — oppure un telefono che randomizza il
    proprio indirizzo per non farsi seguire. In quest'ultimo caso il binding
    MAC↔IP non è un'identità: è valido per questa sessione e basta, e trattarlo
    come un dispositivo stabile produce storie sbagliate sulla client map.
    """
    normalized = _normalize_mac(mac)
    if normalized is None:
        return None

    first = int(normalized[:2], 16)
    oui = normalized[:8]
    local = bool(first & 0b10)

    if normalized == _BROADCAST_MAC:
        category = "broadcast"
    elif first & 0b1:
        category = "multicast"
    else:
        category = "unicast"

    vendor_kind = _VIRTUAL_OUI.get(oui)
    if vendor_kind:
        # Un OUI di virtualizzazione è assegnato dal costruttore: resta
        # "universale" anche se la scheda non esiste fisicamente.
        label = f"macchina virtuale {vendor_kind}"
    elif category == "broadcast":
        label = "Broadcast"
    elif category == "multicast":
        label = "Multicast L2"
    elif local:
        label = "indirizzo amministrato localmente (VM o MAC randomizzato)"
    else:
        label = None

    return {"mac": normalized, "oui": oui, "category": category,
            "administration": "locale" if local else "universale",
            "vendor_kind": vendor_kind, "label": label}


def describe_mac(mac: Optional[str]) -> str:
    """'aa:bb:cc:80:01:00 (indirizzo amministrato localmente)' quando c'è
    qualcosa da dire, altrimenti il MAC nudo."""
    info = classify_mac(mac)
    if info is None:
        return mac or "?"
    if info["label"]:
        return f"{info['mac']} ({info['label']})"
    return info["mac"]


def is_stable_identity(mac: Optional[str]) -> bool:
    """Vero se il MAC può valere come identità persistente di un dispositivo.

    Falso per gli indirizzi amministrati localmente che non appartengono a un
    OUI di virtualizzazione noto: lì il MAC può cambiare alla sessione
    successiva, e correlare lo storico su di esso significa inventare
    continuità dove non ce n'è.
    """
    info = classify_mac(mac)
    return bool(info) and info["category"] == "unicast" and (
        info["administration"] == "universale" or info["vendor_kind"] is not None)


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
