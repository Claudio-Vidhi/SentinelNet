# -*- coding: utf-8 -*-
"""Chi instrada una VLAN, dedotto dai backup di configurazione.

La catena dei trunk della diagnosi si percorre solo se si sa dove finisce, e il
capolinea e' il gateway. Quando l'ARP non ne conosce uno, la risposta e' comunque
scritta nei backup: una SVI su uno switch L3, oppure una sotto-interfaccia VLAN
su un FortiGate. Qui la si legge.

Due regole non negoziabili:

* **Il tenant e' un confine.** Cercare fuori dal tenant del client vuol dire
  poter restituire l'apparato di un altro cliente. ``None`` significa "non si
  sa" e fa rifiutare; ``""`` e' il tenant predefinito e si cerca.
* **Ignoto non e' assente.** Un apparato senza backup non e' un apparato senza
  rotta: se non si e' potuto guardare, lo si dice.
"""
import ipaddress
import logging
from typing import Optional

from core import data_config

logger = logging.getLogger(__name__)

VLAN_ROUTING_JSON = data_config.get_path("vlan_routing.json")


def tenant_key(value) -> str:
    """Chiave di confronto fra tenant.

    ``arp_collector`` scrive ``""`` per un apparato senza ``Group`` e
    ``analyze_all`` legge ``"Generale"``: sono la stessa rete e devono
    coincidere, altrimenti il caso piu' comune (installazione senza gruppi)
    smetterebbe di trovare il proprio gateway.
    """
    return (value or "").strip() or "Generale"


def _svi_candidates(analysis, vlan: str) -> Optional[str]:
    """Indirizzo L3 dell'apparato su quella VLAN, o None se non la instrada.

    Copre le due forme: la SVI IOS e la sotto-interfaccia VLAN FortiOS.
    Un'interfaccia spenta non instrada, quindi non e' un candidato.
    """
    for entry in analysis.get("vlans") or []:
        if str(entry.get("id")) != vlan:
            continue
        svi = entry.get("svi")
        if svi and not svi.get("shutdown"):
            return svi.get("ip") or ""

    firewall = analysis.get("firewall") or {}
    for vif in firewall.get("vlan_interfaces") or []:
        if str(vif.get("vlan")) != vlan:
            continue
        if (vif.get("status") or "up").lower() != "up":
            continue
        return vif.get("ip") or ""
    return None


def _contains(cidr: str, client_ip: str) -> bool:
    if not cidr or not client_ip:
        return False
    try:
        return ipaddress.ip_address(client_ip) in ipaddress.ip_network(
            cidr, strict=False)
    except ValueError:
        return False


def route_owner(vlan, tenant, client_ip: Optional[str] = None) -> dict:
    """Quale apparato instrada ``vlan`` nel tenant indicato.

    ``tenant`` a ``None`` significa che non lo si conosce: si rifiuta senza
    cercare, perche' una ricerca senza confine puo' restituire l'apparato di un
    altro cliente.
    """
    from ai import config_analyzer
    from services import inventory_manager

    if tenant is None:
        return {"known": False, "unreadable": [],
                "reason": "tenant del client sconosciuto: senza confine la "
                          "ricerca potrebbe restituire l'apparato di un'altra "
                          "rete"}

    vlan = str(vlan)
    key = tenant_key(tenant)

    # Entrambi i gate: allowed_groups regge anche se il controllo di falsy di
    # group_filter cambiasse, e da solo impedisce la scansione larga.
    analyses = config_analyzer.analyze_all(
        group_filter=key, allowed_groups=[key]).get("devices") or []

    in_tenant = [d.get("IP") for d in inventory_manager.get_all_devices()
                 if d.get("IP") and tenant_key(d.get("Group")) == key]
    analysed = {a.get("ip") for a in analyses}
    unreadable = sorted(ip for ip in in_tenant if ip not in analysed)

    candidates = []
    for analysis in analyses:
        svi_ip = _svi_candidates(analysis, vlan)
        if svi_ip is not None:
            candidates.append((analysis["ip"], svi_ip, analysis))

    if client_ip:
        narrowed = [c for c in candidates if _contains(c[1], client_ip)]
        if len(narrowed) == 1:
            candidates = narrowed

    if len(candidates) == 1:
        device_ip, svi_ip, analysis = candidates[0]
        return {"known": True, "device_ip": device_ip, "svi_ip": svi_ip or None,
                "source": "config", "backup_age_s": _age(analysis),
                "unreadable": unreadable}

    if len(candidates) > 1:
        return {"known": False, "unreadable": unreadable,
                "candidates": sorted(c[0] for c in candidates),
                "reason": f"{len(candidates)} apparati instradano la VLAN "
                          f"{vlan} e nessuno e' distinguibile dall'indirizzo "
                          "del client: quale sia il suo gateway non si puo' dire"}

    manual = _manual_owner(key, vlan)
    if manual and manual in in_tenant:
        return {"known": True, "device_ip": manual, "svi_ip": None,
                "source": "manual", "backup_age_s": None,
                "unreadable": unreadable}

    if unreadable:
        return {"known": False, "unreadable": unreadable,
                "reason": f"nessuna interfaccia L3 trovata per la VLAN {vlan}, "
                          f"ma {len(unreadable)} apparati del tenant sono senza "
                          f"backup ({', '.join(unreadable)}): la risposta e' "
                          "ignota, non 'nessuna rotta'"}

    return {"known": False, "unreadable": [],
            "reason": f"nessun apparato del tenant '{key}' ha un'interfaccia L3 "
                      f"per la VLAN {vlan}"}


def _age(analysis) -> Optional[int]:
    import time
    ts = analysis.get("backup_ts")
    return int(time.time()) - int(ts) if ts else None


def _manual_owner(tenant_name: str, vlan: str) -> str:
    """Apparato dichiarato a mano per quella VLAN, o "".

    File scritto a mano: rotto o illeggibile vale come assente. Una riga
    sbagliata non deve far fallire una diagnosi che senza di lei funzionerebbe
    comunque - stessa tolleranza di ``snmp_defaults._load``.
    """
    import json
    import os
    if not os.path.exists(VLAN_ROUTING_JSON):
        return ""
    try:
        with open(VLAN_ROUTING_JSON, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return str(((data.get("tenants") or {}).get(tenant_name) or {}).get(
            str(vlan)) or "")
    except Exception as e:
        logger.warning("vlan_routing.json illeggibile, ignorato: %s", e)
        return ""
