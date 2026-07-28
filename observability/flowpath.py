# -*- coding: utf-8 -*-
"""Flow Path: per dove passa il traffico di un incidente.

Il documento elenca il percorso fra le evidenze che un incidente deve mostrare.
Ricostruirlo incrociando exporter diversi lungo la tratta richiederebbe un
exporter per salto — qui invece si usa la TOPOLOGIA già raccolta:

    ARP dei gateway   →  quale MAC ha quell'IP e chi ruota la sua VLAN
    MAC table         →  a quale porta di accesso è attaccato quel MAC
    Endpoint KB       →  se la conversazione esce dal perimetro

Nessuna raccolta nuova: solo un modo diverso di leggere ciò che c'è.

LIMITE DICHIARATO, non aggirato: questo è il percorso LOGICO (host → porta di
accesso → gateway → …), non quello effettivo pacchetto per pacchetto. Non
conosce i salti intermedi fra switch né le decisioni di routing. Un hop assente
significa "non lo sappiamo", e viene detto: ``known: False``. Meglio un
percorso parziale e onesto di uno completo e inventato.
"""

import logging
from typing import Optional

from observability import endpoints

logger = logging.getLogger("sentinelnet.obs")


def _client(ip: str, tenant: str) -> Optional[dict]:
    """Binding noto per un IP: MAC, gateway che ne ruota la VLAN, porta di
    accesso. ``None`` se l'IP non è mai stato visto."""
    try:
        from collectors import mac_history
        entries = mac_history.client_map(ip=ip, tenants=[tenant], limit=1)
    except Exception as e:
        logger.debug("client_map non disponibile per %s: %s", ip, e)
        return None
    return entries[0] if entries else None


def _endpoint_hop(ip: str, info: Optional[dict]) -> dict:
    mac = (info or {}).get("mac")
    return {"kind": "endpoint", "known": True, "ip": ip,
            "mac": mac, "mac_info": endpoints.classify_mac(mac),
            "label": endpoints.describe(ip)}


def _access_hop(info: Optional[dict]) -> dict:
    """Porta di accesso dello switch. Senza una MAC scan recente non si sa, e
    va detto invece di saltare il salto in silenzio."""
    if info is None or not info.get("switch_port"):
        return {"kind": "access", "known": False,
                "label": "porta di accesso sconosciuta (manca una MAC scan)"}
    port = info["switch_port"]
    switch = info.get("switch_name") or info.get("switch_ip")
    vlan = info.get("port_vlan") or info.get("vlan")
    return {"kind": "access", "known": True, "switch": switch,
            "switch_ip": info.get("switch_ip"), "port": port, "vlan": vlan,
            "label": f"{switch}:{port}" + (f" (VLAN {vlan})" if vlan else "")}


def _gateway_hop(info: Optional[dict]) -> Optional[dict]:
    """Chi ruota la VLAN dell'host: è l'apparato che ha risposto all'ARP, quindi
    è noto per costruzione ogni volta che il binding esiste."""
    if not info or not info.get("source_ip"):
        return None
    name = info.get("source_name") or info.get("source_ip")
    kind = info.get("source_type") or "gateway"
    return {"kind": "gateway", "known": True, "device": name,
            "device_ip": info.get("source_ip"), "device_type": kind,
            "label": f"{name} ({kind})"}


def build(src_ip: Optional[str], dst_ip: Optional[str],
          tenant: str) -> dict:
    """{direction, hops[], complete} per una conversazione.

    ``complete`` è falso appena un salto è sconosciuto: chi legge deve poter
    distinguere "il percorso è questo" da "il percorso è questo per quanto ne
    sappiamo".
    """
    direction = endpoints.traffic_direction(src_ip, dst_ip)
    if direction is None or not src_ip or not dst_ip:
        # ``traffic_direction`` non è None solo se ENTRAMBI gli indirizzi sono
        # interpretabili: il controllo è ridondante nei fatti, non per il
        # controllo dei tipi.
        return {"direction": direction, "hops": [], "complete": False}

    source = _client(src_ip, tenant)
    hops = [_endpoint_hop(src_ip, source), _access_hop(source)]

    gateway = _gateway_hop(source)
    if gateway:
        hops.append(gateway)

    if direction == "east_west":
        target = _client(dst_ip, tenant)
        target_gateway = _gateway_hop(target)
        # Stesso gateway per entrambi: il traffico non lo attraversa due volte.
        if target_gateway and (not gateway
                               or target_gateway["device_ip"] != gateway["device_ip"]):
            hops.append(target_gateway)
        hops.append(_access_hop(target))
        hops.append(_endpoint_hop(dst_ip, target))
    elif direction == "north_south":
        hops.append({"kind": "perimeter", "known": True,
                     "label": f"perimetro → {endpoints.describe(dst_ip)}"})
    else:
        # control_plane / local: non c'è un secondo host da raggiungere.
        hops.append({"kind": "destination", "known": True,
                     "label": endpoints.describe(dst_ip)})

    return {"direction": direction, "hops": hops,
            "complete": all(h["known"] for h in hops)}
