# -*- coding: utf-8 -*-
"""Traffico per policy firewall, letto dai contatori che gli apparati tengono.

La vista "Per IP" del tab Traffico nasce da flow_aggregates: telemetria di rete,
finestra temporale, serie storica. Questa no. I byte e le sessioni per policy
vivono SUL firewall, in contatori che il FortiGate azzera solo al reboot o a
richiesta.

Da qui la differenza che la vista deve dichiarare invece di lasciar credere il
contrario: **la finestra del tab non filtra questi numeri**. 850 MB su una
policy sono 850 MB dall'ultimo azzeramento, non nell'ultima ora. Presentarli
sotto un selettore "Ultime 6 ore" senza dirlo e' il modo piu' rapido di far
leggere a un operatore una cifra sbagliata di un ordine di grandezza.

La raccolta e' quella che la tab FortiGate fa gia' per un apparato alla volta
(get_policies_with_stats): qui gira su tutti quelli in scope.
"""
import logging

from services import fortigate_service

logger = logging.getLogger("sentinelnet.firewall_traffic")


def policy_devices(devices) -> list:
    """Gli apparati che tengono contatori per policy: i FortiGate.

    Uno switch non ha policy, e un router con ACL non espone byte per regola:
    allargare questa lista senza un servizio che li legga darebbe righe vuote
    presentate come "nessun traffico"."""
    return [d for d in devices
            if (d.get("Vendor") or "").lower() == "fortinet" and d.get("IP")]


def _joined(value) -> str:
    """srcaddr/dstaddr/service sono liste di oggetti {name: ...}: la vista
    vuole i nomi, non il JSON."""
    if isinstance(value, list):
        return ", ".join(
            str((v.get("name") if isinstance(v, dict) else v) or "")
            for v in value).strip(", ")
    return str(value or "")


def _row(device, entry: dict) -> dict:
    """Una policy con i suoi contatori, nella forma che la vista disegna."""
    return {
        "device": device.get("Hostname") or device.get("IP"),
        "device_ip": device.get("IP"),
        "group": device.get("Group") or "Generale",
        "policyid": entry.get("policyid"),
        "name": entry.get("name") or "",
        "srcaddr": _joined(entry.get("srcaddr")),
        "dstaddr": _joined(entry.get("dstaddr")),
        "srcaddr_ips": _joined(entry.get("srcaddr_ips")),
        "dstaddr_ips": _joined(entry.get("dstaddr_ips")),
        "service": _joined(entry.get("service")),
        "action": (entry.get("action") or "").lower(),
        "status": (entry.get("status") or "").lower(),
        "bytes": entry.get("bytes") or 0,
        "hit_count": entry.get("hit_count") or 0,
        "active_sessions": entry.get("active_sessions") or 0,
        "last_used": entry.get("last_used"),
        # never_hit distingue "contatore a zero" da "nessun contatore": senza,
        # una policy di cui non sappiamo nulla sembrerebbe una regola morta.
        "never_hit": bool(entry.get("never_hit")),
    }


def collect_for(device) -> dict:
    """Policy di UN apparato: ``{"rows": [...]}`` oppure ``{"error": ...}``.

    Non solleva: un firewall irraggiungibile e' una riga di errore accanto agli
    altri, non una tabella vuota per tutti."""
    ip = device.get("IP")
    try:
        answer = fortigate_service.get_policies_with_stats(device)
    except fortigate_service.FortiGateError as e:
        return {"device_ip": ip, "error": str(e)}
    data = answer.get("data")
    if not isinstance(data, list):
        return {"device_ip": ip, "error": "risposta non interpretabile"}
    out = {"device_ip": ip, "source": answer.get("source"),
           "rows": [_row(device, e) for e in data if isinstance(e, dict)]}
    if answer.get("stats_error"):
        # Configurazione arrivata, contatori no: meta' risposta e' meglio di un
        # errore, ma la meta' mancante va nominata o le colonne a zero si
        # leggono come "questa policy non passa traffico".
        out["stats_error"] = answer["stats_error"]
    return out
