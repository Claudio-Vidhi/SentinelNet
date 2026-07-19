# -*- coding: utf-8 -*-
"""Raccolta delle tabelle ARP dai gateway L3 per il matching MAC <-> IP.

Nel mondo reale il gateway di una VLAN può essere uno switch L3 (SVI), un
firewall o un router: la tabella ARP autorevole sta su chi ruota la VLAN.
Questo modulo interroga in modo best-effort TUTTI gli apparati L3-capable
dell'inventario: chi non ruota nulla risponde con una ARP vuota o con un
errore e viene semplicemente saltato.

Trasporti:
  - fortinet: fortigate_service.get_arp_table (REST API primaria, SSH fallback)
  - altri vendor: comando ARP via SSH (Netmiko, device_type dal driver vendor)

Output normalizzato: lista di {mac, ip, vlan, interface} pronta per
mac_history.record_arp_entries().
"""
import re
import logging

log = logging.getLogger("arp_collector")

# Comando ARP per driver (default 'show arp' se non elencato).
ARP_COMMANDS = {
    "cisco_ios":      "show ip arp",
    "cisco_s300":     "show arp",
    "cisco_9800":     "show ip arp",
    "cisco_wlc":      "show arp switch",
    "hp_procurve":    "show arp",
    "juniper_junos":  "show arp no-resolve",
    "aruba_os":       "show arp",
    "paloalto_panos": "show arp all",
}

_MAC_ANY = re.compile(
    r'\b([0-9a-fA-F]{2}([:\-][0-9a-fA-F]{2}){5}|[0-9a-fA-F]{4}(\.[0-9a-fA-F]{4}){2})\b')
_IP = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_VLAN_IF = re.compile(r'\b(?:vlan|vl)\s*(\d+)\b', re.I)


def parse_arp_output(text: str) -> list:
    """Parser generico riga-per-riga: estrae (ip, mac) da qualunque formato
    ARP testuale (Cisco 'Internet 10.0.0.1 5 aabb.ccdd.eeff ARPA Vlan10',
    FortiOS 'get system arp', HP, Juniper, PAN-OS...). L'interfaccia è
    l'ultima parola della riga se non numerica; la VLAN è dedotta da 'VlanN'."""
    out = []
    for line in (text or "").splitlines():
        mac_m = _MAC_ANY.search(line)
        ip_m = _IP.search(line)
        if not mac_m or not ip_m:
            continue
        mac = mac_m.group(1)
        # Scarta broadcast/incomplete
        if mac.lower().replace('-', ':').replace('.', '') in (
                "ffffffffffff", "000000000000"):
            continue
        vlan_m = _VLAN_IF.search(line)
        # Interfaccia: ultimo token non-numerico della riga (euristica valida
        # per Cisco/FortiOS/HP; se sbaglia resta comunque il binding mac<->ip).
        tokens = line.split()
        iface = tokens[-1] if tokens and not tokens[-1].isdigit() else ""
        if iface == mac or iface == ip_m.group(1):
            iface = ""
        out.append({"mac": mac, "ip": ip_m.group(1),
                    "vlan": vlan_m.group(1) if vlan_m else "",
                    "interface": iface})
    return out


def _normalize_api_arp(data) -> list:
    """Normalizza la risposta REST FortiOS monitor/network/arp
    ([{ip, mac, interface, age}, ...])."""
    out = []
    for e in data if isinstance(data, list) else []:
        if not isinstance(e, dict):
            continue
        mac, ip = e.get("mac"), e.get("ip")
        if mac and ip:
            out.append({"mac": mac, "ip": ip, "vlan": "",
                        "interface": e.get("interface") or ""})
    return out


def collect_from_device(device: dict) -> dict:
    """Raccoglie la tabella ARP di UN apparato. Ritorna
    {"status", "source_type", "entries": [...]} — status 'error' se
    l'apparato non risponde (il chiamante decide se è un problema)."""
    from core.core_engine import resolve_driver
    vendor = (device.get("Vendor") or "").lower()

    if vendor == "fortinet":
        from services import fortigate_service
        try:
            res = fortigate_service.get_arp_table(device)
        except fortigate_service.FortiGateError as e:
            return {"status": "error", "source_type": "firewall", "message": str(e)}
        data = res.get("data")
        entries = _normalize_api_arp(data) if res.get("source") == "api" \
            else parse_arp_output(data if isinstance(data, str) else "")
        return {"status": "success", "source_type": "firewall", "entries": entries}

    try:
        driver_name = None
        try:
            from services.inventory_manager import get_all_vendors
            driver_name = (get_all_vendors().get(vendor) or {}).get("driver")
        except Exception:
            pass
        _, netmiko_type = resolve_driver(vendor)
    except ValueError as e:
        return {"status": "error", "source_type": "switch", "message": str(e)}

    command = ARP_COMMANDS.get(driver_name or "", "show arp")
    source_type = "firewall" if driver_name == "paloalto_panos" else "switch"

    from netmiko import ConnectHandler
    from core.core_engine import get_device_credentials
    username, password, secret = get_device_credentials(device)
    params = {"device_type": netmiko_type, "host": device["IP"],
              "username": username, "password": password, "secret": secret,
              "timeout": 20, "auth_timeout": 15, "banner_timeout": 15}
    try:
        with ConnectHandler(**params) as conn:
            try:
                conn.enable()
            except Exception:
                pass
            output = conn.send_command(command, read_timeout=30)
    except Exception as e:
        return {"status": "error", "source_type": source_type, "message": str(e)}
    return {"status": "success", "source_type": source_type,
            "entries": parse_arp_output(output)}


def collect_all(devices: list) -> dict:
    """Raccoglie le ARP da tutti gli apparati indicati e le registra nel DB.
    Ritorna il riepilogo per apparato + totali."""
    from collectors import mac_history
    summary = {"devices": {}, "total_new": 0, "total_updated": 0}
    for device in devices:
        ip = device.get("IP")
        res = collect_from_device(device)
        if res["status"] != "success":
            summary["devices"][ip] = {"status": "error",
                                      "message": res.get("message", "")}
            continue
        entries = res["entries"]
        if not entries:
            summary["devices"][ip] = {"status": "empty",
                                      "message": "nessuna entry ARP (non ruota VLAN?)"}
            continue
        counts = mac_history.record_arp_entries(
            entries, source_ip=ip,
            source_name=device.get("Hostname") or "",
            source_type=res["source_type"],
            tenant=device.get("Group") or "",
            site=device.get("Site") or "central")
        summary["devices"][ip] = {"status": "success",
                                  "entries": len(entries), **counts}
        summary["total_new"] += counts["new"]
        summary["total_updated"] += counts["updated"]
    return summary
