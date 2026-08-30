# -*- coding: utf-8 -*-
"""Collect ARP tables from L3 gateways for MAC <-> IP matching.

In the real world the gateway of a VLAN can be an L3 switch (SVI), a
firewall or a router: the authoritative ARP table lives on whichever routes the VLAN.
This module queries in best-effort fashion ALL the L3-capable devices
of the inventory: whichever routes nothing responds with an empty ARP or with an
error and is simply skipped.

Transports:
  - fortinet: fortigate_service.get_arp_table (REST API primary, SSH fallback)
  - other vendors: ARP command via SSH (Netmiko, device_type from vendor driver)

Normalized output: list of {mac, ip, vlan, interface} ready for
mac_history.record_arp_entries().
"""
import re
import logging

log = logging.getLogger("arp_collector")

# ARP command per driver lives in the drivers layer (plan item 15).
from drivers.registry import arp_command_for

_MAC_ANY = re.compile(
    r'\b([0-9a-fA-F]{2}([:\-][0-9a-fA-F]{2}){5}|[0-9a-fA-F]{4}(\.[0-9a-fA-F]{4}){2})\b')
_IP = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_VLAN_IF = re.compile(r'\b(?:vlan|vl)\s*(\d+)\b', re.I)


def parse_arp_output(text: str) -> list:
    """Generic line-by-line parser: extracts (ip, mac) from any textual
    ARP format (Cisco 'Internet 10.0.0.1 5 aabb.ccdd.eeff ARPA Vlan10',
    FortiOS 'get system arp', HP, Juniper, PAN-OS...). The interface is
    the last word of the line if non-numeric; the VLAN is inferred from 'VlanN'."""
    out = []
    for line in (text or "").splitlines():
        mac_m = _MAC_ANY.search(line)
        ip_m = _IP.search(line)
        if not mac_m or not ip_m:
            continue
        mac = mac_m.group(1)
        # Discard broadcast/incomplete
        if mac.lower().replace('-', ':').replace('.', '') in (
                "ffffffffffff", "000000000000"):
            continue
        vlan_m = _VLAN_IF.search(line)
        # Interface: last non-numeric token of the line (heuristic valid
        # for Cisco/FortiOS/HP; if wrong the mac<->ip binding still holds).
        tokens = line.split()
        iface = tokens[-1] if tokens and not tokens[-1].isdigit() else ""
        if iface == mac or iface == ip_m.group(1):
            iface = ""
        out.append({"mac": mac, "ip": ip_m.group(1),
                    "vlan": vlan_m.group(1) if vlan_m else "",
                    "interface": iface})
    return out


def _normalize_api_arp(data) -> list:
    """Normalize the FortiOS REST response monitor/network/arp
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
    """Collects the ARP table of ONE device. Returns
    {"status", "source_type", "entries": [...]} — status 'error' if
    the device does not respond (caller decides whether it's a problem)."""
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

    command = arp_command_for(driver_name)
    source_type = "firewall" if driver_name == "paloalto_panos" else "switch"

    from core.net_ssh import ConnectHandler
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
            output_str = output if isinstance(output, str) else str(output or "")
    except Exception as e:
        return {"status": "error", "source_type": source_type, "message": str(e)}
    return {"status": "success", "source_type": source_type,
            "entries": parse_arp_output(output_str)}


def collect_all(devices: list) -> dict:
    """Collects ARP from all the listed devices and records them in the DB.
    Returns the per-device summary + totals.

    Collection is pooled, twin of mac_collector.collect_all: the sequential
    loop made one dead gateway cost ~50 s of wall time and scale linearly
    with the estate (app review item 13). Recording stays sequential —
    mac_history owns its own lock and the write phase is cheap next to SSH.
    """
    from concurrent.futures import ThreadPoolExecutor
    from collectors import mac_history
    summary = {"devices": {}, "total_new": 0, "total_updated": 0}
    if not devices:
        return summary
    with ThreadPoolExecutor(max_workers=min(8, len(devices))) as ex:
        collected = list(ex.map(collect_from_device, devices))
    for device, res in zip(devices, collected):
        ip = device.get("IP")
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
