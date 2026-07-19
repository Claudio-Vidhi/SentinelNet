# -*- coding: utf-8 -*-
"""WLC Service — osservabilità wireless per controller Cisco: AireOS
(2504/3504/5508/8540, vWLC) e Catalyst 9800 (IOS-XE).

Trasporto: SSH/Netmiko (device_type risolto dal driver del vendor:
'cisco_wlc' -> cisco_wlc_ssh / AireOS, 'cisco_9800' o 'cisco' -> cisco_xe).
Le due famiglie usano CLI diverse: la mappa COMMANDS traduce ogni servizio
nel comando giusto per piattaforma. Output testuale grezzo, pensato per
essere interpretato da un LLM (MCP / AI assistant).
"""

import re

from core.core_engine import resolve_driver, get_device_credentials


class WlcError(Exception):
    pass


def platform_of(device: dict) -> str:
    """'aireos' oppure 'iosxe', dedotto dal driver associato al vendor.
    Vendor 'cisco' generico viene trattato come 9800/IOS-XE."""
    vendor = (device.get("Vendor") or "").lower()
    if vendor == "cisco_wlc":
        return "aireos"
    return "iosxe"


# servizio -> {piattaforma: comando}; {mac} sostituito nei comandi per-client.
COMMANDS = {
    "status": {
        "aireos": "show sysinfo",
        "iosxe": "show wireless summary",
    },
    "ap_summary": {
        "aireos": "show ap summary",
        "iosxe": "show ap summary",
    },
    "client_summary": {
        "aireos": "show client summary",
        "iosxe": "show wireless client summary",
    },
    "client_detail": {
        "aireos": "show client detail {mac}",
        "iosxe": "show wireless client mac-address {mac} detail",
    },
    "wlan_summary": {
        "aireos": "show wlan summary",
        "iosxe": "show wlan summary",
    },
    "rogue_aps": {
        "aireos": "show rogue ap summary",
        "iosxe": "show wireless wps rogue ap summary",
    },
    "interfaces": {
        "aireos": "show interface summary",
        "iosxe": "show ip interface brief",
    },
}

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:\-.]?[0-9a-fA-F]{2}){5}$")


def normalize_mac(mac: str, platform: str) -> str:
    """Normalizza un MAC nel formato atteso dalla piattaforma
    (entrambe accettano aa:bb:cc:dd:ee:ff)."""
    mac = (mac or "").strip()
    if not _MAC_RE.fullmatch(mac.replace(" ", "")):
        raise WlcError(f"MAC address non valido: '{mac}'")
    digits = re.sub(r"[^0-9a-f]", "", mac.lower())
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def ssh_run(device: dict, command: str, timeout: int = 30) -> str:
    """Esegue un comando show sul WLC. Su IOS-XE entra in enable (best
    effort); su AireOS l'enable non esiste."""
    from netmiko import ConnectHandler
    vendor = (device.get("Vendor") or "").lower()
    try:
        _, netmiko_type = resolve_driver(vendor)
    except ValueError as e:
        raise WlcError(str(e))
    username, password, secret = get_device_credentials(device)
    params = {"device_type": netmiko_type, "host": device["IP"],
              "username": username, "password": password, "secret": secret,
              "timeout": timeout, "auth_timeout": 15, "banner_timeout": 15}
    try:
        with ConnectHandler(**params) as conn:
            if platform_of(device) == "iosxe":
                try:
                    conn.enable()
                except Exception:
                    pass
            return conn.send_command(command, read_timeout=timeout)
    except Exception as e:
        raise WlcError(f"SSH {device.get('IP')}: {e}")


def query(device: dict, service: str, mac: str = None) -> dict:
    """Esegue il servizio richiesto sul WLC e ritorna
    {"platform", "command", "data"}."""
    if service not in COMMANDS:
        raise WlcError(f"Servizio WLC sconosciuto: '{service}'")
    platform = platform_of(device)
    command = COMMANDS[service][platform]
    if "{mac}" in command:
        if not mac:
            raise WlcError(f"Il servizio '{service}' richiede un MAC address.")
        command = command.format(mac=normalize_mac(mac, platform))
    data = ssh_run(device, command, timeout=60 if service == "client_detail" else 30)
    return {"platform": platform, "command": command, "data": data}


def diagnose_wifi_client(device: dict, mac: str) -> dict:
    """Diagnosi aggregata di un client wireless: dettaglio client, stato AP,
    WLAN e rogue AP vicini. Ogni sezione è best-effort (errore riportato
    nella sezione, la diagnosi non fallisce)."""
    result = {"wlc": device.get("IP"), "client_mac": mac,
              "platform": platform_of(device), "sections": {}}
    for name, svc, kw in (("client_detail", "client_detail", {"mac": mac}),
                          ("ap_summary", "ap_summary", {}),
                          ("wlan_summary", "wlan_summary", {}),
                          ("rogue_aps", "rogue_aps", {})):
        try:
            result["sections"][name] = query(device, svc, **kw)
        except Exception as e:
            result["sections"][name] = {"error": str(e)}
    return result
