# -*- coding: utf-8 -*-
"""FortiGate Service — accesso live a un FortiGate per l'osservabilità LAN.

Due trasporti:
  - REST API FortiOS (primario): token API "api-user", header Authorization
    Bearer, endpoint /api/v2/monitor|cmdb|log su HTTPS (porta admin, default
    443). Restituisce JSON strutturato.
  - SSH/CLI (fallback, Netmiko device_type 'fortinet'): usato quando il token
    API non è configurato o la chiamata REST fallisce; output testuale.

I token API sono salvati cifrati (crypto_vault) in data/fortigate_tokens.json,
per IP: {"<ip>": {"token_enc": ..., "port": 443, "verify_tls": false}}.

Le funzioni di alto livello (get_*) accettano il dict `device` dell'inventario
e ritornano sempre {"source": "api"|"ssh", "data": ...} oppure sollevano
FortiGateError con il dettaglio di entrambi i tentativi.
"""

import json
import os
import re
import threading

import requests
import urllib3

import data_config
from crypto_vault import encrypt_password, decrypt_password

TOKENS_FILE = data_config.get_path("fortigate_tokens.json")

_lock = threading.Lock()


class FortiGateError(Exception):
    pass


# --- Persistenza token API ---------------------------------------------------

def _load_tokens() -> dict:
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_tokens(tokens: dict):
    os.makedirs(os.path.dirname(TOKENS_FILE) or ".", exist_ok=True)
    with _lock:
        with open(TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=1)


def set_api_token(ip: str, token: str, port: int = 443, verify_tls: bool = False):
    """Salva (cifrato) il token API di un FortiGate. Token vuoto = rimozione."""
    tokens = _load_tokens()
    if token:
        tokens[ip] = {"token_enc": encrypt_password(token),
                      "port": int(port or 443), "verify_tls": bool(verify_tls)}
    else:
        tokens.pop(ip, None)
    _save_tokens(tokens)


def get_api_config(ip: str):
    """Ritorna (token, port, verify_tls) oppure (None, ...) se non configurato."""
    entry = _load_tokens().get(ip)
    if not entry:
        return None, 443, False
    return (decrypt_password(entry.get("token_enc", "")) or None,
            int(entry.get("port") or 443), bool(entry.get("verify_tls")))


def token_status() -> dict:
    """Elenco IP con token configurato (senza esporre i token)."""
    return {ip: {"port": e.get("port", 443), "verify_tls": e.get("verify_tls", False)}
            for ip, e in _load_tokens().items()}


# --- Trasporto REST ----------------------------------------------------------

def api_get(ip: str, path: str, params: dict = None, timeout: int = 30):
    """GET su /api/v2/<path> con Bearer token. Solleva FortiGateError."""
    token, port, verify = get_api_config(ip)
    if not token:
        raise FortiGateError(f"Nessun token API configurato per {ip}.")
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    url = f"https://{ip}:{port}/api/v2/{path.lstrip('/')}"
    try:
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"},
                         params=params or {}, verify=verify, timeout=timeout)
    except requests.RequestException as e:
        raise FortiGateError(f"REST API {ip} non raggiungibile: {e}")
    if r.status_code == 401:
        raise FortiGateError(f"REST API {ip}: token non valido o scaduto (401). "
                             "Verificare anche i trusted host dell'api-user.")
    if r.status_code == 403:
        raise FortiGateError(f"REST API {ip}: accesso negato (403), profilo "
                             "accprofile dell'api-user insufficiente.")
    if r.status_code >= 400:
        raise FortiGateError(f"REST API {ip} HTTP {r.status_code}: {r.text[:300]}")
    try:
        return r.json()
    except ValueError:
        return {"raw": r.text}


# --- Trasporto SSH (fallback) ------------------------------------------------

def ssh_command(device: dict, command: str, timeout: int = 30) -> str:
    """Esegue un comando CLI FortiOS via Netmiko e ritorna l'output testuale."""
    from netmiko import ConnectHandler
    from core_engine import get_device_credentials
    username, password, _secret = get_device_credentials(device)
    params = {"device_type": "fortinet", "host": device["IP"],
              "username": username, "password": password,
              "timeout": timeout, "auth_timeout": 15, "banner_timeout": 15}
    try:
        with ConnectHandler(**params) as conn:
            return conn.send_command(command, read_timeout=timeout)
    except Exception as e:
        raise FortiGateError(f"SSH {device.get('IP')}: {e}")


# --- Helper API-first con fallback SSH ---------------------------------------

def _api_or_ssh(device, api_path, api_params, ssh_cmd, parser=None):
    ip = device["IP"]
    api_err = None
    try:
        data = api_get(ip, api_path, api_params)
        return {"source": "api", "data": data.get("results", data)}
    except FortiGateError as e:
        api_err = str(e)
    try:
        out = ssh_command(device, ssh_cmd)
        return {"source": "ssh", "api_error": api_err,
                "data": parser(out) if parser else out}
    except FortiGateError as ssh_err:
        raise FortiGateError(f"API: {api_err} | SSH: {ssh_err}")


# --- Servizi di osservabilità -------------------------------------------------

def get_system_status(device):
    return _api_or_ssh(device, "monitor/system/status", None, "get system status")


def get_interfaces(device):
    """Stato interfacce con IP, link, contatori."""
    return _api_or_ssh(device, "monitor/system/interface",
                       {"include_vlan": "true", "include_aggregate": "true"},
                       "get system interface")


def get_arp_table(device):
    return _api_or_ssh(device, "monitor/network/arp", None, "get system arp")


def get_dhcp_leases(device):
    return _api_or_ssh(device, "monitor/system/dhcp", None,
                       "execute dhcp lease-list")


def get_device_inventory(device):
    """Device inventory FortiOS (device-identification): MAC, IP, hostname,
    OS rilevato, interfaccia di ingresso, online/offline."""
    return _api_or_ssh(device, "monitor/user/device/query",
                       {"timestamp_from": 0},
                       "diagnose user device list")


def get_firewall_policies(device):
    """Policy firewall configurate (cmdb) — la 'full config' delle policy."""
    return _api_or_ssh(device, "cmdb/firewall/policy", None,
                       "show firewall policy")


def get_policy_stats(device):
    """Contatori runtime per policy (hit, byte, sessioni attive)."""
    return _api_or_ssh(device, "monitor/firewall/policy", None,
                       "diagnose firewall iprope show 100004")


def policy_lookup(device, src_ip: str, dest: str, protocol: str = "TCP",
                  dest_port: int = 443, srcintf: str = None):
    """Chiede al FortiGate QUALE policy matcherebbe un flusso (senza generare
    traffico): fondamentale per 'perché il client X non raggiunge il sito Y'.
    `dest` può essere IP o FQDN."""
    params = {"srcip": src_ip, "protocol": protocol.lower(),
              "dest": dest, "destport": int(dest_port), "ipv6": "false"}
    if srcintf:
        params["srcintf"] = srcintf
    ip = device["IP"]
    try:
        data = api_get(ip, "monitor/firewall/policy-lookup", params)
        return {"source": "api", "data": data.get("results", data)}
    except FortiGateError as e:
        # Nessun equivalente CLI 1:1 affidabile: si riporta l'errore API.
        raise FortiGateError(f"policy-lookup disponibile solo via REST API: {e}")


def get_sessions(device, src_ip: str = None, dst_ip: str = None,
                 dst_port: int = None, count: int = 100):
    """Sessioni attive (session table), filtrabili per src/dst/porta."""
    params = {"count": int(count)}
    if src_ip:
        params["srcaddr"] = src_ip
    if dst_ip:
        params["dstaddr"] = dst_ip
    if dst_port:
        params["dstport"] = int(dst_port)
    filt = []
    if src_ip:
        filt.append(f"diagnose sys session filter src {src_ip}")
    if dst_ip:
        filt.append(f"diagnose sys session filter dst {dst_ip}")
    if dst_port:
        filt.append(f"diagnose sys session filter dport {dst_port}")
    ssh_cmd = "\n".join(["diagnose sys session filter clear", *filt,
                         "diagnose sys session list"])
    return _api_or_ssh(device, "monitor/firewall/session", params, ssh_cmd)


def get_routes(device):
    return _api_or_ssh(device, "monitor/router/ipv4", None,
                       "get router info routing-table all")


def get_traffic_logs(device, src_ip: str = None, dst_ip: str = None,
                     action: str = None, count: int = 100,
                     log_device: str = "disk"):
    """Log di traffico forward (disk o memory), filtrabili. Risponde a
    'cosa dicono i log del firewall per questo client?'."""
    params = {"rows": int(count)}
    filters = []
    if src_ip:
        filters.append(f"srcip=={src_ip}")
    if dst_ip:
        filters.append(f"dstip=={dst_ip}")
    if action:
        filters.append(f"action=={action}")
    if filters:
        params["filter"] = filters
    ip = device["IP"]
    api_err = None
    for dev in (log_device, "memory" if log_device == "disk" else "disk"):
        try:
            data = api_get(ip, f"log/{dev}/traffic/forward", params)
            return {"source": "api", "log_device": dev,
                    "data": data.get("results", data)}
        except FortiGateError as e:
            api_err = str(e)
    # Fallback CLI: execute log filter + display.
    lines = ["execute log filter reset", "execute log filter category traffic"]
    ssh_filters = []
    if src_ip:
        ssh_filters.append(f"execute log filter field srcip {src_ip}")
    if dst_ip:
        ssh_filters.append(f"execute log filter field dstip {dst_ip}")
    if action:
        ssh_filters.append(f"execute log filter field action {action}")
    lines += ssh_filters + [f"execute log filter view-lines {min(count, 1000)}",
                            "execute log display"]
    try:
        out = ssh_command(device, "\n".join(lines), timeout=60)
        return {"source": "ssh", "api_error": api_err, "data": out}
    except FortiGateError as ssh_err:
        raise FortiGateError(f"API: {api_err} | SSH: {ssh_err}")


def get_wifi_clients(device):
    """Client WiFi connessi ai FortiAP gestiti (RSSI, SNR, AP, SSID)."""
    return _api_or_ssh(device, "monitor/wifi/client", {"with_triangulation": "false"},
                       "diagnose wireless-controller wlac -c sta")


def get_managed_aps(device):
    """FortiAP gestiti: stato, canale, client, versione."""
    return _api_or_ssh(device, "monitor/wifi/managed_ap", None,
                       "diagnose wireless-controller wlac -c wtp")


def get_full_config(device):
    """Configurazione completa del FortiGate (backup testuale).
    Via API: monitor/system/config/backup?scope=global (testo, non JSON)."""
    ip = device["IP"]
    token, port, verify = get_api_config(ip)
    api_err = None
    if token:
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            r = requests.get(
                f"https://{ip}:{port}/api/v2/monitor/system/config/backup",
                headers={"Authorization": f"Bearer {token}"},
                params={"scope": "global"}, verify=verify, timeout=60)
            if r.status_code < 400:
                return {"source": "api", "data": r.text}
            api_err = f"HTTP {r.status_code}: {r.text[:200]}"
        except requests.RequestException as e:
            api_err = str(e)
    else:
        api_err = f"Nessun token API configurato per {ip}."
    try:
        out = ssh_command(device, "show full-configuration", timeout=120)
        return {"source": "ssh", "api_error": api_err, "data": out}
    except FortiGateError as ssh_err:
        raise FortiGateError(f"API: {api_err} | SSH: {ssh_err}")


# --- Diagnosi aggregata client ------------------------------------------------

def diagnose_client(device, client: str, dest: str = None,
                    dest_port: int = 443, protocol: str = "TCP") -> dict:
    """Raccoglie in un colpo solo tutto ciò che il FortiGate sa di un client
    (IP o MAC) ed eventualmente del flusso verso `dest`: inventario device,
    ARP/DHCP, sessioni, policy match e ultimi log. Pensato per l'AI assistant
    e per il tool MCP 'fortigate_diagnose_client'.

    Ogni sezione è best-effort: se una sorgente fallisce si riporta l'errore
    nella sezione invece di far fallire l'intera diagnosi."""
    is_mac = bool(re.fullmatch(r"[0-9a-fA-F]{2}([:\-.]?[0-9a-fA-F]{2}){5}", client))
    result = {"client": client, "client_type": "mac" if is_mac else "ip",
              "fortigate": device.get("IP"), "sections": {}}

    def section(name, fn, *args, **kw):
        try:
            result["sections"][name] = fn(*args, **kw)
        except Exception as e:
            result["sections"][name] = {"error": str(e)}

    client_ip = None if is_mac else client

    section("device_inventory", get_device_inventory, device)
    section("arp", get_arp_table, device)
    section("dhcp_leases", get_dhcp_leases, device)

    # Se il client era un MAC, prova a risolverlo in IP da inventory/ARP/DHCP.
    if is_mac:
        norm = re.sub(r"[^0-9a-f]", "", client.lower())
        for sec in ("device_inventory", "dhcp_leases", "arp"):
            data = result["sections"].get(sec, {}).get("data")
            if not isinstance(data, list):
                continue
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                mac = re.sub(r"[^0-9a-f]", "", str(entry.get("mac", "")).lower())
                if mac == norm and entry.get("ip" if sec != "dhcp_leases" else "ip"):
                    client_ip = entry.get("ip")
                    break
            if client_ip:
                break
        result["resolved_ip"] = client_ip

    if client_ip:
        section("sessions", get_sessions, device, src_ip=client_ip)
        section("traffic_logs", get_traffic_logs, device, src_ip=client_ip, count=50)
        if dest:
            section("policy_lookup", policy_lookup, device, client_ip, dest,
                    protocol=protocol, dest_port=dest_port)
    section("wifi_clients", get_wifi_clients, device)
    return result
