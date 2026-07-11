# -*- coding: utf-8 -*-
"""SentinelNet MCP Server — espone SentinelNet come server MCP (Model Context
Protocol) su stdio, così qualunque client LLM esterno (Claude Desktop, LM
Studio, Cline, ecc.) può interrogare inventario, mappa di rete, MAC tracker,
config analyzer ed eseguire comandi CLI tramite l'API REST del centrale.

Il server NON reimplementa alcuna logica: è un ponte autenticato verso l'API
HTTP di SentinelNet. Autorizzazione (ruoli, gruppi/tenant, blacklist comandi)
resta interamente lato server.

Configurazione (variabili d'ambiente):
    SENTINELNET_URL        Base URL del centrale (default http://127.0.0.1:8765)
    SENTINELNET_USERNAME   Utente SentinelNet con cui autenticarsi
    SENTINELNET_PASSWORD   Password
    SENTINELNET_VERIFY_TLS "0" per non verificare il certificato (default "1")

Esempio (Claude Desktop / claude_desktop_config.json):
    {"mcpServers": {"sentinelnet": {
        "command": "python", "args": ["/percorso/SentinelNet/mcp_server.py"],
        "env": {"SENTINELNET_URL": "http://127.0.0.1:8765",
                "SENTINELNET_USERNAME": "admin",
                "SENTINELNET_PASSWORD": "..."}}}}

Trasporto: JSON-RPC 2.0, un messaggio per riga su stdin/stdout (MCP stdio).
"""
import os
import sys
import json
import time

import requests

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "sentinelnet", "version": "1.0.0"}
MAX_TEXT = 200_000   # limite prudenziale sul testo restituito a un client LLM

BASE_URL = os.environ.get("SENTINELNET_URL", "http://127.0.0.1:8765").rstrip("/")
USERNAME = os.environ.get("SENTINELNET_USERNAME", "")
PASSWORD = os.environ.get("SENTINELNET_PASSWORD", "")
VERIFY_TLS = os.environ.get("SENTINELNET_VERIFY_TLS", "1") != "0"

_token = None


# --- Client HTTP autenticato verso il centrale -----------------------------

def _login() -> str:
    global _token
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"username": USERNAME, "password": PASSWORD},
                      verify=VERIFY_TLS, timeout=15)
    r.raise_for_status()
    _token = r.json()["access_token"]
    return _token


def api(method: str, path: str, params: dict = None, body: dict = None):
    """Chiama l'API REST con JWT; su 401 riprova una volta dopo re-login."""
    global _token
    if _token is None:
        _login()
    for attempt in (1, 2):
        r = requests.request(method, BASE_URL + path,
                             headers={"Authorization": f"Bearer {_token}"},
                             params=params, json=body,
                             verify=VERIFY_TLS, timeout=60)
        if r.status_code == 401 and attempt == 1:
            _login()
            continue
        break
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text
        raise RuntimeError(f"HTTP {r.status_code}: {detail}")
    try:
        return r.json()
    except ValueError:
        return r.text


# --- Definizione dei tool MCP ----------------------------------------------
# Ogni voce: (descrizione, inputSchema, funzione(args) -> oggetto/testo)

def _obj(props: dict = None, required: list = None) -> dict:
    schema = {"type": "object", "properties": props or {}}
    if required:
        schema["required"] = required
    return schema

_S = {"type": "string"}

TOOLS = {
    "list_devices": (
        "List all managed network devices (IP, hostname, vendor, group/site, "
        "status) from the SentinelNet inventory.",
        _obj(),
        lambda a: api("GET", "/api/local-devices"),
    ),
    "get_network_map": (
        "Get the discovered network topology: nodes (devices with type, vendor, "
        "VTP info) and links (local/remote ports, Port-Channel/LAG membership "
        "with per-side aggregate ids).",
        _obj({"group": {**_S, "description": "Site/group filter, 'all' for everything"}}),
        lambda a: api("GET", "/api/network-map", params={"group": a.get("group", "all")}),
    ),
    "get_port_channels": (
        "List all EtherChannel/Port-Channel aggregates detected in the network "
        "with their member interfaces per device.",
        _obj(),
        lambda a: api("GET", "/api/portchannels"),
    ),
    "locate_mac": (
        "Locate a MAC address in the network: returns the access switch/port "
        "where the host is attached (uplink/trunk sightings filtered out).",
        _obj({"mac": {**_S, "description": "MAC address, any format"}}, ["mac"]),
        lambda a: api("GET", "/api/mac/locate", params={"mac": a["mac"]}),
    ),
    "search_mac": (
        "Search the historical MAC address table across all switches. All "
        "filters optional.",
        _obj({"mac": _S, "vlan": _S, "interface": _S,
              "switch": {**_S, "description": "Switch IP"}}),
        lambda a: api("GET", "/api/mac/search",
                      params={k: v for k, v in a.items() if v}),
    ),
    "mac_to_ip": (
        "Resolve MAC <-> IP bindings for network clients, collected from the "
        "ARP tables of the L3 gateways (L3 switches or firewalls, whichever "
        "routes the VLAN). Search by MAC (full or fragment) or IP prefix.",
        _obj({"mac": {**_S, "description": "MAC address or fragment"},
              "ip": {**_S, "description": "IP address or prefix"}}),
        lambda a: api("GET", "/api/arp/search",
                      params={k: v for k, v in a.items() if v}),
    ),
    "client_map": (
        "Unified client view: MAC + current IP (from the routing gateway's "
        "ARP) + access switch/port (from the MAC table). Answers 'who is "
        "10.0.0.5 and which port is it attached to'.",
        _obj({"mac": _S, "ip": _S}),
        lambda a: api("GET", "/api/arp/client-map",
                      params={k: v for k, v in a.items() if v}),
    ),
    "arp_scan": (
        "Collect the ARP tables from managed L3 devices (switches and "
        "firewalls) and store MAC<->IP bindings in the historical DB. "
        "Requires operator role; optionally restrict to one device IP or a "
        "site/group.",
        _obj({"ip": {**_S, "description": "Only this device (optional)"},
              "group": {**_S, "description": "Site/group filter, 'all' default"}}),
        lambda a: api("POST", "/api/arp/scan",
                      body={"ip": a.get("ip"), "group": a.get("group", "all")}),
    ),
    "analyze_config": (
        "Analyze the stored configuration backup of a device: VLANs, SVIs, "
        "routing, trunk/access ports, neighbors, security findings.",
        _obj({"ip": {**_S, "description": "Device IP"}}, ["ip"]),
        lambda a: api("GET", f"/api/config-analyzer/{a['ip']}"),
    ),
    "get_triage_status": (
        "Get the status of the last triage run (reachability, backup, version "
        "detection) for every device.",
        _obj(),
        lambda a: api("GET", "/api/triage-status"),
    ),
    "send_cli_command": (
        "Run a single CLI command on a managed device via SSH and return the "
        "output. Destructive commands are blocked server-side; requires an "
        "account with operator role.",
        _obj({"ip": {**_S, "description": "Device IP"},
              "command": {**_S, "description": "CLI command, e.g. 'show vlan brief'"}},
             ["ip", "command"]),
        lambda a: api("POST", "/api/send-command",
                      body={"ip": a["ip"], "command": a["command"]}),
    ),
    "list_sites": (
        "List the configured sites (central + remote) with mode "
        "(central-poll/agent), subnets and last-seen time.",
        _obj(),
        lambda a: api("GET", "/api/sites"),
    ),
    "fortigate_status": (
        "Get live system status of a FortiGate firewall (version, HA, uptime, "
        "hostname) via REST API or SSH fallback.",
        _obj({"ip": {**_S, "description": "FortiGate IP (must be in inventory)"}}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/status"),
    ),
    "fortigate_interfaces": (
        "Get live interface state of a FortiGate: IPs, link status, speed, "
        "counters, VLANs, aggregates.",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/interfaces"),
    ),
    "fortigate_arp": (
        "Get the live ARP table of a FortiGate (IP <-> MAC on each interface).",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/arp"),
    ),
    "fortigate_dhcp_leases": (
        "Get active DHCP leases from a FortiGate (client IP, MAC, hostname, "
        "expiry, interface).",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/dhcp-leases"),
    ),
    "fortigate_device_inventory": (
        "Get the FortiOS device-identification inventory: every client the "
        "FortiGate has detected with MAC, IP, hostname, OS, ingress interface, "
        "online/offline state.",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/device-inventory"),
    ),
    "fortigate_policies": (
        "Get the configured firewall policies of a FortiGate (full policy "
        "table: src/dst interfaces and addresses, services, action, NAT, UTM "
        "profiles, logging).",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/policies"),
    ),
    "fortigate_policy_lookup": (
        "Ask the FortiGate which firewall policy WOULD match a given flow "
        "(source IP, destination IP/FQDN, protocol, port) without generating "
        "traffic. Key tool for 'why can't client X reach site Y'.",
        _obj({"ip": _S,
              "src_ip": {**_S, "description": "Client source IP"},
              "dest": {**_S, "description": "Destination IP or FQDN"},
              "protocol": {**_S, "description": "TCP | UDP | ICMP (default TCP)"},
              "dest_port": {"type": "integer", "description": "Default 443"}},
             ["ip", "src_ip", "dest"]),
        lambda a: api("POST", f"/api/fortigate/{a['ip']}/policy-lookup",
                      body={"src_ip": a["src_ip"], "dest": a["dest"],
                            "protocol": a.get("protocol", "TCP"),
                            "dest_port": a.get("dest_port", 443)}),
    ),
    "fortigate_sessions": (
        "Get active sessions on a FortiGate, filterable by source IP, "
        "destination IP and destination port.",
        _obj({"ip": _S, "src_ip": _S, "dst_ip": _S,
              "dst_port": {"type": "integer"},
              "count": {"type": "integer", "description": "Max sessions (default 100)"}},
             ["ip"]),
        lambda a: api("POST", f"/api/fortigate/{a['ip']}/sessions",
                      body={k: a.get(k) for k in ("src_ip", "dst_ip", "dst_port", "count")
                            if a.get(k) is not None}),
    ),
    "fortigate_routes": (
        "Get the live IPv4 routing table of a FortiGate.",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/routes"),
    ),
    "fortigate_traffic_logs": (
        "Query FortiGate forward traffic logs (what the firewall logged for a "
        "client/destination: allowed, denied, UTM verdicts). Filters optional.",
        _obj({"ip": _S, "src_ip": _S, "dst_ip": _S,
              "action": {**_S, "description": "accept | deny | ..."},
              "count": {"type": "integer", "description": "Max rows (default 100)"}},
             ["ip"]),
        lambda a: api("POST", f"/api/fortigate/{a['ip']}/logs",
                      body={k: a.get(k) for k in ("src_ip", "dst_ip", "action", "count")
                            if a.get(k) is not None}),
    ),
    "fortigate_wifi_clients": (
        "List WiFi clients connected to FortiAPs managed by a FortiGate, with "
        "signal strength (RSSI/SNR), AP, SSID, data rates. Use for wireless "
        "disconnection troubleshooting.",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/wifi/clients"),
    ),
    "fortigate_managed_aps": (
        "List FortiAPs managed by a FortiGate: status, channel utilization, "
        "connected clients, firmware.",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/wifi/aps"),
    ),
    "fortigate_full_config": (
        "Get the complete live configuration of a FortiGate (full backup "
        "text). Large output; requires operator role.",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/full-config"),
    ),
    "fortigate_diagnose_client": (
        "One-shot diagnosis of a client (IP or MAC) through a FortiGate: "
        "device inventory, ARP, DHCP lease, active sessions, matching firewall "
        "policy toward an optional destination, recent traffic logs, WiFi "
        "state. Answers 'why can't this client reach X' / 'why does this "
        "client disconnect'.",
        _obj({"ip": {**_S, "description": "FortiGate IP"},
              "client": {**_S, "description": "Client IP or MAC address"},
              "dest": {**_S, "description": "Optional destination IP/FQDN for policy lookup"},
              "dest_port": {"type": "integer", "description": "Default 443"},
              "protocol": {**_S, "description": "TCP | UDP | ICMP (default TCP)"}},
             ["ip", "client"]),
        lambda a: api("POST", f"/api/fortigate/{a['ip']}/diagnose-client",
                      body={k: a.get(k) for k in ("client", "dest", "dest_port", "protocol")
                            if a.get(k) is not None}),
    ),
    "wlc_status": (
        "Get status of a Cisco wireless LAN controller (AireOS or Catalyst "
        "9800): version, uptime, AP/client counts.",
        _obj({"ip": {**_S, "description": "WLC IP (must be in inventory)"}}, ["ip"]),
        lambda a: api("GET", f"/api/wlc/{a['ip']}/status"),
    ),
    "wlc_ap_summary": (
        "List access points joined to a Cisco WLC: name, model, IP, clients, "
        "location, state.",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/wlc/{a['ip']}/ap-summary"),
    ),
    "wlc_client_summary": (
        "List wireless clients on a Cisco WLC with AP, WLAN/SSID, state and "
        "protocol.",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/wlc/{a['ip']}/client-summary"),
    ),
    "wlc_client_detail": (
        "Full detail for one wireless client by MAC: AP, SSID, RSSI/SNR, "
        "data rates, roaming/session history, policy state. Use for "
        "disconnection troubleshooting.",
        _obj({"ip": _S, "mac": {**_S, "description": "Client MAC, any format"}},
             ["ip", "mac"]),
        lambda a: api("GET", f"/api/wlc/{a['ip']}/client/{a['mac']}"),
    ),
    "wlc_wlan_summary": (
        "List WLANs/SSIDs configured on a Cisco WLC with status and security "
        "policy.",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/wlc/{a['ip']}/wlan-summary"),
    ),
    "wlc_rogue_aps": (
        "List rogue/interfering access points detected by a Cisco WLC "
        "(possible cause of client disconnections).",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/wlc/{a['ip']}/rogue-aps"),
    ),
    "wlc_diagnose_client": (
        "One-shot wireless diagnosis of a client (MAC) on a Cisco WLC: "
        "client detail (RSSI/SNR/AP/SSID), AP summary, WLAN summary and "
        "nearby rogue APs. Answers 'why do clients on this AP disconnect'.",
        _obj({"ip": {**_S, "description": "WLC IP"},
              "mac": {**_S, "description": "Client MAC address"}},
             ["ip", "mac"]),
        lambda a: api("GET", f"/api/wlc/{a['ip']}/diagnose-client/{a['mac']}"),
    ),
    "generate_fortigate_config": (
        "Generate a hardened day-0 FortiOS configuration for a new FortiGate "
        "(zero-touch provisioning; does not touch any device). Same parameters "
        "as the FortiGate ZTP wizard.",
        _obj({"hostname": _S, "admin_user": _S, "admin_password": _S,
              "mgmt_interface": _S, "mgmt_ip": _S, "mgmt_mask": _S,
              "wan_interface": _S, "wan_mode": {**_S, "description": "dhcp | static"},
              "wan_ip": _S, "wan_mask": _S, "wan_gw": _S,
              "lan_interface": _S, "lan_ip": _S, "lan_mask": _S,
              "dhcp_server": {"type": "boolean"}, "dhcp_start": _S, "dhcp_end": _S,
              "dns_primary": _S, "dns_secondary": _S,
              "ntp_servers": {"type": "array", "items": _S},
              "syslog_server": _S,
              "lan_to_wan_policy": {"type": "boolean"},
              "disable_wan_admin": {"type": "boolean"},
              "banner": _S},
             ["hostname"]),
        lambda a: api("POST", "/api/provisioner/fgt/generate", body=a),
    ),
    "generate_switch_config": (
        "Generate a hardened day-0 Cisco IOS/IOS-XE configuration for a new "
        "switch (does not touch any device). Accepts the same parameters as "
        "the 'Zero-Touch Switch' wizard.",
        _obj({"hostname": _S,
              "role": {**_S, "description": "access | distribution"},
              "mgmt_vlan": {"type": "integer"}, "mgmt_ip": _S, "mgmt_mask": _S,
              "mgmt_gw": _S, "admin_user": _S, "admin_password": _S,
              "enable_secret": _S,
              "vlans": {"type": "array", "items": {"type": "object"},
                        "description": "[{id, name}, ...]"},
              "access_ports": {"type": "array", "items": _S},
              "access_vlan": {"type": "integer"},
              "trunk_ports": {"type": "array", "items": _S},
              "trunk_allowed_vlans": _S,
              "port_security": {"type": "boolean"},
              "dhcp_snooping": {"type": "boolean"},
              "ntp_servers": {"type": "array", "items": _S},
              "syslog_server": _S},
             ["hostname"]),
        lambda a: api("POST", "/api/provisioner/generate", body=a),
    ),
}


# --- Tool disabilitati dall'amministratore (tab "MCP Server" del centrale) ---
# Cache con TTL: si evita una chiamata HTTP per ogni tools/list o tools/call.

_disabled = {"at": 0.0, "tools": set()}


def disabled_tools() -> set:
    if time.monotonic() - _disabled["at"] < 60:
        return _disabled["tools"]
    try:
        data = api("GET", "/api/mcp/tool-config")
        _disabled["tools"] = set(data.get("disabled_tools") or [])
    except Exception:
        pass                     # centrale irraggiungibile: si tiene l'ultimo noto
    _disabled["at"] = time.monotonic()
    return _disabled["tools"]


# --- Ciclo JSON-RPC su stdio -------------------------------------------------

def _reply(msg_id, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _tool_list():
    off = disabled_tools()
    return {"tools": [
        {"name": name, "description": desc, "inputSchema": schema}
        for name, (desc, schema, _fn) in TOOLS.items() if name not in off
    ]}


def _tool_call(params):
    name = params.get("name")
    args = params.get("arguments") or {}
    if name not in TOOLS:
        return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                "isError": True}
    if name in disabled_tools():
        return {"content": [{"type": "text", "text":
                             f"Tool '{name}' disabled by the SentinelNet administrator."}],
                "isError": True}
    try:
        result = TOOLS[name][2](args)
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error: {e}"}],
                "isError": True}
    text = result if isinstance(result, str) \
        else json.dumps(result, ensure_ascii=False, indent=1)
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT] + "\n... [truncated]"
    return {"content": [{"type": "text", "text": text}]}


def main():
    if not USERNAME or not PASSWORD:
        sys.stderr.write("SENTINELNET_USERNAME / SENTINELNET_PASSWORD non impostate.\n")
        sys.exit(1)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        method = msg.get("method")
        msg_id = msg.get("id")
        if method == "initialize":
            _reply(msg_id, {
                "protocolVersion": msg.get("params", {}).get("protocolVersion", PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            })
        elif method == "notifications/initialized":
            pass                       # notifica: nessuna risposta
        elif method == "ping":
            _reply(msg_id, {})
        elif method == "tools/list":
            _reply(msg_id, _tool_list())
        elif method == "tools/call":
            _reply(msg_id, _tool_call(msg.get("params") or {}))
        elif msg_id is not None:
            _reply(msg_id, error={"code": -32601, "message": f"Method not found: {method}"})


if __name__ == "__main__":
    main()
