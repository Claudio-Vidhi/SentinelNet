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
    return {"tools": [
        {"name": name, "description": desc, "inputSchema": schema}
        for name, (desc, schema, _fn) in TOOLS.items()
    ]}


def _tool_call(params):
    name = params.get("name")
    args = params.get("arguments") or {}
    if name not in TOOLS:
        return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}],
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
