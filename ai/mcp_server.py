# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""SentinelNet MCP Server — exposes SentinelNet as an MCP (Model Context
Protocol) server over stdio, so any external LLM client (Claude Desktop, LM
Studio, Cline, etc.) can query inventory, network map, MAC tracker,
config analyzer and run CLI commands through the central server's REST API.

The server does NOT reimplement any logic: it is an authenticated bridge to
SentinelNet's HTTP API. Authorization (roles, groups/tenant, command blacklist)
remains entirely server-side.

Configuration (environment variables):
    SENTINELNET_URL        Base URL of the central server (default http://127.0.0.1:8000)
    SENTINELNET_VERIFY_TLS "0" to skip certificate verification (default "1")

Sign-in, first match wins:
    SENTINELNET_USERNAME + SENTINELNET_PASSWORD
                           legacy: a password kept in the client's config
    SENTINELNET_TOKEN      a revocable grant pasted in the config, for hosts
                           with no keychain or no browser
    OS keychain            the grant left there by a browser sign-in
    browser sign-in        none of the above: the dashboard opens, the
                           operator approves, the grant goes to the keychain

Clients that honour `notifications/tools/list_changed` pick the tools up as
soon as the operator approves; the others see one `sentinelnet_login` tool
until they are restarted. `--login` runs the browser sign-in once from a
terminal and exits, for any client.

Example (Claude Desktop / claude_desktop_config.json):
    {"mcpServers": {"sentinelnet": {
        "command": "/path/to/SentinelNet/.venv/bin/python",
        "args": ["/path/to/SentinelNet/ai/mcp_server.py"],
        "env": {"SENTINELNET_URL": "http://127.0.0.1:8000"}}}}

Transport: JSON-RPC 2.0, one message per line on stdin/stdout (MCP stdio).
"""
import base64
import hashlib
import os
import secrets
import socket
import sys
import json
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from typing import Any, Dict, List, Optional

# Run as a script (the documented client config), sys.path[0] is ai/, not the
# repo root, and `security` would not import.
if not __package__:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.redaction import redact

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "sentinelnet", "version": "1.0.0"}
MAX_TEXT = 200_000   # conservative limit on text returned to an LLM client

BASE_URL = os.environ.get("SENTINELNET_URL", "http://127.0.0.1:8000").rstrip("/")
USERNAME = os.environ.get("SENTINELNET_USERNAME", "")
PASSWORD = os.environ.get("SENTINELNET_PASSWORD", "")
VERIFY_TLS = os.environ.get("SENTINELNET_VERIFY_TLS", "1") != "0"

_token = None
_session = requests.Session()

# Tool currently being executed, sent on every request so the central server
# can attribute its audit lines to the MCP bridge and to the specific tool
# (review item 4). Set by _tool_call, so login and config sync carry the bare
# client name.
_current_tool = ""
CLIENT_TAG_HEADER = "X-SentinelNet-Client"


# --- Browser sign-in (server side: security/mcp_grants.py) ------------------

KEYRING_SERVICE = "SentinelNet MCP"
# Fixed on purpose: binding it is also the lock that keeps the client's
# parallel bridge processes (Claude Desktop starts more than one) from opening
# one browser tab each. The loser waits for the winner's grant in the keychain.
CALLBACK_PORT = 38461
AUTH_TIMEOUT = 300
LOGIN_TOOL = "sentinelnet_login"

# clientInfo.name -> what the consent page shows. Unknown names pass through.
CLIENT_NAMES = {
    "claude-ai": "Claude Desktop", "claude-code": "Claude Code",
    "cursor-vscode": "Cursor", "Visual Studio Code": "VS Code",
    "Cline": "Cline", "windsurf-client": "Windsurf", "lm-studio": "LM Studio",
    "continue-client": "Continue", "Zed": "Zed",
}

_grant = os.environ.get("SENTINELNET_TOKEN") or None
_client_name = ""              # from the client's initialize, for the consent page
_auth_url = ""                 # page the pending sign-in opened, for the login tool
_auth_thread = None
_auth_lock = threading.Lock()


def _log(text: str) -> None:
    # stderr only: stdout is the JSON-RPC channel.
    print(f"[sentinelnet-mcp] {text}", file=sys.stderr, flush=True)


def _stored_grant():
    try:
        import keyring
        return keyring.get_password(KEYRING_SERVICE, BASE_URL)
    except Exception:
        return None


def _store_grant(token: str) -> None:
    global _grant
    _grant = token
    try:
        import keyring
        keyring.set_password(KEYRING_SERVICE, BASE_URL, token)
    except Exception as e:
        _log(f"Portachiavi di sistema non disponibile ({e}). L'accesso vale solo "
             f"per questa sessione; per renderlo stabile metti nel config "
             f"SENTINELNET_TOKEN={token}")


def _forget_grant() -> None:
    global _grant
    _grant = None
    try:
        import keyring
        keyring.delete_password(KEYRING_SERVICE, BASE_URL)
    except Exception:
        pass


def _signed_in() -> bool:
    return bool(PASSWORD or _grant or _stored_grant())


class _CallbackServer(HTTPServer):
    state = ""
    code = None
    denied = False


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        srv = self.server
        assert isinstance(srv, _CallbackServer)
        url = urlparse(self.path)
        q = parse_qs(url.query)
        ours = (url.path == "/callback"
                and secrets.compare_digest(q.get("state", [""])[0], srv.state))
        if ours and q.get("code"):
            srv.code = q["code"][0]
            result = "done"
        elif ours and q.get("error") == ["access_denied"]:
            # Cancel on the consent page: stop waiting now, not in five minutes.
            srv.denied = True
            result = "denied"
        else:
            result = ""
        if result:
            # Back to the consent page, which shows the outcome.
            self.send_response(302)
            self.send_header("Location", f"{BASE_URL}/mcp/authorize?" + urlencode(
                {"result": result, "client": _client_name}))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = "SentinelNet: richiesta non valida.".encode("utf-8")
        self.send_response(400)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def _browser_login() -> str:
    """Loopback redirect + PKCE: opens the dashboard, waits for the operator
    to approve, trades the one-time code for a grant and stores it."""
    global _auth_url
    try:
        srv = _CallbackServer(("127.0.0.1", CALLBACK_PORT), _CallbackHandler)
    except OSError:
        _log("Un altro processo del client sta gia' chiedendo l'autorizzazione: attendo.")
        deadline = time.monotonic() + AUTH_TIMEOUT
        while time.monotonic() < deadline:
            token = _stored_grant()
            if token:
                _store_grant(token)
                return token
            time.sleep(2)
        raise RuntimeError("autorizzazione non completata in tempo")
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    srv.state = secrets.token_urlsafe(16)
    _auth_url = f"{BASE_URL}/mcp/authorize?" + urlencode({
        "port": CALLBACK_PORT, "state": srv.state, "challenge": challenge,
        "client": _client_name, "host": socket.gethostname(),
        # When this bridge stops listening: the page greys out a stale request
        # instead of sending the browser to a closed port.
        "exp": int(time.time()) + AUTH_TIMEOUT})
    _log(f"Autorizza questo client nel browser: {_auth_url}")
    webbrowser.open(_auth_url)
    srv.timeout = 1
    deadline = time.monotonic() + AUTH_TIMEOUT
    with srv:
        while srv.code is None and not srv.denied and time.monotonic() < deadline:
            srv.handle_request()
    if srv.denied:
        raise RuntimeError("autorizzazione annullata nel browser")
    if srv.code is None:
        raise RuntimeError("autorizzazione non completata in tempo")
    r = _session.post(f"{BASE_URL}/api/mcp/token",
                      json={"code": srv.code, "verifier": verifier},
                      verify=VERIFY_TLS, timeout=15)
    r.raise_for_status()
    data = r.json()
    _store_grant(data["token"])
    _log(f"Autorizzato come '{data.get('username')}'.")
    return data["token"]


def _authorize_in_background() -> None:
    """Browser sign-in without blocking the JSON-RPC loop; when it lands the
    client is told to fetch the tool list again."""
    global _auth_thread

    def run():
        try:
            _browser_login()
        except Exception as e:
            _log(f"Autorizzazione non riuscita: {e}")
            return
        _disabled["at"] = 0.0
        _notify("notifications/tools/list_changed")

    with _auth_lock:
        if _auth_thread is not None and _auth_thread.is_alive():
            return
        _auth_thread = threading.Thread(target=run, daemon=True)
        _auth_thread.start()


def _login_tool_call() -> str:
    """The one tool a client sees before sign-in: for clients that ignore
    list_changed, it is how the model can tell the user what to do."""
    if _signed_in():
        return ("Il client e' gia' autorizzato. Se gli strumenti di SentinelNet "
                "non compaiono, ricarica gli strumenti MCP o riavvia il client.")
    _authorize_in_background()
    page = f" ({_auth_url})" if _auth_url else ""
    return (f"Ho aperto nel browser la pagina di accesso di SentinelNet{page}. "
            f"Dopo l'approvazione gli strumenti compaiono da soli; se il client "
            f"non li mostra, ricaricali o riavvia il client.")


# --- Authenticated HTTP client toward the central server --------------------

def _login() -> str:
    global _token
    if PASSWORD:
        r = _session.post(f"{BASE_URL}/api/auth/login",
                          json={"username": USERNAME, "password": PASSWORD},
                          verify=VERIFY_TLS, timeout=15)
    else:
        grant = _grant or _stored_grant()
        if not grant:
            _authorize_in_background()
            raise RuntimeError("client MCP non ancora autorizzato: completa "
                               "l'accesso nella pagina aperta nel browser")
        r = _session.post(f"{BASE_URL}/api/mcp/session", json={"token": grant},
                          verify=VERIFY_TLS, timeout=15)
        if r.status_code == 401:
            _forget_grant()
            _authorize_in_background()
            raise RuntimeError("accesso MCP revocato: autorizza di nuovo nel browser")
    r.raise_for_status()
    _token = r.json()["access_token"]
    _warn_if_privileged_account()
    return _token


def _warn_if_privileged_account() -> None:
    """Posture warning (WP3 follow-up): every MCP client — and the LLM driving
    it — inherits the role of the configured account. Anything above viewer
    makes action tools executable by the model. The warning goes to stderr:
    stdout is the JSON-RPC channel and must never carry prose."""
    try:
        me = api("GET", "/api/auth/me")
    except Exception:
        return
    role = (me or {}).get("role")
    if role and role != "viewer":
        print(f"[sentinelnet-mcp] ATTENZIONE: l'account configurato "
              f"'{me.get('username') or USERNAME}' ha ruolo '{role}'. Ogni client MCP eredita "
              f"questo ruolo: gli strumenti di azione (send_cli_command, "
              f"arp_scan, ...) diventano eseguibili dal modello. Per l'accesso "
              f"in sola lettura usare un account viewer.", file=sys.stderr)


def api(method: str, path: str, params: Optional[dict] = None, body: Optional[dict] = None):
    """Call the REST API with JWT; on 401 retry once after re-login."""
    global _token
    if _token is None:
        _login()
    for attempt in (1, 2):
        tag = f"mcp/{_current_tool}" if _current_tool else "mcp"
        r = _session.request(method, BASE_URL + path,
                             headers={"Authorization": f"Bearer {_token}",
                                      CLIENT_TAG_HEADER: tag},
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
    # Secret redaction (finding I-1): tool results go to an external LLM
    # client, so they pass through the same choke-point as the in-app assistant.
    try:
        return redact(r.json())
    except ValueError:
        return redact(r.text)


# --- MCP tool definitions ---------------------------------------------------
# Each entry: (description, inputSchema, function(args) -> object/text)

def _obj(props: Optional[dict] = None, required: Optional[list] = None) -> dict:
    schema: Dict[str, Any] = {"type": "object", "properties": props or {}}
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
              "switch": {**_S, "description": "Switch IP"},
              "frm": {**_S, "description": "From ISO timestamp (optional)"},
              "to": {**_S, "description": "To ISO timestamp (optional)"}}),
        lambda a: api("GET", "/api/mac/search",
                      params={k: v for k, v in a.items() if v}),
    ),
    "mac_to_ip": (
        "Resolve MAC <-> IP bindings for network clients, collected from the "
        "ARP tables of the L3 gateways (L3 switches or firewalls, whichever "
        "routes the VLAN). Search by MAC (full or fragment) or IP prefix.",
        _obj({"mac": {**_S, "description": "MAC address or fragment"},
              "ip": {**_S, "description": "IP address or prefix"},
              "frm": {**_S, "description": "From ISO timestamp (optional)"},
              "to": {**_S, "description": "To ISO timestamp (optional)"}}),
        lambda a: api("GET", "/api/arp/search",
                      params={k: v for k, v in a.items() if v}),
    ),
    "client_map": (
        "Unified client view: MAC + current IP (from the routing gateway's "
        "ARP) + access switch/port (from the MAC table). Answers 'who is "
        "192.0.2.10 and which port is it attached to'.",
        _obj({"mac": _S, "ip": _S,
              "frm": {**_S, "description": "From ISO timestamp (optional)"},
              "to": {**_S, "description": "To ISO timestamp (optional)"}}),
        lambda a: api("GET", "/api/arp/client-map",
                      params={k: v for k, v in a.items() if v}),
    ),
    "endpoint_inventory": (
        "Endpoint inventory: one entry per (MAC, tenant) with current or historical "
        "IPs, access switch/port, VLAN, vendor, classification, and flags.",
        _obj({"tenant": _S, "switch": _S, "vlan": _S, "q": _S,
              "frm": {**_S, "description": "From ISO timestamp (optional)"},
              "to": {**_S, "description": "To ISO timestamp (optional)"}}),
        lambda a: api("GET", "/api/endpoints/list",
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
    "fortigate_firewall_addresses": (
        "Get the firewall address book of a FortiGate (name, type, subnet/FQDN, "
        "comment) — slim cmdb read, useful to resolve object names used in "
        "policies.",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/firewall/addresses"),
    ),
    "fortigate_firewall_policy_objects": (
        "Get the firewall policy table of a FortiGate with only the fields "
        "relevant to observability (policyid, name, src/dst interfaces and "
        "addresses, service, action, status, logtraffic). Slimmer than "
        "fortigate_policies.",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/firewall/policy-objects"),
    ),
    "fortigate_firewall_services": (
        "Get the custom firewall services of a FortiGate (name, TCP/UDP port "
        "ranges, comment).",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/firewall/services"),
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
    "fortigate_policy_stats": (
        "Runtime counters per firewall policy: hit count, bytes, active "
        "sessions, first/last used. Answers 'which rules are dead' (zero hits "
        "over the counters' lifetime, so candidates for removal) and 'which "
        "rule is actually carrying this traffic'. Pair with fortigate_policies "
        "to map policy id to name and to what it permits.",
        _obj({"ip": {**_S, "description": "FortiGate IP"}}, ["ip"]),
        lambda a: api("GET", f"/api/fortigate/{a['ip']}/policy-stats"),
    ),
    "diagnose_client": (
        "End-to-end L2+L3 diagnosis of ONE client (IP or MAC), across switch "
        "and firewall in a single report: access switch and port, port VLAN, "
        "link state and error-counter delta, whether the client VLAN is "
        "allowed on the switch trunks, the logical traffic path, the matching "
        "firewall policy toward an optional destination, and how many blocks "
        "it suffered in the last hour grouped by policy. Prefer this over "
        "fortigate_diagnose_client when the question is about a client rather "
        "than about one firewall: it picks the right FortiGate itself and adds "
        "the switch-side half. Sections that cannot be answered say so "
        "('known': false with a reason) instead of being omitted.",
        _obj({"client": {**_S, "description": "Client IP or MAC address"},
              "dest": {**_S, "description": "Optional destination IP/FQDN: enables policy lookup and the path"},
              "dest_port": {"type": "integer", "description": "Default 443"},
              "protocol": {**_S, "description": "TCP | UDP | ICMP (default TCP)"},
              "tenant": {**_S, "description": "Restrict to one tenant/site when the address exists in several "
                                              "(a prior call returns 'status': 'ambiguous' with the candidate "
                                              "tenants in that case)"}},
             ["client"]),
        lambda a: api("POST", "/api/diagnose/client",
                      body={k: a.get(k) for k in ("client", "dest", "dest_port", "protocol", "tenant")
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
    # --- Observability (phase 4.4): READ-ONLY, aggregated/summarized data
    # (never raw dump), tenant scoping and redaction applied server-side.
    # Disabled by default: admin enables them from the MCP Server tab.
    "get_top_talkers": (
        "Get the top bandwidth consumers (aggregated flow records) for a time "
        "window. Read-only, tenant-scoped, summarized (top-N only).",
        _obj({"window": {**_S, "description": "Time window, e.g. 15m, 24h (max 7d)"},
              "limit": {"type": "integer", "description": "Max flows (default 20, max 100)"},
              "metric": {**_S, "description": "'bytes' (default) or 'packets'"}}),
        lambda a: api("GET", "/api/observability/top", params={
            "window": a.get("window", "15m"),
            "limit": min(int(a.get("limit", 20)), 100),
            "metric": a.get("metric", "bytes")}),
    ),
    "get_anomalies": (
        "Get correlated security anomalies (blocked traffic matched with flow "
        "evidence and switch port). Read-only, tenant-scoped.",
        _obj({"status": {**_S, "description": "'new' (default), 'ack', 'resolved', 'all'"},
              "window": {**_S, "description": "Time window, e.g. 24h (max 7d)"}}),
        lambda a: api("GET", "/api/observability/anomalies", params={
            "status": a.get("status", "new"),
            "window": a.get("window", "24h"),
            "limit": 50}),
    ),
    "linux_health": (
        "Get the latest health snapshot of a managed Linux host: uptime, "
        "kernel, failed systemd units and the measured CPU / memory / disk "
        "usage. Read-only, tenant-scoped.",
        _obj({"ip": {**_S, "description": "Management IP of the Linux host"}},
             ["ip"]),
        lambda a: api("GET", "/api/observability/api-context",
                      params={"device_ip": a["ip"]}),
    ),
    "policy_trace": (
        "Traces a packet flow through device ACLs, routes, and firewall policies from backup configs (offline). Answers reachability and path validation questions.",
        _obj({
            "ip": {**_S, "description": "Device IP"},
            "src": {**_S, "description": "Source IP address"},
            "dst": {**_S, "description": "Destination IP address"},
            "proto": {**_S, "description": "Protocol: tcp (default), udp, icmp, ip"},
            "dport": {"type": "integer", "description": "Destination port (e.g. 443, 80)"},
            "ingress": {**_S, "description": "Ingress interface name (optional)"},
        }, ["ip", "src", "dst"]),
        lambda a: api("POST", f"/api/policy-test/{a['ip']}/trace", body={
            "src_ip": a["src"],
            "dst_ip": a["dst"],
            "proto": a.get("proto", "tcp"),
            "dport": a.get("dport"),
            "ingress_intf": a.get("ingress"),
        }),
    ),
    "policy_findings": (
        "Returns static configuration findings (shadowed rules, unreachable rules, any-any permits, routes to nowhere, unresolved objects) for a device.",
        _obj({"ip": {**_S, "description": "Device IP"}}, ["ip"]),
        lambda a: api("GET", f"/api/policy-test/{a['ip']}/findings"),
    ),
    # --- "What is wrong and why": incidents, CVE, drift, port errors, routing,
    # classification. Read-only bridges to existing routes.
    "list_incidents": (
        "List correlated incidents (grouped evidence: syslog, flows, port "
        "state) for a time window. Read-only, tenant-scoped.",
        _obj({"status": {**_S, "description": "'new' (default), 'ack', 'resolved', 'all'"},
              "window": {**_S, "description": "Time window, e.g. 24h (default), 7d"},
              "limit": {"type": "integer", "description": "Max incidents (default 50)"}}),
        lambda a: api("GET", "/api/incidents", params={
            "status": a.get("status", "new"), "window": a.get("window", "24h"),
            "limit": int(a.get("limit", 50))}),
    ),
    "get_incident": (
        "Full detail of one incident: timeline, evidence, affected entities.",
        _obj({"incident_id": {"type": "integer"}}, ["incident_id"]),
        lambda a: api("GET", f"/api/incidents/{int(a['incident_id'])}"),
    ),
    "cve_priority": (
        "Devices ranked by vulnerability exposure (CVSS, known-exploited), "
        "i.e. what to patch first. Read-only, tenant-scoped.",
        _obj({"tenant": {**_S, "description": "Site/group filter (optional)"},
              "limit": {"type": "integer", "description": "Max devices (default 200)"}}),
        lambda a: api("GET", "/api/cve/priority", params={
            "tenant": a.get("tenant", ""), "limit": int(a.get("limit", 200))}),
    ),
    "cve_for_device": (
        "Known vulnerabilities matched to one device's vendor/model/version.",
        _obj({"ip": {**_S, "description": "Device IP (must be in inventory)"}}, ["ip"]),
        lambda a: api("GET", f"/api/cve/{a['ip']}"),
    ),
    "search_vulnerabilities": (
        "Search public vulnerability databases (NVD/EUVD) by vendor, model, "
        "free text or CVE id.",
        _obj({"vendor": _S, "model": _S, "text": _S,
              "cve": {**_S, "description": "CVE id, e.g. CVE-2024-0001"}}),
        lambda a: api("GET", "/api/search", params={
            k: a[k] for k in ("vendor", "model", "text", "cve") if a.get(k)}),
    ),
    "drift_summary": (
        "Configuration drift per device: changed since last backup and "
        "deviation from the tenant baseline. Requires an operator account.",
        _obj({"tenant": {**_S, "description": "Site/group filter (optional)"}}),
        lambda a: api("GET", "/api/drift/summary", params={"tenant": a.get("tenant", "")}),
    ),
    "drift_versions": (
        "List the archived configuration versions of a device (for drift_diff). "
        "Requires an operator account.",
        _obj({"ip": _S}, ["ip"]),
        lambda a: api("GET", f"/api/drift/{a['ip']}/versions"),
    ),
    "drift_diff": (
        "Unified, redacted diff between two archived configuration versions "
        "of a device. Requires an operator account.",
        _obj({"ip": _S,
              "from_version": {**_S, "description": "'seen_at' of the older version, from drift_versions"},
              "to_version": {**_S, "description": "'seen_at' of the newer version, from drift_versions"}},
             ["ip", "from_version", "to_version"]),
        lambda a: api("GET", f"/api/drift/{a['ip']}/diff", params={
            "from_version": a["from_version"], "to_version": a["to_version"]}),
    ),
    "interface_errors": (
        "Ports with interface errors (CRC, input/output errors, drops) over a "
        "time window, worst first. Read-only, tenant-scoped.",
        _obj({"window": {**_S, "description": "e.g. 1h (default), 24h"},
              "device": {**_S, "description": "Limit to one device IP (optional)"},
              "tenant": {**_S, "description": "Tenant of that device when its IP is ambiguous"}}),
        lambda a: api("GET", "/api/interface-errors", params={
            k: a[k] for k in ("window", "device", "tenant") if a.get(k)}),
    ),
    "interface_errors_port": (
        "Error counters and their trend for one port of one device.",
        _obj({"device": {**_S, "description": "Device IP"},
              "port": {**_S, "description": "Interface name, e.g. Gi1/0/1"},
              "window": {**_S, "description": "e.g. 24h (default)"},
              "tenant": _S},
             ["device", "port"]),
        lambda a: api("GET", "/api/interface-errors/port", params={
            k: a[k] for k in ("device", "port", "window", "tenant") if a.get(k)}),
    ),
    "get_routes": (
        "Routing tables read live (read-only show commands) from the given "
        "devices, optionally filtered by route type or text.",
        _obj({"devices": {**_S, "description": "Comma-separated device IPs"},
              "type": {**_S, "description": "Route type filter, e.g. static, ospf, bgp (optional)"},
              "q": {**_S, "description": "Text/prefix filter (optional)"}},
             ["devices"]),
        lambda a: api("GET", "/api/routes", params={
            "device": a["devices"], "type": a.get("type", ""), "q": a.get("q", "")}),
    ),
    "trace_route": (
        "Hop-by-hop path to a destination computed from the routing tables of "
        "the given devices, starting at device 'src'. No packet is sent.",
        _obj({"devices": {**_S, "description": "Comma-separated device IPs to consider (must include src)"},
              "src": {**_S, "description": "Starting device IP"},
              "dst": {**_S, "description": "Destination IP"}},
             ["devices", "src", "dst"]),
        lambda a: api("GET", "/api/routes/trace", params={
            "device": a["devices"], "src": a["src"], "dst": a["dst"]}),
    ),
    "get_device_classification": (
        "Inventoried and CDP/LLDP-discovered devices with category, "
        "subcategory, vendor, model, HA group and whether the classification "
        "is manual or inferred; plus the category list and counts.",
        _obj(),
        lambda a: api("GET", "/api/device-classification"),
    ),
}


# --- Tools disabled by the administrator (central server "MCP Server" tab) ---
# Cache with TTL: avoids one HTTP call per tools/list or tools/call.

_disabled = {"at": 0.0, "tools": set(), "synced": False}


def disabled_tools() -> set:
    if time.monotonic() - _disabled["at"] < 60:
        return _disabled["tools"]
    try:
        data = api("GET", "/api/mcp/tool-config")
        _disabled["tools"] = set(data.get("disabled_tools") or [])
        _disabled["synced"] = True
    except Exception:
        if not _disabled["synced"]:
            # Fail closed before the first successful sync: serving an empty
            # disable set here would expose every tool, action tools
            # included, with no operator decision ever applied.
            return set(TOOLS)
        # central server unreachable after a known-good sync: keep last value
    _disabled["at"] = time.monotonic()
    return _disabled["tools"]


# --- JSON-RPC loop on stdio -------------------------------------------------

_out_lock = threading.Lock()   # the sign-in thread writes notifications too


def _write(out: dict) -> None:
    with _out_lock:
        sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
        sys.stdout.flush()


def _reply(msg_id, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    _write(out)


def _notify(method: str) -> None:
    _write({"jsonrpc": "2.0", "method": method})


def _tool_list():
    if not _signed_in():
        return {"tools": [{
            "name": LOGIN_TOOL,
            "description": ("SentinelNet non e' ancora autorizzato su questo client. "
                            "Chiamalo per aprire la pagina di accesso nel browser; "
                            "spiega all'utente di approvare e poi ricaricare gli strumenti."),
            "inputSchema": {"type": "object", "properties": {}},
        }]}
    off = disabled_tools()
    return {"tools": [
        {"name": name, "description": desc, "inputSchema": schema}
        for name, (desc, schema, _fn) in TOOLS.items() if name not in off
    ]}


def _tool_call(params):
    name = params.get("name")
    args = params.get("arguments") or {}
    if name == LOGIN_TOOL:
        return {"content": [{"type": "text", "text": _login_tool_call()}]}
    if name not in TOOLS:
        return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                "isError": True}
    if name in disabled_tools():
        return {"content": [{"type": "text", "text":
                             f"Tool '{name}' disabled by the SentinelNet administrator."}],
                "isError": True}
    global _current_tool
    _current_tool = name
    try:
        result = TOOLS[name][2](args)
    except Exception as e:
        err_msg = str(e)
        hint = ""
        if "HTTP 404" in err_msg:
            hint = " [Hint: check target device IP, site parameter, or resource path]"
        elif "HTTP 403" in err_msg:
            hint = " [Hint: action unauthorized for current account permissions]"
        elif "HTTP 422" in err_msg:
            hint = " [Hint: check tool parameter types and required fields]"
        elif "Connection" in err_msg or "ConnectTimeout" in err_msg:
            hint = f" [Hint: failed to reach base URL {BASE_URL}]"
        return {"content": [{"type": "text", "text": f"Error: {err_msg}{hint}"}],
                "isError": True}
    finally:
        _current_tool = ""
    text = result if isinstance(result, str) \
        else json.dumps(result, ensure_ascii=False, indent=1)
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT] + "\n... [truncated]"
    return {"content": [{"type": "text", "text": text}]}


def main():
    global _client_name
    if PASSWORD and not USERNAME:
        _log("SENTINELNET_PASSWORD senza SENTINELNET_USERNAME.")
        sys.exit(1)
    if "--login" in sys.argv:
        _client_name = "Terminale"
        try:
            _browser_login()
        except Exception as e:
            _log(f"Autorizzazione non riuscita: {e}")
            sys.exit(1)
        return
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
            info = (msg.get("params") or {}).get("clientInfo") or {}
            name = str(info.get("name") or "")
            _client_name = CLIENT_NAMES.get(name, name)[:60]
            if not _signed_in():
                # Here and not at start-up: clients start throwaway probe
                # processes that never initialize, and each would open a tab.
                _authorize_in_background()
            _reply(msg_id, {
                "protocolVersion": msg.get("params", {}).get("protocolVersion", PROTOCOL_VERSION),
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": SERVER_INFO,
            })
        elif method == "notifications/initialized":
            pass                       # notification: no response
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
