# -*- coding: utf-8 -*-
"""Client MCP verso server ESTERNI via Streamable HTTP (JSON-RPC 2.0).

PREVIEW: supporta solo il trasporto HTTP "streamable" (POST JSON-RPC con
risposta application/json oppure text/event-stream). Il trasporto stdio NON
e' supportato in questa preview (limitazione documentata).

Nessuna dipendenza pip aggiuntiva: usa `requests` (gia' nel bundle). La sessione
MCP e' per-richiesta: si esegue `initialize` (catturando l'header
`Mcp-Session-Id`), poi la chiamata effettiva (`tools/list` / `tools/call`).
"""

import json
import requests

_TIMEOUT = 30
# Versione del protocollo MCP richiesta in initialize.
_PROTOCOL_VERSION = "2025-06-18"
# Limite dimensione risposta da server MCP esterni (non fidati): evita di
# caricare in memoria body arbitrariamente grandi.
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024


def _read_capped(resp: "requests.Response", max_bytes: int = _MAX_RESPONSE_BYTES) -> str:
    """Legge il body di `resp` (richiesta con stream=True) fino a `max_bytes`.

    Solleva McpClientError se il body supera il limite, senza caricare oltre
    il cap in memoria.
    """
    chunks = []
    total = 0
    try:
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise McpClientError(
                    f"Risposta del server MCP troppo grande (> {max_bytes} byte)."
                )
            chunks.append(chunk)
    except requests.RequestException as e:
        raise McpClientError(f"Errore di rete verso il server MCP: {e}")
    encoding = resp.encoding or resp.apparent_encoding or "utf-8"
    try:
        return b"".join(chunks).decode(encoding, errors="replace")
    except (LookupError, TypeError):
        return b"".join(chunks).decode("utf-8", errors="replace")


class McpClientError(Exception):
    """Errore lato client MCP (rete, HTTP, JSON-RPC o SSE malformato)."""


def parse_sse_last_data(text: str) -> str:
    """Estrae l'ultimo evento `data:` da una risposta text/event-stream.

    Un server MCP streamable puo' rispondere in SSE: piu' eventi separati da
    riga vuota, ognuno con una o piu' righe `data:`. La risposta JSON-RPC utile
    e' l'ultimo evento con dati. Le righe che iniziano con `:` sono commenti SSE
    e vanno ignorate. Ritorna la stringa (JSON) dell'ultimo evento, o "".
    """
    events = []
    current = []
    for raw in (text or "").splitlines():
        line = raw.rstrip("\r")
        if line == "":
            if current:
                events.append("\n".join(current))
                current = []
            continue
        if line.startswith(":"):
            continue  # commento SSE (keep-alive)
        if line.startswith("data:"):
            current.append(line[5:].lstrip(" "))
    if current:
        events.append("\n".join(current))
    return events[-1] if events else ""


def _parse_response(resp: "requests.Response") -> dict:
    ctype = (resp.headers.get("Content-Type") or "").lower()
    text = _read_capped(resp)
    if "text/event-stream" in ctype:
        payload = parse_sse_last_data(text)
        if not payload:
            raise McpClientError("Risposta SSE senza righe 'data:'.")
        try:
            return json.loads(payload)
        except ValueError as e:
            raise McpClientError(f"Evento SSE non e' JSON valido: {e}")
    try:
        return json.loads(text)
    except ValueError as e:
        raise McpClientError(f"Risposta non e' JSON valido: {e}")


def _base_headers(auth_token: str = None) -> dict:
    h = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if auth_token:
        h["Authorization"] = f"Bearer {auth_token}"
    return h


def _rpc(url, headers, method, params, req_id):
    """POST JSON-RPC; ritorna (data, response). Solleva McpClientError su errore."""
    body = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}
    try:
        resp = requests.post(url, json=body, headers=headers, timeout=_TIMEOUT, stream=True)
    except requests.RequestException as e:
        raise McpClientError(f"Errore di rete verso il server MCP: {e}")
    if resp.status_code >= 400:
        raise McpClientError(f"HTTP {resp.status_code}: {(_read_capped(resp) or '')[:300]}")
    data = _parse_response(resp)
    if isinstance(data, dict) and data.get("error"):
        err = data["error"] or {}
        raise McpClientError(f"Errore JSON-RPC {err.get('code')}: {err.get('message')}")
    return data, resp


def _open_session(url, auth_token=None) -> dict:
    """Esegue initialize + notifications/initialized; ritorna gli header (con
    l'eventuale Mcp-Session-Id) da riusare per la chiamata successiva."""
    headers = _base_headers(auth_token)
    params = {
        "protocolVersion": _PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "SentinelNet", "version": "preview"},
    }
    _, resp = _rpc(url, headers, "initialize", params, 1)
    session_id = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    # Notifica di completamento handshake (best-effort: alcuni server la esigono).
    try:
        requests.post(url, json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                      headers=headers, timeout=_TIMEOUT)
    except requests.RequestException:
        pass
    return headers


def list_tools(url, auth_token=None) -> list:
    headers = _open_session(url, auth_token)
    data, _ = _rpc(url, headers, "tools/list", {}, 2)
    return (data.get("result") or {}).get("tools", [])


def call_tool(url, name, arguments=None, auth_token=None) -> dict:
    headers = _open_session(url, auth_token)
    data, _ = _rpc(url, headers, "tools/call", {"name": name, "arguments": arguments or {}}, 3)
    return data.get("result") or {}
