# -*- coding: utf-8 -*-
"""MCP client to EXTERNAL servers via Streamable HTTP (JSON-RPC 2.0).

PREVIEW: supports only the "streamable" HTTP transport (POST JSON-RPC with
application/json or text/event-stream response). The stdio transport is NOT
supported in this preview (documented limitation).

No extra pip dependencies: uses `requests` (already in the bundle). The MCP
session is per-request: runs `initialize` (capturing the `Mcp-Session-Id`
header), then the actual call (`tools/list` / `tools/call`).
"""

import json
from typing import Optional
import requests

_TIMEOUT = 30
# MCP protocol version requested in initialize.
_PROTOCOL_VERSION = "2025-06-18"
# Response size limit from untrusted external MCP servers: avoids
# loading arbitrarily large bodies into memory.
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024


def _read_capped(resp: "requests.Response", max_bytes: int = _MAX_RESPONSE_BYTES) -> str:
    """Reads the body of `resp` (request with stream=True) up to `max_bytes`.

    Raises McpClientError if the body exceeds the limit, without loading
    beyond the cap into memory.
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
    """MCP client-side error (network, HTTP, JSON-RPC, or malformed SSE)."""


def parse_sse_last_data(text: str) -> str:
    """Extracts the last `data:` event from a text/event-stream response.

    A streamable MCP server may respond in SSE: multiple events separated by
    blank lines, each with one or more `data:` lines. The useful JSON-RPC
    response is the last event with data. Lines starting with `:` are SSE
    comments and are ignored. Returns the (JSON) string of the last event, or "".
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
            continue  # SSE comment (keep-alive)
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


def _base_headers(auth_token: Optional[str] = None) -> dict:
    h = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if auth_token:
        h["Authorization"] = f"Bearer {auth_token}"
    return h


def _rpc(url, headers, method, params, req_id):
    """POST JSON-RPC; returns (data, response). Raises McpClientError on error."""
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


def _open_session(url: str, auth_token: Optional[str] = None) -> dict:
    """Runs initialize + notifications/initialized; returns headers (with
    any Mcp-Session-Id) to reuse for the subsequent call."""
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
    # Handshake completion notification (best-effort: some servers require it).
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
