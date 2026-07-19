# -*- coding: utf-8 -*-
"""Router MCP Client (PREVIEW).

SentinelNet come CLIENT MCP verso server esterni (Jira/ServiceNow/... via
Streamable HTTP). Gated: le operazioni live richiedono il flag
`mcp_preview_enabled`. Solo admin (rispecchia la RBAC della tab MCP Server).

Storage (app_settings.json):
  - `mcp_preview_enabled`: bool (default False)
  - `mcp_client_servers`: [{name, url, auth_enc}]  -> auth_enc cifrato con
    crypto_vault (mai in chiaro su disco, mai restituito al frontend).
"""

from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from security import crypto_vault
from ai import mcp_client
from core.app_settings import get_app_settings, save_app_settings
from routers.deps import require_admin
from security.security_manager import log_audit

router = APIRouter(tags=["MCP-Client"])


class PreviewSchema(BaseModel):
    enabled: bool


class ServerSchema(BaseModel):
    name: str
    url: str
    auth_token: Optional[str] = None


class CallSchema(BaseModel):
    tool: str
    arguments: Dict[str, Any] = {}


def _preview_enabled() -> bool:
    return bool(get_app_settings().get("mcp_preview_enabled", False))


def _servers() -> list:
    raw = get_app_settings().get("mcp_client_servers") or []
    return [s for s in raw if isinstance(s, dict) and s.get("name")]


def _find(name: str) -> Optional[dict]:
    return next((s for s in _servers() if s.get("name") == name), None)


def _require_preview():
    if not _preview_enabled():
        raise HTTPException(status_code=403,
                            detail="MCP Client (preview) non abilitato.")


def _public_server(s: dict) -> dict:
    return {"name": s.get("name"), "url": s.get("url"), "has_auth": bool(s.get("auth_enc"))}


# --- SETTINGS / GATING -------------------------------------------------------

@router.get("/api/mcp-client/settings")
def get_settings(current_user=Depends(require_admin)):
    """Stato del flag preview + elenco server (token mascherato)."""
    return {
        "preview_enabled": _preview_enabled(),
        "servers": [_public_server(s) for s in _servers()],
    }


@router.post("/api/mcp-client/preview")
def set_preview(payload: PreviewSchema, current_user=Depends(require_admin)):
    save_app_settings({"mcp_preview_enabled": bool(payload.enabled)})
    log_audit(f"MCP Client (preview) {'abilitato' if payload.enabled else 'disabilitato'} "
              f"da '{current_user.get('sub')}'.")
    return {"status": "success", "preview_enabled": bool(payload.enabled)}


# --- SERVER CRUD -------------------------------------------------------------

@router.get("/api/mcp-client/servers")
def list_servers(current_user=Depends(require_admin)):
    return {"servers": [_public_server(s) for s in _servers()]}


@router.post("/api/mcp-client/servers")
def upsert_server(payload: ServerSchema, current_user=Depends(require_admin)):
    name = (payload.name or "").strip()
    url = (payload.url or "").strip()
    if not name or not url:
        raise HTTPException(status_code=400, detail="Nome e URL sono obbligatori.")
    if not url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="L'URL deve iniziare con http:// o https://.")
    servers = _servers()
    existing = _find(name)
    # Token: se fornito lo (ri)cifra; se assente in update mantiene il precedente.
    if payload.auth_token:
        auth_enc = crypto_vault.encrypt_password(payload.auth_token)
    else:
        auth_enc = existing.get("auth_enc") if existing else ""
    entry = {"name": name, "url": url, "auth_enc": auth_enc}
    servers = [s for s in servers if s.get("name") != name] + [entry]
    save_app_settings({"mcp_client_servers": servers})
    log_audit(f"Server MCP client '{name}' salvato da '{current_user.get('sub')}'.")
    return {"status": "success", "server": _public_server(entry)}


@router.delete("/api/mcp-client/servers/{name}")
def delete_server(name: str, current_user=Depends(require_admin)):
    servers = _servers()
    if not any(s.get("name") == name for s in servers):
        raise HTTPException(status_code=404, detail="Server non trovato.")
    save_app_settings({"mcp_client_servers": [s for s in servers if s.get("name") != name]})
    log_audit(f"Server MCP client '{name}' eliminato da '{current_user.get('sub')}'.")
    return {"status": "success"}


# --- LIVE (gated dal flag preview) ------------------------------------------

def _auth_of(server: dict) -> Optional[str]:
    enc = server.get("auth_enc")
    return crypto_vault.decrypt_password(enc) if enc else None


@router.get("/api/mcp-client/{name}/tools")
def get_tools(name: str, current_user=Depends(require_admin)):
    _require_preview()
    server = _find(name)
    if not server:
        raise HTTPException(status_code=404, detail="Server non trovato.")
    try:
        tools = mcp_client.list_tools(server["url"], _auth_of(server))
    except mcp_client.McpClientError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return {"tools": tools}


@router.post("/api/mcp-client/{name}/call")
def call(name: str, payload: CallSchema, current_user=Depends(require_admin)):
    _require_preview()
    server = _find(name)
    if not server:
        raise HTTPException(status_code=404, detail="Server non trovato.")
    if not payload.tool:
        raise HTTPException(status_code=400, detail="Nome del tool obbligatorio.")
    try:
        result = mcp_client.call_tool(server["url"], payload.tool,
                                      payload.arguments, _auth_of(server))
    except mcp_client.McpClientError as e:
        raise HTTPException(status_code=502, detail=str(e))
    log_audit(f"Tool MCP client '{payload.tool}' invocato su '{name}' "
              f"da '{current_user.get('sub')}'.")
    return {"result": result}
