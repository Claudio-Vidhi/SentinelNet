# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router MCP. Estratto da app_server.py (fase 6.6)."""

import json
import os
import sys
from urllib.parse import urlencode
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from routers.deps import require_tab
from pydantic import BaseModel, Field
from security import mcp_grants, user_manager
from security.security_manager import create_access_token, log_audit

from core.app_settings import get_app_settings, save_app_settings
from routers.deps import get_current_user, require_unscoped_admin
from ai import mcp_server

_MCP_DEFAULT_DISABLED = {"get_top_talkers", "get_anomalies", "linux_health"}

router = APIRouter(tags=["MCP"])

class McpSettingsSchema(BaseModel):
    disabled_tools: List[str] = []

def _mcp_disabled_tools() -> list:
    mcp = get_app_settings().get("mcp")
    if mcp is None:
        # Nessuna configurazione salvata: vale il default (tool flussi spenti).
        return sorted(t for t in _MCP_DEFAULT_DISABLED if t in mcp_server.TOOLS)
    return [t for t in (mcp.get("disabled_tools") or []) if t in mcp_server.TOOLS]

def _mcp_client_launch() -> dict:
    """How this very install starts the bridge, for the ready-to-paste client
    snippet. Exact when the LLM client runs on this machine; elsewhere the
    admin adapts the paths. A bare "python" is never right: the client does
    not inherit the venv, and on Windows it hits the Store alias."""
    if getattr(sys, "frozen", False):
        return {"command": sys.executable, "args": ["--mcp"]}
    return {"command": sys.executable, "args": [os.path.abspath(mcp_server.__file__)]}

@router.get("/api/mcp/settings", dependencies=[Depends(require_tab("tab-mcp"))])
def get_mcp_settings(current_user = Depends(require_unscoped_admin)):
    """Catalogo dei tool MCP con descrizione + elenco dei tool disabilitati."""
    return {
        "tools": [{"name": name, "description": desc}
                  for name, (desc, _schema, _fn) in mcp_server.TOOLS.items()],
        "disabled_tools": _mcp_disabled_tools(),
        "client_launch": _mcp_client_launch(),
    }

@router.post("/api/mcp/settings", dependencies=[Depends(require_tab("tab-mcp"))])
def set_mcp_settings(payload: McpSettingsSchema, current_user = Depends(require_unscoped_admin)):
    unknown = [t for t in payload.disabled_tools if t not in mcp_server.TOOLS]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Tool sconosciuti: {', '.join(unknown)}")
    save_app_settings({"mcp": {"disabled_tools": payload.disabled_tools}})
    log_audit(f"Tool MCP disabilitati impostati a {payload.disabled_tools or '[]'} "
              f"da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.get("/api/mcp/tool-config")
def get_mcp_tool_config(current_user = Depends(get_current_user)):
    """Letto dal processo mcp_server.py (con l'account con cui si autentica)
    per sapere quali tool NON esporre al client LLM."""
    return {"disabled_tools": _mcp_disabled_tools()}


# --- Browser sign-in for the bridge (security/mcp_grants.py) ----------------

class McpAuthorizeSchema(BaseModel):
    # The redirect always goes to 127.0.0.1: only the port is the caller's,
    # and only unprivileged ones, so a code never reaches a system service.
    port: int = Field(ge=1024, le=65535)
    state: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    challenge: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    # What the client says it is and where it runs: shown on the consent page
    # and the grant list, never trusted for anything else.
    client: str = Field(default="", max_length=60, pattern=r"^[^\x00-\x1f]*$")
    host: str = Field(default="", max_length=64, pattern=r"^[^\x00-\x1f]*$")
    read_only: bool = True

class McpTokenSchema(BaseModel):
    code: str = Field(max_length=128)
    verifier: str = Field(min_length=43, max_length=128)

class McpSessionSchema(BaseModel):
    token: str = Field(max_length=128)

class McpRevokeSchema(BaseModel):
    id: str = Field(max_length=32)

# What the consent page lists. Each capability is the set of tools behind it
# and the lowest role that can use them; a tool the admin switched off in the
# MCP tab does not count, so the page never promises what the bridge refuses.
_ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2, "super_admin": 3}
_CONFIG_TOOLS = {"fortigate_full_config", "drift_summary", "drift_versions", "drift_diff"}
_ACTION_TOOLS = {"send_cli_command", "arp_scan"}

def _consent_permissions(role: str) -> list:
    enabled = set(mcp_server.TOOLS) - set(_mcp_disabled_tools())
    rank = _ROLE_RANK.get(role, 0)
    rows = []
    for key, tools, min_rank in (("read", enabled - _CONFIG_TOOLS - _ACTION_TOOLS, 0),
                                 ("config", _CONFIG_TOOLS & enabled, 1),
                                 ("actions", _ACTION_TOOLS & enabled, 1)):
        rows.append({"key": key,
                     "full": bool(tools) and rank >= min_rank,
                     "read_only": bool(tools) and min_rank == 0})
    return rows

@router.get("/api/mcp/authorize/info")
def mcp_authorize_info(current_user = Depends(get_current_user)):
    """What the consent page shows: who is approving and what the client
    could do with full rights and with read-only ones."""
    role = current_user.get("role", "viewer")
    return {"username": current_user.get("sub"), "role": role,
            "can_choose": _ROLE_RANK.get(role, 0) > 0,
            "permissions": _consent_permissions(role)}

@router.post("/api/mcp/authorize")
def authorize_mcp_client(payload: McpAuthorizeSchema, current_user = Depends(get_current_user)):
    """The signed-in operator approves a bridge waiting on its loopback port."""
    user = current_user.get("sub")
    read_only = payload.read_only or _ROLE_RANK.get(current_user.get("role"), 0) == 0
    label = " · ".join(x for x in (payload.client or "Client MCP", payload.host) if x)
    code = mcp_grants.create_code(user, payload.challenge, label, read_only)
    log_audit(f"Client MCP '{label}' autorizzato da '{user}' "
              f"({'sola lettura' if read_only else 'permessi del ruolo'}).")
    query = urlencode({"code": code, "state": payload.state})
    return {"redirect": f"http://127.0.0.1:{payload.port}/callback?{query}"}

@router.post("/api/mcp/token")
def redeem_mcp_code(payload: McpTokenSchema):
    """Public: the one-time code plus the PKCE verifier are the proof."""
    grant = mcp_grants.redeem_code(payload.code, payload.verifier)
    if not grant:
        raise HTTPException(status_code=400, detail="Codice di autorizzazione non valido o scaduto.")
    log_audit(f"Accesso MCP emesso per '{grant['user']}'.")
    return {"token": grant["token"], "username": grant["user"]}

@router.post("/api/mcp/session")
def open_mcp_session(payload: McpSessionSchema):
    """Public: trades a grant for the same short-lived JWT a login gives."""
    grant = mcp_grants.user_for_grant(payload.token)
    if not grant:
        raise HTTPException(status_code=401, detail="Accesso MCP revocato o non valido.")
    user = grant["user"]
    claims = {"sub": user, "role": user_manager.get_role(user),
              "sep": user_manager.session_epoch(user)}
    if grant["read_only"]:
        claims["ro"] = True    # get_current_user turns it into a viewer session
    token = create_access_token(data=claims)
    return {"access_token": token, "token_type": "bearer"}

@router.get("/api/mcp/my-grants")
def list_my_mcp_grants(current_user = Depends(get_current_user)):
    """Every user manages their own clients from the profile, admin or not."""
    return {"grants": mcp_grants.list_grants(current_user.get("sub"))}

@router.post("/api/mcp/my-grants/revoke")
def revoke_my_mcp_grant(payload: McpRevokeSchema, current_user = Depends(get_current_user)):
    user = current_user.get("sub")
    if mcp_grants.revoke(payload.id, user) is None:
        raise HTTPException(status_code=404, detail="Accesso MCP non trovato.")
    log_audit(f"Accesso MCP revocato dal proprio utente '{user}'.")
    return {"status": "success"}

@router.get("/api/mcp/grants", dependencies=[Depends(require_tab("tab-mcp"))])
def list_mcp_grants(current_user = Depends(require_unscoped_admin)):
    return {"grants": mcp_grants.list_grants()}

@router.post("/api/mcp/grants/revoke", dependencies=[Depends(require_tab("tab-mcp"))])
def revoke_mcp_grant(payload: McpRevokeSchema, current_user = Depends(require_unscoped_admin)):
    user = mcp_grants.revoke(payload.id)
    if user is None:
        raise HTTPException(status_code=404, detail="Accesso MCP non trovato.")
    log_audit(f"Accesso MCP di '{user}' revocato da '{current_user.get('sub')}'.")
    return {"status": "success"}
