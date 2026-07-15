# -*- coding: utf-8 -*-
"""Router MCP. Estratto da app_server.py (fase 6.6)."""

import json
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from security_manager import log_audit

from routers.settings import get_app_settings, save_app_settings
from routers.deps import get_current_user, require_admin
import mcp_server

_MCP_DEFAULT_DISABLED = {"get_top_talkers", "get_anomalies"}

router = APIRouter(tags=["MCP"])

class McpSettingsSchema(BaseModel):
    disabled_tools: List[str] = []

def _mcp_disabled_tools() -> list:
    mcp = get_app_settings().get("mcp")
    if mcp is None:
        # Nessuna configurazione salvata: vale il default (tool flussi spenti).
        return sorted(t for t in _MCP_DEFAULT_DISABLED if t in mcp_server.TOOLS)
    return [t for t in (mcp.get("disabled_tools") or []) if t in mcp_server.TOOLS]

@router.get("/api/mcp/settings")
def get_mcp_settings(current_user = Depends(require_admin)):
    """Catalogo dei tool MCP con descrizione + elenco dei tool disabilitati."""
    return {
        "tools": [{"name": name, "description": desc}
                  for name, (desc, _schema, _fn) in mcp_server.TOOLS.items()],
        "disabled_tools": _mcp_disabled_tools(),
    }

@router.post("/api/mcp/settings")
def set_mcp_settings(payload: McpSettingsSchema, current_user = Depends(require_admin)):
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

