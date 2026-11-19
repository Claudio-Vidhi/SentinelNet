# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Enter and leave demo mode (docs/demo.md).

Both directions are a marker in the REAL data directory plus a restart:
core.data_config decides at import which directory the process runs on, so
switching inside a running process would leave every path already bound
pointing at the old one.
"""
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials

from core import data_config
from routers.deps import get_current_user, require_super_admin, security_scheme
from security import user_manager
from security.security_manager import log_audit
from services import self_update

router = APIRouter(tags=["Demo"])

_NO_SUPERVISOR = ("No supervisor would restart the application, so it cannot switch "
                  "in or out of demo mode by itself. From source run "
                  "`uv run python scripts/dev/run_demo.py`; an installation must run "
                  "as a service (systemd or the Windows service).")


def _restart(rollback) -> None:
    try:
        self_update.restart()
    except self_update.SelfUpdateError as e:
        rollback()
        raise HTTPException(status_code=409, detail=str(e))


@router.post("/api/demo/start")
def demo_start(request: Request,
               credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme)):
    """super_admin, or anyone while the user store is empty: the same
    condition that opens the first-admin registration (routers/auth.py)."""
    if data_config.DEMO_MODE:
        raise HTTPException(status_code=409, detail="Demo mode is already active.")
    who = "first-run screen (no users yet)"
    if user_manager.has_any_user():
        user = get_current_user(request, credentials)
        if user.get("role") != "super_admin":
            raise HTTPException(status_code=403, detail="Insufficient privileges for this operation.")
        who = f"'{user.get('sub')}'"
    if not self_update.supervisor():
        raise HTTPException(status_code=409, detail=_NO_SUPERVISOR)

    from services import demo_seed
    username, password = demo_seed.credentials()
    with open(data_config.DEMO_MARKER, "w", encoding="utf-8") as fh:
        fh.write("requested from the app\n")
    log_audit(f"Modalita' demo avviata da {who}: riavvio sui dati sintetici in "
              f"{data_config.DEMO_DIR}.")
    _restart(lambda: os.remove(data_config.DEMO_MARKER))
    return {"status": "restarting", "username": username, "password": password}


@router.post("/api/demo/stop")
def demo_stop(current_user=Depends(require_super_admin)):
    if not data_config.DEMO_MODE:
        raise HTTPException(status_code=409, detail="Demo mode is not active.")
    if not self_update.supervisor():
        raise HTTPException(status_code=409, detail=_NO_SUPERVISOR)
    # Written to the demo audit log: the real one is not touched in demo mode.
    log_audit(f"Modalita' demo chiusa da '{current_user.get('sub')}': riavvio sui dati reali.")
    os.remove(data_config.DEMO_MARKER)

    def rollback():
        with open(data_config.DEMO_MARKER, "w", encoding="utf-8") as fh:
            fh.write("requested from the app\n")
    _restart(rollback)
    return {"status": "restarting"}
