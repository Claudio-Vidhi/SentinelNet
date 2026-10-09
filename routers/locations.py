# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router Locations (spec 2026-10-09 organizations-locations)."""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from core import app_settings
from routers.deps import get_current_user, require_admin, require_tab, user_group_scope, assert_group_allowed
from security.security_manager import log_audit
from services import location_manager

router = APIRouter(tags=["Locations"])


class LocationCreateSchema(BaseModel):
    org: str
    name: str
    role: str = "branch"
    subnets: List[str] = []
    probe: str = "central"


class LocationUpdateSchema(BaseModel):
    id: str
    name: Optional[str] = None
    role: Optional[str] = None
    subnets: Optional[List[str]] = None
    probe: Optional[str] = None
    apply_probe_to_devices: bool = False


class LocationDeleteSchema(BaseModel):
    id: str


@router.get("/api/locations", dependencies=[Depends(require_tab("tab-groups", "tab-devices", "tab-import", "tab-provisioning", "tab-provisioner"))])
def list_locations_ep(org: Optional[str] = Query(None), current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    if org is not None and scope is not None and org not in scope:
        raise HTTPException(status_code=403, detail=f"Group '{org}' is not allowed for your profile.")

    locs = location_manager.list_locations(org=org)
    if scope is not None:
        locs = [loc for loc in locs if loc.get("org") in scope]

    for loc in locs:
        loc["devices"] = location_manager.devices_in(loc["id"])
    return {"locations": locs}


@router.post("/api/locations", dependencies=[Depends(require_tab("tab-groups"))])
def create_location_ep(payload: LocationCreateSchema, current_user = Depends(require_admin)):
    who = current_user.get("sub")
    assert_group_allowed(current_user, payload.org)
    try:
        loc = location_manager.create_location(
            payload.org, payload.name, role=payload.role,
            subnets=payload.subnets, probe=payload.probe,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    log_audit(f"Sede '{loc['id']}' (organizzazione: '{payload.org}', ruolo: '{payload.role}') creata dall'utente '{who}'.")
    return {"status": "success", "location": loc}


@router.post("/api/locations/update", dependencies=[Depends(require_tab("tab-groups"))])
def update_location_ep(payload: LocationUpdateSchema, current_user = Depends(require_admin)):
    who = current_user.get("sub")
    loc = location_manager.get_location(payload.id)
    if not loc:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    assert_group_allowed(current_user, loc["org"])
    try:
        updated = location_manager.update_location(
            payload.id, name=payload.name, role=payload.role,
            subnets=payload.subnets, probe=payload.probe,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    extra = ""
    if payload.apply_probe_to_devices:
        count = location_manager.apply_probe_to_devices(payload.id)
        extra = f" Sonda applicata a {count} apparati."
    log_audit(f"Sede '{payload.id}' aggiornata dall'utente '{who}'.{extra}")
    return {"status": "success", "location": updated}


@router.post("/api/locations/delete", dependencies=[Depends(require_tab("tab-groups"))])
def delete_location_ep(payload: LocationDeleteSchema, current_user = Depends(require_admin)):
    who = current_user.get("sub")
    loc = location_manager.get_location(payload.id)
    if not loc:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    assert_group_allowed(current_user, loc["org"])
    try:
        location_manager.delete_location(payload.id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    log_audit(f"Sede '{payload.id}' (organizzazione: '{loc['org']}') eliminata dall'utente '{who}'.")
    return {"status": "success"}


@router.post("/api/locations/dismiss-review", dependencies=[Depends(require_tab("tab-groups"))])
def dismiss_review_ep(current_user = Depends(require_admin)):
    who = current_user.get("sub")
    app_settings.save_app_settings({"locations_review_pending": False})
    log_audit(f"Revisione sedi confermata dall'utente '{who}'.")
    return {"status": "success"}
