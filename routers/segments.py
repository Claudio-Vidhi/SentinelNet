# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router network segments (plan 2026-11-03 network-segments)."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from routers.deps import assert_group_allowed, get_current_user, require_operator, require_tab
from security.security_manager import log_audit
from services import segment_manager

router = APIRouter(tags=["Segments"])
_MAP_TABS = ("tab-map", "tab-map-interactive")


class SegmentSaveSchema(BaseModel):
    org: str
    id: Optional[str] = None
    name: str
    color: str
    subnets: List[str] = []
    members: List[str] = []
    excluded: List[str] = []


class SegmentDeleteSchema(BaseModel):
    org: str
    id: str


class SegmentLinkSchema(BaseModel):
    org: str
    a: str
    b: str
    decision: Optional[str] = None


@router.get("/api/segments", dependencies=[Depends(require_tab(*_MAP_TABS))])
def list_segments_ep(org: str = Query(...), current_user=Depends(get_current_user)):
    assert_group_allowed(current_user, org)
    return segment_manager.list_segments(org)


@router.post("/api/segments", dependencies=[Depends(require_tab(*_MAP_TABS))])
def save_segment_ep(payload: SegmentSaveSchema, current_user=Depends(require_operator)):
    assert_group_allowed(current_user, payload.org)
    try:
        seg = segment_manager.save_segment(payload.org, payload.id, payload.name, payload.color,
                                           payload.subnets, payload.members, payload.excluded)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    log_audit(f"Segmento '{seg['name']}' ({payload.org}) salvato dall'utente '{current_user.get('sub')}'.")
    return {"status": "success", "segment": seg}


@router.post("/api/segments/delete", dependencies=[Depends(require_tab(*_MAP_TABS))])
def delete_segment_ep(payload: SegmentDeleteSchema, current_user=Depends(require_operator)):
    assert_group_allowed(current_user, payload.org)
    try:
        segment_manager.delete_segment(payload.org, payload.id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    log_audit(f"Segmento '{payload.id}' ({payload.org}) eliminato dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}


@router.post("/api/segments/link", dependencies=[Depends(require_tab(*_MAP_TABS))])
def link_decision_ep(payload: SegmentLinkSchema, current_user=Depends(require_operator)):
    assert_group_allowed(current_user, payload.org)
    try:
        segment_manager.set_link_decision(payload.org, payload.a, payload.b, payload.decision)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    log_audit(f"Collegamento {payload.a} - {payload.b} ({payload.org}): decisione "
              f"'{payload.decision or 'da verificare'}' dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}
