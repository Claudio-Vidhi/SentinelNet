# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router Network Blueprint (spec 2026-10-11 network-blueprint)."""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers.deps import assert_group_allowed, get_current_user, require_admin, require_tab
from security.security_manager import log_audit
from services import blueprint, blueprint_assistant, inventory_manager

router = APIRouter(tags=["Blueprint"])
_TAB = [Depends(require_tab("tab-blueprint"))]
# Sources a client may name; «preset» and «restore» are set by the server.
_CLIENT_SOURCES = ("manual", "checks")


class DraftAddSchema(BaseModel):
    ops: List[dict] = []
    source: str = "manual"
    preset: Optional[str] = None
    n: int = 1
    restore: Optional[int] = None


class DraftReplaceSchema(BaseModel):
    ops: List[dict]


class ApplySchema(BaseModel):
    note: str = ""


class AssistantDescribeSchema(BaseModel):
    text: str


class AssistantDeriveSchema(BaseModel):
    use_ai: bool = False


class InstructionsSchema(BaseModel):
    text: str


def _org(org: str, user) -> None:
    assert_group_allowed(user, org)
    if org not in inventory_manager.get_all_groups():
        raise HTTPException(status_code=404, detail={"message": f"Organizzazione '{org}' inesistente."})


def _call(fn, *args):
    try:
        return fn(*args)
    except blueprint.Conflict as e:
        raise HTTPException(status_code=409, detail={"message": str(e)})
    except LookupError as e:
        raise HTTPException(status_code=404, detail={"message": str(e)})
    except ValueError as e:
        raise HTTPException(status_code=422, detail={"message": str(e), "index": getattr(e, "index", None)})


@router.get("/api/blueprint/{org}", dependencies=_TAB)
def state_ep(org: str, current_user=Depends(get_current_user)):
    _org(org, current_user)
    return blueprint.state(org)


@router.get("/api/blueprint/{org}/checks", dependencies=_TAB)
def checks_ep(org: str, current_user=Depends(get_current_user)):
    _org(org, current_user)
    return blueprint.checks(org)


@router.post("/api/blueprint/{org}/observe", dependencies=_TAB)
def observe_ep(org: str, current_user=Depends(require_admin)):
    _org(org, current_user)
    out = blueprint.observe(org)
    log_audit(f"Blueprint '{org}': dati raccolti da {len(out['gateways'])} gateway "
              f"dall'utente '{current_user.get('sub')}'.")
    return out


@router.post("/api/blueprint/{org}/draft", dependencies=_TAB)
def draft_add_ep(org: str, payload: DraftAddSchema, current_user=Depends(require_admin)):
    _org(org, current_user)
    who = current_user.get("sub")
    if payload.restore is not None:
        out = _call(blueprint.restore, org, payload.restore, who)
        log_audit(f"Blueprint '{org}': bozza di ripristino alla revisione {payload.restore} "
                  f"aperta dall'utente '{who}'.")
        return out
    if payload.preset is not None:
        return _call(blueprint.preset, org, payload.preset, payload.n, who)
    if payload.source not in _CLIENT_SOURCES:
        raise HTTPException(status_code=422, detail={"message": f"Origine non valida: {payload.source}", "index": None})
    return _call(blueprint.add_ops, org, payload.ops, payload.source, who)


@router.put("/api/blueprint/{org}/draft", dependencies=_TAB)
def draft_replace_ep(org: str, payload: DraftReplaceSchema, current_user=Depends(require_admin)):
    _org(org, current_user)
    return _call(blueprint.replace_ops, org, payload.ops, current_user.get("sub"))


@router.post("/api/blueprint/{org}/draft/apply", dependencies=_TAB)
def draft_apply_ep(org: str, payload: ApplySchema, current_user=Depends(require_admin)):
    _org(org, current_user)
    who = current_user.get("sub")
    out = _call(blueprint.apply, org, who, payload.note)
    log_audit(f"Blueprint '{org}': bozza applicata (revisione {out['rev']}) dall'utente '{who}'.")
    return out


@router.post("/api/blueprint/{org}/draft/discard", dependencies=_TAB)
def draft_discard_ep(org: str, current_user=Depends(require_admin)):
    _org(org, current_user)
    blueprint.discard(org)
    log_audit(f"Blueprint '{org}': bozza scartata dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}


@router.post("/api/blueprint/{org}/draft/align", dependencies=_TAB)
def draft_align_ep(org: str, current_user=Depends(require_admin)):
    _org(org, current_user)
    return _call(blueprint.align, org, current_user.get("sub"))


@router.get("/api/blueprint/{org}/revisions", dependencies=_TAB)
def revisions_ep(org: str, current_user=Depends(get_current_user)):
    _org(org, current_user)
    return {"revisions": blueprint.revisions(org)}


@router.get("/api/blueprint/{org}/revisions/{rev}", dependencies=_TAB)
def revision_ep(org: str, rev: int, current_user=Depends(get_current_user)):
    _org(org, current_user)
    return _call(blueprint.revision, org, rev)


@router.get("/api/blueprint/{org}/diff", dependencies=_TAB)
def diff_ep(org: str, a: int, b: int, current_user=Depends(get_current_user)):
    _org(org, current_user)
    return _call(blueprint.diff, org, a, b)


# --- Assistant (spec 2026-10-11 blueprint-assistant) ------------------------
# Every route below only appends to the draft; applying stays a human action.

@router.post("/api/blueprint/{org}/assistant/describe", dependencies=_TAB)
def assistant_describe_ep(org: str, payload: AssistantDescribeSchema, current_user=Depends(require_admin)):
    _org(org, current_user)
    who = current_user.get("sub")
    out = _call(blueprint_assistant.describe, org, payload.text, who)
    log_audit(f"Blueprint '{org}': {out['added']} modifiche proposte dall'assistente (descrizione) "
              f"per l'utente '{who}'.")
    return out


@router.post("/api/blueprint/{org}/assistant/derive", dependencies=_TAB)
def assistant_derive_ep(org: str, payload: AssistantDeriveSchema, current_user=Depends(require_admin)):
    _org(org, current_user)
    who = current_user.get("sub")
    out = _call(blueprint_assistant.derive, org, who, payload.use_ai)
    log_audit(f"Blueprint '{org}': {out['added']} modifiche ricavate dalle configurazioni "
              f"per l'utente '{who}'.")
    return out


@router.put("/api/blueprint/{org}/instructions", dependencies=_TAB)
def instructions_ep(org: str, payload: InstructionsSchema, current_user=Depends(require_admin)):
    _org(org, current_user)
    text = _call(blueprint_assistant.set_instructions, org, payload.text)
    log_audit(f"Blueprint '{org}': istruzioni dell'assistente aggiornate dall'utente '{current_user.get('sub')}'.")
    return {"instructions": text}
