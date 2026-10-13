# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router Network Blueprint (spec 2026-10-11 network-blueprint)."""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from routers.deps import assert_group_allowed, get_current_user, require_admin, require_tab
from security import user_manager
from security.security_manager import log_audit
from services import blueprint, blueprint_assistant, blueprint_model, inventory_manager

router = APIRouter(tags=["Blueprint"])
_TAB = [Depends(require_tab("tab-blueprint"))]
# Sources a client may name; «preset» and «restore» are set by the server.
_CLIENT_SOURCES = ("manual", "checks")


class DraftAddSchema(BaseModel):
    ops: List[dict] = Field(default=[], max_length=blueprint_model.MAX_DRAFT_OPS)
    source: str = "manual"
    preset: Optional[str] = None
    n: int = 1
    restore: Optional[int] = None


class DraftReplaceSchema(BaseModel):
    ops: List[dict] = Field(max_length=blueprint_model.MAX_DRAFT_OPS)


class ApplySchema(BaseModel):
    note: str = ""


class AssistantDescribeSchema(BaseModel):
    text: str = Field(max_length=blueprint_assistant.MAX_TEXT)


class AssistantDeriveSchema(BaseModel):
    use_ai: bool = False


class InstructionsSchema(BaseModel):
    text: str = Field(max_length=blueprint_assistant.MAX_TEXT)


class AssistantDraftSchema(BaseModel):
    ops: List[dict] = Field(min_length=1, max_length=200)
    note: str = Field(default="", max_length=500)


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


def _drafter(current_user=Depends(get_current_user)):
    """An admin session, or a read-only MCP session lent «bpd» (spec
    2026-10-11 blueprint-assistant). The role is read from disk, not from the
    token: a user demoted after the session opened loses the right at once."""
    if not user_manager.is_admin(user_manager.get_role(current_user.get("sub"))) or \
            (current_user.get("ro") and not current_user.get("bpd")):
        raise HTTPException(status_code=403, detail="Serve un amministratore, o un client MCP autorizzato "
                                                    "a proporre bozze del Blueprint.")
    return current_user


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


@router.post("/api/blueprint/{org}/assistant-draft", dependencies=_TAB)
def assistant_draft_ep(org: str, payload: AssistantDraftSchema, current_user=Depends(_drafter)):
    """Append-only door for MCP clients: no preset, restore, apply, discard,
    align. The source is always «assistant»."""
    _org(org, current_user)
    who = current_user.get("sub")
    st = blueprint.state(org)
    before = len(st["draft"]["ops"]) if st["draft"] else 0
    try:
        out = blueprint.add_ops(org, payload.ops, "assistant", who)
    except blueprint_model.OpError as e:
        # add_ops numbers the whole draft; the caller knows only the ops it posted.
        k = e.index - before
        if k < 0:
            raise HTTPException(status_code=422, detail={"message": str(e), "index": e.index})
        raise HTTPException(status_code=422, detail={"message": f"Modifica {k + 1}: {e.reason}", "index": k})
    except blueprint.Conflict as e:
        raise HTTPException(status_code=409, detail={"message": str(e)})
    except LookupError as e:
        raise HTTPException(status_code=404, detail={"message": str(e)})
    except ValueError as e:
        raise HTTPException(status_code=422, detail={"message": str(e), "index": None})
    note = " ".join(payload.note.split())
    log_audit(f"Blueprint '{org}': {len(payload.ops)} modifiche proposte via MCP dall'utente '{who}'"
              + (f" — nota: {note}" if note else "") + ".")
    return out
