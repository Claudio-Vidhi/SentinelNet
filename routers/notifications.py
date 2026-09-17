# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router API per la gestione delle notifiche (preferenze, regole admin, storico invii).

Design: docs/superpowers/specs/2026-09-16-email-notifications-design.md.
"""

import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from routers.deps import (
    assert_groups_within_scope,
    get_current_user,
    require_admin,
    require_tab,
)
from security import user_manager
from security.security_manager import log_audit
from services import mailer, notifications

router = APIRouter(
    tags=["Notifications"],
    dependencies=[Depends(require_tab("tab-notifications"))],
)

VALID_DIGEST_MINUTES = {15, 60, 240, 1440}
TIME_REGEX = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class UserPrefsSchema(BaseModel):
    enabled: bool = True
    kinds: list[str] = Field(default_factory=lambda: list(notifications.KINDS))
    min_severity: str = "low"
    groups: list[str] = Field(default_factory=list)
    mode: str = "immediate"
    digest_every_min: int = 60
    quiet_start: Optional[str] = None
    quiet_end: Optional[str] = None
    quiet_bypass_critical: bool = True

    @field_validator("kinds")
    @classmethod
    def validate_kinds(cls, v):
        for k in v:
            if k not in notifications.KINDS:
                raise ValueError(f"Tipo evento non valido: {k}")
        return v

    @field_validator("min_severity")
    @classmethod
    def validate_min_severity(cls, v):
        if v not in notifications.SEVERITIES:
            raise ValueError(f"Severità non valida: {v}")
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v):
        if v not in ("immediate", "digest"):
            raise ValueError("Modalità deve essere 'immediate' o 'digest'")
        return v

    @field_validator("digest_every_min")
    @classmethod
    def validate_digest(cls, v):
        if v not in VALID_DIGEST_MINUTES:
            raise ValueError(f"Intervallo digest non valido. Valori ammessi: {VALID_DIGEST_MINUTES}")
        return v

    @field_validator("quiet_start", "quiet_end")
    @classmethod
    def validate_time(cls, v):
        if v is not None and v != "":
            if not TIME_REGEX.match(v):
                raise ValueError("Formato orario non valido: atteso HH:MM")
            return v
        return None


class RuleSchema(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    enabled: bool = True
    recipients: list[str] = Field(..., min_length=1, max_length=20)
    kinds: list[str] = Field(default_factory=lambda: list(notifications.KINDS))
    min_severity: str = "low"
    groups: list[str] = Field(default_factory=list)
    mode: str = "immediate"
    digest_every_min: int = 60
    quiet_start: Optional[str] = None
    quiet_end: Optional[str] = None
    quiet_bypass_critical: bool = True

    @field_validator("recipients")
    @classmethod
    def validate_recipients(cls, v):
        if not v or len(v) > 20:
            raise ValueError("Da 1 a 20 destinatari per regola")
        for r in v:
            if not r or "@" not in r:
                raise ValueError(f"Indirizzo email non valido: '{r}'")
        return v

    @field_validator("kinds")
    @classmethod
    def validate_kinds(cls, v):
        for k in v:
            if k not in notifications.KINDS:
                raise ValueError(f"Tipo evento non valido: {k}")
        return v

    @field_validator("min_severity")
    @classmethod
    def validate_min_severity(cls, v):
        if v not in notifications.SEVERITIES:
            raise ValueError(f"Severità non valida: {v}")
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v):
        if v not in ("immediate", "digest"):
            raise ValueError("Modalità deve essere 'immediate' o 'digest'")
        return v

    @field_validator("digest_every_min")
    @classmethod
    def validate_digest(cls, v):
        if v not in VALID_DIGEST_MINUTES:
            raise ValueError(f"Intervallo digest non valido. Valori ammessi: {VALID_DIGEST_MINUTES}")
        return v

    @field_validator("quiet_start", "quiet_end")
    @classmethod
    def validate_time(cls, v):
        if v is not None and v != "":
            if not TIME_REGEX.match(v):
                raise ValueError("Formato orario non valido: atteso HH:MM")
            return v
        return None


# --- ENDPOINT PREFERENZE PERSONALI ---

@router.get("/api/notifications/prefs")
def get_preferences(current_user: dict = Depends(get_current_user)):
    """Restituisce le preferenze di notifica personali e l'email associata."""
    uname = current_user["sub"]
    prefs = notifications.get_user_prefs(uname)
    email = user_manager.get_email(uname)
    return {
        "prefs": prefs,
        "email": email,
        "has_email": bool(email and "@" in email),
    }


@router.put("/api/notifications/prefs")
def update_preferences(data: UserPrefsSchema, current_user: dict = Depends(get_current_user)):
    """Salva le preferenze di notifica dell'utente (gruppi validati contro scope)."""
    assert_groups_within_scope(current_user, data.groups)
    uname = current_user["sub"]
    notifications.save_user_prefs(uname, data.model_dump())
    return {"ok": True}


@router.post("/api/notifications/prefs/test")
def send_test_to_self(current_user: dict = Depends(get_current_user)):
    """Invia un'email di prova all'indirizzo registrato per l'utente loggato."""
    uname = current_user["sub"]
    email = user_manager.get_email(uname)
    if not email or "@" not in email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nessun indirizzo email configurato nel profilo utente.",
        )
    try:
        mailer.send_email(
            email,
            "[SentinelNet] Test notifiche personali",
            f"Ciao {uname},\n\nQuesto è un messaggio di prova inviato da SentinelNet "
            f"per verificare le tue preferenze di notifica.",
        )
    except mailer.MailerError as e:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(e))
    return {"ok": True}


# --- ENDPOINT REGOLE ADMIN ---

@router.get("/api/notifications/rules")
def get_rules(current_user: dict = Depends(require_admin)):
    """Elenco regole di notifica configurate."""
    return notifications.list_rules()


@router.post("/api/notifications/rules")
def create_rule(data: RuleSchema, current_user: dict = Depends(require_admin)):
    """Crea una nuova regola di notifica."""
    rule_id = notifications.create_rule(data.model_dump(), created_by=current_user["sub"])
    log_audit(f"Creata regola notifica #{rule_id} ({data.name}) da {current_user['sub']}")
    return {"id": rule_id, "ok": True}


@router.put("/api/notifications/rules/{rule_id}")
def update_rule(rule_id: int, data: RuleSchema, current_user: dict = Depends(require_admin)):
    """Aggiorna una regola di notifica esistente."""
    existing = notifications.get_rule(rule_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Regola non trovata.")
    ok = notifications.update_rule(rule_id, data.model_dump())
    log_audit(f"Aggiornata regola notifica #{rule_id} ({data.name}) da {current_user['sub']}")
    return {"ok": ok}


@router.delete("/api/notifications/rules/{rule_id}")
def delete_rule(rule_id: int, current_user: dict = Depends(require_admin)):
    """Elimina una regola di notifica."""
    existing = notifications.get_rule(rule_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Regola non trovata.")
    ok = notifications.delete_rule(rule_id)
    log_audit(f"Eliminata regola notifica #{rule_id} ({existing['name']}) da {current_user['sub']}")
    return {"ok": ok}


@router.post("/api/notifications/rules/{rule_id}/test")
def test_rule(rule_id: int, current_user: dict = Depends(require_admin)):
    """Invia un'email di prova a tutti i destinatari della regola."""
    rule = notifications.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Regola non trovata.")
    recipients = rule.get("recipients") or []
    if not recipients:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nessun destinatario specificato.")

    errors = []
    for rec in recipients:
        try:
            mailer.send_email(
                rec,
                f"[SentinelNet] Test regola: {rule['name']}",
                f"Messaggio di test per la regola di notifica '{rule['name']}'.\n"
                f"Filtri: severità minima {rule['min_severity']}, modalità {rule['mode']}.",
            )
        except mailer.MailerError as e:
            errors.append(f"{rec}: {e}")

    if errors:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Errori durante l'invio: {'; '.join(errors)}",
        )
    return {"ok": True, "sent": len(recipients)}


# --- ENDPOINT STORICO INVIO ---

@router.get("/api/notifications/log")
def get_log(
    limit: int = Query(100, ge=1, le=500),
    status_filter: Optional[str] = Query(None, alias="status"),
    current_user: dict = Depends(get_current_user),
):
    """Storico invii: gli admin vedono tutto, gli altri utenti solo le righe user:<sé>."""
    is_admin = user_manager.is_admin(current_user.get("role"))
    target_filter = None if is_admin else f"user:{current_user['sub']}"
    return notifications.list_log(limit=limit, target_filter=target_filter, status_filter=status_filter)
