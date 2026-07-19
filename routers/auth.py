# -*- coding: utf-8 -*-
"""Router Auth: autenticazione JWT/cookie e gestione utenti. Estratto da
app_server.py (fase 6.6): percorsi, metodi, parametri e risposte identici al
monolite."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel

from services import inventory_manager
from security import user_manager
from security.security_manager import (
    create_access_token, log_audit,
    is_locked_out, record_failed_attempt, reset_failed_attempts,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from routers.deps import SESSION_COOKIE, get_current_user, require_admin

router = APIRouter(tags=["Auth"])

class UserSchema(BaseModel):
    username: str
    password: str

LoginRequest = UserSchema

class ChangePasswordSchema(BaseModel):
    old_password: str
    new_password: str

class UserCreateSchema(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    groups: List[str] = []

class UserDeleteSchema(BaseModel):
    username: str

class UserRoleSchema(BaseModel):
    username: str
    role: str

class UserGroupsSchema(BaseModel):
    username: str
    groups: List[str]

class UserDisableSchema(BaseModel):
    username: str
    disabled: bool

class UserTabsSchema(BaseModel):
    username: str
    allowed_tabs: List[str] = []

# --- ROTTE DI AUTENTICAZIONE (JWT) ---

@router.get("/api/auth/status")
def setup_status():
    return {"has_users": user_manager.has_any_user()}

@router.post("/api/auth/register")
def setup_admin(payload: UserSchema):
    if user_manager.has_any_user():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Setup già completato. Registrazione non consentita."
        )
    pw_err = user_manager.password_error(payload.password)
    if pw_err:
        raise HTTPException(status_code=400, detail=pw_err)
    if not payload.username.strip():
        raise HTTPException(status_code=400, detail="Lo username è obbligatorio.")
    success = user_manager.create_user(payload.username, payload.password, role="admin")
    if success:
        log_audit(f"Nuovo utente amministratore '{payload.username}' registrato con successo via Setup Wizard.")
        return {"status": "success", "message": "Primo account amministratore creato correttamente."}
    raise HTTPException(status_code=400, detail="Impossibile creare l'account.")

def _set_session_cookie(request: Request, response: Response, token: str):
    """Imposta il cookie di sessione HttpOnly (L-1). ``Secure`` è attivo quando
    la richiesta è arrivata su HTTPS (TLS nativo o reverse proxy con
    X-Forwarded-Proto)."""
    secure = (request.url.scheme == "https"
              or request.headers.get("x-forwarded-proto", "").lower() == "https")
    response.set_cookie(
        SESSION_COOKIE, token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True, secure=secure, samesite="strict", path="/",
    )


@router.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    if is_locked_out(payload.username):
        log_audit(f"Tentativo di login bloccato per lockout (username: '{payload.username}').")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Troppi tentativi di accesso falliti. Riprova più tardi."
        )

    if user_manager.verify_user(payload.username, payload.password):
        if user_manager.is_disabled(payload.username):
            log_audit(f"Login rifiutato per account disabilitato '{payload.username}'.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account disabilitato. Contatta un amministratore."
            )
        reset_failed_attempts(payload.username)
        role = user_manager.get_role(payload.username) or "viewer"
        access_token = create_access_token(data={"sub": payload.username, "role": role})
        log_audit(f"Utente '{payload.username}' (ruolo: {role}) loggato con successo.")
        # Cookie HttpOnly per il browser (L-1); il token resta nel body per i
        # client programmatici (MCP/script) che usano Authorization: Bearer.
        _set_session_cookie(request, response, access_token)
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "role": role,
            "must_change_password": user_manager.must_change_password(payload.username),
        }

    record_failed_attempt(payload.username)
    log_audit(f"Tentativo di login fallito per l'utente '{payload.username}' (credenziali errate).")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenziali amministratore non valide o utente non registrato."
    )

@router.post("/api/auth/change-password")
def change_password(payload: ChangePasswordSchema,
                    current_user = Depends(get_current_user)):
    username = current_user.get("sub")
    pw_err = user_manager.password_error(payload.new_password)
    if pw_err:
        raise HTTPException(status_code=400, detail=pw_err)
    success = user_manager.change_password(
        username, payload.old_password, payload.new_password
    )
    if not success:
        raise HTTPException(status_code=400, detail="Password attuale non corretta.")
    log_audit(f"Password cambiata per l'utente '{username}'.")
    return {"status": "success"}

@router.post("/api/auth/logout")
def logout_ep(response: Response, current_user = Depends(get_current_user)):
    """Chiude la sessione browser cancellando il cookie HttpOnly. Il JWT è
    stateless: la scadenza resta quella del token (max 60 min)."""
    response.delete_cookie(SESSION_COOKIE, path="/")
    log_audit(f"Logout utente '{current_user.get('sub')}'.")
    return {"status": "success"}


@router.get("/api/auth/me")
def whoami(current_user = Depends(get_current_user)):
    username = current_user.get("sub")
    role = current_user.get("role", "viewer")
    # Gli admin non sono mai ristretti: niente tab da nascondere lato frontend.
    allowed_tabs = [] if role == "admin" else user_manager.get_allowed_tabs(username)
    return {"username": username, "role": role, "allowed_tabs": allowed_tabs}

# --- GESTIONE UTENTI (solo amministratori) ---

@router.get("/api/users")
def list_users_ep(current_user = Depends(require_admin)):
    return user_manager.list_users()

@router.post("/api/users")
def create_user_ep(payload: UserCreateSchema, current_user = Depends(require_admin)):
    if payload.role not in user_manager.VALID_ROLES:
        raise HTTPException(status_code=400, detail="Ruolo non valido.")
    if not payload.username.strip() or not payload.password:
        raise HTTPException(status_code=400, detail="Username e password obbligatori.")
    pw_err = user_manager.password_error(payload.password)
    if pw_err:
        raise HTTPException(status_code=400, detail=pw_err)
    valid_groups = set(inventory_manager.get_all_groups().keys())
    groups = [g for g in payload.groups if g in valid_groups]
    # Gli account creati da un amministratore devono cambiare la password al
    # primo accesso: la password iniziale è nota all'amministratore.
    if not user_manager.create_user(payload.username.strip(), payload.password,
                                    payload.role, groups, must_change_password=True):
        raise HTTPException(status_code=400, detail="Utente già esistente.")
    log_audit(
        f"Utente '{payload.username}' (ruolo: {payload.role}, sedi: "
        f"{groups or 'tutte'}) creato da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

@router.post("/api/users/delete")
def delete_user_ep(payload: UserDeleteSchema, current_user = Depends(require_admin)):
    if payload.username == current_user.get("sub"):
        raise HTTPException(status_code=400, detail="Non puoi eliminare il tuo stesso account.")
    if user_manager.get_role(payload.username) == "admin" and user_manager.count_admins() <= 1:
        raise HTTPException(status_code=400, detail="Deve restare almeno un amministratore.")
    if not user_manager.delete_user(payload.username):
        raise HTTPException(status_code=404, detail="Utente non trovato.")
    log_audit(f"Utente '{payload.username}' eliminato da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/users/role")
def set_user_role_ep(payload: UserRoleSchema, current_user = Depends(require_admin)):
    if payload.role not in user_manager.VALID_ROLES:
        raise HTTPException(status_code=400, detail="Ruolo non valido.")
    if (user_manager.get_role(payload.username) == "admin"
            and payload.role != "admin" and user_manager.count_admins() <= 1):
        raise HTTPException(status_code=400, detail="Deve restare almeno un amministratore.")
    if not user_manager.set_role(payload.username, payload.role):
        raise HTTPException(status_code=404, detail="Utente non trovato.")
    log_audit(f"Ruolo di '{payload.username}' impostato a '{payload.role}' da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/users/disable")
def disable_user_ep(payload: UserDisableSchema, current_user = Depends(require_admin)):
    """Abilita/disabilita un utente. Un utente disabilitato non può autenticarsi."""
    if payload.disabled and payload.username == current_user.get("sub"):
        raise HTTPException(status_code=400, detail="Non puoi disabilitare il tuo stesso account.")
    if (payload.disabled and user_manager.get_role(payload.username) == "admin"
            and user_manager.count_active_admins() <= 1):
        raise HTTPException(status_code=400, detail="Deve restare almeno un amministratore attivo.")
    if not user_manager.set_disabled(payload.username, payload.disabled):
        raise HTTPException(status_code=404, detail="Utente non trovato.")
    log_audit(
        f"Utente '{payload.username}' {'disabilitato' if payload.disabled else 'riabilitato'} "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

@router.post("/api/users/groups")
def set_user_groups_ep(payload: UserGroupsSchema, current_user = Depends(require_admin)):
    """Assegna le sedi/gruppi visibili e gestibili da un utente (vuoto = tutte)."""
    valid_groups = set(inventory_manager.get_all_groups().keys())
    groups = [g for g in payload.groups if g in valid_groups]
    if not user_manager.set_groups(payload.username, groups):
        raise HTTPException(status_code=404, detail="Utente non trovato.")
    log_audit(
        f"Sedi di '{payload.username}' impostate a {groups or 'tutte'} "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

@router.post("/api/users/tabs")
def set_user_tabs_ep(payload: UserTabsSchema, current_user = Depends(require_admin)):
    """Assegna le tab della dashboard visibili a un utente (vuoto = tutte).
    # ponytail: enforcement solo lato frontend (nasconde i pulsanti tab). Le API
    # sensibili sono già protette da ruolo/gruppo indipendentemente da questo campo."""
    if not user_manager.set_allowed_tabs(payload.username, payload.allowed_tabs):
        raise HTTPException(status_code=404, detail="Utente non trovato.")
    log_audit(
        f"Tab visibili di '{payload.username}' impostate a {payload.allowed_tabs or 'tutte'} "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success"}
