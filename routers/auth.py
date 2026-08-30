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
    clear_account_lockouts,
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
    # Indirizzo di recupero, opzionale: senza, il reset via email non e'
    # disponibile per l'account e resta il break-glass da CLI.
    email: str = ""

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
    store_err = user_manager.store_integrity_error()
    if store_err:
        # Fail closed: a corrupt user store must never be read as "no users
        # yet", or this unauthenticated endpoint would mint a fresh admin.
        log_audit(f"Registrazione rifiutata: archivio utenti corrotto ({store_err}).")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Archivio utenti corrotto: registrazione non consentita. Ripristinare users.json."
        )
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
    store_err = user_manager.store_integrity_error()
    if store_err:
        log_audit(f"Login sospeso: archivio utenti corrotto ({store_err}).")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Archivio utenti non disponibile: accesso sospeso. Ripristinare users.json."
        )

    # WP6: lockout keyed source+account. Username-only let an unauthenticated
    # caller lock out any named account; the key survives restarts (persisted).
    client_ip = request.client.host if request.client else "unknown"
    limit_key = f"login:{client_ip}:{payload.username}"

    if is_locked_out(limit_key):
        log_audit(f"Tentativo di login bloccato per lockout (username: '{payload.username}', ip: '{client_ip}').")
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
        reset_failed_attempts(limit_key)
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

    record_failed_attempt(limit_key)
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
    email = payload.email.strip()
    if email and "@" not in email:
        raise HTTPException(status_code=400, detail="Indirizzo email non valido.")
    if not user_manager.create_user(payload.username.strip(), payload.password,
                                    payload.role, groups, must_change_password=True,
                                    email=email):
        raise HTTPException(status_code=400, detail="Utente già esistente.")
    log_audit(
        f"Utente '{payload.username}' (ruolo: {payload.role}, sedi: "
        f"{groups or 'tutte'}) creato da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

@router.post("/api/users/delete")
def delete_user_ep(payload: UserDeleteSchema, current_user = Depends(get_current_user)):
    # Chiunque può cancellare il PROPRIO account; per quello di un altro serve
    # il ruolo di amministratore. Niente docstring: FastAPI la pubblicherebbe
    # come description nello schema OpenAPI, che il parity test tiene congelato.
    #
    # Il quorum resta l'unico altro limite, e qui smette di essere teorico:
    # cancellare un altro amministratore presuppone di esserlo a propria volta,
    # quindi ce ne sono sempre almeno due. È la cancellazione del proprio
    # account che può davvero togliere l'ultimo amministratore utilizzabile.
    if payload.username != current_user.get("sub") and current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient privileges for this operation."
        )
    if user_manager.is_last_active_admin(payload.username):
        raise HTTPException(status_code=400, detail="Deve restare almeno un amministratore attivo.")
    if not user_manager.delete_user(payload.username):
        raise HTTPException(status_code=404, detail="Utente non trovato.")
    log_audit(f"Utente '{payload.username}' eliminato da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/users/role")
def set_user_role_ep(payload: UserRoleSchema, current_user = Depends(require_admin)):
    if payload.role not in user_manager.VALID_ROLES:
        raise HTTPException(status_code=400, detail="Ruolo non valido.")
    if payload.role != "admin" and user_manager.is_last_active_admin(payload.username):
        raise HTTPException(status_code=400, detail="Deve restare almeno un amministratore attivo.")
    if not user_manager.set_role(payload.username, payload.role):
        raise HTTPException(status_code=404, detail="Utente non trovato.")
    log_audit(f"Ruolo di '{payload.username}' impostato a '{payload.role}' da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/users/disable")
def disable_user_ep(payload: UserDisableSchema, current_user = Depends(require_admin)):
    """Abilita/disabilita un utente. Un utente disabilitato non può autenticarsi."""
    if payload.disabled and payload.username == current_user.get("sub"):
        raise HTTPException(status_code=400, detail="Non puoi disabilitare il tuo stesso account.")
    if payload.disabled and user_manager.is_last_active_admin(payload.username):
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


# --- RECUPERO PASSWORD VIA EMAIL ---

class ForgotPasswordSchema(BaseModel):
    username: str

class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str

class UserEmailSchema(BaseModel):
    username: str
    email: str = ""

# Risposta identica in ogni esito: esistenza dell'account, presenza di un
# indirizzo e stato del server di posta non devono essere deducibili da chi
# non è ancora autenticato.
_FORGOT_GENERIC = ("Se l'account esiste ed ha un indirizzo email configurato, "
                   "riceverà le istruzioni per reimpostare la password.")


@router.post("/api/auth/forgot-password")
def forgot_password(payload: ForgotPasswordSchema, request: Request):
    """Invia il link di reimpostazione all'indirizzo REGISTRATO dell'utente.

    Non esiste un indirizzo di ripiego: senza email sull'account il recupero
    via posta non è disponibile e resta il break-glass da CLI. Spedire a un
    mittente condiviso consegnerebbe il token a chiunque legga quella casella.
    """
    from core.app_settings import BaseUrlError, resolve_base_url
    from security import password_reset
    from services import mailer

    # Limite di frequenza sull'IP sorgente: l'endpoint non è autenticato ed è
    # sia un oracolo di generazione token sia un amplificatore di posta.
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"forgot-password:{client_ip}"
    if is_locked_out(rate_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Troppe richieste di recupero. Riprova più tardi.")
    record_failed_attempt(rate_key)

    username = payload.username.strip()
    email = user_manager.get_email(username)
    if (not email
            or user_manager.get_role(username) is None
            or user_manager.is_disabled(username)):
        log_audit(f"Richiesta di recupero password non evasa per '{username}' "
                  f"(account assente, disabilitato o senza email).")
        return {"status": "success", "message": _FORGOT_GENERIC}

    try:
        base_url = resolve_base_url()
    except BaseUrlError as e:
        # Configurazione incompleta: è un errore dell'installazione, non una
        # informazione sull'account, quindi si registra e si risponde generico.
        log_audit(f"Recupero password non inviato per '{username}': {e}")
        return {"status": "success", "message": _FORGOT_GENERIC}

    token = password_reset.issue(username)
    try:
        mailer.send_email(
            email,
            "SentinelNet - Reimpostazione password",
            "È stata richiesta la reimpostazione della password del tuo "
            f"account SentinelNet '{username}'.\n\n"
            "Apri questo link per scegliere una nuova password "
            f"(valido {password_reset.TTL_SECONDS // 60} minuti):\n"
            f"{base_url}/?reset_token={token}\n\n"
            "Se non hai richiesto tu la reimpostazione, ignora questo "
            "messaggio: la password attuale resta valida.\n",
        )
        log_audit(f"Link di reimpostazione password inviato per l'utente '{username}'.")
    except mailer.MailerError as e:
        log_audit(f"Invio del link di reimpostazione fallito per '{username}': {e}")
    return {"status": "success", "message": _FORGOT_GENERIC}


@router.post("/api/auth/reset-password")
def reset_password(payload: ResetPasswordSchema):
    """Consuma un token di reimpostazione e imposta la nuova password."""
    from security import password_reset

    pw_err = user_manager.password_error(payload.new_password)
    if pw_err:
        raise HTTPException(status_code=400, detail=pw_err)

    username = password_reset.consume(payload.token)
    if not username:
        raise HTTPException(status_code=400,
                            detail="Link di reimpostazione non valido o scaduto.")
    if user_manager.get_role(username) is None or user_manager.is_disabled(username):
        raise HTTPException(status_code=403, detail="Account non disponibile.")

    if not user_manager.reset_password_break_glass(username, payload.new_password):
        raise HTTPException(status_code=400, detail="Aggiornamento della password fallito.")
    # Il token è bruciato: chi rientra sblocca anche il lockout accumulato.
    clear_account_lockouts(username)
    log_audit(f"Password reimpostata via email per l'utente '{username}'.")
    return {"status": "success"}


@router.post("/api/users/email")
def set_user_email(payload: UserEmailSchema, current_user = Depends(require_admin)):
    """Imposta o rimuove ("" rimuove) l'indirizzo di recupero di un utente."""
    email = payload.email.strip()
    if email and "@" not in email:
        raise HTTPException(status_code=400, detail="Indirizzo email non valido.")
    if not user_manager.set_email(payload.username, email):
        raise HTTPException(status_code=404, detail="Utente non trovato.")
    log_audit(f"Indirizzo email dell'utente '{payload.username}' "
              f"{'impostato' if email else 'rimosso'} da '{current_user.get('sub')}'.")
    return {"status": "success"}


# --- INVITI UTENTE VIA EMAIL ---

class InviteUserSchema(BaseModel):
    email: str
    role: str = "viewer"

class AcceptInviteSchema(BaseModel):
    token: str
    password: str


@router.post("/api/users/invite")
def invite_user(payload: InviteUserSchema, current_user = Depends(require_admin)):
    """Invia un invito: l'account viene creato solo quando l'invitato lo accetta.

    Nessun utente a metà nel frattempo: un invito mai accettato scade e non
    lascia niente dietro di sé.
    """
    from core.app_settings import BaseUrlError, resolve_base_url
    from security import user_invite
    from services import mailer

    email = payload.email.strip()
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Indirizzo email non valido.")
    if payload.role not in user_manager.VALID_ROLES:
        raise HTTPException(status_code=400, detail="Ruolo non valido.")
    # Lo username dell'account sarà l'indirizzo invitato: se esiste già, è
    # l'amministratore a doverlo sapere subito, non l'invitato al momento
    # dell'accettazione.
    if user_manager.get_role(email) is not None:
        raise HTTPException(status_code=400, detail="Esiste già un account con questo indirizzo.")

    try:
        base_url = resolve_base_url()
    except BaseUrlError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    token = user_invite.issue(email, payload.role)
    try:
        mailer.send_email(
            email,
            "SentinelNet - Invito di accesso",
            f"Sei stato invitato ad accedere a SentinelNet con ruolo "
            f"'{payload.role}'.\n\n"
            "Apri questo link per scegliere la tua password e completare la "
            f"registrazione (valido {user_invite.TTL_SECONDS // 3600} ore):\n"
            f"{base_url}/?invite_token={token}\n\n"
            "Se non ti aspettavi questo invito, ignora il messaggio.\n",
        )
    except mailer.MailerError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    log_audit(f"Invito inviato a '{email}' (ruolo: {payload.role}) "
              f"da '{current_user.get('sub')}'.")
    return {"status": "success"}


@router.post("/api/auth/accept-invite")
def accept_invite(payload: AcceptInviteSchema):
    """Crea l'account dall'invito. Username e ruolo vengono dall'invito, non
    dalla richiesta: l'invitato sceglie soltanto la propria password."""
    from security import user_invite

    pw_err = user_manager.password_error(payload.password)
    if pw_err:
        raise HTTPException(status_code=400, detail=pw_err)

    invited = user_invite.consume(payload.token)
    if not invited:
        raise HTTPException(status_code=400, detail="Invito non valido o scaduto.")
    email, role = invited

    # La password è scelta dall'invitato: non c'è nessun cambio da imporre.
    if not user_manager.create_user(email, payload.password, role,
                                    must_change_password=False, email=email):
        raise HTTPException(status_code=400, detail="Esiste già un account con questo indirizzo.")

    log_audit(f"Account '{email}' (ruolo: {role}) creato dall'accettazione di un invito.")
    return {"status": "success", "username": email}


# --- SINGLE SIGN-ON (OIDC) ---

def _sso_redirect_uri() -> str:
    from core.app_settings import resolve_base_url
    return resolve_base_url() + "/api/auth/sso/callback"


@router.get("/api/auth/sso/config")
def sso_public_config():
    """Ciò che la schermata di login può sapere prima di autenticarsi: se il
    pulsante va mostrato e come si chiama. Nient'altro esce da qui."""
    from security import sso
    cfg = sso.get_config()
    if not cfg["enabled"] or not cfg["client_id"] or not cfg["issuer_url"]:
        return {"enabled": False}
    return {"enabled": True, "provider_name": cfg["provider_name"]}


@router.get("/api/auth/sso/login")
def sso_login():
    """Avvia il flusso authorization code + PKCE verso l'IdP."""
    from core.app_settings import BaseUrlError
    from fastapi.responses import RedirectResponse
    from security import sso

    cfg = sso.get_config()
    if not cfg["enabled"]:
        raise HTTPException(status_code=400, detail="Single Sign-On non abilitato.")
    try:
        auth_url = sso.start_login(cfg, _sso_redirect_uri())
    except (sso.SSOError, BaseUrlError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return RedirectResponse(auth_url, status_code=302)


@router.get("/api/auth/sso/callback")
def sso_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    """Ritorno dall'IdP: verifica, risoluzione dell'utente, sessione locale."""
    from core.app_settings import BaseUrlError
    from fastapi.responses import RedirectResponse
    from security import crypto_vault, sso

    if error:
        raise HTTPException(status_code=401, detail=f"Accesso rifiutato dall'IdP: {error}")
    if not code or not state:
        raise HTTPException(status_code=400, detail="Parametri 'code' o 'state' mancanti.")

    cfg = sso.get_config()
    if not cfg["enabled"]:
        raise HTTPException(status_code=400, detail="Single Sign-On non abilitato.")

    # Lo state è a uso singolo: se non è uno che abbiamo emesso noi, la
    # richiesta non nasce da un login iniziato qui.
    pending = sso.consume_state(state)
    if not pending:
        raise HTTPException(status_code=400, detail="Sessione di login scaduta o non valida.")
    nonce, verifier = pending

    client_secret = crypto_vault.decrypt_password(cfg["client_secret_enc"])
    try:
        redirect_uri = _sso_redirect_uri()
        tokens = sso.exchange_code(cfg, code, verifier, redirect_uri, client_secret)
        claims = sso.verify_id_token(cfg, tokens["id_token"], nonce)
        username = sso.resolve_username(claims)
    except (sso.SSOError, BaseUrlError) as e:
        log_audit(f"Login SSO fallito: {e}")
        raise HTTPException(status_code=401, detail=str(e)) from e

    mapped_role = sso.resolve_role(cfg, claims)
    existing_role = user_manager.get_role(username)

    if existing_role is None:
        if not cfg["auto_provision"]:
            log_audit(f"Login SSO rifiutato per '{username}': nessun account locale "
                      f"e provisioning automatico disattivato.")
            raise HTTPException(
                status_code=403,
                detail="Nessun account SentinelNet per questa identità. "
                       "Contatta un amministratore.")
        # Password locale casuale e mai comunicata: l'accesso passa solo
        # dall'IdP, ma l'account resta recuperabile col break-glass.
        import secrets as _secrets
        user_manager.create_user(username, _secrets.token_urlsafe(32), mapped_role,
                                 must_change_password=False,
                                 email=(claims.get("email") or "").strip())
        role = mapped_role
        log_audit(f"Account '{username}' (ruolo: {role}) creato automaticamente da login SSO.")
    else:
        if user_manager.is_disabled(username):
            log_audit(f"Login SSO rifiutato per l'account disabilitato '{username}'.")
            raise HTTPException(status_code=403, detail="Account disabilitato.")
        role = mapped_role if cfg["sync_roles"] else existing_role
        if cfg["sync_roles"] and mapped_role != existing_role:
            user_manager.set_role(username, mapped_role)
            log_audit(f"Ruolo di '{username}' allineato a '{mapped_role}' dai gruppi dell'IdP.")

    access_token = create_access_token(data={"sub": username, "role": role})
    clear_account_lockouts(username)
    log_audit(f"Utente '{username}' (ruolo: {role}) autenticato via SSO.")
    response = RedirectResponse("/", status_code=302)
    _set_session_cookie(request, response, access_token)
    return response
