# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import json
import os
import threading
from datetime import datetime, timezone

import bcrypt
from core import data_config

USERS_JSON = data_config.get_path("users.json")

# Serializes every access to users.json. Readers hold it for the file read,
# mutators hold it across the whole read-modify-write, so a write can never
# be observed half-written and two concurrent mutations cannot lose updates.
_users_lock = threading.RLock()


class UsersStoreError(RuntimeError):
    """users.json exists but cannot be parsed or read.

    A corrupt store is treated as OCCUPIED, never empty: first-start
    registration stays closed and authentication fails loudly. Reading it as
    an empty dict would let an unauthenticated caller recreate the
    administrator account over the corrupted file.
    """

# Ruoli supportati, dal più al meno privilegiato:
#   super_admin → everything, including managing other admin-level accounts
#   admin    → controllo totale, incluso la gestione utenti
#   operator → tutte le operazioni di rete (triage, comandi, CRUD apparati) ma non utenti
#   viewer   → sola lettura (inventario, mappe, threat intel)
VALID_ROLES = ("super_admin", "admin", "operator", "viewer")
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2, "super_admin": 3}
ADMIN_ROLES = ("super_admin", "admin")
# Accounts predating roles are single-user installs: their owner.
LEGACY_ROLE = "super_admin"


def is_admin(role) -> bool:
    return role in ADMIN_ROLES


def can_manage(actor_role: str, target_role: str) -> bool:
    """FortiGate model: only a super_admin touches its peers; everyone else
    manages strictly lower ranks."""
    if actor_role == "super_admin":
        return True
    return ROLE_RANK.get(target_role, 0) < ROLE_RANK.get(actor_role, 0)


def can_assign(actor_role: str, new_role: str) -> bool:
    if new_role not in ROLE_RANK:
        return False
    return actor_role == "super_admin" or ROLE_RANK[new_role] < ROLE_RANK.get(actor_role, 0)

# Policy password minima applicata LATO SERVER (unica fonte di verità: il
# controllo lato browser è solo un aiuto UX, aggirabile con una chiamata diretta).
MIN_PASSWORD_LENGTH = 8

def password_error(password: str):
    """Ritorna un messaggio d'errore se la password non rispetta la policy,
    altrimenti None. Usato da tutti gli endpoint che impostano una password."""
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f"La password deve contenere almeno {MIN_PASSWORD_LENGTH} caratteri."
    return None

def get_users():
    with _users_lock:
        if not os.path.exists(USERS_JSON):
            return {}
        try:
            with open(USERS_JSON, "r", encoding="utf-8") as f:
                raw = f.read()
        except OSError as e:
            raise UsersStoreError(f"Il file utenti non e' leggibile: {e}") from e
    if not raw.strip():
        raise UsersStoreError("Il file utenti e' vuoto: archivio account da ripristinare.")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise UsersStoreError(f"Il file utenti e' corrotto: {e}") from e
    if not isinstance(data, dict):
        raise UsersStoreError("Il file utenti ha un formato inatteso.")
    return data

def _save_users(users: dict):
    """Atomic write: the store is only ever replaced whole.

    Truncating in place is how the corrupt store this module now refuses to
    read gets created (crash or full disk mid-write). data_config.atomic_write
    is the one temp-then-rename implementation every sibling JSON store shares;
    restrict=True is not optional here, the file holds every password hash.
    """
    with _users_lock:
        data_config.atomic_write(USERS_JSON, users, indent=4, restrict=True)

def has_any_user() -> bool:
    try:
        return len(get_users()) > 0
    except UsersStoreError:
        # Fail closed: a corrupt store counts as occupied, so the setup
        # endpoint cannot mint a fresh administrator over it.
        return True

def store_integrity_error():
    """Messaggio se l'archivio utenti e' corrotto o illeggibile, altrimenti
    None. Usato dagli endpoint di autenticazione per rifiutare con una
    spiegazione invece di restituire errori generici."""
    try:
        get_users()
        return None
    except UsersStoreError as e:
        return str(e)

def get_role(username: str):
    """Ruolo dell'utente, o None se non esiste. Gli account legacy senza campo
    'role' (installazioni mono-utente preesistenti) sono trattati come super_admin."""
    user = get_users().get(username)
    if not user:
        return None
    return user.get("role", LEGACY_ROLE)

def create_user(username: str, password: str, role: str = "viewer", groups=None,
                must_change_password: bool = False, email: str = "",
                pending_approval: bool = False) -> bool:
    if role not in VALID_ROLES:
        role = "viewer"
    with _users_lock:
        users = get_users()
        if username in users:
            return False

        # Hashing sicuro con bcrypt (salt automatico, cost factor 12)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        users[username] = {
            "hashed_password": hashed_password.decode('utf-8'),
            "role": role,
            # Elenco delle sedi/gruppi visibili e gestibili. Lista vuota = tutte.
            "groups": list(groups) if groups else [],
            # Indirizzo per il recupero password. Vuoto = recupero via email non
            # disponibile per questo account (resta il break-glass da CLI).
            "email": (email or "").strip(),
            # Tab dashboard visibili all'utente. Lista vuota = tutte (come per "groups").
            "allowed_tabs": [],
            "disabled": False,
            # True per gli account creati da un amministratore: al primo login
            # l'utente è obbligato a impostare una nuova password personale.
            "must_change_password": bool(must_change_password),
            # Accounts born from an invitation: they cannot sign in until an
            # administrator approves them, so an invite mailed to the wrong
            # address does not open the dashboard on its own.
            "pending_approval": bool(pending_approval),
        }
        _save_users(users)
    return True

def verify_user(username: str, password: str) -> bool:
    users = get_users()
    if username not in users:
        return False
    # Confronto sicuro a tempo costante nativo di bcrypt
    return bcrypt.checkpw(password.encode('utf-8'), users[username]["hashed_password"].encode('utf-8'))

def change_password(username: str, old_password: str, new_password: str) -> bool:
    """Permette di cambiare la password verificando quella attuale."""
    if not verify_user(username, old_password):
        return False
    with _users_lock:
        users = get_users()
        if username not in users:
            return False
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        users[username]["hashed_password"] = hashed.decode('utf-8')
        # La password è ora personale: rimuoviamo l'obbligo di cambio al primo accesso.
        users[username]["must_change_password"] = False
        _save_users(users)
    return True

def must_change_password(username: str) -> bool:
    """True se l'utente deve cambiare la password al primo accesso (account
    creato da un amministratore e non ancora personalizzato)."""
    user = get_users().get(username)
    return bool(user and user.get("must_change_password", False))

# --- GESTIONE UTENTI (CRUD, ruoli) ---

def list_users() -> list:
    """Elenco utenti (senza hash) con ruolo, sedi assegnate e stato."""
    return [
        {
            "username": u,
            "role": d.get("role", LEGACY_ROLE),
            "email": d.get("email", ""),
            "groups": d.get("groups", []),
            "allowed_tabs": d.get("allowed_tabs", []),
            "disabled": d.get("disabled", False),
            "must_change_password": d.get("must_change_password", False),
            "pending_approval": d.get("pending_approval", False),
            "last_login": d.get("last_login", ""),
        }
        for u, d in get_users().items()
    ]

def is_disabled(username: str) -> bool:
    user = get_users().get(username)
    return bool(user and user.get("disabled", False))

def is_pending(username: str) -> bool:
    user = get_users().get(username)
    return bool(user and user.get("pending_approval", False))

def _update(username: str, **fields) -> bool:
    with _users_lock:
        users = get_users()
        if username not in users:
            return False
        users[username].update(fields)
        _save_users(users)
    return True

def approve(username: str) -> bool:
    return _update(username, pending_approval=False)

def mark_awaiting_password(username: str) -> bool:
    """Account created with no usable password: its first one comes from a
    setup link, chosen by the user, so it is not forced to change again."""
    return _update(username, awaiting_password=True)

def awaiting_password(username: str) -> bool:
    return bool((get_users().get(username) or {}).get("awaiting_password", False))

def password_chosen_by_user(username: str) -> bool:
    """Closes the setup: the password in place is personal."""
    return _update(username, awaiting_password=False, must_change_password=False)

def record_login(username: str) -> None:
    _update(username, last_login=datetime.now(timezone.utc).isoformat(timespec="seconds"))

def get_profile(username: str) -> dict:
    """The user's own view of the account: no hash, nothing about others."""
    d = get_users().get(username) or {}
    return {
        "username": username,
        "role": d.get("role", LEGACY_ROLE),
        "email": d.get("email", ""),
        "groups": d.get("groups", []),
        "allowed_tabs": d.get("allowed_tabs", []),
        "last_login": d.get("last_login", ""),
    }

def session_epoch(username: str) -> int:
    """Tokens carry the epoch they were issued in; bumping it invalidates
    every session of the user at once ("sign out everywhere")."""
    return int((get_users().get(username) or {}).get("session_epoch", 0))

def bump_session_epoch(username: str) -> bool:
    with _users_lock:
        return _update(username, session_epoch=session_epoch(username) + 1)

def find_by_login(identifier: str) -> list:
    """Accounts named by a username or by their recovery address (case
    insensitive). An address can belong to more than one account."""
    ident = (identifier or "").strip()
    folded = ident.casefold()
    return [u for u, d in get_users().items()
            if u == ident or (folded and (d.get("email") or "").strip().casefold() == folded)]

def set_disabled(username: str, disabled: bool) -> bool:
    with _users_lock:
        users = get_users()
        if username not in users:
            return False
        users[username]["disabled"] = bool(disabled)
        _save_users(users)
    return True

def count_active_super_admins() -> int:
    """Active super administrators (not disabled, not awaiting approval)."""
    return sum(1 for d in get_users().values()
               if d.get("role", LEGACY_ROLE) == "super_admin" and not d.get("disabled", False)
               and not d.get("pending_approval", False))

def is_last_active_super_admin(username: str) -> bool:
    """True if removing this account's role, access or existence would leave
    the install without a USABLE super administrator.

    Only active accounts count: a disabled one cannot pass get_current_user,
    so counting it is the same as having none, and the app reopens only by
    editing users.json by hand. For the same reason an already disabled
    super_admin is never "the last".
    """
    user = get_users().get(username)
    if (not user or user.get("role", LEGACY_ROLE) != "super_admin" or user.get("disabled", False)
            or user.get("pending_approval", False)):
        return False
    return count_active_super_admins() <= 1

def get_user_groups(username: str):
    """Sedi/gruppi assegnati all'utente. Lista vuota o assente = nessuna
    restrizione (tutte le sedi). Ritorna [] se l'utente non esiste."""
    user = get_users().get(username)
    if not user:
        return []
    return user.get("groups", [])

def set_groups(username: str, groups) -> bool:
    with _users_lock:
        users = get_users()
        if username not in users:
            return False
        users[username]["groups"] = list(groups) if groups else []
        _save_users(users)
    return True

def get_allowed_tabs(username: str):
    """Tab dashboard visibili all'utente. Lista vuota o assente = nessuna
    restrizione (tutte le tab). Ritorna [] se l'utente non esiste."""
    user = get_users().get(username)
    if not user:
        return []
    return user.get("allowed_tabs", [])

def set_allowed_tabs(username: str, tabs) -> bool:
    with _users_lock:
        users = get_users()
        if username not in users:
            return False
        users[username]["allowed_tabs"] = list(tabs) if tabs else []
        _save_users(users)
    return True

# Legacy tab ids merged into one during the endpoint-inventory consolidation
# (four panels became one tab). A saved legacy id must keep resolving, same as
# the JS-side normalizeAllowedTabs() alias map in static/js/core.js — kept in
# parity by tests/js/test_tab_alias_parity.mjs.
TAB_ALIASES = {
    "tab-mac": "tab-endpoint",
    "tab-clientmap": "tab-endpoint",
    "tab-diagnosi": "tab-endpoint",
    "tab-endpoints": "tab-endpoint",
}

# A tab that implicitly grants a sub-tab living inside the same panel.
SUBTAB_GRANTS = {
    "tab-map": ("tab-map-interactive",),
    "tab-provisioning": ("tab-provisioner",),
}

# Tabs every restricted user holds anyway: home is the fallback panel for
# everyone and the frontend never offers it as a grant.
ALWAYS_GRANTED_TABS = ("tab-home",)


def effective_tabs(username: str):
    """Tabs the server enforces for this user, or None if unrestricted.

    Server-side counterpart of get_allowed_tabs: normalizes legacy aliases,
    adds implied sub-tab grants. None means "no gate" (super_admin, or an
    empty allowed_tabs list, same as the client-side convention)."""
    if get_role(username) == "super_admin":
        return None
    raw = get_allowed_tabs(username)
    if not raw:
        return None
    tabs = {TAB_ALIASES.get(t, t) for t in raw}
    for t in list(tabs):
        tabs.update(SUBTAB_GRANTS.get(t, ()))
    tabs.update(ALWAYS_GRANTED_TABS)
    return tabs

def delete_user(username: str) -> bool:
    with _users_lock:
        users = get_users()
        if username not in users:
            return False
        del users[username]
        _save_users(users)
    return True

def set_role(username: str, role: str) -> bool:
    if role not in VALID_ROLES:
        return False
    with _users_lock:
        users = get_users()
        if username not in users:
            return False
        users[username]["role"] = role
        _save_users(users)
    return True


def first_admin_username():
    """Highest-ranked admin account, alphabetical within a rank, or None.
    Used by the break-glass CLI when no username is given. Plain admins are
    the fallback for a CLI run before the role migration ever executed."""
    admins = sorted((-ROLE_RANK[d.get("role", LEGACY_ROLE)], u)
                    for u, d in get_users().items()
                    if is_admin(d.get("role", LEGACY_ROLE)))
    return admins[0][1] if admins else None

def reset_password_break_glass(username: str, new_password: str) -> bool:
    """Reimposta la password senza conoscere quella attuale (recupero da CLI).

    Riabilita l'account e impone il cambio password al primo accesso: chi
    esegue il recupero non deve restare in possesso di credenziali valide.
    Ritorna False se l'utente non esiste.
    """
    with _users_lock:
        users = get_users()
        if username not in users:
            return False
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        users[username]["hashed_password"] = hashed.decode('utf-8')
        users[username]["must_change_password"] = True
        users[username]["disabled"] = False
        _save_users(users)
    return True


def get_email(username: str) -> str:
    """Recovery address of the user, or "" when none is on file."""
    user = get_users().get(username)
    return (user or {}).get("email", "") or ""


def set_email(username: str, email: str) -> bool:
    """Sets or clears ("" clears) the recovery address. False if no such user."""
    with _users_lock:
        users = get_users()
        if username not in users:
            return False
        users[username]["email"] = (email or "").strip()
        _save_users(users)
    return True


def migrate_admins_to_super_admin() -> list:
    """Upgrade to the super_admin ladder: every existing admin is promoted,
    so nobody loses power on upgrade.

    Idempotence is keyed off users.json itself (count_active_super_admins),
    not an app_settings marker: a restored or corrupt settings file must
    neither re-promote admins created after the upgrade nor lock the install
    out with zero super_admins and no way to create one.
    """
    if count_active_super_admins() > 0:
        return []
    promoted = []
    with _users_lock:
        users = get_users()
        for name, d in users.items():
            if d.get("role") == "admin":
                d["role"] = "super_admin"
                promoted.append(name)
        if promoted:
            _save_users(users)
    return sorted(promoted)
