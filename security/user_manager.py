import json
import os
import bcrypt
import data_config

USERS_JSON = data_config.get_path("users.json")

# Ruoli supportati, dal più al meno privilegiato:
#   admin    → controllo totale, incluso la gestione utenti
#   operator → tutte le operazioni di rete (triage, comandi, CRUD apparati) ma non utenti
#   viewer   → sola lettura (inventario, mappe, threat intel)
VALID_ROLES = ("admin", "operator", "viewer")

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
    if not os.path.exists(USERS_JSON):
        return {}
    with open(USERS_JSON, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def _save_users(users: dict):
    with open(USERS_JSON, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4)

def has_any_user() -> bool:
    return len(get_users()) > 0

def get_role(username: str):
    """Ruolo dell'utente, o None se non esiste. Gli account legacy senza campo
    'role' (installazioni mono-utente preesistenti) sono trattati come admin."""
    user = get_users().get(username)
    if not user:
        return None
    return user.get("role", "admin")

def create_user(username: str, password: str, role: str = "viewer", groups=None,
                must_change_password: bool = False) -> bool:
    if role not in VALID_ROLES:
        role = "viewer"
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
        # Tab dashboard visibili all'utente. Lista vuota = tutte (come per "groups").
        "allowed_tabs": [],
        "disabled": False,
        # True per gli account creati da un amministratore: al primo login
        # l'utente è obbligato a impostare una nuova password personale.
        "must_change_password": bool(must_change_password),
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
    users = get_users()
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
            "role": d.get("role", "admin"),
            "groups": d.get("groups", []),
            "allowed_tabs": d.get("allowed_tabs", []),
            "disabled": d.get("disabled", False),
            "must_change_password": d.get("must_change_password", False),
        }
        for u, d in get_users().items()
    ]

def is_disabled(username: str) -> bool:
    user = get_users().get(username)
    return bool(user and user.get("disabled", False))

def set_disabled(username: str, disabled: bool) -> bool:
    users = get_users()
    if username not in users:
        return False
    users[username]["disabled"] = bool(disabled)
    _save_users(users)
    return True

def count_active_admins() -> int:
    """Amministratori attivi (ruolo admin e non disabilitati)."""
    return sum(1 for d in get_users().values()
               if d.get("role", "admin") == "admin" and not d.get("disabled", False))

def get_user_groups(username: str):
    """Sedi/gruppi assegnati all'utente. Lista vuota o assente = nessuna
    restrizione (tutte le sedi). Ritorna [] se l'utente non esiste."""
    user = get_users().get(username)
    if not user:
        return []
    return user.get("groups", [])

def set_groups(username: str, groups) -> bool:
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
    users = get_users()
    if username not in users:
        return False
    users[username]["allowed_tabs"] = list(tabs) if tabs else []
    _save_users(users)
    return True

def delete_user(username: str) -> bool:
    users = get_users()
    if username not in users:
        return False
    del users[username]
    _save_users(users)
    return True

def set_role(username: str, role: str) -> bool:
    if role not in VALID_ROLES:
        return False
    users = get_users()
    if username not in users:
        return False
    users[username]["role"] = role
    _save_users(users)
    return True

def count_admins() -> int:
    return sum(1 for d in get_users().values() if d.get("role", "admin") == "admin")
