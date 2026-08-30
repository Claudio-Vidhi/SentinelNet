import os
import hashlib
import logging
from contextvars import ContextVar
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from core import data_config
from security import secure_key_store

JWT_KEY_FILE = data_config.get_path("jwt_secret.key")

def load_or_create_jwt_secret() -> str:
    """Carica o genera una chiave segreta separata ed indipendente per i token JWT."""
    # 1. Priorità massima alla variabile d'ambiente per deployment cloud o containerizzati
    env_secret = os.getenv("SENTINELNET_JWT_SECRET")
    if env_secret:
        return hashlib.sha256(env_secret.encode('utf-8')).hexdigest()

    # 2. Fallback su file persistito localmente (jwt_secret.key), protetto a
    #    riposo con DPAPI su Windows. I file legacy in chiaro vengono migrati
    #    in-place mantenendo lo stesso segreto (le sessioni restano valide).
    import secrets
    try:
        raw = secure_key_store.load_or_create(JWT_KEY_FILE, lambda: secrets.token_hex(32))
        secret = raw.decode("utf-8").strip()
        if not secret:
            raise ValueError("Il file della chiave JWT è vuoto.")
        return secret
    except Exception as e:
        # Fail-closed: mai ripiegare su un segreto hardcoded/prevedibile, altrimenti
        # i token JWT diventerebbero falsificabili da chiunque conosca il sorgente.
        raise RuntimeError(
            f"Impossibile caricare la chiave segreta JWT da '{JWT_KEY_FILE}': {e}. "
            "Impostare SENTINELNET_JWT_SECRET oppure garantire l'accesso al file."
        ) from e

JWT_SECRET_KEY = load_or_create_jwt_secret()
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Configurazione logger di Audit protetto
AUDIT_LOG_FILE = data_config.get_path("audit.log")
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)

if not audit_logger.handlers:
    # The audit trail is the security record of the installation: 5 MB x 3
    # rotated away too fast on a busy estate. 10 MB x 9 keeps ~100 MB.
    fh = RotatingFileHandler(
        AUDIT_LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=9,
        encoding="utf-8"
    )
    fh.setFormatter(logging.Formatter('%(asctime)s - [AUDIT] - %(message)s'))
    audit_logger.addHandler(fh)

# Attribution of the calling client, per request. Every audit line already
# passes through log_audit, so stamping it here reaches every existing call
# site instead of touching a hundred of them.
#
# The value comes from a request HEADER, so it is a CLAIM, not proof: any
# holder of a valid token can send it. It answers "which client says it made
# this call" (an MCP tool run vs. the dashboard) and is worded as declared in
# the log for exactly that reason. Identity itself stays the JWT's.
_client_tag: "ContextVar[str]" = ContextVar("audit_client_tag", default="")

CLIENT_TAG_HEADER = "X-SentinelNet-Client"
_CLIENT_TAG_MAX = 48


def set_client_tag(raw: "str | None") -> str:
    """Normalizes and stores the client tag for the current request."""
    tag = "".join(c for c in (raw or "")
                  if c.isalnum() or c in "-_./:")[:_CLIENT_TAG_MAX]
    _client_tag.set(tag)
    return tag


def log_audit(message: str):
    """Scrive un record di tracciabilità all'interno del registro sicuro audit.log."""
    tag = _client_tag.get()
    if tag:
        message = f"{message} [client dichiarato: {tag}]"
    audit_logger.info(message)

# --- JWT AUTHENTICATION ---

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Genera un token JWT di accesso."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str) -> Optional[dict]:
    """Valida un token JWT. Ritorna il payload se valido, altrimenti None."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

from collections import defaultdict
import json
import threading
import time

_failed_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300

# WP6: lockout state survives restarts and is keyed source+account by the
# callers. A username-only key let an unauthenticated attacker lock out any
# named account, and the in-memory dict evaporated at every restart.
ATTEMPTS_FILE = data_config.get_path("login_attempts.json")
_attempts_lock = threading.RLock()
_attempts_loaded = False


def _load_attempts() -> None:
    """Lazily loads persisted attempts, pruning expired entries."""
    global _failed_attempts, _attempts_loaded
    with _attempts_lock:
        if _attempts_loaded:
            return
        raw = {}
        try:
            if os.path.exists(ATTEMPTS_FILE):
                with open(ATTEMPTS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    raw = {k: v for k, v in data.items() if isinstance(v, list)}
        except (OSError, json.JSONDecodeError):
            raw = {}  # a corrupt attempt store must never block authentication
        now = time.time()
        _failed_attempts = defaultdict(list, {
            k: [t for t in v if isinstance(t, (int, float))
                and now - t < LOCKOUT_SECONDS]
            for k, v in raw.items()
        })
        _attempts_loaded = True


def _save_attempts() -> None:
    now = time.time()
    payload = {k: v for k, v in _failed_attempts.items()
               if v and now - v[-1] < LOCKOUT_SECONDS}
    tmp = ATTEMPTS_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, ATTEMPTS_FILE)  # never leave a half-written store
    except OSError:
        pass  # best effort: persistence must never block authentication


def is_locked_out(key: str) -> bool:
    """Verifica se la chiave (sorgente+account) è bloccata per troppi tentativi."""
    _load_attempts()
    with _attempts_lock:
        now = time.time()
        attempts = [t for t in _failed_attempts[key] if now - t < LOCKOUT_SECONDS]
        _failed_attempts[key] = attempts
        return len(attempts) >= MAX_ATTEMPTS


def record_failed_attempt(key: str):
    """Registra un tentativo fallito e lo persiste (sopravvive ai restart)."""
    _load_attempts()
    with _attempts_lock:
        _failed_attempts[key].append(time.time())
        _save_attempts()


def reset_failed_attempts(key: str):
    """Resetta i tentativi falliti dopo un accesso corretto."""
    _load_attempts()
    with _attempts_lock:
        if _failed_attempts.pop(key, None) is not None:
            _save_attempts()


def clear_account_lockouts(username: str):
    """Rimuove tutti i lockout di login dell'account, da ogni sorgente.
    Usato dai recuperi password: chi ha appena recuperato le credenziali
    non deve restare bloccato dai tentativi fatti per rientrare."""
    _load_attempts()
    suffix = f":{username}"
    with _attempts_lock:
        keys = [k for k in _failed_attempts
                if k.startswith("login:") and k.endswith(suffix)]
        for k in keys:
            _failed_attempts.pop(k, None)
        if keys:
            _save_attempts()
