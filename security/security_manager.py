import os
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta, timezone
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
    fh = RotatingFileHandler(
        AUDIT_LOG_FILE,
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=3,
        encoding="utf-8"
    )
    fh.setFormatter(logging.Formatter('%(asctime)s - [AUDIT] - %(message)s'))
    audit_logger.addHandler(fh)

def log_audit(message: str):
    """Scrive un record di tracciabilità all'interno del registro sicuro audit.log."""
    audit_logger.info(message)

# --- JWT AUTHENTICATION ---

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    """Genera un token JWT di accesso."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str) -> dict:
    """Valida un token JWT. Ritorna il payload se valido, altrimenti None."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

from collections import defaultdict
import time

_failed_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300

def is_locked_out(username: str) -> bool:
    """Verifica se l'utente è attualmente bloccato per troppi tentativi falliti."""
    now = time.time()
    attempts = [t for t in _failed_attempts[username] if now - t < LOCKOUT_SECONDS]
    _failed_attempts[username] = attempts
    return len(attempts) >= MAX_ATTEMPTS

def record_failed_attempt(username: str):
    """Registra un tentativo di login fallito."""
    _failed_attempts[username].append(time.time())

def reset_failed_attempts(username: str):
    """Resetta i tentativi falliti al login corretto."""
    _failed_attempts.pop(username, None)
