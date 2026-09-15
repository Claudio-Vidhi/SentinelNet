import os
import hashlib
import hmac
import logging
import threading
import uuid
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
_chain_lock = threading.RLock()
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Session lifetime, set by the administrator (Settings > Sessions) and read at
# every token issue, so a change applies to the next request without restart.
# idle_minutes: how long a browser session survives without user input (it is
# also the lifetime of every token). max_hours: no session is renewed past this
# many hours from its sign-in.
SESSION_IDLE_DEFAULT = ACCESS_TOKEN_EXPIRE_MINUTES
SESSION_MAX_HOURS_DEFAULT = 12
SESSION_IDLE_LIMITS = (5, 1440)
SESSION_MAX_HOURS_LIMIT = 720


def session_settings() -> dict:
    from core.app_settings import get_app_settings
    raw = get_app_settings().get("session") or {}

    def _int(key, default, lo, hi):
        try:
            return min(max(int(raw[key]), lo), hi)
        except (KeyError, TypeError, ValueError):
            return default
    return {"idle_minutes": _int("idle_minutes", SESSION_IDLE_DEFAULT, *SESSION_IDLE_LIMITS),
            "max_hours": _int("max_hours", SESSION_MAX_HOURS_DEFAULT, 1, SESSION_MAX_HOURS_LIMIT)}

# Configurazione logger di Audit protetto
AUDIT_LOG_FILE = data_config.get_path("audit.log")
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)

# S2 -- evidenza di manomissione. Ogni riga porta un HMAC della precedente
# piu' la propria: modificarne una senza ricalcolare le successive si vede.
#
# HMAC e non SHA-256 nudo: l'algoritmo e' pubblico, quindi con un digest
# semplice chi riscrive una riga ricalcola anche i tag a valle e la catena non
# prova niente. La chiave e' derivata dal segreto JWT (file con ACL al solo
# proprietario), con separazione di dominio: nessun file nuovo da proteggere,
# e chi non legge quel file non puo' forgiare un tag.
#
# Cosa NON prova, dichiarato: il troncamento della coda e la cancellazione del
# file. Per quelli serve un sink esterno, che e' un'altra funzionalita'.
_CHAIN_TAG = "chain:"
_CHAIN_SEED = "sentinelnet-audit-chain-v1"
NEWLINE = chr(10)
_chain_key = hashlib.sha256(b"audit-chain|" + JWT_SECRET_KEY.encode("utf-8")).digest()
_chain_prev: Optional[str] = None


def _chain_tag_of(prev: str, line: str) -> str:
    return hmac.new(_chain_key, (prev + NEWLINE + line).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _split_chain_tag(line: str):
    """``(riga_resa, tag)`` per una riga concatenata, ``(riga, None)`` per una
    riga senza tag (registro scritto prima di questa modifica)."""
    suffix_start = line.rfind(" [" + _CHAIN_TAG)
    if suffix_start < 0 or not line.endswith("]"):
        return line, None
    tag = line[suffix_start + len(_CHAIN_TAG) + 2:-1]
    if len(tag) != 64 or any(c not in "0123456789abcdef" for c in tag):
        return line, None
    return line[:suffix_start], tag


def _last_chain_tag() -> str:
    """Riprende la catena dal registro su disco: senza questo ogni riavvio
    ricominciava dal seme e la verifica si rompeva sulla prima riga nuova."""
    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            last = None
            for line in f:
                line = line.rstrip(NEWLINE)
                if line:
                    _, tag = _split_chain_tag(line)
                    if tag:
                        last = tag
        if last:
            return last
    except OSError:
        pass
    return _CHAIN_SEED


class _ChainedFormatter(logging.Formatter):
    """Formatter e non Filter: il tag deve coprire la riga RESA, timestamp
    compreso, e il timestamp esiste solo dopo la formattazione."""

    def format(self, record):
        global _chain_prev
        # RotatingFileHandler.shouldRollover() formatta il record una volta in
        # piu' solo per misurarne la lunghezza, e scarta il risultato: senza
        # questa memoria la catena avanzava due volte per riga e il tag
        # scritto non era quello che la verifica si aspettava.
        cached = getattr(record, "_sn_chain_line", None)
        if cached is not None:
            return cached
        base = super().format(record)
        with _chain_lock:
            if _chain_prev is None:
                _chain_prev = _last_chain_tag()
            tag = _chain_tag_of(_chain_prev, base)
            _chain_prev = tag
        line = f"{base} [{_CHAIN_TAG}{tag}]"
        record._sn_chain_line = line
        return line


def verify_audit_chain(path: Optional[str] = None) -> Optional[int]:
    """Numero (da 1) della prima riga il cui tag non torna, o ``None`` se il
    registro e' integro.

    Ogni file riparte dal seme (vedi ``_ChainedRotatingHandler``), quindi anche
    la prima riga viene verificata e un file ruotato si controlla da solo.

    Le righe senza tag sono salti: un registro scritto prima di questa
    modifica non e' manomesso, e' solo vecchio."""
    target = path or AUDIT_LOG_FILE
    prev = _CHAIN_SEED
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            for n, raw in enumerate(f, start=1):
                line = raw.rstrip(NEWLINE)
                if not line:
                    continue
                base, tag = _split_chain_tag(line)
                if tag is None:
                    continue
                if not hmac.compare_digest(tag, _chain_tag_of(prev, base)):
                    return n
                prev = tag
    except OSError:
        return None
    return None


class _ChainedRotatingHandler(RotatingFileHandler):
    """La catena riparte dal seme a ogni rotazione, cosi' ogni file e'
    verificabile da solo. Continuarla da un file all'altro rendeva la prima
    riga di ogni segmento non verificabile senza il segmento precedente, e
    quella diventava l'unica riga riscrivibile a piacere. Il confine fra
    segmenti non e' coperto: la cancellazione di un segmento intero non lo
    era comunque (vedi il limite dichiarato sopra)."""

    def doRollover(self):
        global _chain_prev
        super().doRollover()
        with _chain_lock:
            _chain_prev = None      # il nuovo file e' vuoto: si riparte dal seme


if not audit_logger.handlers:
    # The audit trail is the security record of the installation: 5 MB x 3
    # rotated away too fast on a busy estate. 10 MB x 9 keeps ~100 MB.
    fh = _ChainedRotatingHandler(
        AUDIT_LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=9,
        encoding="utf-8"
    )
    fh.setFormatter(_ChainedFormatter('%(asctime)s - [AUDIT] - %(message)s'))
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

# S1 -- revoca. Il JWT e' stateless: prima di questa denylist il logout
# cancellava il cookie e nient'altro, quindi un Bearer copiato restava valido
# fino a un'ora dopo.
#
# La denylist e' limitata per costruzione: una voce serve solo finche' il
# token che nomina potrebbe ancora essere accettato, e oltre ``exp`` quel
# token e' invalido comunque. Potare a ogni scrittura basta: nessun processo
# di pulizia, nessuna tabella di sessioni. E una tabella di sessioni
# sposterebbe la fonte di verita' dell'autenticazione, che e' un cambiamento
# piu' grande del buco.
#
# Il logout revoca IL token con cui e' chiamato, non l'utente: un taglio per
# utente chiuderebbe anche l'altro browser e la sessione MCP.
REVOKED_FILE = data_config.get_path("revoked_tokens.json")
_revoked: "dict[str, float]" = {}
_revoked_lock = threading.RLock()
_revoked_loaded = False


def _load_revoked() -> None:
    global _revoked, _revoked_loaded
    with _revoked_lock:
        if _revoked_loaded:
            return
        raw = {}
        try:
            if os.path.exists(REVOKED_FILE):
                with open(REVOKED_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    raw = data
        except (OSError, json.JSONDecodeError):
            # Una denylist corrotta non deve bloccare l'autenticazione: il
            # costo e' che i token revocati tornano validi fino a scadenza,
            # ed e' meno grave di un'app che non fa piu' entrare nessuno.
            raw = {}
        now = time.time()
        _revoked = {k: float(v) for k, v in raw.items()
                    if isinstance(v, (int, float)) and float(v) > now}
        _revoked_loaded = True


def _save_revoked() -> None:
    try:
        data_config.atomic_write(REVOKED_FILE, _revoked, restrict=True)
    except (OSError, RuntimeError):
        pass  # best effort, come per i tentativi di login


def revoke_token(payload: dict) -> bool:
    """Invalida il token descritto da ``payload`` (l'uscita di
    ``verify_access_token``). Ritorna False se il token non ha ``jti``:
    quelli emessi prima di questa modifica non sono revocabili e scadono da
    soli entro ``ACCESS_TOKEN_EXPIRE_MINUTES``."""
    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        return False
    _load_revoked()
    with _revoked_lock:
        now = time.time()
        # Potatura in linea: le voci scadute non servono piu' a nessuno.
        for k in [k for k, v in _revoked.items() if v <= now]:
            _revoked.pop(k, None)
        _revoked[str(jti)] = float(exp)
        _save_revoked()
    return True


def is_revoked(jti: str) -> bool:
    if not jti:
        return False
    _load_revoked()
    with _revoked_lock:
        exp = _revoked.get(str(jti))
        return exp is not None and exp > time.time()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Genera un token JWT di accesso."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=session_settings()["idle_minutes"])
    to_encode.update({"exp": expire})
    # jti: identifica QUESTO token, cosi' il logout puo' revocare solo lui.
    to_encode.setdefault("jti", uuid.uuid4().hex)
    # auth_time: when the user actually signed in. A renewed token copies it,
    # so the session's absolute cap counts from the sign-in, not the renewal.
    to_encode.setdefault("auth_time", int(time.time()))
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str) -> Optional[dict]:
    """Valida un token JWT. Ritorna il payload se valido, altrimenti None.

    Unico punto di verifica dell'app (routers/deps.py), quindi la denylist
    controllata qui copre ogni consumatore senza toccarne nessuno."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None
    if is_revoked(payload.get("jti", "")):
        return None
    return payload

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
