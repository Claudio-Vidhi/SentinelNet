"""Gestione delle SEDI (siti) multi-sede su VPN.

Ogni sito ha una modalità:
  - "central": il SentinelNet centrale raggiunge i dispositivi remoti
    direttamente tramite il routing VPN esistente (nessun processo remoto).
  - "agent":   un processo agente leggero gira nella sede remota, si connette
    IN USCITA verso il centrale (HTTPS) e vi spinge inventario, MAC e stato;
    il centrale gli inoltra comandi CLI tramite una coda di job.

I siti sono persistiti in sites.json (come user_manager/inventory_manager).
Il token per-sede è generato una sola volta e memorizzato SOLO come hash
SHA-256: il valore in chiaro è mostrato all'admin al momento della creazione /
rigenerazione e non è più recuperabile.

La coda dei job di comando (relay CLI centrale -> agente) usa SQLite, come
mac_history, così sopravvive ai riavvii del processo.
"""
import os
import json
import time
import uuid
import hashlib
import secrets
import sqlite3
import threading
from typing import Optional

from core import data_config

SITES_JSON = data_config.get_path("sites.json")
JOBS_DB = data_config.get_path("agent_jobs.db")

DEFAULT_SITE_ID = "central"
VALID_MODES = ("central", "agent")

_lock = threading.RLock()
_jobs_lock = threading.Lock()
_jobs_init_done = False


# --- Persistenza sites.json ---

def _default_sites() -> dict:
    return {
        DEFAULT_SITE_ID: {
            "id": DEFAULT_SITE_ID,
            "name": "Central",
            "mode": "central",
            "subnets": [],
            "token_hash": None,
            "created": time.time(),
            "last_seen": None,
        }
    }


def _load() -> dict:
    if not os.path.exists(SITES_JSON):
        data = _default_sites()
        _save(data)
        return data
    try:
        with open(SITES_JSON, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("formato non valido")
    except Exception:
        data = _default_sites()
        _save(data)
        return data
    # Il sito di default 'central' deve esistere sempre.
    if DEFAULT_SITE_ID not in data:
        data[DEFAULT_SITE_ID] = _default_sites()[DEFAULT_SITE_ID]
    return data


def _save(data: dict) -> None:
    tmp = SITES_JSON + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    try:
        os.replace(tmp, SITES_JSON)
    except PermissionError:
        with open(SITES_JSON, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _slugify(name: str) -> str:
    import re
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return slug or "site"


def _public(site: dict) -> dict:
    """Copia del sito senza l'hash del token (aggiunge has_token)."""
    d = {k: v for k, v in site.items() if k != "token_hash"}
    d["has_token"] = bool(site.get("token_hash"))
    return d


# --- CRUD siti ---

def list_sites() -> list:
    with _lock:
        return [_public(s) for s in _load().values()]


def get_site(site_id: str):
    with _lock:
        s = _load().get(site_id)
        return _public(s) if s else None


def create_site(name: str, mode: str, subnets=None):
    """Crea un sito. Ritorna (site_pubblico, token_in_chiaro|None).
    Per i siti in modalità 'agent' viene generato un token (mostrato una volta)."""
    name = (name or "").strip()
    if not name:
        raise ValueError("Il nome del sito è obbligatorio.")
    if mode not in VALID_MODES:
        raise ValueError(f"Modalità non valida: {mode}")
    subnets = [s.strip() for s in (subnets or []) if s and s.strip()]
    with _lock:
        data = _load()
        base = _slugify(name)
        site_id = base
        while site_id in data:
            site_id = f"{base}-{uuid.uuid4().hex[:4]}"
        token_plain = None
        token_hash = None
        if mode == "agent":
            token_plain = secrets.token_urlsafe(32)
            token_hash = _hash_token(token_plain)
        data[site_id] = {
            "id": site_id,
            "name": name,
            "mode": mode,
            "subnets": subnets,
            "token_hash": token_hash,
            "created": time.time(),
            "last_seen": None,
        }
        _save(data)
        return _public(data[site_id]), token_plain


def set_site_flow_status(site_id: str, active: bool) -> bool:
    with _lock:
        data = _load()
        site = data.get(site_id)
        if not site:
            return False
        site["flow_active"] = bool(active)
        _save(data)
        return True


def update_site(site_id: str, name=None, mode=None, subnets=None, **kwargs) -> bool:
    with _lock:
        data = _load()
        site = data.get(site_id)
        if not site:
            return False
        if isinstance(name, dict):
            kwargs.update(name)
            name = kwargs.pop("name", None)
            mode = kwargs.pop("mode", mode)
            subnets = kwargs.pop("subnets", subnets)
        if name is not None and isinstance(name, str) and name.strip():
            site["name"] = name.strip()
        if mode is not None:
            if mode not in VALID_MODES:
                raise ValueError(f"Modalità non valida: {mode}")
            site["mode"] = mode
            # Passando a 'central' il token non serve più.
            if mode == "central":
                site["token_hash"] = None
        if subnets is not None:
            site["subnets"] = [s.strip() for s in subnets if isinstance(s, str) and s.strip()]
        for k, v in kwargs.items():
            site[k] = v
        _save(data)
        return True


def delete_site(site_id: str) -> bool:
    if site_id == DEFAULT_SITE_ID:
        return False
    with _lock:
        data = _load()
        if site_id not in data:
            return False
        del data[site_id]
        _save(data)
        return True


def regenerate_token(site_id: str):
    """Rigenera il token di un sito agent. Ritorna il token in chiaro o None."""
    with _lock:
        data = _load()
        site = data.get(site_id)
        if not site or site.get("mode") != "agent":
            return None
        token_plain = secrets.token_urlsafe(32)
        site["token_hash"] = _hash_token(token_plain)
        _save(data)
        return token_plain


def touch_last_seen(site_id: str) -> None:
    with _lock:
        data = _load()
        site = data.get(site_id)
        if site:
            site["last_seen"] = time.time()
            _save(data)


# --- Autenticazione agente (token per-sede, separata dal JWT utente) ---

def authenticate(token: Optional[str] = None) -> Optional[str]:
    """Ritorna l'id del sito agent il cui token corrisponde, altrimenti None."""
    if not token:
        return None
    h = _hash_token(token)
    with _lock:
        for site in _load().values():
            if site.get("mode") == "agent" and site.get("token_hash") \
                    and secrets.compare_digest(site["token_hash"], h):
                return site["id"]
    return None


# --- Coda dei job di comando (relay CLI centrale -> agente), SQLite ---

def _connect():
    conn = sqlite3.connect(JOBS_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


VALID_JOB_KINDS = ("cli", "rest")

# Percorsi REST che l'agente può eseguire per conto del centrale.
#
# Il relay esiste perché in modalità agent il centrale non raggiunge gli
# apparati, e le domande più utili di una diagnosi (quale policy matcherebbe,
# quali sessioni, quale rotta, il tunnel è su?) non hanno un equivalente CLI
# affidabile — ``policy_lookup`` non ne ha proprio uno.
#
# La lista è il confine di autorità: senza, un token di sede diventerebbe
# accesso arbitrario alle API di ogni apparato della sede, e la separazione fra
# piano agente e piano apparato (roadmap §2) sparirebbe. Sola LETTURA:
# ``monitor/`` e ``log/``. Mai ``cmdb/`` (scrive configurazione), mai
# ``config-script/upload``. Vedi ADR-0008.
REST_RELAY_ALLOWLIST = (
    "monitor/firewall/policy-lookup",
    "monitor/firewall/session",
    "monitor/firewall/policy",
    "monitor/router/ipv4",
    "monitor/vpn/ipsec",
    "monitor/network/arp",
    "monitor/system/interface",
    "monitor/system/status",
    "log/*/traffic/forward",
)


def rest_path_allowed(path: str) -> bool:
    """Il percorso REST è fra quelli che l'agente può eseguire.

    Applicata DUE volte di proposito: dal centrale quando accoda il job, e
    dall'agente prima di eseguirlo. La seconda non è ridondante — il modello
    della modalità agent è che le credenziali restino nella sede anche se il
    centrale viene compromesso, e un centrale compromesso che detta percorsi
    arbitrari annullerebbe proprio quella garanzia.
    """
    import fnmatch

    p = (path or "").strip().lstrip("/")
    if not p or ".." in p or "://" in p:
        return False
    return any(fnmatch.fnmatchcase(p, pat) for pat in REST_RELAY_ALLOWLIST)


def _init_jobs():
    global _jobs_init_done
    with _jobs_lock:
        if _jobs_init_done:
            return
        with _connect() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS command_jobs (
                    id           TEXT PRIMARY KEY,
                    site_id      TEXT NOT NULL,
                    device_ip    TEXT NOT NULL,
                    command      TEXT NOT NULL,
                    status       TEXT NOT NULL DEFAULT 'pending',
                    result       TEXT DEFAULT '',
                    requested_by TEXT DEFAULT '',
                    created      REAL NOT NULL,
                    updated      REAL NOT NULL
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS ix_jobs_site ON command_jobs(site_id, status)")
            # Migrazione in avanti: i job esistenti sono tutti CLI, ed è il
            # default giusto — un agente vecchio che riceve solo 'cli' continua
            # a funzionare senza sapere che 'rest' esiste.
            cols = {r["name"] for r in c.execute("PRAGMA table_info(command_jobs)")}
            if "kind" not in cols:
                c.execute("ALTER TABLE command_jobs ADD COLUMN kind TEXT NOT NULL DEFAULT 'cli'")
        _jobs_init_done = True


def enqueue_job(site_id: str, device_ip: str, command: str,
                requested_by: str = "", kind: str = "cli") -> dict:
    """Accoda un lavoro per l'agente della sede.

    ``kind='cli'``: ``command`` è il comando da eseguire in SSH.
    ``kind='rest'``: ``command`` è un JSON ``{"path": ..., "params": {...}}``
    e il percorso deve stare nell'allowlist.
    """
    if kind not in VALID_JOB_KINDS:
        raise ValueError(f"Tipo di job non valido: {kind}")
    if kind == "rest":
        try:
            spec = json.loads(command)
        except (TypeError, ValueError):
            raise ValueError("Job REST: 'command' deve essere un JSON valido.")
        if not rest_path_allowed(spec.get("path", "")):
            raise ValueError(
                f"Percorso REST non consentito nel relay: {spec.get('path')!r}. "
                f"Consentiti (sola lettura): {', '.join(REST_RELAY_ALLOWLIST)}")
    _init_jobs()
    job_id = uuid.uuid4().hex
    now = time.time()
    with _jobs_lock, _connect() as c:
        c.execute("""INSERT INTO command_jobs
                     (id, site_id, device_ip, command, kind, status, result, requested_by, created, updated)
                     VALUES (?,?,?,?,?, 'pending', '', ?, ?, ?)""",
                   (job_id, site_id, device_ip, command, kind, requested_by, now, now))
    res = get_job(job_id)
    return res if res is not None else {}


def get_job(job_id: str):
    _init_jobs()
    with _jobs_lock, _connect() as c:
        row = c.execute("SELECT * FROM command_jobs WHERE id=?", (job_id,)).fetchone()
    return dict(row) if row else None


def claim_pending_jobs(site_id: str, limit: int = 20) -> list:
    """Restituisce i job 'pending' del sito marcandoli 'running' (chiamata
    dall'agente in polling). Operazione atomica sotto lock."""
    _init_jobs()
    now = time.time()
    with _jobs_lock, _connect() as c:
        rows = c.execute(
            "SELECT * FROM command_jobs WHERE site_id=? AND status='pending' "
            "ORDER BY created ASC LIMIT ?", (site_id, limit)).fetchall()
        jobs = [dict(r) for r in rows]
        for j in jobs:
            c.execute("UPDATE command_jobs SET status='running', updated=? WHERE id=?",
                      (now, j["id"]))
            j["status"] = "running"
    return jobs


def complete_job(job_id: str, site_id: str, status: str, result: str) -> bool:
    """Registra l'esito di un job (chiamata dall'agente). Verifica che il job
    appartenga al sito che lo dichiara concluso."""
    _init_jobs()
    if status not in ("done", "error"):
        status = "done"
    now = time.time()
    with _jobs_lock, _connect() as c:
        cur = c.execute(
            "UPDATE command_jobs SET status=?, result=?, updated=? WHERE id=? AND site_id=?",
            (status, result or "", now, job_id, site_id))
        return cur.rowcount > 0


def find_recent_rest_result(site_id: str, device_ip: str, path: str,
                            max_age_s: int = 300):
    """Ultimo job REST concluso per quell'apparato e quel percorso, se recente.

    L'agente esegue in polling (default 60s): una richiesta sincrona non può
    aspettarlo. Il referto quindi accoda e torna subito; alla chiamata
    successiva questo recupera il risultato ormai pronto. ``max_age_s`` evita
    di spacciare per attuale la risposta di mezz'ora fa.

    Ritorna il job (dict) oppure ``None``.
    """
    _init_jobs()
    cutoff = time.time() - max_age_s
    with _jobs_lock, _connect() as c:
        rows = c.execute(
            """SELECT * FROM command_jobs
               WHERE site_id=? AND device_ip=? AND kind='rest'
                 AND status IN ('done','error') AND updated >= ?
               ORDER BY updated DESC LIMIT 20""",
            (site_id, device_ip, cutoff)).fetchall()
    for row in rows:
        try:
            if json.loads(row["command"]).get("path") == path:
                return dict(row)
        except (TypeError, ValueError):
            continue
    return None


def has_pending_rest_job(site_id: str, device_ip: str, path: str) -> bool:
    """Un job identico è già in coda o in esecuzione: non se ne accoda un
    altro a ogni apertura del referto."""
    _init_jobs()
    with _jobs_lock, _connect() as c:
        rows = c.execute(
            """SELECT command FROM command_jobs
               WHERE site_id=? AND device_ip=? AND kind='rest'
                 AND status IN ('pending','running')""",
            (site_id, device_ip)).fetchall()
    for row in rows:
        try:
            if json.loads(row["command"]).get("path") == path:
                return True
        except (TypeError, ValueError):
            continue
    return False


def list_jobs(site_id: Optional[str] = None, limit: int = 100) -> list:
    _init_jobs()
    with _jobs_lock, _connect() as c:
        if site_id:
            rows = c.execute("SELECT * FROM command_jobs WHERE site_id=? "
                             "ORDER BY created DESC LIMIT ?", (site_id, limit)).fetchall()
        else:
            rows = c.execute("SELECT * FROM command_jobs ORDER BY created DESC LIMIT ?",
                             (limit,)).fetchall()
    return [dict(r) for r in rows]
