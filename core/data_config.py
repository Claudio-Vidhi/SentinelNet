import logging
import os
import subprocess
import sys

# Read the data directory from the environment (e.g. '/app/data' in Docker).
# Without the variable, state files are confined to ./data
# instead of filling the current directory next to the executable (DF-1).
DATA_DIR = os.getenv("SENTINELNET_DATA_DIR") or os.path.join(os.getcwd(), "data")

# Known state files, candidates for one-time migration from CWD to DATA_DIR.
_STATE_FILES = [
    "app_settings.json", "audit.log", "error_log.txt", "groups.json",
    "jwt_secret.key", "mac_history.db", "mac_history.db-shm",
    "mac_history.db-wal", "redundancy.db", "redundancy.db-shm",
    "redundancy.db-wal", "secret.key", "sites.json", "users.json",
    "vendors.json", "detected_versions.json", "device_models.json",
    "device_categories.json", "network_hosts.csv",
]

# Sensitive files to protect with restrictive ACLs.
_SENSITIVE_FILES = {"secret.key", "jwt_secret.key", "users.json",
                    "sites.json", "mac_history.db"}


def restrict_permissions(path: str):
    """Restricts the file permissions to the current user only (best effort)."""
    try:
        if sys.platform == "win32":
            # icacls non solleva su fallimento: senza guardare il returncode
            # l'irrigidimento delle ACL fallisce in silenzio e il file resta
            # coi permessi ereditati dalla cartella.
            res = subprocess.run(
                ["icacls", path, "/inheritance:r",
                 "/grant:r", f"{os.environ.get('USERNAME', '')}:F"],
                capture_output=True, timeout=15)
            if res.returncode != 0:
                logging.warning(
                    "ACL non ristrette su %s: icacls uscito con %s (%s)",
                    path, res.returncode,
                    res.stderr.decode(errors="ignore").strip()[:200])
        else:
            os.chmod(path, 0o600)
    except (OSError, subprocess.SubprocessError) as e:
        logging.warning("ACL non ristrette su %s: %s", path, e)


def get_path(filename: str) -> str:
    """
    Resolves the absolute path of a configuration or database file
    inside SENTINELNET_DATA_DIR / DATA_DIR, creating the folder if necessary.
    """
    active_dir = os.getenv("SENTINELNET_DATA_DIR") or DATA_DIR
    if active_dir:
        try:
            os.makedirs(active_dir, exist_ok=True)
        except Exception:
            pass
        return os.path.join(active_dir, filename)
    return filename


def _app_adv(key, default=None):
    """'app' section of app_settings.json (advanced settings from GUI).
    Fallback when the corresponding environment variable is not set."""
    try:
        import json as _json
        with open(get_path("app_settings.json"), encoding="utf-8") as _f:
            return ((_json.load(_f) or {}).get("app") or {}).get(key, default)
    except Exception:
        return default


def obs_config() -> dict:
    """Configuration of the observability listeners (phase 3.6).

    Safe defaults: EVERYTHING OFF (exe/desktop and Docker), bind on loopback,
    high non-privileged ports (never 514 in-process: privileged mapping only
    via Docker). ``0.0.0.0`` requires explicit opt-in.
    """
    # Base: "observability" section of app_settings.json (GUI config, §9.5);
    # environment variables, if set, take precedence. Listeners
    # start at boot: changes require a restart.
    try:
        import json as _json
        with open(get_path("app_settings.json"), encoding="utf-8") as _f:
            _saved = (_json.load(_f) or {}).get("observability", {}) or {}
    except Exception:
        _saved = {}

    def _flag(name, key, default=False):
        env = os.environ.get(name)
        if env is not None:
            return env.strip() in ("1", "true", "True")
        return bool(_saved.get(key, default))

    def _port(name, key, default):
        env = os.environ.get(name)
        if env is not None:
            return int(env)
        val = _saved.get(key)
        return int(val) if val is not None else int(default)

    enabled = _flag("SENTINELNET_OBS_ENABLE", "enabled")
    return {
        "enabled": enabled,
        "bind": os.environ.get("SENTINELNET_OBS_BIND",
                               _saved.get("bind", "127.0.0.1")).strip(),
        "ipfix": {
            "enabled": enabled and _flag("SENTINELNET_OBS_IPFIX_ENABLE", "ipfix_enabled", True),
            "port": _port("SENTINELNET_OBS_IPFIX_PORT", "ipfix_port", 4739),
        },
        "sflow": {
            "enabled": enabled and _flag("SENTINELNET_OBS_SFLOW_ENABLE", "sflow_enabled", True),
            "port": _port("SENTINELNET_OBS_SFLOW_PORT", "sflow_port", 6343),
        },
        "syslog": {
            "enabled": enabled and _flag("SENTINELNET_OBS_SYSLOG_ENABLE", "syslog_enabled", True),
            "port": _port("SENTINELNET_OBS_SYSLOG_PORT", "syslog_port", 5514),
        },
        # Classic NetFlow (v5/v9) on the canonical port 2055: same decoder
        # as ipfix.parse (handles v5/v9/IPFIX from the header).
        "netflow": {
            "enabled": enabled and _flag("SENTINELNET_OBS_NETFLOW_ENABLE", "netflow_enabled", True),
            "port": _port("SENTINELNET_OBS_NETFLOW_PORT", "netflow_port", 2055),
        },
        # REST poller (§9.2): interval in seconds, 0 = disabled.
        "api_poll_s": _port("SENTINELNET_OBS_API_POLL_S", "api_poll_s", 300),
        # SNMP poller: default 0 (off). It must be turned on deliberately, because
        # it queries devices with a credential — it must not start on its own
        # just because observability is active.
        "snmp_poll_s": _port("SENTINELNET_OBS_SNMP_POLL_S", "snmp_poll_s", 0),
        # Linux host health poller: default 0 (off), same reason
        # as the SNMP poller — it opens an SSH session with a credential.
        "linux_poll_s": _port("SENTINELNET_OBS_LINUX_POLL_S", "linux_poll_s", 0),
        "retention_days": {
            "flow_aggregates": int(os.environ.get("SENTINELNET_OBS_RETENTION_FLOWS_DAYS")
                                   or _app_adv("retention_flows_days") or 30),
            "syslog_events": int(os.environ.get("SENTINELNET_OBS_RETENTION_SYSLOG_DAYS")
                                 or _app_adv("retention_syslog_days") or 7),
            # The unified model mixes projections with different lifetimes: the
            # flow window is kept, the longest among the projected sources,
            # so no event disappears before its own origin.
            "events": int(os.environ.get("SENTINELNET_OBS_RETENTION_FLOWS_DAYS")
                          or _app_adv("retention_flows_days") or 30),
            # Orphan evidence (rule fired, incident never formed): those
            # tied to an incident follow the incident via CASCADE.
            "evidence": int(os.environ.get("SENTINELNET_OBS_RETENTION_EVENTS_DAYS")
                            or _app_adv("retention_events_days") or 90),
            "incidents": int(os.environ.get("SENTINELNET_OBS_RETENTION_EVENTS_DAYS")
                             or _app_adv("retention_events_days") or 90),
        },
    }


class TlsConfigError(Exception):
    """Incomplete or invalid native TLS configuration (fail-closed)."""
    pass


def resolve_tls_config():
    """Resolves the optional native TLS configuration (finding H-1).

    Reads SENTINELNET_SSL_CERTFILE and SENTINELNET_SSL_KEYFILE. Returns
    (certfile, keyfile) if both present and readable, (None, None) if
    both absent (HTTP unchanged). If only one is set, or a file is
    not readable, raises TlsConfigError with an Italian message
    (the caller must terminate with exit code != 0).

    Relative paths are resolved against DATA_DIR, so the
    behavior is identical across source, exe, and Docker.
    """
    cert = (os.environ.get("SENTINELNET_SSL_CERTFILE")
            or _app_adv("ssl_certfile") or "").strip()
    key = (os.environ.get("SENTINELNET_SSL_KEYFILE")
           or _app_adv("ssl_keyfile") or "").strip()
    if not cert and not key:
        return None, None
    if not cert or not key:
        missing = "SENTINELNET_SSL_CERTFILE" if not cert else "SENTINELNET_SSL_KEYFILE"
        raise TlsConfigError(
            f"Configurazione TLS incompleta: la variabile {missing} non è impostata. "
            "Impostare entrambe le variabili SENTINELNET_SSL_CERTFILE e "
            "SENTINELNET_SSL_KEYFILE, oppure nessuna delle due."
        )
    paths = {}
    for var, value in (("SENTINELNET_SSL_CERTFILE", cert), ("SENTINELNET_SSL_KEYFILE", key)):
        path = value if os.path.isabs(value) else os.path.join(DATA_DIR, value)
        if not os.path.isfile(path):
            raise TlsConfigError(
                f"Il file indicato da {var} non esiste o non è leggibile: {path}"
            )
        try:
            with open(path, "rb"):
                pass
        except OSError as e:
            raise TlsConfigError(
                f"Impossibile leggere il file indicato da {var} ({path}): {e}"
            )
        paths[var] = path
    return paths["SENTINELNET_SSL_CERTFILE"], paths["SENTINELNET_SSL_KEYFILE"]


def _migrate_legacy_files():
    """One-time migration: moves state files left in CWD by
    previous versions into DATA_DIR (without touching backup-config/ and
    templates/)."""
    cwd = os.getcwd()
    if not DATA_DIR or os.path.abspath(DATA_DIR) == os.path.abspath(cwd):
        return
    for name in _STATE_FILES:
        src = os.path.join(cwd, name)
        dst = os.path.join(DATA_DIR, name)
        if os.path.isfile(src) and not os.path.exists(dst):
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                os.replace(src, dst)
            except OSError as e:
                if name in _SENSITIVE_FILES:
                    # Se secret.key non arriva in DATA_DIR, load_or_create la
                    # legge come primo avvio e ne genera una NUOVA: tutte le
                    # password gia' cifrate in inventario diventano
                    # indecifrabili, decrypt_password ritorna "" e ogni
                    # apparato prova ad autenticarsi con password vuota.
                    # Non ripartire e' meglio che ripartire senza chiave.
                    raise RuntimeError(
                        f"Migrazione di '{name}' in {DATA_DIR} fallita: {e}. "
                        f"Spostare il file a mano prima di riavviare."
                    ) from e
                logging.error("Migrazione di '%s' fallita: %s", name, e)
                continue
        if name in _SENSITIVE_FILES and os.path.exists(dst):
            restrict_permissions(dst)


_migrate_legacy_files()
