import os
import subprocess
import sys

# Leggi la directory dati dall'ambiente (es. '/app/data' in Docker).
# In assenza della variabile, i file di stato vengono confinati in ./data
# invece di riempire la directory corrente accanto all'eseguibile (DF-1).
DATA_DIR = os.getenv("SENTINELNET_DATA_DIR") or os.path.join(os.getcwd(), "data")

# File di stato noti, candidati alla migrazione una tantum da CWD a DATA_DIR.
_STATE_FILES = [
    "app_settings.json", "audit.log", "error_log.txt", "groups.json",
    "jwt_secret.key", "mac_history.db", "mac_history.db-shm",
    "mac_history.db-wal", "secret.key", "sites.json", "users.json",
    "vendors.json", "detected_versions.json", "device_models.json",
    "device_categories.json", "network_hosts.csv",
]

# File sensibili da proteggere con ACL restrittive.
_SENSITIVE_FILES = {"secret.key", "jwt_secret.key", "users.json",
                    "sites.json", "mac_history.db"}


def restrict_permissions(path: str):
    """Restringe i permessi del file al solo utente corrente (best effort)."""
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["icacls", path, "/inheritance:r",
                 "/grant:r", f"{os.environ.get('USERNAME', '')}:F"],
                capture_output=True, timeout=15)
        else:
            os.chmod(path, 0o600)
    except Exception:
        pass


def get_path(filename: str) -> str:
    """
    Risolve il percorso assoluto di un file di configurazione o database
    all'interno di DATA_DIR, creando la cartella se necessario.
    """
    if DATA_DIR:
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
        except Exception:
            pass
        return os.path.join(DATA_DIR, filename)
    return filename


class TlsConfigError(Exception):
    """Configurazione TLS nativa incompleta o non valida (fail-closed)."""
    pass


def resolve_tls_config():
    """Risolve la configurazione TLS nativa opzionale (finding H-1).

    Legge SENTINELNET_SSL_CERTFILE e SENTINELNET_SSL_KEYFILE. Ritorna
    (certfile, keyfile) se entrambe presenti e leggibili, (None, None) se
    entrambe assenti (HTTP invariato). Se ne è impostata una sola, o un file
    non è leggibile, solleva TlsConfigError con messaggio in italiano
    (il chiamante deve terminare con exit code != 0).

    I percorsi relativi sono risolti rispetto a DATA_DIR, così il
    comportamento è identico tra sorgente, exe e Docker.
    """
    cert = os.environ.get("SENTINELNET_SSL_CERTFILE", "").strip()
    key = os.environ.get("SENTINELNET_SSL_KEYFILE", "").strip()
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
    """Migrazione una tantum: sposta i file di stato lasciati in CWD dalle
    versioni precedenti dentro DATA_DIR (senza toccare backup-config/ e
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
            except Exception:
                continue
        if name in _SENSITIVE_FILES and os.path.exists(dst):
            restrict_permissions(dst)


_migrate_legacy_files()
