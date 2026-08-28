# -*- coding: utf-8 -*-
"""Configuration of the offsite mirror, stored in app_settings.json.

Secrets go through the same Fernet vault the device credentials use: they are
written encrypted and never returned to the API in clear.
"""

from core import app_settings
from security.crypto_vault import encrypt_password, decrypt_password

SECTION = "cloud_backup"

# Secret fields: stored as "<name>_enc", returned to the API as "" plus a
# has_<name> flag so the UI can show "configured" without ever seeing it.
_SECRETS = ("password", "key_passphrase")

_DEFAULTS = {
    "enabled": False,
    "kind": "sftp",
    "host": "",
    "port": 22,
    "username": "",
    "auth": "key",              # "key" | "password"
    "key_path": "",
    "remote_root": "",
    "host_key_fingerprint": "",
    "encrypt_payload": False,
    "run_after_backup": True,
    "stale_after_hours": 48,
}


def _stored() -> dict:
    section = app_settings.get_app_settings().get(SECTION)
    return dict(section) if isinstance(section, dict) else {}


def read() -> dict:
    """Full config with secrets decrypted. Internal use only."""
    cfg = dict(_DEFAULTS)
    cfg.update(_stored())
    for name in _SECRETS:
        cfg[name] = decrypt_password(str(cfg.pop(f"{name}_enc", "") or ""))
    return cfg


def redacted() -> dict:
    """Config for the API: no secret, only whether one is configured."""
    stored = _stored()
    cfg = dict(_DEFAULTS)
    cfg.update(stored)
    for name in _SECRETS:
        cfg.pop(f"{name}_enc", None)
        cfg[name] = ""
        cfg[f"has_{name}"] = bool(stored.get(f"{name}_enc"))
    return cfg


def save(cfg: dict) -> None:
    """Persists the config. An empty secret keeps the stored one: the UI never
    receives the current value, so it cannot send it back."""
    stored = _stored()
    out = {k: v for k, v in cfg.items() if k not in _SECRETS}
    for name in _SECRETS:
        value = (cfg.get(name) or "").strip()
        key = f"{name}_enc"
        if value:
            out[key] = encrypt_password(value)
        elif stored.get(key):
            out[key] = stored[key]
    app_settings.save_app_settings({SECTION: out})


def is_enabled() -> bool:
    return bool(_stored().get("enabled"))


def validate(cfg: dict) -> list[str]:
    """Boundary validation: this config comes from a user form."""
    errors = []
    if not (cfg.get("host") or "").strip():
        errors.append("host: obbligatorio")
    try:
        port = int(cfg.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    if not 1 <= port <= 65535:
        errors.append("port: fuori intervallo 1-65535")
    if not (cfg.get("username") or "").strip():
        errors.append("username: obbligatorio")
    remote_root = (cfg.get("remote_root") or "").strip()
    if not remote_root:
        errors.append("remote_root: obbligatorio")
    elif not remote_root.startswith("/"):
        # ensure_dir() always builds an absolute path while put() writes
        # relative to the SSH home: a relative root makes the two disagree and
        # every upload fails with "No such file".
        errors.append("remote_root: percorso assoluto obbligatorio (deve iniziare con /)")
    if cfg.get("auth") == "key" and not (cfg.get("key_path") or "").strip():
        errors.append("key_path: obbligatorio con autenticazione a chiave")
    if (cfg.get("auth") == "password" and not (cfg.get("password") or "").strip()
            and not _stored().get("password_enc")):
        errors.append("password: obbligatoria con autenticazione a password")
    return errors
