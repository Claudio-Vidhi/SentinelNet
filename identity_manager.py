# -*- coding: utf-8 -*-
"""Identita' (profili credenziali) legate a un tenant.

Ogni identita' e' un set nominato di credenziali SSH (username, password,
enable secret) riusabile dai device dell'inventario tramite il valore
'identity:<id>' del campo Profile in hosts.csv. Le password sono cifrate
con Fernet (crypto_vault) come per hosts.csv; le API di lettura non
espongono MAI i segreti.
"""
import os
import json
import uuid
import threading

import data_config
from crypto_vault import encrypt_password, decrypt_password

IDENTITIES_JSON = data_config.get_path("identities.json")
_lock = threading.RLock()


def _load() -> list:
    if not os.path.exists(IDENTITIES_JSON):
        return []
    with open(IDENTITIES_JSON, "r", encoding="utf-8") as f:
        return json.load(f).get("identities", [])


def _save(identities: list):
    from inventory_manager import safe_json_write
    safe_json_write(IDENTITIES_JSON, {"identities": identities})


def _devices_using(identity_id: str) -> list:
    import inventory_manager
    key = f"identity:{identity_id}"
    return [d.get("IP") for d in inventory_manager.get_all_devices()
            if d.get("Profile") == key]


def get_identities(tenant: str = None) -> list:
    """Lista identita' SENZA segreti; opzionale filtro per tenant."""
    with _lock:
        rows = _load()
    if tenant:
        rows = [r for r in rows if r.get("tenant") == tenant]
    return [{"id": r["id"], "name": r["name"], "tenant": r["tenant"],
             "username": r["username"],
             "devices_using": len(_devices_using(r["id"]))} for r in rows]


def get_identity_credentials(identity_id: str):
    """(username, password, secret) in chiaro — SOLO per uso interno
    (connessioni agli apparati). None se l'identita' non esiste."""
    with _lock:
        for r in _load():
            if r["id"] == identity_id:
                return (r["username"],
                        decrypt_password(r.get("password_enc", "")),
                        decrypt_password(r.get("secret_enc", "")))
    return None


def add_identity(name: str, tenant: str, username: str,
                 password: str, secret: str) -> dict:
    ident = {
        "id": uuid.uuid4().hex,
        "name": name.strip(),
        "tenant": tenant,
        "username": username,
        "password_enc": encrypt_password(password),
        "secret_enc": encrypt_password(secret),
    }
    with _lock:
        rows = _load()
        rows.append(ident)
        _save(rows)
    return {"id": ident["id"], "name": ident["name"], "tenant": tenant}


def update_identity(identity_id: str, name: str, tenant: str,
                    username: str, password: str, secret: str) -> bool:
    with _lock:
        rows = _load()
        for r in rows:
            if r["id"] == identity_id:
                r.update(name=name.strip(), tenant=tenant, username=username,
                         password_enc=encrypt_password(password),
                         secret_enc=encrypt_password(secret))
                _save(rows)
                return True
    return False


def delete_identity(identity_id: str):
    """Ritorna (ok, devices_bloccanti). Rifiuta se qualche device usa
    l'identita' (il chiamante risponde 409 con la lista IP)."""
    devices = _devices_using(identity_id)
    if devices:
        return False, devices
    with _lock:
        rows = [r for r in _load() if r["id"] != identity_id]
        _save(rows)
    return True, []
