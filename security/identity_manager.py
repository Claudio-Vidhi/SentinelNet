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
import logging
from typing import Optional

from core import data_config
from security.crypto_vault import encrypt_password, decrypt_password

IDENTITIES_JSON = data_config.get_path("identities.json")
_lock = threading.RLock()


def _load() -> list:
    if not os.path.exists(IDENTITIES_JSON):
        return []
    try:
        with open(IDENTITIES_JSON, "r", encoding="utf-8") as f:
            return json.load(f).get("identities", [])
    except Exception as e:
        # Tolleranza per identities.json corrotto: log avviso e ritorna lista vuota
        logging.warning(f"Errore caricamento identities.json: {e}")
        return []


def _save(identities: list):
    from services.inventory_manager import safe_json_write
    safe_json_write(IDENTITIES_JSON, {"identities": identities})


def _devices_using(identity_id: str) -> list:
    from services import inventory_manager
    key = f"identity:{identity_id}"
    return [d.get("IP") for d in inventory_manager.get_all_devices()
            if d.get("Profile") == key]


def _matches_tenant(r_tenant, target_tenant: str) -> bool:
    if not target_tenant or target_tenant == "all":
        return True
    if not r_tenant or r_tenant == "all":
        return True
    if isinstance(r_tenant, list):
        return target_tenant in r_tenant or "all" in r_tenant
    if isinstance(r_tenant, str):
        tenants = [t.strip() for t in r_tenant.split(",") if t.strip()]
        return target_tenant in tenants or "all" in tenants
    return False


def _normalize_tenant(tenant):
    if not tenant:
        return "all"
    if isinstance(tenant, list):
        clean = [str(t).strip() for t in tenant if str(t).strip()]
        if not clean or "all" in clean:
            return "all"
        if len(clean) == 1:
            return clean[0]
        return clean
    if isinstance(tenant, str):
        clean_str = tenant.strip()
        if not clean_str or clean_str == "all":
            return "all"
        if "," in clean_str:
            clean_list = [t.strip() for t in clean_str.split(",") if t.strip()]
            if not clean_list or "all" in clean_list:
                return "all"
            if len(clean_list) == 1:
                return clean_list[0]
            return clean_list
        return clean_str
    return "all"


def get_identities(tenant: Optional[str] = None) -> list:
    """Lista identita' SENZA segreti; opzionale filtro per tenant. 'all' o vuoto include globali."""
    with _lock:
        rows = _load()
    if tenant and tenant != "all":
        rows = [r for r in rows if _matches_tenant(r.get("tenant"), tenant)]
    return [{"id": r["id"], "name": r["name"], "tenant": r.get("tenant", "all"),
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


def identity_visible_to(identity_id: str, tenants) -> bool:
    """True if a caller whose allowed sites are ``tenants`` may use this
    identity. ``tenants`` is a set of site names, or None for an unrestricted
    caller (admin) — the same shape routers/deps.py:user_group_scope returns.
    Global identities ('all') are visible to everyone. Unknown id -> False."""
    with _lock:
        row = next((r for r in _load() if r["id"] == identity_id), None)
    if row is None:
        return False
    if tenants is None:
        return True
    return any(_matches_tenant(row.get("tenant"), t) for t in tenants)


def add_identity(name: str, tenant, username: str,
                 password: str, secret: str) -> dict:
    ident = {
        "id": uuid.uuid4().hex,
        "name": name.strip(),
        "tenant": _normalize_tenant(tenant),
        "username": username,
        "password_enc": encrypt_password(password),
        "secret_enc": encrypt_password(secret),
    }
    with _lock:
        rows = _load()
        rows.append(ident)
        _save(rows)
    return {"id": ident["id"], "name": ident["name"], "tenant": ident["tenant"]}


def update_identity(identity_id: str, name: str, tenant,
                    username: str, password: str = "", secret: str = "") -> bool:
    with _lock:
        rows = _load()
        for r in rows:
            if r["id"] == identity_id:
                r["name"] = name.strip()
                r["tenant"] = _normalize_tenant(tenant)
                r["username"] = username
                if password:
                    r["password_enc"] = encrypt_password(password)
                if secret:
                    r["secret_enc"] = encrypt_password(secret)
                _save(rows)
                return True
    return False


def delete_identity(identity_id: str):
    """Ritorna (ok, devices_bloccanti). Rifiuta se qualche device usa
    l'identita' (il chiamante risponde 409 con la lista IP)."""
    with _lock:
        devices = _devices_using(identity_id)
        if devices:
            return False, devices
        rows = [r for r in _load() if r["id"] != identity_id]
        _save(rows)
    return True, []
