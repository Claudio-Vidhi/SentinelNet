# -*- coding: utf-8 -*-
"""Community SNMP predefinita per tenant, con override per apparato.

PERCHE' UN FILE A PARTE E NON ``groups.json``: ``routers/inventory.py``
restituisce al browser il dizionario di ogni gruppo per intero. Un segreto
messo li' verrebbe spedito a ogni utente, e la protezione dipenderebbe dal
fatto che ogni futuro serializzatore di gruppi si ricordi di ripulirlo. Qui
la fuga e' strutturalmente impossibile — stessa scelta gia' fatta per le
identita' in ``identity_manager.py``.

La community e' cifrata con Fernet come ogni altra credenziale. Le API di
lettura espongono i NOMI dei tenant che ne hanno una, mai il valore.
"""
import json
import logging
import os
import threading
from typing import Optional

from core import data_config
from security.crypto_vault import encrypt_password, decrypt_password

TENANT_SNMP_JSON = data_config.get_path("tenant_snmp.json")
_lock = threading.RLock()


def _load() -> dict:
    if not os.path.exists(TENANT_SNMP_JSON):
        return {}
    try:
        with open(TENANT_SNMP_JSON, "r", encoding="utf-8") as f:
            return json.load(f).get("tenants", {})
    except Exception as e:
        # Stessa tolleranza di identities.json: un file corrotto non deve
        # impedire l'avvio, ma non deve nemmeno fingere che ci sia un default.
        logging.warning("Errore caricamento tenant_snmp.json: %s", e)
        return {}


def _save(tenants: dict) -> None:
    from services.inventory_manager import safe_json_write
    safe_json_write(TENANT_SNMP_JSON, {"tenants": tenants})


def get_tenant_community(tenant: str) -> str:
    """Community predefinita del tenant, in chiaro. "" se non configurata.

    SOLO per uso interno (interrogazione degli apparati): non deve finire in
    nessuna risposta HTTP.
    """
    with _lock:
        entry = _load().get(tenant or "Generale") or {}
    return decrypt_password(entry.get("community_enc", "")) or ""


def set_tenant_community(tenant: str, community: str) -> None:
    """Imposta o rimuove ("" rimuove) il default del tenant."""
    key = tenant or "Generale"
    with _lock:
        tenants = _load()
        if community:
            tenants[key] = {"community_enc": encrypt_password(community)}
        else:
            tenants.pop(key, None)
        _save(tenants)


def tenants_with_default() -> set:
    """I NOMI dei tenant che hanno un default. Nessun segreto."""
    with _lock:
        return set(_load().keys())


def resolve_snmp_community(device: dict) -> str:
    """Community effettiva di un apparato. "" significa NON interrogarlo.

    Precedenza, dalla piu' forte: il flag di esclusione, poi la community
    dell'apparato, poi il default del tenant.

    Il flag esiste perche' senza di lui "non impostata" e "spenta di
    proposito" sarebbero lo stesso valore: attivare un default di tenant
    comincerebbe a interrogare apparati che erano volutamente fuori, e la
    community viaggia in chiaro (SNMPv2c).
    """
    if str(device.get("SNMP Disabled") or "").strip() in ("1", "true", "True"):
        return ""
    own = decrypt_password(device.get("SNMP Community") or "") or ""
    if own:
        return own
    return get_tenant_community(device.get("Group") or "Generale")
