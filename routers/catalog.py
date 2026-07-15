# -*- coding: utf-8 -*-
"""Router Catalog. Estratto da app_server.py (fase 6.6): percorsi, metodi,
parametri e risposte identici al monolite."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import inventory_manager
import core_engine
from security_manager import log_audit
from routers.deps import (
    get_current_user, require_operator, user_group_scope, filter_map_to_scope
)

router = APIRouter(tags=["Catalog"])

class GroupSchema(BaseModel):
    name: str
    description: str = ""

class GroupDeleteSchema(BaseModel):
    name: str

class GroupRenameSchema(BaseModel):
    old_name: str
    new_name: str
    description: str = ""

class VendorSchema(BaseModel):
    name: str
    euvd_term: str
    driver: Optional[str] = None

class VendorDeleteSchema(BaseModel):
    name: str

class CategoryCreateSchema(BaseModel):
    key: str
    label: str = ""
    subcategory: str = ""

class CategoryDeleteSchema(BaseModel):
    key: str

class SubcategoryDeleteSchema(BaseModel):
    key: str
    subcategory: str

class DeviceCategorySchema(BaseModel):
    node_id: str
    category: Optional[str] = None     # "" rimuove l'override (torna ad auto); None = invariato
    subcategory: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    ha_group: Optional[str] = None     # etichetta coppia HA (vuoto = nessuna)
    name: Optional[str] = None         # nome scelto per risolvere conflitti CDP/LLDP
    version: Optional[str] = None      # versione scelta per risolvere conflitti

class ModelSchema(BaseModel):
    vendor: str
    model: str


# --- ROTTE ---

@router.get("/api/groups")
def list_groups(current_user = Depends(get_current_user)):
    groups = inventory_manager.get_all_groups()
    scope = user_group_scope(current_user)
    if scope is not None:
        groups = {g: v for g, v in groups.items() if g in scope}
    return groups

@router.post("/api/groups")
def create_group(group: GroupSchema, current_user = Depends(require_operator)):
    name = group.name
    if not name:
        raise HTTPException(status_code=400, detail="Il nome del gruppo è obbligatorio.")
    groups = inventory_manager.get_all_groups()
    groups[name] = {"description": group.description}
    inventory_manager.save_groups(groups)
    log_audit(f"Gruppo '{name}' (descrizione: '{group.description}') creato dall'utente '{current_user.get('sub')}'.")
    return {"status": "success", "message": "Gruppo creato"}

@router.post("/api/groups/rename")
def rename_group(payload: GroupRenameSchema, current_user = Depends(require_operator)):
    """Rinomina una sede/gruppo (admin/operator) e riassegna i relativi apparati.
    'Generale' non è rinominabile."""
    old = payload.old_name.strip()
    new = payload.new_name.strip()
    if not old or not new:
        raise HTTPException(status_code=400, detail="Nomi gruppo obbligatori.")
    if old == "Generale":
        raise HTTPException(status_code=400, detail="Il gruppo 'Generale' non è rinominabile.")
    assert_group_allowed(current_user, old)
    groups = inventory_manager.get_all_groups()
    if old not in groups:
        raise HTTPException(status_code=404, detail="Gruppo non trovato.")
    if new != old and new in groups:
        raise HTTPException(status_code=400, detail=f"Esiste già un gruppo '{new}'.")
    if not inventory_manager.update_group(old, new, payload.description):
        raise HTTPException(status_code=400, detail="Rinomina non riuscita.")
    log_audit(f"Gruppo '{old}' rinominato in '{new}' dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/groups/delete")
def remove_group(payload: GroupDeleteSchema, current_user = Depends(require_operator)):
    group_name = payload.name
    assert_group_allowed(current_user, group_name)
    groups = inventory_manager.get_all_groups()
    if group_name in groups and group_name != "Generale":
        inventory_manager.delete_group(group_name)
        log_audit(f"Gruppo '{group_name}' eliminato dall'utente '{current_user.get('sub')}'. Tutti i relativi apparati sono riassegnati a 'Generale'.")
        return {"status": "success"}
    raise HTTPException(status_code=400, detail="Impossibile eliminare il gruppo")

@router.get("/api/vendors")
def list_vendors(current_user = Depends(get_current_user)):
    return inventory_manager.get_all_vendors()

@router.post("/api/vendors")
def create_vendor(v: VendorSchema, current_user = Depends(require_operator)):
    vendors = inventory_manager.get_all_vendors()
    vendors[v.name.lower().strip()] = {"euvd_term": v.euvd_term, "driver": v.driver}
    inventory_manager.save_vendors(vendors)
    log_audit(f"Vendor '{v.name}' aggiunto/aggiornato da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/vendors/delete")
def delete_vendor(v: VendorDeleteSchema, current_user = Depends(require_operator)):
    vendors = inventory_manager.get_all_vendors()
    if v.name.lower() in ("cisco", "hpe"):
        raise HTTPException(status_code=400, detail="Vendor di sistema non eliminabile.")
    vendors.pop(v.name.lower().strip(), None)
    inventory_manager.save_vendors(vendors)
    log_audit(f"Vendor '{v.name}' eliminato da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.get("/api/device-classification")
def device_classification(current_user = Depends(get_current_user)):
    """Elenco completo dei dispositivi (inventariati + scoperti via CDP/LLDP) con
    categoria, sede e conteggi per categoria. Usato dal pannello Dispositivi."""
    scope = user_group_scope(current_user)
    data = core_engine.generate_network_map(group_filter="all")
    data = filter_map_to_scope(data, scope)

    cats = inventory_manager.get_device_categories()
    assignments = cats["assignments"]

    nodes = []
    counts_by_category: dict = {}
    counts_by_group: dict = {}
    for n in data["nodes"]:
        a = assignments.get(n["id"], {})
        dtype = n.get("device_type", "switch")
        group = n.get("group", "Generale")
        discovered = n.get("status") == "discovered"
        # IP mostrato in tabella: per i nodi scoperti l'IP annunciato (CDP/LLDP),
        # non l'id sintetico "discovered_<hostname>".
        display_ip = (n.get("reported_ip") or "") if discovered else n["id"]
        node = {
            "id": n["id"],
            "display_ip": display_ip,
            "label": n.get("label", n["id"]),
            "group": group,
            "status": n.get("status"),
            "device_type": dtype,
            "subcategory": a.get("subcategory", ""),
            "is_manual": bool(a.get("category")),
            "vendor": a.get("vendor") or n.get("vendor"),
            "model": a.get("model") or n.get("model") or "",
            "ha_group": a.get("ha_group", ""),
            "version": n.get("version"),
            "vtp_domain": n.get("vtp_domain"),
            "vtp_mode": n.get("vtp_mode"),
            "discovered": discovered,
            "name_options": n.get("name_options") or [],
        }
        nodes.append(node)
        counts_by_category[dtype] = counts_by_category.get(dtype, 0) + 1
        counts_by_group[group] = counts_by_group.get(group, 0) + 1

    return {
        "categories": cats["categories"],
        "nodes": nodes,
        "counts_by_category": counts_by_category,
        "counts_by_group": counts_by_group,
        "vendors": sorted(inventory_manager.get_all_vendors().keys()),
        "models": inventory_manager.get_models(),
        "total": len(nodes),
    }

@router.post("/api/device-categories")
def create_device_category(payload: CategoryCreateSchema, current_user = Depends(require_operator)):
    """Crea una categoria custom o aggiunge una sottocategoria (admin/operator)."""
    if not inventory_manager.add_category(payload.key, payload.label, payload.subcategory):
        raise HTTPException(status_code=400, detail="Chiave categoria non valida.")
    log_audit(
        f"Categoria '{payload.key}' (sub: '{payload.subcategory or '-'}') creata/aggiornata "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

@router.post("/api/device-categories/delete")
def delete_device_category(payload: CategoryDeleteSchema, current_user = Depends(require_operator)):
    if not inventory_manager.delete_category(payload.key):
        raise HTTPException(status_code=400, detail="Categoria di sistema o inesistente.")
    log_audit(f"Categoria '{payload.key}' eliminata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/device-categories/delete-subcategory")
def delete_subcategory_ep(payload: SubcategoryDeleteSchema, current_user = Depends(require_operator)):
    if not inventory_manager.delete_subcategory(payload.key, payload.subcategory):
        raise HTTPException(status_code=404, detail="Sottocategoria non trovata.")
    log_audit(f"Sottocategoria '{payload.subcategory}' di '{payload.key}' eliminata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/device-categories/assign")
def assign_device_category(payload: DeviceCategorySchema, current_user = Depends(require_operator)):
    """Aggiorna gli attributi manuali di un dispositivo: categoria, sottocategoria,
    vendor e/o modello (admin/operator). I campi non forniti restano invariati."""
    fields = {k: v for k, v in {
        "category": payload.category,
        "subcategory": payload.subcategory,
        "vendor": payload.vendor,
        "model": payload.model,
        "ha_group": payload.ha_group,
        "name": payload.name,
        "ver": payload.version,
    }.items() if v is not None}
    if not inventory_manager.set_device_meta(payload.node_id, **fields):
        raise HTTPException(status_code=400, detail="Aggiornamento non valido.")
    # Se è stato indicato un nuovo modello con un vendor, lo si registra anche nel
    # catalogo modelli del vendor, così diventa riutilizzabile.
    if payload.model and payload.vendor:
        inventory_manager.add_model(payload.vendor, payload.model)
    log_audit(
        f"Attributi dispositivo '{payload.node_id}' aggiornati ({fields}) "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

@router.get("/api/models")
def list_models(current_user = Depends(get_current_user)):
    return inventory_manager.get_models()

@router.post("/api/models")
def create_model(payload: ModelSchema, current_user = Depends(require_operator)):
    if not inventory_manager.add_model(payload.vendor, payload.model):
        raise HTTPException(status_code=400, detail="Vendor e modello obbligatori.")
    log_audit(f"Modello '{payload.model}' (vendor: {payload.vendor}) aggiunto da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/models/delete")
def remove_model(payload: ModelSchema, current_user = Depends(require_operator)):
    if not inventory_manager.delete_model(payload.vendor, payload.model):
        raise HTTPException(status_code=404, detail="Modello non trovato.")
    log_audit(f"Modello '{payload.model}' (vendor: {payload.vendor}) eliminato da '{current_user.get('sub')}'.")
    return {"status": "success"}

