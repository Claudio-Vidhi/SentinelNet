# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router Catalog. Estratto da app_server.py (fase 6.6): percorsi, metodi,
parametri e risposte identici al monolite."""

import json
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from routers.deps import require_tab
from pydantic import BaseModel, Field

from services import inventory_manager
from core import core_engine, data_config
from security.security_manager import log_audit
from routers.deps import (
    get_current_user, require_unscoped_admin, require_operator, user_group_scope,
    filter_map_to_scope, assert_group_allowed, assert_device_allowed
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


# --- ROTTE ---

@router.get("/api/groups", dependencies=[Depends(require_tab("tab-groups", "tab-provisioning"))])
def list_groups(current_user = Depends(get_current_user)):
    groups = inventory_manager.get_all_groups()
    scope = user_group_scope(current_user)
    if scope is not None:
        groups = {g: v for g, v in groups.items() if g in scope}
    return groups

# Open to scoped users on purpose: creating a tenant touches no other tenant's data (rename/delete are guarded).
@router.post("/api/groups", dependencies=[Depends(require_tab("tab-groups", "tab-provisioning"))])
def create_group(group: GroupSchema, current_user = Depends(require_operator)):
    name = group.name
    if not name:
        raise HTTPException(status_code=400, detail="Il nome del gruppo è obbligatorio.")
    groups = inventory_manager.get_all_groups()
    groups[name] = {"description": group.description}
    inventory_manager.save_groups(groups)
    log_audit(f"Gruppo '{name}' (descrizione: '{group.description}') creato dall'utente '{current_user.get('sub')}'.")
    return {"status": "success", "message": "Gruppo creato"}

@router.post("/api/groups/rename", dependencies=[Depends(require_tab("tab-groups"))])
def rename_group(payload: GroupRenameSchema, current_user = Depends(require_unscoped_admin)):
    """Rinomina un tenant e riassegna i relativi apparati. 'Generale' non è
    rinominabile.

    Solo admin: rinominare un tenant riscrive l'assegnazione di TUTTI i suoi
    apparati e cambia lo scope RBAC di chi vi è limitato. La creazione resta
    operator (serve durante il provisioning, tab Provisioning)."""
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

@router.post("/api/groups/delete", dependencies=[Depends(require_tab("tab-groups"))])
def remove_group(payload: GroupDeleteSchema, current_user = Depends(require_unscoped_admin)):
    """Elimina un tenant. Solo admin: e' distruttivo e tocca lo scope RBAC."""
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

@router.post("/api/vendors", dependencies=[Depends(require_tab("tab-groups"))])
def create_vendor(v: VendorSchema, current_user = Depends(require_operator)):
    vendors = inventory_manager.get_all_vendors()
    vendors[v.name.lower().strip()] = {"driver": v.driver}
    inventory_manager.save_vendors(vendors)
    log_audit(f"Vendor '{v.name}' aggiunto/aggiornato da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/vendors/delete", dependencies=[Depends(require_tab("tab-groups"))])
def delete_vendor(v: VendorDeleteSchema, current_user = Depends(require_operator)):
    vendors = inventory_manager.get_all_vendors()
    if v.name.lower() in ("cisco", "hpe"):
        raise HTTPException(status_code=400, detail="Vendor di sistema non eliminabile.")
    vendors.pop(v.name.lower().strip(), None)
    inventory_manager.save_vendors(vendors)
    log_audit(f"Vendor '{v.name}' eliminato da '{current_user.get('sub')}'.")
    return {"status": "success"}

def assemble_classification(scope):
    """Build the classification rows shared by the tab endpoint and the CSV
    export: network map filtered to scope, merged with manual category
    assignments, plus per-category/per-group counts."""
    data = core_engine.generate_network_map(group_filter="all")
    data = filter_map_to_scope(data, scope)

    cats = inventory_manager.get_device_categories()
    assignments = cats["assignments"]

    nodes = []
    counts_by_category: dict = {}
    counts_by_group: dict = {}
    for n in data["nodes"]:
        red = n.get("redundancy") or {}
        dtype = n.get("device_type", "switch")
        group = n.get("group", "Generale")
        discovered = n.get("status") == "discovered"
        # Same key the save path writes: a discovered node has no site of its
        # own and is filed under 'Generale' (see tenant_for_node).
        a = assignments.get(inventory_manager._akey(None if discovered else group, n["id"]), {})
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
            "serial": n.get("serial") or "",
            "ha_group": a.get("ha_group", ""),
            "version": n.get("version"),
            "vtp_domain": n.get("vtp_domain"),
            "vtp_mode": n.get("vtp_mode"),
            "discovered": discovered,
            # A saved name is the user's answer to the CDP/LLDP conflict.
            "name_options": [] if a.get("name") else (n.get("name_options") or []),
            # Badge stack (già calcolato da generate_network_map): unità fisiche
            # dietro questo IP di management.
            "stack": red if red.get("type") == "stack" else None,
        }
        nodes.append(node)
        counts_by_category[dtype] = counts_by_category.get(dtype, 0) + 1
        counts_by_group[group] = counts_by_group.get(group, 0) + 1

    return {
        "categories": cats["categories"],
        "nodes": nodes,
        "links": data.get("links", []),
        "counts_by_category": counts_by_category,
        "counts_by_group": counts_by_group,
        "vendors": sorted(inventory_manager.get_all_vendors().keys()),
        "models": inventory_manager.get_models(),
        "total": len(nodes),
    }

@router.get("/api/device-classification", dependencies=[Depends(require_tab("tab-categories"))])
def device_classification(current_user = Depends(get_current_user)):
    """Elenco completo dei dispositivi (inventariati + scoperti via CDP/LLDP) con
    categoria, sede e conteggi per categoria. Usato dal pannello Dispositivi."""
    data = assemble_classification(user_group_scope(current_user))
    # `links` is only needed by the export: adding it here would change the
    # shape of this response, which the frontend and the OpenAPI snapshot rely on.
    return {k: v for k, v in data.items() if k != "links"}


_CLASSIFICATION_COLUMNS = {
    "hostname":         ("Hostname",         lambda n, l: n.get("label") or n["id"]),
    "ip":               ("IP",               lambda n, l: n.get("display_ip", "")),
    "tenant":           ("Tenant",           lambda n, l: n.get("group", "")),
    "category":         ("Category",         lambda n, l: n.get("device_type", "")),
    "subcategory":      ("Subcategory",      lambda n, l: n.get("subcategory", "")),
    "vendor":           ("Vendor",           lambda n, l: n.get("vendor", "")),
    "model":            ("Model",            lambda n, l: n.get("model", "")),
    "version":          ("Version",          lambda n, l: n.get("version") or ""),
    "status":           ("Status",           lambda n, l: n.get("status", "")),
    "discovered":       ("Discovered",       lambda n, l: "yes" if n.get("discovered") else "no"),
    "serial":           ("Serial",           lambda n, l: n.get("serial", "")),
    "serial_seen_at":   ("Serial Seen At",   lambda n, l: n.get("serial_seen_at", "")),
    "neighbour_device": ("Neighbour Device", lambda n, l: l.get("device", "")),
    "neighbour_port":   ("Neighbour Port",   lambda n, l: l.get("port", "")),
    "neighbour_category": ("Neighbour Category", lambda n, l: l.get("category", "")),
    "neighbour_subcategory": ("Neighbour Subcategory", lambda n, l: l.get("subcategory", "")),
    "neighbour_ip":     ("Neighbour IP",     lambda n, l: l.get("ip", "")),
    "neighbour_model":  ("Neighbour Model",  lambda n, l: l.get("model", "")),
    "neighbour_serial": ("Neighbour Serial", lambda n, l: l.get("serial", "")),
    "member_index":     ("Member #",         lambda n, l: l.get("member_index", "")),
    "member_role":      ("Member Role",      lambda n, l: l.get("member_role", "")),
    "member_serial":    ("Member Serial",    lambda n, l: l.get("member_serial", "")),
    "member_model":     ("Member Model",     lambda n, l: l.get("member_model", "")),
}

# Asking for one of these columns means asking for one row per neighbour: a
# device with redundant uplinks has more than one, and a joined cell cannot be
# filtered or looked up in a spreadsheet -- the same reason _MEMBER_COLUMNS
# explodes rows in the device export.
_NEIGHBOUR_COLUMNS = frozenset((
    "neighbour_device", "neighbour_port", "neighbour_category",
    "neighbour_subcategory", "neighbour_ip", "neighbour_model", "neighbour_serial"
))

# A stack answers on one management IP but carries one serial per physical
# unit, and the scan stores those on the redundancy group, not on the device:
# without these columns the Serial cell of every stacked switch is empty.
# Same rule as the device export -- one row per unit, never a joined cell.
_MEMBER_COLUMNS = frozenset(("member_index", "member_role",
                             "member_serial", "member_model"))

_DEFAULT_CLASSIFICATION_COLUMNS = ["hostname", "ip", "tenant", "category", "status"]


def _neighbours_of(node_id: str, links: list, label_of: dict,
                   category_of: dict, versions: Optional[dict] = None,
                   ap_entries: Optional[dict] = None, nodes_by_id: Optional[dict] = None) -> list:
    """Neighbours of one node, each as {device, port, category, subcategory, ip, model, serial}.

    The port reported is the NEIGHBOUR's own port -- the one you patch -- not
    the port on the device whose row this is. A link stores local_port for its
    source and remote_port for its target, so which one to read depends on
    which end this node sits at.
    """
    from services import ap_store
    out = []
    versions = versions or {}
    ap_entries = ap_entries or {}
    nodes_by_id = nodes_by_id or {}
    for link in links:
        if link.get("target") == node_id:
            other, port = link.get("source"), link.get("local_port")
        elif link.get("source") == node_id:
            other, port = link.get("target"), link.get("remote_port")
        else:
            continue

        other_node = nodes_by_id.get(other) or {}
        other_label = label_of.get(other, other or "")
        other_cat = category_of.get(other, "")
        other_subcat = other_node.get("subcategory", "")
        other_ip = str(other_node.get("display_ip") or other_node.get("reported_ip")
                        or other_node.get("ip") or (versions.get(other) or {}).get("ip", "") or "")

        scan = (versions.get(other)
                or (versions.get(other_ip) if other_ip else None)
                or (versions.get(other_node.get("id")) if other_node else None)
                or {})
        entry = (ap_store.lookup_in(ap_entries, other_label, other_node.get("group"), ip=other_ip)
                 or ap_store.lookup_in(ap_entries, other_label, other_node.get("group")))
        other_serial = other_node.get("serial") or scan.get("serial") or (entry or {}).get("serial", "")
        other_model = other_node.get("model") or scan.get("model") or (entry or {}).get("model", "")

        out.append({
            "device": other_label,
            "port": port or "",
            "category": other_cat,
            "subcategory": other_subcat,
            "ip": other_ip,
            "model": other_model,
            "serial": other_serial,
        })
    return out


@router.get("/api/export/classification/columns", dependencies=[Depends(require_tab("tab-categories"))])
def export_classification_columns(current_user = Depends(get_current_user)):
    """Available columns and defaults, so the UI does not duplicate the
    registry."""
    return {
        "columns": [
            {"key": k, "header": h,
             "per_neighbour": k in _NEIGHBOUR_COLUMNS,
             "explodes": k in _NEIGHBOUR_COLUMNS or k in _MEMBER_COLUMNS}
            for k, (h, _) in _CLASSIFICATION_COLUMNS.items()
        ],
        "default": _DEFAULT_CLASSIFICATION_COLUMNS,
    }


def assemble_classification_rows(
    current_user: dict,
    columns: str = "",
    groups: str = "",
    categories: str = "",
    neighbour_categories: str = "",
    neighbour_source_categories: str = "",
    only_matching_neighbours: bool = False,
):
    from services import ap_store
    from redundancy import service as redundancy_service

    selected = [c.strip() for c in columns.split(",") if c.strip()] \
        or _DEFAULT_CLASSIFICATION_COLUMNS
    unknown = [c for c in selected if c not in _CLASSIFICATION_COLUMNS]
    if unknown:
        raise HTTPException(status_code=400,
                            detail=f"Colonne sconosciute: {', '.join(unknown)}")

    data = assemble_classification(user_group_scope(current_user))
    nodes, links = data["nodes"], data["links"]

    want_groups = {v.strip() for v in groups.split(",") if v.strip()}
    want_categories = {v.strip() for v in categories.split(",") if v.strip()}
    if want_groups:
        nodes = [n for n in nodes if n.get("group", "") in want_groups]
    if want_categories:
        nodes = [n for n in nodes if n.get("device_type", "") in want_categories]

    versions = inventory_manager.get_detected_versions()
    ap_entries = ap_store.read_all()
    label_of = {n["id"]: (n.get("label") or n["id"]) for n in data["nodes"]}
    category_of = {n["id"]: n.get("device_type", "") for n in data["nodes"]}
    nodes_by_id = {n["id"]: n for n in data["nodes"]}
    explode = any(c in _NEIGHBOUR_COLUMNS for c in selected)
    badges = (redundancy_service.redundancy_badges_by_ip()
              if any(c in _MEMBER_COLUMNS for c in selected) else {})
    want_neighbour_categories = {v.strip()
                                 for v in neighbour_categories.split(",") if v.strip()}
    want_neighbour_sources = {v.strip()
                              for v in neighbour_source_categories.split(",") if v.strip()}

    headers = [_CLASSIFICATION_COLUMNS[c][0] for c in selected]
    all_rows = []

    for node in nodes:
        node_ip = str(node.get("display_ip") or node.get("reported_ip") or "")
        scan = (versions.get(node["id"])
                or (versions.get(node_ip) if node_ip else None)
                or {})
        entry = (ap_store.lookup_in(ap_entries, node.get("label") or node.get("id") or "", node.get("group"), ip=node_ip)
                 or ap_store.lookup_in(ap_entries, node.get("label") or node.get("id") or "", node.get("group")))
        row_node = dict(node)
        row_node["serial"] = node.get("serial") or scan.get("serial") or (entry or {}).get("serial", "")
        row_node["serial_seen_at"] = (entry or {}).get("seen_at", "")

        node_cat = node.get("device_type", "")
        should_explode_neighbours = (
            (explode or only_matching_neighbours)
            and (not want_neighbour_sources or node_cat in want_neighbour_sources)
        )

        neighbours = (_neighbours_of(node["id"], links, label_of, category_of,
                                     versions=versions, ap_entries=ap_entries,
                                     nodes_by_id=nodes_by_id)
                      if should_explode_neighbours else [])

        if want_neighbour_categories and should_explode_neighbours:
            neighbours = [x for x in neighbours
                          if x["category"] in want_neighbour_categories]
            if not neighbours and only_matching_neighbours:
                continue
        elif want_neighbour_sources and node_cat not in want_neighbour_sources and only_matching_neighbours:
            continue

        members = [
            {"member_index": m.get("index", ""), "member_role": m.get("role", ""),
             "member_serial": m.get("serial", ""), "member_model": m.get("model", "")}
            for m in ((badges.get(node["id"]) or {}).get("members") or [])
        ]
        for link in (neighbours or [{}]):
            for member in (members or [{}]):
                all_rows.append([
                    _CLASSIFICATION_COLUMNS[c][1](row_node, {**link, **member})
                    for c in selected
                ])

    return headers, all_rows


@router.get("/api/export/classification", dependencies=[Depends(require_tab("tab-categories"))])
def export_classification_csv(
    columns: str = "",
    groups: str = "",
    categories: str = "",
    neighbour_categories: str = "",
    neighbour_source_categories: str = "",
    only_matching_neighbours: bool = False,
    current_user = Depends(get_current_user),
):
    import csv, io
    from fastapi.responses import Response as FastResponse
    from core.csv_safe import csv_cell

    headers, rows = assemble_classification_rows(
        current_user=current_user,
        columns=columns,
        groups=groups,
        categories=categories,
        neighbour_categories=neighbour_categories,
        neighbour_source_categories=neighbour_source_categories,
        only_matching_neighbours=only_matching_neighbours,
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    for r in rows:
        writer.writerow([csv_cell(val) for val in r])

    log_audit(f"Export CSV classificazione richiesto dall'utente "
              f"'{current_user.get('sub')}' (colonne: {columns or ','.join(_DEFAULT_CLASSIFICATION_COLUMNS)}).")
    return FastResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition":
                 "attachment; filename=sentinelnet-classification.csv"},
    )


@router.get("/api/export/classification/preview", dependencies=[Depends(require_tab("tab-categories"))])
def preview_classification_export(
    columns: str = "",
    groups: str = "",
    categories: str = "",
    neighbour_categories: str = "",
    neighbour_source_categories: str = "",
    only_matching_neighbours: bool = False,
    limit: int = 15,
    current_user = Depends(get_current_user),
):
    headers, rows = assemble_classification_rows(
        current_user=current_user,
        columns=columns,
        groups=groups,
        categories=categories,
        neighbour_categories=neighbour_categories,
        neighbour_source_categories=neighbour_source_categories,
        only_matching_neighbours=only_matching_neighbours,
    )
    safe_limit = max(1, min(limit, 100))
    return {
        "headers": headers,
        "rows": rows[:safe_limit],
        "total_rows": len(rows),
    }

@router.post("/api/device-categories", dependencies=[Depends(require_tab("tab-categories"))])
def create_device_category(payload: CategoryCreateSchema, current_user = Depends(require_operator)):
    """Crea una categoria custom o aggiunge una sottocategoria (admin/operator)."""
    if not inventory_manager.add_category(payload.key, payload.label, payload.subcategory):
        raise HTTPException(status_code=400, detail="Chiave categoria non valida.")
    log_audit(
        f"Categoria '{payload.key}' (sub: '{payload.subcategory or '-'}') creata/aggiornata "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

@router.post("/api/device-categories/delete", dependencies=[Depends(require_tab("tab-categories"))])
def delete_device_category(payload: CategoryDeleteSchema, current_user = Depends(require_operator)):
    if not inventory_manager.delete_category(payload.key):
        raise HTTPException(status_code=400, detail="Categoria di sistema o inesistente.")
    log_audit(f"Categoria '{payload.key}' eliminata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/device-categories/delete-subcategory", dependencies=[Depends(require_tab("tab-categories"))])
def delete_subcategory_ep(payload: SubcategoryDeleteSchema, current_user = Depends(require_operator)):
    if not inventory_manager.delete_subcategory(payload.key, payload.subcategory):
        raise HTTPException(status_code=404, detail="Sottocategoria non trovata.")
    log_audit(f"Sottocategoria '{payload.subcategory}' di '{payload.key}' eliminata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/device-categories/assign", dependencies=[Depends(require_tab("tab-categories"))])
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
    # Scope before writing: the assignment key carries the tenant, so resolve it
    # from the device the caller may see. A node outside inventory lives in
    # 'Generale', and the caller needs that group.
    device = assert_device_allowed(current_user, payload.node_id)
    tenant = (device.get("Group") or "Generale") if device else "Generale"
    assert_group_allowed(current_user, tenant)
    if not inventory_manager.set_device_meta(payload.node_id, tenant=tenant, **fields):
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


# --- AI suggestions (classification, naming, model catalogue) -----------------
# One request covers many devices: free AI tiers allow a few requests a day.
# Nothing here writes a device record except /api/device-models/merge, which
# the user confirms per merge; classification proposals are applied through
# /api/device-categories/assign like any manual edit.

def _ai_suggest_file() -> str:
    # Resolved per call, not at import: the data dir is pinned by tests and
    # set by the launcher, both after this module may have been imported.
    return data_config.get_path("ai_classification_suggestions.json")


class AiSuggestSchema(BaseModel):
    group: str = "all"
    lang: str = "it"


class AiModelsSchema(BaseModel):
    lang: str = "it"


class ModelMergeSchema(BaseModel):
    vendor: str
    canonical: str
    duplicates: list[str] = Field(default_factory=list)


def _load_ai_suggestions() -> dict:
    try:
        with open(_ai_suggest_file(), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = {}
    return {"suggestions": data.get("suggestions") or {},
            "conventions": data.get("conventions") or {}}


def _classify_queue(nodes: list, group: str = "all") -> list:
    """Same rule as the tab's "Da classificare": discovered, never confirmed."""
    return [n for n in nodes if n["discovered"] and not n["is_manual"]
            and (group in ("", "all") or n["group"] == group)]


@router.get("/api/device-classification/ai-suggestions", dependencies=[Depends(require_tab("tab-categories"))])
def get_ai_classification_suggestions(current_user = Depends(get_current_user)):
    """Saved proposals for devices still in the queue, so reopening the tab
    does not spend another request."""
    data = assemble_classification(user_group_scope(current_user))
    queue_ids = {n["id"] for n in _classify_queue(data["nodes"])}
    store = _load_ai_suggestions()
    return {
        "suggestions": {k: v for k, v in store["suggestions"].items() if k in queue_ids},
        "conventions": {t: c for t, c in store["conventions"].items() if t in data["counts_by_group"]},
    }


@router.post("/api/device-classification/ai-suggest", dependencies=[Depends(require_tab("tab-categories"))])
def run_ai_classification_suggest(payload: AiSuggestSchema, current_user = Depends(require_operator)):
    """One AI request for the classification queue: category, subcategory,
    vendor, model and, where the name breaks the tenant's convention, a name."""
    from ai import classification_assist as ca
    from routers.ai import chat_with_active_profile

    data = assemble_classification(user_group_scope(current_user))
    nodes = data["nodes"]
    queue = _classify_queue(nodes, payload.group)
    if not queue:
        raise HTTPException(status_code=400, detail="Nessun dispositivo da classificare.")
    store = _load_ai_suggestions()
    # Devices without a proposal first; once all have one, a run refreshes them.
    pending = [n for n in queue if n["id"] not in store["suggestions"]] or queue
    batch_nodes = pending[:ca.MAX_DEVICES_PER_RUN]

    by_id = {n["id"]: n for n in nodes}
    neighbours: dict = {}
    for link in data.get("links", []):
        src, dst = link.get("source"), link.get("target")
        for me, other, port in ((src, dst, link.get("local_port")),
                                (dst, src, link.get("remote_port"))):
            o = by_id.get(other)
            if me and o:
                neighbours.setdefault(me, []).append(
                    {"device": o["label"], "category": o["device_type"], "own_port": port or ""})

    def _vendor(n):
        return n.get("vendor") if n.get("vendor") not in (None, "", "discovered") else ""

    batch = [{
        "id": n["id"], "name": n["label"], "tenant": n["group"],
        "vendor": _vendor(n), "model": n.get("model") or "", "version": n.get("version") or "",
        "neighbours": neighbours.get(n["id"], [])[:ca.MAX_NEIGHBOURS],
    } for n in batch_nodes]
    tenants = {n["group"] for n in batch_nodes}
    examples: dict = {}
    for n in nodes:
        if n["group"] in tenants and (not n["discovered"] or n["is_manual"]):
            examples.setdefault(n["group"], []).append({
                "name": n["label"], "category": n["device_type"],
                "subcategory": n.get("subcategory") or "", "model": n.get("model") or "",
                "ha_group": n.get("ha_group") or ""})

    reply, profile = chat_with_active_profile(
        ca.build_messages(batch, examples, data["categories"], payload.lang))
    suggestions, conventions = ca.parse_suggestions(
        reply, [b["id"] for b in batch], data["categories"])

    now = int(time.time())
    for k, v in suggestions.items():
        store["suggestions"][k] = dict(v, ts=now)
    store["conventions"].update({t: c for t, c in conventions.items() if t in tenants})
    inventory_manager.safe_json_write(_ai_suggest_file(), store)
    log_audit(f"Suggerimenti AI di classificazione: {len(suggestions)}/{len(batch)} dispositivi "
              f"da '{current_user.get('sub')}' (provider {profile.get('provider', '')}).")
    return {"suggestions": suggestions, "conventions": conventions,
            "requested": len(batch), "remaining": max(0, len(pending) - len(batch))}


@router.post("/api/device-models/ai-normalize", dependencies=[Depends(require_tab("tab-categories"))])
def run_ai_model_normalize(payload: AiModelsSchema, current_user = Depends(require_operator)):
    """Propose merges of duplicate spellings in the model catalogue. Sends the
    catalogue only, no device."""
    from ai import classification_assist as ca
    from routers.ai import chat_with_active_profile

    models = {v: m for v, m in inventory_manager.get_models().items() if len(m) > 1}
    if not models:
        raise HTTPException(status_code=400, detail="Nessun vendor con piu' di un modello nel catalogo.")
    reply, _profile = chat_with_active_profile(ca.build_model_messages(models, payload.lang))
    merges = ca.parse_model_merges(reply, models)
    log_audit(f"Proposte AI di unione modelli: {len(merges)}, da '{current_user.get('sub')}'.")
    return {"merges": merges}


@router.post("/api/device-models/merge", dependencies=[Depends(require_tab("tab-categories"))])
def merge_device_models(payload: ModelMergeSchema, current_user = Depends(require_operator)):
    """Apply one merge: catalogue and the devices that use a duplicate."""
    # The catalogue and the device assignments it rewrites span every tenant.
    if user_group_scope(current_user) is not None:
        raise HTTPException(status_code=403, detail="Serve un utente senza restrizioni di sede.")
    known = inventory_manager.get_models().get(payload.vendor.strip().lower(), [])
    if payload.canonical not in known or not payload.duplicates \
            or any(d not in known for d in payload.duplicates):
        raise HTTPException(status_code=400, detail="Modelli non presenti nel catalogo.")
    changed = inventory_manager.merge_models(payload.vendor, payload.canonical, payload.duplicates)
    log_audit(f"Modelli {payload.duplicates} uniti in '{payload.canonical}' ({payload.vendor}), "
              f"{changed} dispositivi aggiornati, da '{current_user.get('sub')}'.")
    return {"status": "success", "devices_updated": changed}
