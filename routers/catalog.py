# -*- coding: utf-8 -*-
"""Router Catalog. Estratto da app_server.py (fase 6.6): percorsi, metodi,
parametri e risposte identici al monolite."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from services import inventory_manager
from core import core_engine
from security.security_manager import log_audit
from routers.deps import (
    get_current_user, require_admin, require_operator, user_group_scope,
    filter_map_to_scope, assert_group_allowed
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
def rename_group(payload: GroupRenameSchema, current_user = Depends(require_admin)):
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

@router.post("/api/groups/delete")
def remove_group(payload: GroupDeleteSchema, current_user = Depends(require_admin)):
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

@router.post("/api/vendors")
def create_vendor(v: VendorSchema, current_user = Depends(require_operator)):
    vendors = inventory_manager.get_all_vendors()
    vendors[v.name.lower().strip()] = {"driver": v.driver}
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
        a = assignments.get(n["id"], {})
        red = n.get("redundancy") or {}
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

@router.get("/api/device-classification")
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
    "member_index":     ("Member #",         lambda n, l: l.get("member_index", "")),
    "member_role":      ("Member Role",      lambda n, l: l.get("member_role", "")),
    "member_serial":    ("Member Serial",    lambda n, l: l.get("member_serial", "")),
    "member_model":     ("Member Model",     lambda n, l: l.get("member_model", "")),
}

# Asking for one of these columns means asking for one row per neighbour: a
# device with redundant uplinks has more than one, and a joined cell cannot be
# filtered or looked up in a spreadsheet -- the same reason _MEMBER_COLUMNS
# explodes rows in the device export.
_NEIGHBOUR_COLUMNS = frozenset(("neighbour_device", "neighbour_port",
                                "neighbour_category"))

# A stack answers on one management IP but carries one serial per physical
# unit, and the scan stores those on the redundancy group, not on the device:
# without these columns the Serial cell of every stacked switch is empty.
# Same rule as the device export -- one row per unit, never a joined cell.
_MEMBER_COLUMNS = frozenset(("member_index", "member_role",
                             "member_serial", "member_model"))

_DEFAULT_CLASSIFICATION_COLUMNS = ["hostname", "ip", "tenant", "category", "status"]


def _neighbours_of(node_id: str, links: list, label_of: dict,
                   category_of: dict) -> list:
    """Neighbours of one node, each as {device, port, category}.

    The port reported is the NEIGHBOUR's own port -- the one you patch -- not
    the port on the device whose row this is. A link stores local_port for its
    source and remote_port for its target, so which one to read depends on
    which end this node sits at.
    """
    out = []
    for link in links:
        if link.get("target") == node_id:
            other, port = link.get("source"), link.get("local_port")
        elif link.get("source") == node_id:
            other, port = link.get("target"), link.get("remote_port")
        else:
            continue
        out.append({"device": label_of.get(other, other or ""), "port": port or "",
                    "category": category_of.get(other, "")})
    return out


@router.get("/api/export/classification/columns")
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


@router.get("/api/export/classification")
def export_classification_csv(
    columns: str = "",
    groups: str = "",
    categories: str = "",
    neighbour_categories: str = "",
    only_matching_neighbours: bool = False,
    current_user = Depends(get_current_user),
):
    import csv, io
    from fastapi.responses import Response as FastResponse
    from core.csv_safe import csv_cell
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
    explode = any(c in _NEIGHBOUR_COLUMNS for c in selected)
    badges = (redundancy_service.redundancy_badges_by_ip()
              if any(c in _MEMBER_COLUMNS for c in selected) else {})
    want_neighbour_categories = {v.strip()
                                 for v in neighbour_categories.split(",") if v.strip()}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([_CLASSIFICATION_COLUMNS[c][0] for c in selected])
    for node in nodes:
        # Serial has two sources and one of them is a cache: an inventoried
        # device carries it from the last scan, an access point only from
        # whatever controller last reported it. The AP store lookup is
        # scoped to the node's own tenant, so a name collision across
        # tenants never hands one customer another's serial.
        scan = versions.get(node["id"], {})
        entry = (ap_store.lookup_in(ap_entries, node.get("label") or "", node.get("group"))
                 if node.get("discovered") else None)
        row_node = dict(node)
        row_node["serial"] = scan.get("serial") or (entry or {}).get("serial", "")
        row_node["serial_seen_at"] = (entry or {}).get("seen_at", "")

        # A device with no links still gets its row: selecting a column must
        # never make devices disappear from the export.
        # Looked up with no neighbour column selected too, because
        # only_matching_neighbours decides on the links alone.
        neighbours = (_neighbours_of(node["id"], links, label_of, category_of)
                      if (explode or only_matching_neighbours) else [])
        # Two legitimate readings of a neighbour filter, so the caller picks:
        # the default keeps every device and blanks the neighbour cells of the
        # ones that have no match (a full device table, AP uplinks only), while
        # only_matching_neighbours narrows the export to the devices that
        # actually have such a neighbour.
        if want_neighbour_categories:
            neighbours = [x for x in neighbours
                          if x["category"] in want_neighbour_categories]
            if not neighbours and only_matching_neighbours:
                continue
        # Members and neighbours are two independent explosions: a stacked
        # switch with two uplinks and four units gets every (uplink, unit)
        # pair, so both the port and the serial stay in a cell of their own.
        members = [
            {"member_index": m.get("index", ""), "member_role": m.get("role", ""),
             "member_serial": m.get("serial", ""), "member_model": m.get("model", "")}
            for m in ((badges.get(node["id"]) or {}).get("members") or [])
        ]
        for link in (neighbours or [{}]):
            for member in (members or [{}]):
                writer.writerow([
                    csv_cell(_CLASSIFICATION_COLUMNS[c][1](row_node, {**link, **member}))
                    for c in selected
                ])

    log_audit(f"Export CSV classificazione richiesto dall'utente "
              f"'{current_user.get('sub')}' (colonne: {','.join(selected)}).")
    return FastResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition":
                 "attachment; filename=sentinelnet-classification.csv"},
    )

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

