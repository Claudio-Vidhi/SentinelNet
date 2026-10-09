# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Manual config upload for devices SentinelNet cannot reach.

The same ingest as the probe agent's POST /api/agent/backup (routers/agent.py),
with an operator instead of an agent as the source. One device per call: the
UI posts the rows one after another and shows each outcome as it lands.
Spec: docs/superpowers/specs/2026-10-08-manual-config-repository-design.md
"""
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ai.config_analyzer import detect_config_type
from core import backup_store
from routers.agent import MAX_CONFIG_BYTES
from routers.deps import assert_group_allowed, require_operator, require_tab
from security.security_manager import log_audit
from services import inventory_manager, manual_config, probe_manager

router = APIRouter(tags=["manual-config"])
# Opened from the Import tab and from a manual device's row in Devices.
_TABS = ("tab-import", "tab-devices")


class ManualPreviewSchema(BaseModel):
    text: str
    vendor: str = ""


class ManualImportSchema(BaseModel):
    text: str
    ip: str
    vendor: str
    group: str
    probe: str = "central"
    hostname: str = ""
    category: str = ""
    subcategory: str = ""
    version: str = ""
    model: str = ""


def _check_text(text: str) -> None:
    if not text.strip():
        raise HTTPException(status_code=400, detail="Config vuota: niente da caricare.")
    if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise HTTPException(status_code=413,
                            detail="Config oltre il limite di 5 MB: rifiutata, non troncata.")


def _row(ip: str, group: str):
    return next((d for d in inventory_manager.get_all_devices()
                 if d.get("IP") == ip and (d.get("Group") or "Generale") == group), None)


@router.get("/api/manual-config/guide", dependencies=[Depends(require_tab(*_TABS))])
def manual_config_guide(current_user=Depends(require_operator)):
    # Categories and probes ride along: the review form needs them, and their
    # own routes belong to tabs this user may not hold.
    cats = inventory_manager.get_device_categories()["categories"]
    return {
        "vendors": manual_config.guide(),
        "categories": {k: {"label": v["label"], "subcategories": v["subcategories"]}
                       for k, v in cats.items()},
        "probes": [{"id": s["id"], "name": s.get("name") or s["id"]}
                  for s in probe_manager.list_probes()],
    }


@router.post("/api/manual-config/preview", dependencies=[Depends(require_tab(*_TABS))])
def manual_config_preview(payload: ManualPreviewSchema, current_user=Depends(require_operator)):
    _check_text(payload.text)
    vendor = inventory_manager.normalize_vendor(payload.vendor) if payload.vendor else ""
    if vendor and vendor not in manual_config.GUIDE_VENDORS:
        raise HTTPException(status_code=400, detail=f"Vendor '{payload.vendor}' non supportato.")
    return manual_config.preview(payload.text, vendor)


@router.post("/api/manual-config/import", dependencies=[Depends(require_tab(*_TABS))])
def manual_config_import(payload: ManualImportSchema, current_user=Depends(require_operator)):
    _check_text(payload.text)
    assert_group_allowed(current_user, payload.group)
    # update_version_inventory is keyed by IP only: refuse an address that
    # belongs to a tenant this user may not touch (same gate as /api/add-device).
    for d in inventory_manager.get_all_devices():
        if d.get("IP") == payload.ip:
            assert_group_allowed(current_user, d.get("Group") or "Generale")
    if payload.group not in inventory_manager.get_all_groups():
        raise HTTPException(status_code=400, detail=f"Tenant '{payload.group}' inesistente.")
    if payload.probe not in {s["id"] for s in probe_manager.list_probes()}:
        raise HTTPException(status_code=400, detail=f"Sonda '{payload.probe}' inesistente.")
    vendor = inventory_manager.normalize_vendor(payload.vendor)
    if vendor not in manual_config.GUIDE_VENDORS:
        raise HTTPException(status_code=400, detail=f"Vendor '{payload.vendor}' non supportato.")
    existing = _row(payload.ip, payload.group)
    if existing is not None and not inventory_manager.is_manual(existing):
        raise HTTPException(status_code=409, detail=(
            f"{payload.ip} e' gia' in inventario come dispositivo raggiungibile: "
            "il prossimo triage sovrascriverebbe la config caricata."))
    # Pure computation first: a failure here must not leave an orphan row.
    parsed = manual_config.to_backup(vendor, payload.text)
    try:
        inventory_manager.add_or_update_device(
            payload.ip, vendor, "", "", "", "", payload.group,
            probe=payload.probe, transports={"manual": None})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    device = _row(payload.ip, payload.group)
    assert device is not None  # add_or_update_device just wrote it

    hostname = payload.hostname.strip() or parsed["hostname"] or payload.ip
    file_path = backup_store.save_backup(device, hostname, parsed["backup"])
    try:
        from services.config_drift import history
        history.record_version(device, parsed["backup"])
    except Exception as e:
        logging.warning(f"Storico config non aggiornato per {payload.ip}: {e}")
    version = payload.version.strip() or parsed["version"]
    inventory_manager.update_version_inventory(
        payload.ip, vendor, version or "Non Rilevata", "manual",
        model=payload.model.strip() or parsed["model"] or None,
        serial=parsed["serial"] or None)
    inventory_manager.update_device_hostname(payload.ip, hostname, payload.group)
    if payload.category:
        inventory_manager.set_device_meta(payload.ip, tenant=payload.group,
                                          category=payload.category,
                                          subcategory=payload.subcategory)
    log_audit(f"Config manuale caricata per '{payload.ip}' (tenant '{payload.group}', "
              f"{len(payload.text)} caratteri) dall'utente '{current_user.get('sub')}'.")
    config_type = detect_config_type(parsed["backup"], device)
    return {"status": "success", "file": file_path, "hostname": hostname,
            "analyses": manual_config.analyses_for(vendor, config_type, version)}
