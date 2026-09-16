# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router Config Drift: cosa e' cambiato, e cosa non rispetta lo standard."""

import difflib

from fastapi import APIRouter, Depends, HTTPException
from routers.deps import require_tab
from pydantic import BaseModel

from routers.deps import (require_operator, require_admin, user_group_scope,
                          assert_device_allowed)
from security.security_manager import log_audit
from security import redaction
from services import inventory_manager
from services.config_drift import baseline, history, normalize

router = APIRouter(tags=["Config Drift"])


class BaselineSchema(BaseModel):
    text: str = ""


def _unified(vendor: str, before: str, after: str, a_label: str, b_label: str) -> str:
    """A unified diff of two configs, with credentials masked.

    Redaction happens on each side BEFORE the diff, not on the assembled diff:
    unified_diff prefixes every line with '+', '-' or a space, and the patterns
    in security/redaction.py are anchored at line start, so they would not match
    a prefixed line and every secret would pass straight through.

    A rotated password therefore renders as '-enable secret ***' / '+enable
    secret ***': the line still shows as changed, the value is never disclosed.
    """
    diff = difflib.unified_diff(
        redaction.redact(normalize.normalize(vendor, before)).splitlines(),
        redaction.redact(normalize.normalize(vendor, after)).splitlines(),
        fromfile=a_label, tofile=b_label, lineterm="")
    return "\n".join(diff)


def _device_or_404(current_user, ip: str) -> dict:
    device = assert_device_allowed(current_user, ip)
    if not device:
        raise HTTPException(status_code=404, detail=f"Apparato {ip} non trovato.")
    return device


def _rules_for(cache: dict, device: dict) -> tuple:
    """(profile, baseline text) for one device, memoised per tenant+profile."""
    key = (device.get("Group") or "", baseline.profile_for(device))
    if key not in cache:
        cache[key] = baseline.load(*key)
    return key[1], cache[key]


def drift_summary_for(devices: list) -> dict:
    """Devices whose latest stored config breaks their tenant baseline.

    `checked` is the denominator: a device counts only when its tenant has
    rules for its profile AND a config has been collected. "0 deviating" out
    of 0 checked means nothing was verified, not that everything complies.
    """
    rules_cache: dict = {}
    checked = 0
    deviating = []
    # Tenants with collected configs but no baseline: the usual reason
    # nothing was checked, and the one the operator can act on.
    no_baseline = set()
    for device in devices:
        tenant = device.get("Group") or ""
        _profile, rules = _rules_for(rules_cache, device)
        versions = history.list_versions(device)
        if versions and not rules:
            no_baseline.add(tenant)
        if not rules or not versions:
            continue
        checked += 1
        text = history.read_version(device, versions[0]["seen_at"])
        problems = baseline.evaluate(device.get("Vendor") or "", text, rules)
        if problems:
            deviating.append({"ip": device.get("IP"), "hostname": device.get("Hostname"),
                              "tenant": tenant, "deviations": len(problems)})
    deviating.sort(key=lambda d: d["deviations"], reverse=True)
    return {"devices": len(devices), "checked": checked, "deviating": deviating,
            "no_baseline": sorted(no_baseline)}


# Before /api/drift/{ip}/...: a literal segment must not be read as an IP.
@router.get("/api/drift/summary", dependencies=[Depends(require_tab("tab-home", "tab-config-drift"))])
def drift_summary(tenant: str = "", current_user=Depends(require_operator)):
    scope = user_group_scope(current_user)
    devices = [d for d in inventory_manager.get_all_devices()
               if (scope is None or d.get("Group") in scope)
               and (not tenant or tenant == "all" or d.get("Group") == tenant)]
    return drift_summary_for(devices)


@router.get("/api/drift/devices", dependencies=[Depends(require_tab("tab-config-drift"))])
def drift_devices(current_user=Depends(require_operator)):
    """Devices the caller may see, with when they last changed.

    `deviations` is None when the device could not be checked (no baseline for
    its tenant, or no collected config): the list pane must not paint that as
    compliant.
    """
    scope = user_group_scope(current_user)
    rules_cache: dict = {}
    out = []
    for device in inventory_manager.get_all_devices():
        if scope is not None and device.get("Group") not in scope:
            continue
        versions = history.list_versions(device)
        profile, rules = _rules_for(rules_cache, device)
        deviations = None
        if rules and versions:
            text = history.read_version(device, versions[0]["seen_at"])
            deviations = baseline.evaluate(device.get("Vendor") or "", text, rules)
        out.append({
            "deviations": deviations,
            "profile": profile,
            "ip": device.get("IP"),
            "hostname": device.get("Hostname"),
            "tenant": device.get("Group"),
            "vendor": device.get("Vendor"),
            "versions": len(versions),
            "last_change": versions[0]["seen_at"] if versions else "",
            "last_seen": history.last_seen_at(device),
        })
    return {"devices": out}


@router.get("/api/drift/{ip}/versions", dependencies=[Depends(require_tab("tab-config-drift"))])
def drift_versions(ip: str, current_user=Depends(require_operator)):
    return {"versions": history.list_versions(_device_or_404(current_user, ip))}


@router.get("/api/drift/{ip}/diff", dependencies=[Depends(require_tab("tab-config-drift"))])
def drift_diff(ip: str, from_version: str = "", to_version: str = "",
               current_user=Depends(require_operator)):
    """Redacted diff between two archived versions of one device."""
    device = _device_or_404(current_user, ip)
    before = history.read_version(device, from_version)
    after = history.read_version(device, to_version)
    if not before or not after:
        raise HTTPException(status_code=404, detail="Versione non trovata.")
    return {"diff": _unified(device.get("Vendor") or "", before, after,
                             from_version, to_version)}


@router.get("/api/drift/baseline/{tenant}", dependencies=[Depends(require_tab("tab-config-drift"))])
def drift_baseline_get(tenant: str, profile: str = "ios",
                       current_user=Depends(require_operator)):
    scope = user_group_scope(current_user)
    if scope is not None and tenant not in scope:
        raise HTTPException(status_code=403, detail="Tenant non consentito.")
    return {"tenant": tenant, "profile": profile, "text": baseline.load(tenant, profile)}


@router.put("/api/drift/baseline/{tenant}", dependencies=[Depends(require_tab("tab-config-drift"))])
def drift_baseline_put(tenant: str, payload: BaselineSchema, profile: str = "ios",
                       current_user=Depends(require_admin)):
    if profile not in baseline.PROFILES:
        raise HTTPException(status_code=422, detail=f"Profilo '{profile}' sconosciuto.")
    baseline.save(tenant, profile, payload.text)
    log_audit(f"Baseline config del tenant '{tenant}' (profilo {profile}) aggiornata da "
              f"'{current_user.get('sub')}'.")
    return {"status": "success"}


@router.post("/api/drift/baseline/{tenant}/seed", dependencies=[Depends(require_tab("tab-config-drift"))])
def drift_baseline_seed(tenant: str, ip: str, current_user=Depends(require_admin)):
    """Candidate rules from one device, for the operator to prune. Saves nothing."""
    device = _device_or_404(current_user, ip)
    if device.get("Group") != tenant:
        raise HTTPException(status_code=400,
                            detail=f"Apparato {ip} non appartiene al tenant '{tenant}'.")
    versions = history.list_versions(device)
    if not versions:
        raise HTTPException(status_code=404, detail="Nessuna configurazione archiviata.")
    text = history.read_version(device, versions[0]["seen_at"])
    return {"text": baseline.seed_from_config(device.get("Vendor") or "", text)}


@router.get("/api/drift/{ip}/baseline", dependencies=[Depends(require_tab("tab-config-drift"))])
def drift_device_baseline(ip: str, current_user=Depends(require_operator)):
    device = _device_or_404(current_user, ip)
    versions = history.list_versions(device)
    if not versions:
        return {"deviations": [], "checked": False}
    text = history.read_version(device, versions[0]["seen_at"])
    _profile, rules = _rules_for({}, device)
    return {"deviations": baseline.evaluate(device.get("Vendor") or "", text, rules),
            "checked": bool(rules)}
