# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Gestione configurazione granularita telemetria per tenant (Sede).

Consente di abilitare o disabilitare selettivamente Ping ICMP, polling SNMP,
polling API REST e Triage CLI automatico su ciascun tenant / gruppo dell'inventario.
"""

import ipaddress
from typing import Any, Dict, Iterable, List, Optional
from core.app_settings import get_app_settings, save_app_settings
from security.security_manager import log_audit

# Every telemetry service that can be turned off per tenant. Unset means on.
FEATURES = ("ping", "snmp", "api", "triage")


def get_all_tenant_telemetry() -> Dict[str, Dict[str, Any]]:
    """Restituisce il dizionario tenant_telemetry da app_settings.json."""
    return get_app_settings().get("tenant_telemetry") or {}


def get_tenant_telemetry(tenant: str) -> Dict[str, Any]:
    """Restituisce le opzioni di telemetria per un singolo tenant con fallback predefiniti (tutto attivo)."""
    t_cfg = (get_all_tenant_telemetry().get(tenant) or {}) if tenant else {}
    ot_safe = bool(t_cfg.get("ot_safe_mode", False))
    out: Dict[str, Any] = {"tenant": tenant or "", "ot_safe_mode": ot_safe}
    for f in FEATURES:
        out[f"{f}_enabled"] = False if ot_safe else bool(t_cfg.get(f"{f}_enabled", True))
    return out


def save_tenant_telemetry(tenant: str, config: Dict[str, Any], username: str) -> Dict[str, Any]:
    """Salva la configurazione di telemetria specifica per un tenant."""
    if not tenant:
        raise ValueError("Tenant non specificato")
    all_cfg = get_all_tenant_telemetry()
    current = all_cfg.get(tenant) or {}
    ot_safe = bool(config.get("ot_safe_mode", False))
    current["ot_safe_mode"] = ot_safe
    for f in FEATURES:
        current[f"{f}_enabled"] = False if ot_safe else bool(config.get(f"{f}_enabled", True))

    all_cfg[tenant] = current
    save_app_settings({"tenant_telemetry": all_cfg})
    flags = ", ".join(f"{f}={current[f'{f}_enabled']}" for f in FEATURES)
    log_audit(
        f"Configurazione telemetria per tenant '{tenant}' aggiornata da '{username}': "
        f"ot_safe_mode={ot_safe}, {flags}."
    )
    return get_tenant_telemetry(tenant)


def is_ot_safe_mode(tenant: str) -> bool:
    """True when the tenant is configured in passive-only OT Safe Mode."""
    if not tenant:
        return False
    return bool(get_tenant_telemetry(tenant).get("ot_safe_mode", False))


def is_telemetry_enabled(tenant: str, feature: str) -> bool:
    """Helper rapido per verificare se un servizio di telemetria (ping, snmp, api, triage)
    e' attivo per un dato tenant."""
    if not tenant:
        return True
    cfg = get_tenant_telemetry(tenant)
    if cfg.get("ot_safe_mode"):
        return False
    return cfg.get(f"{feature}_enabled", True)


def ot_safe_orgs_for_network(network: ipaddress.IPv4Network, orgs: Optional[Iterable[str]] = None) -> List[str]:
    """Return OT Safe Mode tenants whose declared location subnets overlap ``network``."""
    from services import inventory_manager, location_manager
    candidates = list(orgs) if orgs is not None else list(inventory_manager.get_all_groups())
    blocked: List[str] = []
    for org in candidates:
        if not is_ot_safe_mode(org):
            continue
        for loc in location_manager.list_locations(org):
            for raw in loc.get("subnets") or []:
                try:
                    declared = ipaddress.ip_network(str(raw).strip(), strict=False)
                except ValueError:
                    continue
                if declared.version == 4 and network.overlaps(declared):
                    blocked.append(org)
                    break
            else:
                continue
            break
    return blocked


def ot_safe_orgs_for_ips(ips: Iterable[str], orgs: Optional[Iterable[str]] = None) -> List[str]:
    """Return OT Safe Mode tenants owning any of ``ips`` via inventory or location subnets."""
    from services import inventory_manager, location_manager
    candidates = list(orgs) if orgs is not None else list(inventory_manager.get_all_groups())
    ot_orgs = [org for org in candidates if is_ot_safe_mode(org)]
    if not ot_orgs:
        return []
    ot_set = set(ot_orgs)
    blocked: set[str] = set()
    ip_list = list(ips)
    ip_set = set(ip_list)
    for dev in inventory_manager.get_all_devices():
        grp = dev.get("Group") or ""
        if grp in ot_set and dev.get("IP") in ip_set:
            blocked.add(grp)
    addrs = []
    for raw_ip in ip_list:
        try:
            addrs.append(ipaddress.ip_address(raw_ip))
        except ValueError:
            continue
    for org in ot_orgs:
        if org in blocked:
            continue
        for loc in location_manager.list_locations(org):
            for raw in loc.get("subnets") or []:
                try:
                    declared = ipaddress.ip_network(str(raw).strip(), strict=False)
                except ValueError:
                    continue
                if any(a.version == declared.version and a in declared for a in addrs):
                    blocked.add(org)
                    break
            if org in blocked:
                break
    return sorted(blocked)
