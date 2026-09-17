# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Gestione configurazione granularita telemetria per tenant (Sede).

Consente di abilitare o disabilitare selettivamente Ping ICMP, polling SNMP,
polling API REST e Triage CLI automatico su ciascun tenant / gruppo dell'inventario.
"""

from typing import Dict, Any
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
    out: Dict[str, Any] = {"tenant": tenant or ""}
    for f in FEATURES:
        out[f"{f}_enabled"] = bool(t_cfg.get(f"{f}_enabled", True))
    return out


def save_tenant_telemetry(tenant: str, config: Dict[str, Any], username: str) -> Dict[str, Any]:
    """Salva la configurazione di telemetria specifica per un tenant."""
    if not tenant:
        raise ValueError("Tenant non specificato")
    all_cfg = get_all_tenant_telemetry()
    current = all_cfg.get(tenant) or {}
    for f in FEATURES:
        current[f"{f}_enabled"] = bool(config.get(f"{f}_enabled", True))

    all_cfg[tenant] = current
    save_app_settings({"tenant_telemetry": all_cfg})
    flags = ", ".join(f"{f}={current[f'{f}_enabled']}" for f in FEATURES)
    log_audit(f"Configurazione telemetria per tenant '{tenant}' aggiornata da '{username}': {flags}.")
    return get_tenant_telemetry(tenant)


def is_telemetry_enabled(tenant: str, feature: str) -> bool:
    """Helper rapido per verificare se un servizio di telemetria (ping, snmp, api, triage)
    e' attivo per un dato tenant."""
    if not tenant:
        return True
    cfg = get_tenant_telemetry(tenant)
    return cfg.get(f"{feature}_enabled", True)
