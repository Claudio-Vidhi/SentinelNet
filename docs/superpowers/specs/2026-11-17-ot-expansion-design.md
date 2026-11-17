# OT (ICS / SCADA) Expansion Design

Source: [ot-expansion-ideas.md](../../ot-expansion-ideas.md)
Target version line: `0.66.0`+ (phased MINOR/PATCH increments)

## 1. Goal & Principles

Extend SentinelNet for **Operational Technology (OT)** and **IT/OT convergence** without breaking IT workflows or risking fragile PLC/RTU hardware.

Non-negotiable constraints:
1. **Zero active probing by default on OT tenants**: active ICMP/SSH/SNMP sweeps must be opt-in or suppressed by `OT Safe Mode`.
2. **Reuse existing primitives**: `tenant_telemetry`, `inventory_store` (SQLite), `segment_manager`, `drivers/registry.py`, `cve_intel.py`, `backup_store.py`, `status_report/mapping.json`.
3. **Public repo safety**: zero real customer OUIs/IPs/models in tracked files (`scripts/check_no_private_data.py`); use RFC 5737 (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) and vendor-doc examples only.

## 2. Phased Architecture

| Phase | Scope | Core Modules |
|---|---|---|
| **Phase 1: Foundation** | `OT Safe Mode` preset, `Purdue Level` on devices & segments, Rogue MAC alert on OT VLANs | `services/tenant_telemetry.py`, `services/inventory_store.py`, `services/segment_manager.py`, `collectors/mac_history.py`, `routers/settings.py`, `routers/inventory.py` |
| **Phase 2: Passive Discovery & Read-Only Probes** | Industrial OUI database, passive protocol tagging from SPAN/NetFlow/syslog, opt-in rate-limited read-only OT probes (`ListIdentity`, Modbus FC 43/14, OPC-UA `GetEndpoints`, BACnet `Who-Is`) | `collectors/mac_collector.py`, `observability/ingesters/`, `services/probe_agent.py` |
| **Phase 3: Industrial Drivers & Ring Redundancy** | Drivers for Siemens SCALANCE, Hirschmann HiOS, Moxa EDS/EDR, Westermo, Phoenix Contact, Cisco IE; SNMP/trap monitoring for MRP, DLR, PRP/HSR, RSTP ring state | `drivers/`, `drivers/registry.py`, `collectors/iface_counters_cli.py`, `observability/ingesters/snmp_poller.py` |
| **Phase 4: Purdue Topology & IT/OT Violations** | Vis.js Purdue band view (`L0`–`L4` + `L3.5` DMZ) with Zone & Conduit overlay; cross-layer violation checks (`L1`/`L2` -> `L4`/Internet bypassing `L3.5`) | `static/js/`, `services/blueprint_checks.py`, `services/firewall_traffic.py` |
| **Phase 5: OT Vulnerability Intel, Air-Gap & Vault** | CISA ICS Advisories alongside NVD + KEV; signed offline NVD/ICS bundle export/import; maintenance-window/hot-patchable metadata; SHA-256 OT project vault (`.zap*`, `.acd`, SCL/ICD); expanded IEC 62443 checks in `status_report` | `services/cve_intel.py`, `services/nvd.py`, `core/backup_store.py`, `services/status_report/` |

## 3. Data Model Additions (Summary)

- **Tenant Telemetry (`app_settings.json` via `services/tenant_telemetry.py`)**:
  - Add `"ot_safe_mode": bool` (default `False`) and `"preset": "standard" | "ot_safe"` per tenant.
  - When `ot_safe_mode=True`: `ping_enabled=False`, `snmp_enabled=False`, `api_enabled=False`, `triage_enabled=False`, and `collectors/network_scanner.py` refuses active scan on that tenant. Passive listeners (syslog, SNMP traps, manual/CSV import) remain active.
- **Inventory (`services/inventory_store.py`)**:
  - `hosts` / `decommissioned_hosts`: add `"Purdue Level"` (`""`, `"L0"`, `"L1"`, `"L2"`, `"L3"`, `"L3.5"`, `"L4"`) and `"Maintenance Window"` (`""`, `"hot_patchable"`, `"planned_outage_only"`).
  - `segments`: add `purdue_level TEXT NOT NULL DEFAULT ''` and `is_ot INTEGER NOT NULL DEFAULT 0`.
- **OT Project Vault (`core/backup_store.py`)**:
  - Store binary/project artifacts under `backup-config/<group>/_ot_vault/<host_key>/<timestamp>_<filename>` with sidecar `.sha256` manifest.

## 4. Compliance Mapping (`services/status_report/`)

`services/status_report/mapping.json` already defines `iec62443` (`SR 5.1`, `SR 5.2`). Subsequent phases extend `iec62443` controls and `evidence.py` with:
- Insecure cleartext protocols active on OT segments (Telnet, HTTP, SNMPv1/v2c, unsegregated Modbus/S7).
- Unused physical ports left `admin up` on field switches.
- Remote vendor access / jump-host segregation.
