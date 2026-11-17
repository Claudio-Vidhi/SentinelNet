# OT Phase 1: OT Safe Mode, Purdue Level & OT VLAN Rogue Alert

> **For agentic workers:** Execute task-by-task using `superpowers:executing-plans`. Follow `AGENTS.md` (Caveman replies, `uv run pyrefly check`, `uv run pytest tests -n 4`, `uv run python scripts/check_no_private_data.py`, `graphify update .`).

**Goal:** Deliver the non-invasive OT foundation: per-tenant `OT Safe Mode` preset, `Purdue Level` attribute on devices and network segments, and immediate rogue-MAC alerting on segments marked `is_ot`.

**Spec:** [2026-11-17-ot-expansion-design.md](../specs/2026-11-17-ot-expansion-design.md)

---

### Task 1: `OT Safe Mode` in `services/tenant_telemetry.py` & `routers/settings.py`

**Files:**
- Modify: `services/tenant_telemetry.py`
- Modify: `collectors/network_scanner.py` (or scan router caller — verify callers of `parse_network` / active scan)
- Modify: `routers/settings.py`
- Test: `tests/test_tenant_telemetry.py`

**Steps:**
1. Extend `get_tenant_telemetry(tenant)` in `services/tenant_telemetry.py` to include `"ot_safe_mode": bool(t_cfg.get("ot_safe_mode", False))`.
2. In `save_tenant_telemetry(tenant, config, username)`:
   - If `config.get("ot_safe_mode")` is `True`, force `ping_enabled`, `snmp_enabled`, `api_enabled`, `triage_enabled` to `False` and persist `"ot_safe_mode": True`.
   - When `ot_safe_mode` is `False`, use explicit per-feature booleans as before.
3. Add `is_ot_safe_mode(tenant: str) -> bool` helper in `services/tenant_telemetry.py`.
4. Guard active network scan endpoint (find via `rg "network_scanner" routers/`) so scanning a tenant with `is_ot_safe_mode(tenant) == True` returns HTTP 409 / refuses active sweep unless explicitly overridden or disabled.
5. Add unit tests in `tests/test_tenant_telemetry.py` covering `ot_safe_mode=True` forcing all active features off and `is_ot_safe_mode`.
6. Run `uv run pytest tests/test_tenant_telemetry.py` and `uv run pyrefly check`.

---

### Task 2: `Purdue Level` on Devices & Segments (`inventory_store.py` & `segment_manager.py`)

**Files:**
- Modify: `services/inventory_store.py`
- Modify: `services/segment_manager.py`
- Modify: `routers/segments.py` (or segment API router — check with `rg "save_segment" routers/`)
- Test: `tests/test_segments.py` (or `tests/test_inventory_store.py`)

**Steps:**
1. Define `PURDUE_LEVELS = ("", "L0", "L1", "L2", "L3", "L3.5", "L4")` in `services/inventory_store.py` (or shared constant).
2. Add `"Purdue Level"` to `HOST_FIELDS` in `services/inventory_store.py` and migrate existing SQLite `hosts` / `decommissioned_hosts` tables in `connect()` via `PRAGMA table_info` + `ALTER TABLE ... ADD COLUMN "Purdue Level" TEXT NOT NULL DEFAULT ''`.
3. Add `purdue_level TEXT NOT NULL DEFAULT ''` and `is_ot INTEGER NOT NULL DEFAULT 0` to `segments` table in `services/inventory_store.py` (both `_SCHEMA` and `ALTER TABLE` migration in `connect()`).
4. Update `services/segment_manager.py` (`_row`, `save_segment`) to validate `purdue_level in PURDUE_LEVELS` and persist `purdue_level` and `bool(is_ot)`.
5. Add tests for schema migration on existing DBs, invalid `purdue_level` rejection, and round-trip persistence.
6. Run `uv run pytest tests -k "inventory or segment"` and `uv run pyrefly check`.

---

### Task 3: Rogue MAC Alert on OT Segments (`collectors/mac_history.py`)

**Files:**
- Modify: `collectors/mac_history.py`
- Modify: `services/notifications.py` (verify alert/notification hook)
- Test: `tests/test_mac_history.py` (or dedicated `tests/test_ot_rogue_mac.py`)

**Steps:**
1. Check how `collectors/mac_history.py` records new MAC sightings (`record_sightings`) and how `services/notifications.py` dispatches alerts.
2. When a MAC not previously seen in `(org, vlan)` or `(device_ip, interface)` appears on a device/subnet belonging to a segment with `is_ot=True`, emit a critical notification/event (`ot_rogue_mac`).
3. Keep IT segments unchanged (no noise on dynamic IT/guest/Wi-Fi VLANs).
4. Write unit test with synthetic MACs (`AA:BB:CC:DD:EE:01`) verifying alert fires for `is_ot=True` segment and does not fire for `is_ot=False`.
5. Run full gate:
   - `uv run pyrefly check`
   - `uv run pytest tests -n 4`
   - `uv run python scripts/check_no_private_data.py`
   - `graphify update .`
