# Device Provisioning Identities + Threat Intel Revamp — Design

Date: 2026-07-17
Status: approved

## Goal

Two features:
1. Device Provisioning tab: named credential profiles ("identities")
   scoped to a tenant, reorganized two-column layout.
2. Threat Intel tab: port euvd_dashboard vendor-watch UI + rework the
   matcher into tenant/category-grouped batch analysis.

## 1. Data: tenant identities

- New file `identities.json` (repo data dir, same location pattern as
  `groups.json`), written via the existing `safe_json_write` pattern.
- Record shape: `{id, name, tenant, username, password_enc, secret_enc}`.
  `id` is a uuid4 hex string. `password_enc`/`secret_enc` encrypted with the
  existing `encrypt_password`/`decrypt_password` (same as hosts.csv).
- New module `identity_manager.py`:
  - `get_identities(tenant=None)` — list, secrets NEVER included in output
    (returns id, name, tenant, username only).
  - `get_identity_credentials(identity_id)` — internal use only: returns
    decrypted (username, password, secret).
  - `add_identity(name, tenant, username, password, secret)`
  - `update_identity(identity_id, ...)` — password/secret re-entered to change.
  - `delete_identity(identity_id)` — refuses if any device references it;
    returns list of blocking device IPs.

## 2. API endpoints (routers/provisioner.py)

All `require_operator`, all mutations audit-logged via `log_audit`.

- `GET  /api/identities?tenant=<name>` — list (no secrets).
- `POST /api/identities` — create.
- `PUT  /api/identities/{id}` — update.
- `DELETE /api/identities/{id}` — delete; 409 with device list if in use.

## 3. Device linkage

- hosts.csv `Profile` field gains a third form: `identity:<id>`
  (existing values: `default`, `custom`).
- `core_engine.get_device_credentials`: if profile starts with
  `identity:`, resolve via `identity_manager.get_identity_credentials`;
  if the identity no longer exists, fall through to env defaults
  (should not happen because delete is blocked while in use).
- Devices-using count computed from hosts.csv by matching Profile value.

## 4. UI: tab-provisioning reorganization (templates/dashboard.html)

Two-column grid (stacks to one column on narrow width):

**Left panel — device form**, grouped fieldsets with section headers:
1. *Tenant* — tenant select + inline "+ new tenant" button opening a small
   popover input (replaces the current bottom "Aggiungi Nuovo Gruppo"
   section).
2. *Device* — IP with inline format validation and duplicate-IP hint
   ("already in inventory" → offers switch to edit mode), vendor select.
3. *Connectivity* — existing transports `<details>` block unchanged.
4. *Credentials* — profile select becomes: Default / <tenant identities,
   filtered by selected tenant> / Custom. Custom shows the existing
   inline user/pass/secret fields. Selecting an identity shows a
   read-only hint (identity name + username).

**Right panel — Tenant Identities manager**: table of identities for the
selected tenant (name, username, devices-using count) with add / edit /
delete. Edit requires re-entering password/secret (same rule as device
edit). Delete shows blocking devices when refused.

i18n: all new strings added in both IT and EN dictionaries following the
existing key pattern.

## 5. Testing

`test_identity_manager.py` (unittest, runnable as script per repo
convention):
- CRUD round-trip, encryption round-trip.
- delete blocked while a device references the identity.
- `get_device_credentials` resolves `identity:<id>` correctly.

## 6. Threat Intel tab revamp (templates/dashboard.html, tab-security)

Two sub-tabs, using the same sub-tab pattern as the analyzer firewall
sub-tab.

### Sub-tab A: Vendor Watch (ported from ~/dev_ved/euvd_dashboard)

- Vendor scope buttons generated dynamically from the SentinelNet vendor
  registry (`euvd_term` field), not hardcoded.
- Filters: min CVSS score, min EPSS, exploited-only toggle, date range,
  free-text search over loaded rows.
- Results table: CVE/EUVD id, product, severity badge, CVSS, EPSS,
  exploited, published date. Row click opens a right-side drawer with
  summary, scores, dates, and reference links.
- Data source: existing authenticated proxy `GET /api/search`
  (routers/backup.py) — no new backend endpoints.
- Restyled to SentinelNet CSS variables and theme; all strings i18n
  IT + EN.

### Sub-tab B: Vulnerability Matcher (rework of existing view)

- Devices grouped tenant → device-type category (from existing category
  assignments; "Uncategorized" fallback). Inventory devices and
  discovered neighbors (with detected version) shown in the same tree.
- Per-tenant "Analyze all": runs EUVD queries for every online device
  with a known firmware version, throttled to ~4 concurrent requests,
  with a progress indicator and a per-tenant severity rollup
  (critical / high / exploited counts).
- Per-device Analyze button kept; existing `runManagedVulnCheck` /
  `runDiscoveredVulnCheck` reused for the actual query + rendering.
- No persistence of scan results, no server-side version matching.

## 7. Execution

Subagent-driven, three tasks:
- Task A: backend identities (identity_manager + endpoints +
  core_engine + tests).
- Task B: provisioning tab UI (reorg + identities panel). Depends on
  Task A's API contract.
- Task C: threat intel UI (Vendor Watch port + Matcher rework).
  Independent of A/B.

Final step: rebuild exe with `pyinstaller SentinelNet.spec`.

## Out of scope

- SNMP/API-token identities (SSH credentials only).
- Changes to the Zero-Touch Provisioner tab (tab-provisioner).
- Server-side CVE version-range matching; scan result persistence.
