# Device Provisioning: Tenant Identities + Tab Reorganization — Design

Date: 2026-07-17
Status: approved

## Goal

Improve Device Provisioning tab UX for a network security engineer:
named credential profiles ("identities") scoped to a tenant, and a
reorganized two-column tab layout.

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

## 6. Execution

Subagent-driven: Task A backend (identity_manager + endpoints +
core_engine + tests), Task B frontend (tab reorg + identities panel),
B depends on A's API contract. Final step: rebuild exe with
`pyinstaller SentinelNet.spec`.

## Out of scope

- SNMP/API-token identities (SSH credentials only).
- Changes to the Zero-Touch Provisioner tab (tab-provisioner).
