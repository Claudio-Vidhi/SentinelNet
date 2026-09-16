# super_admin role — design (2026-09-16)

## Problem

Roles are flat: `VALID_ROLES = ("admin", "operator", "viewer")`
(`security/user_manager.py:32`). Any admin can create, demote, disable, delete
or reset another admin. There is no account that the other administrators
cannot take over.

## Model we copy

FortiGate, which SentinelNet already provisions (`services/fortigate_provisioner.py`):
the `super_admin` profile is the only one that can create or modify
`super_admin` accounts; a `prof_admin` manages what sits below it; the last
`super_admin` cannot be removed.

## Decision

Hierarchy: `super_admin > admin > operator > viewer`.

**Rule, in one place:** an actor may act on a target account only if the
target's current rank is strictly lower than the actor's, and may assign only
a role strictly lower than its own. `super_admin` is the exception: it may act
on anyone, including other `super_admin` accounts.

Acting on **yourself** keeps today's behaviour (delete own account, change own
email/password) and is not a way to change your own role.

### Backend

- `user_manager`: `VALID_ROLES` gains `super_admin`; `ROLE_RANK` dict;
  `is_admin(role)` → role in (`super_admin`, `admin`).
- `routers/deps.py`:
  - `require_admin = require_role("super_admin", "admin")` — the 101 existing
    `Depends(require_admin)` stay untouched and keep working for both.
  - `require_super_admin = require_role("super_admin")`.
  - `assert_can_manage(actor, target_username, new_role=None)` → 403 when the
    rule above is broken, 404 when the target does not exist.
  - `user_group_scope`: unrestricted for `is_admin`.
- Every `/api/users/*` endpoint that touches another account calls
  `assert_can_manage`: `role`, `disable`, `delete` (other user), `groups`,
  `tabs`, `email`, `send-reset`, `approve`. `POST /api/users` and `invite`
  check only `new_role`.
- The ~6 backend `role == "admin"` comparisons (`commands.py`,
  `cloud_backup.py`, `auth.py:317`, `auth.py:408`) become `is_admin(...)`.
- **Last-account guard** moves up one level: `is_last_active_admin` becomes
  `is_last_active_super_admin`, used by role/disable/delete. Admins are no
  longer the quorum; super_admins are.
- First-run setup (`auth.py:92`) creates `super_admin`.
  `first_admin_username` (break-glass CLI) returns a `super_admin`.
- `get_role` default for legacy accounts without a `role` field:
  `super_admin` (those are single-user installs, the owner).
- **SSO:** `resolve_role` never returns `super_admin` — an IdP group must not
  be able to mint the top role. With `sync_roles` on, an existing
  `super_admin` is left untouched (not demoted by the IdP). Audited.

Role is already re-read from disk on every request (`deps.py:63`), so a
demotion takes effect immediately without token revocation.

### Migration

Once, in the app lifespan: every existing `admin` becomes `super_admin`
(nobody loses power on upgrade). Marker `user_roles_version: 2` in
`app_settings.json` so admins created later are never promoted. One audit
line per promoted account. The migration writes only the `role` field.

### Frontend

- `isAdminRole(role)` helper in `core.js` (+ `types/globals.d.ts`); the ~15
  `currentRole === 'admin'` checks use it.
- Users table: role select offers only roles below the viewer's own
  (all for `super_admin`); edit/disable/delete controls hidden for rows the
  viewer cannot manage. Hiding is convenience; the API is the enforcement.
- Label `coreSuperAdministrator` via `tr()`, IT + EN.

## Tests

`tests/test_super_admin_role.py`:
- matrix actor × target × action: admin→super_admin 403 on every endpoint;
  admin assigning `super_admin` or `admin` 403; admin→operator ok;
  super_admin→super_admin ok;
- last active super_admin cannot be demoted/disabled/deleted;
- migration: admins promoted once, marker prevents second run;
- SSO: admin group maps to `admin`, never `super_admin`; `sync_roles` does
  not demote a super_admin;
- `TestClient` smoke: 403 carries through for a real admin session.

## Out of scope

Per-role permission profiles (FortiGate `accprofile`-style custom profiles).
Add when a fixed four-level ladder stops being enough.

## Versioning

MINOR (new role, migration is additive and automatic).
