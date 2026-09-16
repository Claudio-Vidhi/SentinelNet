# Per-user tab permissions and tenant scope for admins — design (2026-09-16)

Builds on `2026-09-16-super-admin-role-design.md` (roles `super_admin > admin > operator > viewer`, one gate `assert_can_manage`).

Route inventory this design was derived from: `2026-09-16-admin-permissions-route-map.md` (296 routes, 27 tabs). It is input data, not the authority: the code registry below is.

## Problem

1. "Visible tabs" (`allowed_tabs` in users.json) only hide nav buttons. Every API behind a hidden tab still answers (`routers/auth.py` `set_user_tabs_ep` says so in a `ponytail:` comment).
2. Admins are never tenant-scoped: `user_group_scope` returns `None` for any admin. A super_admin cannot give an admin a subset of tenants.

The user wants the super_admin to decide, per admin, **which tenants** and **which features (tabs)** that admin can use, enforced by the server.

## Decisions

### D1. Tabs enforced server-side, for every role

- `allowed_tabs` keeps its meaning: empty = all tabs. `super_admin` is always unrestricted.
- Stored ids are normalised on read with the same legacy aliases the frontend uses (`tab-mac`, `tab-clientmap`, `tab-diagnosi`, `tab-endpoints` → `tab-endpoint`) — one Python copy of the map in `user_manager`, tested against the JS one.
- Sub-tabs are granted with their parent: `tab-map` ⇒ `tab-map-interactive`, `tab-provisioning` ⇒ `tab-provisioner`.
- New dependency `require_tab(*tab_ids)` in `routers/deps.py`: passes if the user is unrestricted or holds any of the listed tabs; otherwise 403 `"Funzionalita' non abilitata per questo utente."`. The returned callable carries its tab ids (attribute) so tests can introspect it.
- Applied per route (decorator `dependencies=[Depends(require_tab(...))]`) or per router when a whole router belongs to one tab.

### D2. Every route is classified, fail-closed

Each `/api/*` HTTP and WebSocket route falls in exactly one class:

| Class | Meaning | Examples |
|---|---|---|
| TAB | behind `require_tab(...)` | `/api/drift/*` → `tab-config-drift` |
| BASE | any authenticated user, whatever their tabs | login/logout/me/profile, inventory reads used by most tabs, groups list, i18n/boot data, terminal (`/api/ws-token`, `/api/ws-terminal/{ip}`, `/api/send-command` — governed by role, reachable from device rows in many tabs) |
| PUBLIC | no session by design | register (first run), login, password reset, invite accept, SSO login/callback |
| MACHINE | non-user credential | `/api/agent/*` (X-Site-Token) |

BASE, PUBLIC and MACHINE are explicit sets of `(method, path)` in one module, `routers/route_classes.py`. A test walks `app.routes` and fails if a route is in none of the four classes or in more than one. A new route therefore breaks the suite until someone classifies it — nothing is open by omission.

Routes with no dashboard caller (MCP-only, orphans — route map §C) take the tab of the feature they belong to (e.g. `/api/provisioner/generate` → `tab-provisioning`, `/api/observability/*` → `tab-flows`), not BASE.

### D3. Tenant scope applies to admins

- `user_group_scope(user)`: `None` only for `super_admin`; `admin`, `operator`, `viewer` use their groups (empty = all). Every route already calling `user_group_scope` / `devices_in_scope` / `assert_group_allowed` / `assert_device_allowed` starts scoping admins with no further change.
- New dependency `require_unscoped_admin`: `super_admin`, or `admin` with no groups. Used for **global** admin routes (class G in the route map): settings (SMTP, SSO, base URL, TLS, updates, ping monitor, fleet), cloud backup, MCP config, sites CRUD, tenant (group) CRUD, incident rule parameters, FortiGate target/token management not tied to one device. A tenant-scoped admin can never reach a setting that affects other tenants — this is what closes the SSO/SMTP escalation (a scoped admin re-mapping the IdP admin group, or redirecting password-reset mail).
- Admin routes on **tenant data** (class T) that do not scope today get the existing helper: per-device routes `assert_device_allowed`, list routes `devices_in_scope` / group filter. FortiGate `{ip}` routes are T.
- A global route is gated by BOTH its tab and `require_unscoped_admin`.

### D4. User management inside the admin's perimeter

For an actor whose scope is not `None` (scoped admin):
- `GET /api/users` returns only users whose groups are non-empty and a subset of the actor's groups (a user with "all tenants" is outside any scoped perimeter), plus the actor itself.
- `assert_can_manage` additionally requires target groups ⊆ actor groups and non-empty; groups assignment (`/api/users/groups`, create) accepts only non-empty subsets of the actor's groups.
- A scoped admin cannot grant tabs it does not hold (`/api/users/tabs`, create): the granted set must be ⊆ the actor's effective tabs. Same rule for any admin with a restricted tab list.
- `POST /api/users/invite` → 403 for a scoped admin (invites carry no groups).
- Unscoped admins and super_admins keep today's behaviour (rank ladder only).

### D5. UI

- Users table: on rows the actor can manage, the Tenant and Tab editors are shown for admin rows too (today admin rows show "all"). Tab checkboxes include the admin-group tabs (`tab-users`, `tab-groups`, `tab-sites`, `tab-mcp`, `tab-settings`) when the row's role is admin-level, and are limited to tabs the actor holds.
- Next to `tab-settings`, `tab-sites`, `tab-groups`, `tab-mcp`: a hint via `tr()` that these also require the admin to have no tenant restriction.
- The frontend hides nav buttons as today; a 403 from `require_tab` shows the standard error toast (no silent empty panels): verify per lazy tab loader that `apiFetch` surfaces it.
- New i18n keys it + en; a11y rules unchanged.

### D6. Behaviour change for existing installs

Users who already have `allowed_tabs` set lose API access to the hidden tabs. That is the point, but it is a change: CHANGELOG entry under Changed. No data migration.

## Error codes

401 unauthenticated (unchanged); 403 tab not granted; 403 tenant outside scope; 403 global route for a scoped admin; 404 target user not found or not visible to a scoped admin (don't leak existence outside the perimeter).

## Testing

- `tests/test_route_classes.py`: completeness (every route in exactly one class); every TAB route's tab ids exist in `templates/dashboard.html` `data-tab`/`data-tabs`.
- `tests/test_tab_enforcement.py`: per router at least one TAB route — user with the tab passes the tab gate; without → 403; empty list → allowed; super_admin → allowed; legacy alias and sub-tab rules.
- `tests/test_admin_tenant_scope.py`: scoped admin — device in scope ok, out of scope 403; list endpoints filtered; every G route → 403 for scoped admin, ok for unscoped admin; SSO and SMTP settings explicitly (escalation paths).
- `tests/test_super_admin_api.py` extended: scoped admin user-management perimeter (list filtered, manage outside perimeter 404, assign groups/tabs outside own set 403, invite 403).
- JS: alias map parity (Python vs `normalizeAllowedTabs`); assignable tabs on admin rows (`tests/js/test_assignable_tabs.mjs`).
- WebSocket: one connect test for `/api/ws-terminal/{ip}` stays BASE-authenticated.

## Out of scope

Read/write granularity per tab and reusable named profiles (FortiGate `accprofile`); tenant scoping of audit-checklist engagements; editable mail templates (notifications spec, part 2).

## Versioning

MINOR (new enforcement; behaviour change for users with a tab list).
