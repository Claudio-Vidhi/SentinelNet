# Email notifications — design, part 1 of 3 (2026-09-16)

Depends on `2026-09-16-super-admin-role-design.md` ("admin" below means
`is_admin`: `super_admin` or `admin`).

## Scope and decomposition

| Part | Content | This doc |
|---|---|---|
| 1 | Engine + "Notifications" tab: per-user preferences, admin rules, history | yes |
| 2 | Editable subject/body templates with placeholders and preview | no |
| 3 | Scheduled reports (Netsec audit, CVE) configured from the GUI | no |

Parts 2 and 3 reuse part 1's dispatcher, recipients, context and history.

## Today

- `services/mailer.py` sends only account mail (reset, invite, email change).
- Operational alerts are a chime + browser notification (`static/js/devices.js:867-911`).
- `events` / `incidents` already unify all observability sources (ADR-0002).

## 1. Sources

A single entry point, `services/notifications.py::emit(kind, device_ip,
severity, title, ctx, dedup_key)`. Producers know nothing about email.

| kind | Source | Hook |
|---|---|---|
| `incident.opened` | `incidents` | dispatcher reads rows with `id > cursor` |
| `siem.alert` | `events` where `event_type='log.security'` | same, own cursor |
| `device.down` / `device.up` | `services/ping_monitor.py::_run_cycle` | emit on transition confirmed by **2 consecutive cycles** (flapping) |
| `cve.new` | `services/cve_intel.py::refresh` | diff CVE ids old vs new snapshot, emit only new ones |

**Severity** is one 4-step scale `critical|high|medium|low`:
- syslog 0-2 critical, 3 high, 4 medium, 5-7 low;
- CVSS ≥9 critical, ≥7 high, ≥4 medium, else low;
- `device.down` high, `device.up` low.

**Group** is always resolved `device_ip → inventory → Group`, the same field
`user_group_scope` uses. Unknown device → group `None`: only admins and rules
without a group filter receive it.

**Loop:** `notification_loop()` asyncio task, 60 s tick, started from the
lifespan in `app_server.py` next to `ping_monitor.start()` — not from
`listener_manager`, so it runs with observability disabled.

## 2. Data model and delivery

Tables in the main DB (`core/db.py`, idempotent migration):

| Table | Columns |
|---|---|
| `notify_prefs` | `username` PK, `enabled`, `kinds_json`, `min_severity`, `groups_json` (empty = whole scope), `mode` (`immediate`\|`digest`), `digest_every_min`, `quiet_start`, `quiet_end`, `quiet_bypass_critical` |
| `notify_rules` | `id`, `name`, `enabled`, `recipients_json`, `kinds_json`, `min_severity`, `groups_json`, `mode`, `digest_every_min`, quiet fields, `created_by` |
| `notify_outbox` | `id`, `target` (`user:<name>`\|`rule:<id>`), `kind`, `severity`, `device_ip`, `grp`, `title`, `ctx_json`, `dedup_key`, `created_ts`, `due_ts`, `attempts` |
| `notify_log` | `ts`, `target`, `recipient`, `kind`, `title`, `status` (`sent`\|`failed`\|`suppressed`), `error`, `item_count` |
| `notify_cursors` | `source` PK, `last_id` |

A user preference and an admin rule have the same filter shape; only the
recipient differs. One filter function serves both.

### emit()

1. If SMTP is disabled: return (the outbox never grows unbounded).
2. Resolve group.
3. For each target (users with `enabled` and a non-empty email; enabled rules):
   - **scope** — users: group must be inside `user_group_scope`; an event
     outside scope is never mailed regardless of filters. Rules: no scope
     check (configured by an admin).
   - **filters** — kind in `kinds`, severity ≥ `min_severity`, group in
     `groups` when non-empty.
   - **anti-flood** — same `dedup_key` + target within 30 min → log
     `suppressed`, skip.
   - enqueue with `due_ts`: now (immediate) / next digest boundary (digest) /
     end of quiet window (quiet hours, unless critical and bypass on).
     Quiet hours **defer**, never drop.

### Tick

1. Read new `incidents`/`events` rows past the cursors → `emit`.
2. Group outbox rows with `due_ts <= now` by target: 1 row → single mail,
   >1 → digest mail ("5 notifications: 2 critical …").
3. Send via `mailer.send_email` inside `asyncio.to_thread`; write `notify_log`;
   delete sent rows.
4. `MailerError` → log `failed`, `attempts += 1`, retry next tick; drop after 3.

Retention: `notify_log` 30 days. Mail text in part 1 is fixed (IT/EN by
kind + ctx); part 2 makes it editable over the same `ctx`.

## 3. API and UI

Router `routers/notifications.py`:

| Method | Route | Who |
|---|---|---|
| GET/PUT | `/api/notifications/prefs` | authenticated user, own prefs only; `groups` validated against `user_group_scope` |
| POST | `/api/notifications/prefs/test` | user, test mail to own address |
| GET/POST | `/api/notifications/rules` | admin |
| PUT/DELETE | `/api/notifications/rules/{id}` | admin |
| POST | `/api/notifications/rules/{id}/test` | admin |
| GET | `/api/notifications/log` | admin: all; user: own `user:<self>` rows |

Pydantic at the boundary: `kinds`/`severity` enums, recipients contain `@`,
max 20 recipients, times `HH:MM`, digest ∈ {15, 60, 240, 1440}. Rule writes
go through `log_audit`.

Tab `tab-notifications`, nav item `fa-bell`, **no** `requires-admin`;
`static/js/notifications.js` lazy-loaded via `LAZY_TAB_SCRIPTS`.

- **My preferences** (Linear-style): master toggle with destination address
  (warning + link to profile when missing); one row per kind with toggle and
  description; min severity; groups (checkboxes limited to scope); immediate
  vs digest; quiet hours (two `<input type="time">` + critical bypass);
  Save, Send test.
- **Rules** (`requires-admin`, Railway/Vercel-style): table Name / Kinds
  (chips) / Severity / Groups / Recipients / Mode / toggle / actions;
  "+ Rule" opens a modal via `openModal`.
- **History** (Sentry-style): Time / Recipient / Kind / Title / Status,
  filter by status.
- Banner when SMTP is disabled, linking to Settings → SMTP.
- Frontend rules: `tr()` IT+EN, no inline handlers, accessible names.

## Tests

`tests/test_notifications.py` (mailer mocked): filters; scope (restricted
user never receives other groups); anti-flood; quiet hours defer + critical
bypass; digest grouping; retry ×3 then drop; cursor idempotence; ping 2-cycle
confirmation; CVE diff; SMTP disabled enqueues nothing.

`tests/test_notifications_api.py` (`TestClient`): 401 unauthenticated; 403
on `/rules` for operator; user cannot read another user's log; 422 on bad
input.

Existing i18n / a11y / lazy-tab / modal tests cover the frontend rules.

## Versioning

MINOR.
