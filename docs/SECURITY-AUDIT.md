# SentinelNet — Security Audit

**Date:** 2026-07-11
**Scope:** authentication/authorization, RBAC + tenant scoping, secrets handling,
CLI command safety, path handling, and the newly added FortiGate/WLC/ARP surfaces.
**Method:** manual source review (no live pentest — no target device available).

Severity legend: 🔴 High · 🟠 Medium · 🟡 Low · 🟢 Good (no action).

---

## Summary

The core auth model is solid: bcrypt (cost 12), JWT with a fail-closed secret,
per-tenant scoping enforced server-side on every data endpoint, login lockout,
OTP-gated WebSocket terminal, encrypted device/API secrets, and a path-traversal
guard on backup download. The findings below are mostly hardening items; the two
worth acting on first are **server-side password policy** (H) and **unverified
TLS to FortiGate REST APIs** (M).

| # | Sev | Area | Finding |
|---|-----|------|---------|
| 1 | 🔴 | Auth | No server-side password strength/length validation |
| 2 | 🟠 | FortiGate API | REST calls default to `verify_tls=false` + warnings suppressed |
| 3 | 🟠 | CLI safety | Command blacklist is denylist-based and incomplete |
| 4 | 🟡 | Login | Username enumeration via distinct error copy |
| 5 | 🟡 | JWT | No revocation list; 60-min token stays valid after logout |
| 6 | 🟡 | Backup path | Traversal guard relies on `backup-config` existing at CWD |
| 7 | 🟢 | ARP/WLC (new) | Reviewed — scoped, parametrized, MAC-validated |

---

## Findings

### 1. 🔴 No server-side password policy
`UserSchema` (`app_server.py`) accepts any `password: str`. `POST /api/auth/register`,
`POST /api/users` and `POST /api/auth/change-password` never check length or
complexity — the "min 6 characters" rule exists **only** in the dashboard JS, so a
scripted request can set an empty or trivial admin password.

**Impact:** weak/empty credentials on privileged accounts; frontend control is
trivially bypassed.
**Fix:** enforce a minimum in Pydantic and in `user_manager.create_user` /
`change_password`, e.g. `password: str = Field(..., min_length=8)`, rejecting
server-side regardless of client. Consider a shared `validate_password()` helper.

### 2. 🟠 Unverified TLS to FortiGate REST API
`fortigate_service.py` stores `verify_tls` defaulting to **false**, calls
`urllib3.disable_warnings(...)`, and passes `verify=False` to `requests`. The API
**Bearer token is a long-lived credential**; over an unverified channel a
man-in-the-middle on the management path can capture it and gain the api-user's
FortiGate privileges.

**Impact:** token/credential disclosure and FortiGate compromise if the mgmt
network is not fully trusted.
**Fix:** default `verify_tls=true`; when a self-signed cert is unavoidable, let the
admin pin the FortiGate CA/cert per device rather than globally disabling
verification. At minimum surface the insecure state in the UI.

### 3. 🟠 CLI command blacklist is a denylist
`COMMAND_BLACKLIST` blocks `reload`, `erase`, `delete`, `format`, `reboot`,
`conf t`, `configure terminal`, `copy … startup-config`. Denylists miss variants:
`write erase` is caught only via `erase`, but `clear`, `write memory`/`wr mem`,
platform-specific destructive verbs, and command chaining/abbreviations
(`rel`, `del`) are not covered. `send_cli_command` is `require_operator`, so this
is defense-in-depth, not the only gate.

**Impact:** an operator (or a compromised operator token) can run destructive
commands the blacklist intends to stop.
**Fix:** prefer an allowlist of read-only verbs (`show`, `get`, `display`,
`diagnose … list`) for the one-shot command API; keep config changes behind the
explicit provisioning/bulk paths.

### 4. 🟡 Username enumeration
`POST /api/auth/login` returns lockout (429) and "credentials invalid" copy that
lets an attacker distinguish existing from non-existing usernames over time (the
lockout counter also keys on username). Low impact given bcrypt + lockout.
**Fix:** uniform error/response timing; consider keying lockout partly on source IP.

### 5. 🟡 No JWT revocation
`logout()` only clears client `sessionStorage`; a stolen 60-minute token remains
valid until expiry. Disabled/deleted accounts *are* re-checked on each request
(good), but an active user's leaked token cannot be force-revoked.
**Fix:** short access token + refresh, or a server-side token-version/jti denylist
bumpable on logout/compromise.

### 6. 🟡 Backup path guard depends on CWD
`download_backup` builds `os.path.realpath("backup-config")` from the current
working directory. The traversal check itself is correct (`startswith(backup_dir +
os.sep)`), but resolving a **relative** root is fragile under the bundled exe /
service launch. Use `data_config.get_path("backup-config")` (absolute) as the root.

### 7. 🟢 New code reviewed (ARP / WLC / FortiGate services)
- **SQL:** all `mac_history` ARP queries are parameterized; `ip LIKE ?` and MAC
  fragment matching use bound params — no injection.
- **Tenant scoping:** `/api/arp/*`, `/api/wlc/*`, `/api/fortigate/*` resolve the
  device through `assert_device_allowed` / `user_group_scope`; `arp/scan` and
  `full-config` require operator. Cross-tenant reads are blocked.
- **CLI injection:** `wlc_client_detail` and FortiGate client tools pass MACs
  through `normalize_mac`, which rejects anything but 12 hex digits before
  building the CLI string — no command injection via MAC.
- **ARP collection is read-only** (`show ip arp` / `get system arp`), best-effort:
  a device that doesn't route the VLAN returns empty and is skipped, so the
  feature can't be abused to run arbitrary commands.

---

## Recommendation order
1. Add server-side password validation (#1) — small change, closes a real gap.
2. Flip FortiGate `verify_tls` default and add cert pinning (#2).
3. Move the one-shot command API to a read-only allowlist (#3).
4. Address #4–#6 as hardening in a follow-up.
