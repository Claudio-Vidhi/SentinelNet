# SentinelNet — Security Audit & Hardening Plan

**Last updated:** 2026-07-11
**Scope:** full application source (FastAPI central `app_server.py`, auth/RBAC, credential storage, MCP server, site agents, WebSocket terminal, provisioners, FortiGate/WLC/ARP observability, web UI).
**Method:** white-box source review. No live pentest; no real devices available.

This is the single canonical security document (it supersedes the earlier dated copy). Each finding carries a **Status**: ✅ fixed · 🔧 in progress · 📋 planned · ⏸️ accepted/deferred.

---

## 1. Executive summary

Posture is **good for an internal network-operations tool**: bcrypt password storage, fail-closed JWT, RBAC with tenant scoping enforced server-side, secrets encrypted at rest, audit logging. No critical vulnerabilities (unauth RCE, SQLi, auth bypass) found. Residual risks are transport security (no built-in HTTPS), operational hardening of the data files on disk, and defence-in-depth around the CLI guardrail.

| Severity | Open | Fixed |
|---|---|---|
| High | 1 (H-1 TLS) | H-2 password policy |
| Medium | 3 | M-1 CLI, M-5 verify_tls |
| Low | 5 | L-4 arp/stats scope |
| Info | 2 | — |

---

## 2. Controls verified correct

- **Password storage:** bcrypt cost 12, auto salt, constant-time verify (`user_manager.py`).
- **JWT:** HS256, random 256-bit secret (DPAPI-protected at rest, env override), **fail-closed** if unreadable; 60-min expiry; deleted/disabled accounts re-checked every request.
- **Login lockout:** 5 fails → 5-min per-username lock, audited.
- **First-run register:** refused once any user exists.
- **RBAC + tenant scoping:** `require_admin/operator`, `user_group_scope`/`assert_device_allowed` applied to inventory, MAC tracker, config analyzer, AI context, backups, FortiGate/WLC/ARP; WS terminal re-checks the OTP owner's scope.
- **Secrets at rest:** device passwords, FortiGate API tokens, AI keys Fernet-encrypted; Fernet key DPAPI-protected or from `SENTINELNET_MASTER_KEY`.
- **Site-agent auth:** per-site `secrets.token_urlsafe(32)`, stored SHA-256-only, shown once, regenerable, constant-time compare.
- **WS terminal:** single-use 30-s OTP, tenant-scoped.
- **Path traversal:** `download_backup` realpath-guarded to the absolute backup root.
- **SQLi:** all SQLite access parameterized (incl. `arp_entries`).
- **CORS:** explicit origin list, no wildcard-with-credentials.
- **MCP:** pure re-authenticating bridge; per-tool disable; 200k output cap.

---

## 3. Findings

### H-1 — No built-in TLS on the management panel · ⏸️ accepted (documented)
Panel/API serve plain HTTP; JWTs, device creds, FortiGate tokens, configs transit unencrypted. Default bind `127.0.0.1` mitigates local installs; `0.0.0.0`/Docker exposes it.
**Plan:** terminate TLS at a reverse proxy (Caddy/nginx/Traefik) or add optional `uvicorn ssl_certfile/ssl_keyfile` via settings + HSTS. Document in README/compose.

### H-2 — No server-side password policy · ✅ fixed
`user_manager.MIN_PASSWORD_LENGTH=8` + `password_error()` enforced in register / create-user / change-password; frontend hints aligned to 8. (Recommend raising to 10 + reject username==password later.)

### M-1 — CLI blacklist bypassable · 🔧 in progress
Denylist (`COMMAND_BLACKLIST`/`DANGEROUS_COMMANDS`) misses abbreviations. Now being reworked so **admins bypass entirely**, **operators are subject to it by an admin-controlled toggle**, and an optional allowlist mode remains the longer-term boundary. Full command+output already audited.

### M-2 — Default device credentials `Admin`/`admin` · 📋 planned
`core_engine.DEFAULT_*` fall back to `Admin/admin/admin` for `default`-profile devices when env unset.
**Plan:** refuse triage/commands on `default`-profile devices when `SENTINELNET_ADMIN_*` unset, or warn prominently at startup + UI.

### M-3 — Login throttling per-username, in-memory · 📋 planned
Keyed on username only; username spray from one IP not slowed; restart clears counters.
**Plan:** add per-source-IP throttle in `login`.

### M-4 — No JWT revocation on logout · 📋 planned
Logout is client-side only; stolen token valid ≤ 60 min.
**Plan:** in-memory JTI denylist until expiry (add `jti` to token claims), cleared on natural expiry; or short access token + refresh.

### M-5 — FortiGate REST `verify_tls` default false · ✅ fixed
Default flipped to `True` (`FgtTokenSchema`). Opt-out remains for self-signed certs; recommend importing the FortiGate CA. Same rule to apply to future WLC RESTCONF.

### L-1 — JWT in `sessionStorage` · 📋 planned (with L-2)
Readable by any XSS. **Plan:** add CSP header (below); consider httpOnly cookie + CSRF later.

### L-2 — No security headers · 📋 planned
Missing CSP, `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`, `Referrer-Policy`.
**Plan:** small response middleware setting these.

### L-3 — Audit log not tamper-evident · ⏸️ accepted
Plain rotating file. **Plan (optional):** forward to syslog/SIEM or hash-chain entries.

### L-4 — `/api/arp/stats` not tenant-scoped · 🔧 fixing now
Returns global aggregate counts to any authenticated user (no addresses leak). Being scoped with `user_group_scope` alongside the per-tenant client-map work.

### L-5 — MCP bridge credentials in client config · ⏸️ documented
`SENTINELNET_USERNAME/PASSWORD` live in the LLM client's plaintext config.
**Plan:** document using a dedicated least-privilege account (viewer / single-tenant operator) for MCP.

### DF-1 — Sensitive data files created in the working directory · 🔧 in progress *(new)*
On exe launch the CWD gains `secret.key`, `jwt_secret.key`, `users.json` (password hashes), `sites.json` (token hashes), `*.db`, `audit.log`, etc. On a shared host these sit beside the exe with default ACLs.
**Plan (this iteration):** (1) default all state under a dedicated `data/` subdirectory (env `SENTINELNET_DATA_DIR` still wins); (2) restrict ACLs on the secret/credential files to the owner at startup (Windows `icacls`, POSIX `chmod 600`); (3) confirm no endpoint serves the data dir (verified: only specific typed endpoints exist, no static mount). `templates/` is extracted code, not secret.

### I-1 — AI context can send full configs to third-party LLMs · ⏸️ by design
`attach_device_ip`/`attach_fortigate_ip` send configs (with in-config secrets) to the configured provider. Prefer Ollama for sensitive tenants; per-profile rate limit bounds volume.

### I-2 — Provisioner day-0 configs contain plaintext secrets · ⏸️ by design
Generated day-0 configs embed admin passwords/community strings in cleartext (expected for bootstrap). Treat downloads as sensitive.

---

## 4. Prioritised implementation plan (remaining)

1. **DF-1 data-file hardening** — `data/` default + ACL lockdown (this iteration).
2. **M-1 CLI role controls** — admin bypass + operator toggle (this iteration).
3. **L-4 arp/stats scoping** (this iteration).
4. **L-2/L-1 security headers + CSP** — one middleware, low risk.
5. **M-4 JWT revocation** — jti claim + logout denylist.
6. **M-3 per-IP login throttle.**
7. **M-2 default-credential guard.**
8. **H-1 TLS** — reverse-proxy guidance + optional uvicorn TLS.
9. Optional: L-3 audit hardening, L-5 MCP account guidance, raise password min to 10.
