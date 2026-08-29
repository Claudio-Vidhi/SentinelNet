# App review — fix plan

Source: full-app audit of 2026-08-28 (three independent read-only review
passes plus adversarial re-verification of every claim). Detailed findings
with locations are kept in the private audit draft and in `data/security/`
per CONTRIBUTING §6; this plan records the remediation work, not the
exploitable detail.

Conventions used below: every WP lists the modules it touches and its
acceptance gate. New tests are pytest files under `tests/`; user-facing
strings stay Italian; comments stay English.

Status: **Phase 1 and Phase 2 fully landed; Phase 3 items 12 (partial),
13 (script), 16, 17, 18 landed.** Second batch (2026-08-29): device SSH
host-key pinning (review P0-6), audit-log cap raised to ~100 MB, docs
contradictions resolved (design-system deleted, GO_PORT_PLAN scoped,
architecture.md refreshed), PyInstaller spec cleaned (redundant drivers
data entry removed, console=True documented), exe rebuilt and
smoke-tested. Third batch (2026-08-29): quick wins — dead reimport
contract removed, `test_multi_ip` clock flake fixed, ARP collection
pooled, host-key runbook entry, MCP privileged-account startup warning,
`db_health` writer chip in the observability tab. Fourth batch
(2026-08-29): core_engine split continued (credential chain →
`core/device_credentials.py`, backup storage → `core/backup_store.py`,
netmap deliberately kept), ARP command table moved to the drivers layer,
vendor-knowledge placement documented in architecture.md. Fifth batch
(2026-08-29, self-review of the four batches): `users.json` and
`login_attempts.json` writes made atomic (tmp + `os.replace`, the pattern
every sibling store already used — the read was hardened in WP1 but the
write that creates a corrupt store was not); device host-key pins scoped
per bastion (`ssh_known_hosts.<bastion>`), since two tenants may run the
same private IP behind two bastions and a single file keyed by bare IP
turned the second into a false key-change; `login_attempts.json` added to
`.gitignore`; the L2 cycle moved off the shared threadpool onto the
`device-ssh` pool; MCP per-call audit attribution closed (see follow-ups).
Sixth batch (2026-08-29): the frontend block — modal manager, i18n
migration to `tr()`, accessibility pass (items 13 and 14). Remaining:
netmap extraction (blocked on a parser layer).

---

## Phase 1 — immediate (security edges + artifact correctness) — DONE

### WP1. User store integrity and concurrency — done 2026-08-28

Landed in `security/user_manager.py`, `routers/auth.py`: an unparseable
user store is treated as occupied and broken (registration refuses, login
suspends with 503, corruption is audited); an `RLock` serializes every
read-modify-write and every file read. Covered by
`tests/test_user_store_integrity.py` (10 tests).

### WP2. Explicit failure on credential decryption failure — done 2026-08-28

Landed in `core/core_engine.py`: stored ciphertext that fails to decrypt
raises `CredentialDecryptError` naming the device instead of sliding into
the default-credential fallback; rows without stored credentials keep the
fallback unchanged. Covered by `tests/test_device_credentials.py`.

### WP3. Fail-closed MCP tool gating — done 2026-08-28

Landed in `ai/mcp_server.py`: before the first successful config sync, a
fetch failure disables the whole catalogue (fail closed); after a sync,
last-known state is kept. Covered by additions to
`tests/test_mcp_server_tools.py`. Remaining: shared-account posture and
per-call MCP audit attribution.

### WP4. One dependency truth for both artifacts — done 2026-08-28

`requirements.txt` gained `pysnmp` + `python-docx` (Docker image no longer
crashes on SNMP polling / DOCX export); `pyproject.toml` gained `ncclient`;
`uv.lock` refreshed; `httpx` moved into the dev group so `uv sync` keeps
TestClient alive. Follow-up (same day): exact `==` pins in
`requirements.txt`, floor lowered to `>=3.11`, `fastapi<0.141` cap — see
item 17.

---

## Phase 2 — near-term (reliability and noise) — DONE

### WP5. One command-blacklist policy — done 2026-08-28

Landed in `security/command_policy.py`: the three lists now live in one
module as named tiers (`INTERACTIVE_PATTERNS` — admins bypass, operators
subject to the setting; `BULK_ALWAYS_PATTERNS` — binds every role;
`SYSTEM_SUBSTRINGS` — the core_engine relay net). `routers/commands.py` and
`core/core_engine.py` keep their public names as aliases; the WS terminal,
one-shot API, bulk runs and the agent relay all consume the same lists.
Covered by `tests/test_command_policy.py` (11 tests) plus existing
blacklist regressions.

### WP6. Persistent lockout + request rate limiting — done 2026-08-28

Landed in `security/security_manager.py`, `routers/auth.py`,
`app_server.py`: lockout keys combine source IP + account (a remote caller
can no longer lock out a named account from elsewhere), state persists to
`login_attempts.json` across restarts, recovery paths clear every source
for the account (`clear_account_lockouts`). A per-IP sliding-window
rate-limit middleware guards the expensive endpoints (scans, triage, bulk
commands, audits, ws-token) at 30 req/min. Covered by
`tests/test_rate_limit_and_lockout.py` (7 tests).

### WP7. Loud loss in the ingest/write pipeline — done 2026-08-28

Landed in `core/db.py`, `observability/ingesters/udp_server.py`,
`routers/observability.py`: queue-full drops in the DB writer and in the
ingest listeners are announced by a rate-limited log line (once per minute,
not per packet) in addition to the counters; the writer supervisor sets a
persistent `writer_dead` state when the restart budget is exhausted
(cleared on `start_writer`); the health endpoint publishes a `db_health`
block with a `degraded` flag (any drop or a dead writer since startup).
Covered by `tests/test_db_loud_loss.py`. Remaining: a UI surface for the
degraded state (frontend change, lands with the next observability-tab
work).

### WP8. Throughput lag metrics — done 2026-08-28

Landed in `observability/normalize.py`, `observability/correlator.py`: a
source reading exactly its per-cycle cap increments
`normalize_capped{source=...}` and a rate-limited warning; a saturated
correlation window increments `correlation_capped` likewise. Both are
visible in the health snapshot. Covered by
`tests/test_pipeline_cap_metrics.py` (4 tests).

### WP9. L2 discovery scheduler — done 2026-08-28

Landed in `collectors/l2_scheduler.py`, `core/data_config.py`,
`observability/listener_manager.py`: `l2_poll_s` in the obs config
(default 0 = off, same deliberate-opt-in family as the SNMP/Linux pollers,
env `SENTINELNET_OBS_L2_POLL_S`) starts a scheduled cycle: MAC collection
(pooled), ARP collection, and `mac_history` pruning — pruning now has its
own clock instead of riding manual scans. Phases are isolated: one
collector failing does not stop the others. Covered by
`tests/test_l2_scheduler.py` (6 tests, including the first
listener-manager wiring tests).

### WP10. Verified MAC-collection transports — done 2026-08-28

Landed in `collectors/mac_collector.py`: the advanced setting
`mac_transport_verify_tls` drives TLS verification (RESTCONF `verify`,
NETCONF `hostkey_verify`) across all four transport call sites; warning
suppression only applies while verification is off. Default stays off for
compatibility with self-signed management certificates; estates with a CA
opt in. Covered by `tests/test_mac_transport_verify.py` (6 tests).

### WP11. SSH work isolation — done 2026-08-28

Landed in `core/ssh_pool.py`: a dedicated bounded executor
(`device-ssh`, 16 workers) with a `run_ssh` helper; the four routes that
held the shared anyio pool across 15–90 s netmiko sessions
(`triage_single_device`, `arp_scan`, `mac_scan`, `test_bastion`) are now
async and dispatch device work to the pool. Covered by
`tests/test_ssh_pool.py` (5 tests).

---

## Phase 3 — structural

| # | Item | Notes |
|---|---|---|
| 12 | Split `core_engine.py` — **partial, 2026-08-29** | driver registry → `drivers/registry.py`; credential fallback chain → `core/device_credentials.py`; backup storage + offsite mirror → `core/backup_store.py` (re-exports keep every call site and test patch point; core_engine now ~2200 lines). The netmap block stays: it is coupled to the CDP/LLDP parsers in the same file, and extracting it would create cross-imports until a parser layer exists |
| 13 | ~~Frontend UI kit + i18n migration~~ — **done 2026-08-29** | `static/js/ui-modal.js`: one modal manager (dialog semantics, focus trap, Esc, backdrop click, an `onClose` hook for the windows that release a resource, `data-esc-close="off"` for the CLI terminal, whose Esc belongs to the SSH session); all 37 ad-hoc `style.display` toggles migrated. i18n: `tr(key, vars)` added to `i18n.js` — its absence is why the ternaries grew — **414 inline ternaries → 0** and **14 Italian-only alerts → 0**, ~700 strings now in both languages; `scripts/check_i18n_coverage.py` also counts the `const en = …` form (it was hiding 204 of them) and reports zero. Gated by `tests/test_ui_modal.py` and `tests/test_i18n_keys.py`. `escapeHtml`/`showToast` already existed: reused, not rewritten |
| 14 | ~~Accessibility pass toward WCAG 2.1 AA~~ — **done 2026-08-29** | focus trap and `role="dialog"`/`aria-modal` come from the modal manager; the sidenav is a real tablist (`role=tablist/tab/tabpanel`, `aria-selected`, `aria-controls`, roving tabindex, arrow/Home/End); **366 form controls, 0 without an accessible name** (175 adjacent `<label>`s linked with `for=`, 45 named from their translated placeholder, 43 given hand-written bilingual `aria-label`s; the AT-hidden vendor mirror is deliberately left unnamed). `scripts/check_a11y.py` + `tests/test_a11y_dashboard.py` keep the count at zero |
| 15 | ~~Widen the driver contract or document the vendor-logic leak~~ — **done 2026-08-29** | ARP command table moved to `drivers/registry.py` (`arp_command_for`); the remaining vendor knowledge (syslog field parsers, private MIB OIDs, config parsers) is documented as deliberate adapter-layer placement in `docs/architecture.md` §9 "Where vendor knowledge lives" |
| 16 | ~~Docker hardening~~ — **done 2026-08-28** | non-root user (uid 1000, documented bind-mount ownership), HEALTHCHECK on `/api/version`, compose references fixed to `docs/hardening.md`, `admin/admin` example credentials removed from compose |
| 17 | ~~Python version policy~~ — **done 2026-08-28** | floor lowered to `>=3.11` after the full suite passed on 3.11.15 with the lock's dependency set (and on 3.14); the 3.11-slim image now satisfies the floor; `.python-version` stays 3.14 as the dev interpreter; `requirements.txt` pinned to the exact known-good versions so the Docker artifact installs what the lockfile tests; `fastapi<0.141` cap added — 0.141's lazy routing (`_IncludedRouter`) breaks the route-contract tests, verified by re-resolution drift on 3.11 |
| 18 | ~~Incident retention semantics~~ — **done 2026-08-28** | schema v10: `incidents.resolved_ts`, set on the resolve transition and backfilled from `closed_ts`/`opened_ts` at migration; retention prunes from the resolution moment, so a year-long incident resolved yesterday keeps its evidence; covered in `tests/test_observability_ingest.py` |

## Out of scope

- Anything already owned by `docs/roadmap.md` (confirm-before-concluding,
  `device.unreachable`, acknowledgement fields, notification engine, plane
  separation).
- New features; this plan remediates, it does not extend.

## Order of execution

Phase 1 WP1→WP4 landed first, then Phase 2 WP5→WP11, then the Phase 3
items above; each with its test gate and the standard pre-commit gates
(pyrefly, full pytest, frontend check only if `static/js` or `templates/`
change). Final state 2026-08-29: pyrefly 0 errors, 2182 tests passed,
exe artifact rebuilt and smoke-tested (`/api/version` answers).

## Known follow-ups (tracked, not forgotten)

- `core_engine.BACKUP_FOLDER` is a re-exported *value*: it and
  `core.backup_store.BACKUP_FOLDER` are two bindings. Redirecting the
  backup tree must patch the `backup_store` one (noted at the re-export).

- ~~MCP per-call audit attribution~~ — **done 2026-08-29**: the MCP bridge
  sends `X-SentinelNet-Client: mcp/<tool>` on every request, a middleware
  stores it per request and `log_audit` stamps it on every line, so no audit
  call site changed. Header-supplied, so the log words it as *declared*:
  identity stays the JWT's, the tag answers "which client says it made this
  call". Covered by `tests/test_audit_client_attribution.py` (8 tests,
  including the round trip through the middleware).
- Default flip for `mac_transport_verify_tls` after one announced release
  (WP10 remainder).
- Docker image build verification on a Linux/CI host (no Docker daemon on
  the dev machine; Dockerfile changes are unverified there).
