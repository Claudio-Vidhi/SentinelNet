# Plan — deferred backlog (2026-09-12)

Spec: [2026-09-12-deferred-backlog-design.md](../specs/2026-09-12-deferred-backlog-design.md).
Item codes (S1, B, G1, N1, V1…) are the spec's.

**Ordering criterion**: a real hole before a missing convenience, and within
each tier the cheapest first. Phases 1-5 are work; Phase 0 is four questions
to the user that block nothing, so it runs alongside.

Every phase ends with the gates from `docs/development.md` §6. One commit per
numbered item unless the item says otherwise — a shared fix does not get split
per caller, and unrelated fixes do not get merged to save a commit.

---

## Phase 0 — ANSWERED 2026-09-12

1. **P1 — endpoint inventory KPIs: stay exact.** Closed; see the spec.
2. **P3 — port bounce: TESTED ON REAL HARDWARE AND IT WORKS** (user,
   2026-09-12). The last unverified write path in the product has now run
   against a switch. The procedure below stays as the way to re-verify it
   after a change to `services/port_action.py`, not as pending work.
3. **P4 — Windows: over SSH, not WinRM** (user's call, 2026-09-12). See the
   spec §P4: Windows ships an OpenSSH *server* since Windows 10 / Server 2019,
   which means the existing netmiko transport reaches it with no new
   dependency and no second remote-execution path to secure.
4. **P2 — FortiGate HA: no cluster available.** Stays unverified, stated.

### P3 — the port bounce field test (passed 2026-09-12; keep as the re-verification recipe)

`services/port_action.py` has never run `send_config_set` against real
hardware. What makes this test worth planning rather than just clicking the
button: the failure mode is a port left administratively down on someone's
switch, and the recovery is the same command that failed.

Pick the target first: an **access port with nothing plugged into it**, on a
switch that is not the one carrying the management path to itself. Bouncing
the uplink you are managing the switch through disconnects you mid-command,
and whether the second half ran is then unknowable.

1. Record the before state from the CLI, not from the panel:
   `show running-config interface <if>` and `show interface <if> status`. The
   panel reads a cache; the switch is the authority.
2. Bounce it from the Client Map row action, and watch the job result rather
   than the toast.
3. Read the state again. Expected: `shutdown` then `no shutdown` applied, the
   port back to its original admin state, and the running-config otherwise
   byte-identical to step 1.
4. If step 3 shows the port still down, that is the whole reason for the test:
   re-enable it by hand (`interface <if>` / `no shutdown`) before debugging
   anything, then report what the job result said versus what the switch did.
5. Only then repeat on a port with a device attached, to see that the device
   comes back — the two cases fail differently.

**Outcome 2026-09-12: it works.** Run by the user on real hardware. The port
came back up and the running-config was otherwise unchanged, which is the whole
contract. Re-run this recipe after any change to the command tables in
`services/port_action.py` — a vendor whose `shutdown`/`no shutdown` pair is
wrong fails silently until someone looks at the port.

---

## Phase 1 — The security holes (S1, S2, S4) and the RBAC gap (B)

The only items whose absence is exploitable rather than inconvenient. All four
are small.

### 1.1 — S4: carry the blacklist bypass to the relay

Smallest of the four and a pure correctness fix: same admin, same command, two
different outcomes depending on where the device lives.

- `command_jobs` gains the flag next to `kind`; `site_manager.enqueue_job`
  accepts it; `routers/commands.py` sets it from the same decision it already
  audits at line 181, never from anything the agent sends.
- `services/site_agent.py:693` passes it through to `send_custom_command`.
- The agent's independent allowlist check does **not** consult it. The flag
  widens the *blacklist* only; widening the allowlist would undo ADR-0008.

**Test**: an admin-bypass relay job whose command contains a blacklisted
substring completes; the same job from an operator is refused *by the agent*; a
`rest` job with the flag set still cannot reach a `cmdb/` path. Confirm the
first test fails before the fix.

### 1.2 — S1: JWT revocation

- `jti` (uuid4) added at mint in `routers/auth.py`; `get_current_user` rejects a
  token whose `jti` is in the denylist.
- Denylist persisted under `DATA_DIR` with the same `restrict_permissions()`
  treatment as the other secrets. Entries carry the token's `exp` and are
  dropped once past it, so the file is bounded without a sweeper.
- Writers: `/api/auth/logout`, and disabling or deleting a user (revoke every
  outstanding `jti` for that subject).
- **Do not** touch `users.json` or any credential store; report, do not write.

**Test**: a token valid before logout is rejected after; a disabled user's live
token is rejected; an expired entry is pruned on next write; the WS terminal OTP
path (which rides the cookie) still connects.

### 1.3 — S2: audit tamper-evidence

- Each `log_audit` line gains the SHA-256 of the previous line. The first line
  chains from a fixed seed.
- One `verify_audit_chain()` returning the first divergent line number.
- The docstring states the limit plainly: this detects modification, not
  truncation of the tail.

**Test**: mutate a middle line, expect the verifier to name it; append normally,
expect clean. Confirm red before the fix.

### 1.4 — B: derive `ASSIGNABLE_TABS` from the template

Six tabs are ungrantable today, and a hand-maintained list will drift again next
time a tab ships. So do not add six entries.

- Build the list from the tab bar in `dashboard.html` — `data-tab` minus
  `requires-admin` — at load, keeping the existing i18n key per tab.
- Whatever shape that takes, the cross-module contract stays: `window.X` plus an
  entry in `types/globals.d.ts`.
- New Python test, both halves like `tests/test_lazy_tab_scripts.py`: every
  non-`requires-admin` `data-tab` in the template is grantable, and every id in
  the list exists in the template.
- Check `LAZY_TAB_SCRIPTS` covers the six newly-grantable tabs: a module binding
  controls in another tab needs an entry for that tab too, or the tab is dead
  when opened cold.

---

## Phase 2 — Finish GUI management Phase 2 (G1-G5)

All backend exists; this is UI only, and it is what stops an operator
hand-crafting API calls. One commit per item — they are independent, and G3
carries risk the others do not.

- **G1** name + subnets, inline in the sites table.
- **G2** bastion host + port, same pattern.
- **G3** mode change with the three guard rails (`central` drops the token,
  `agent` mints one and shows it once, `jump` requires bastion fields). Confirm
  before switching: it invalidates a token an agent in the field is using.
- **G4** agent config panel: syslog listener on/off (the port is already
  settable) and the resolved data directory, read-only.
- **G5** enrollment helper: generated `agent.json` + install commands with the
  token filled in, shown in the same one-time moment as the token.

House rules this phase will trip over if ignored: no inline `onclick` (id or
`data-action` + delegated listener, bound to an id that exists);
`openModal`/`closeModal` for anything modal; every new control gets a
`<label for>` or `aria-label` + `data-i18n-aria-label`; every string through
`tr('key')` with both languages present.

**Gate**: `scripts/check_frontend.py`, `check_i18n_coverage.py --strict`,
`check_a11y.py --strict`, plus `TestClient` coverage on `/api/sites/update` for
each field newly exposed.

---

## Phase 3 — Consumers for data already collected (V1, V2) and the ack columns (N3)

Cheap, and each makes an existing screen answer a question it currently cannot.

- **V1 — MAC → server correlation.** Join Linux inventory hosts against
  `mac_history` so the map can say which switch port a server is on. A join; no
  collector, no schema change. The roadmap names this the entry point for the
  server work.
- **V2 — `IFACE_ERRORS_001`.** `ifInErrors`/`ifOutErrors` already reach the
  diagnosis; this is one catalog entry plus a threshold, following the shape of
  `IFACE_FLAPPING_001`.
- **N3 — full acknowledgement.** `acknowledged_by`, timestamp and note on
  `incidents` (schema bump + migration), written by the existing `new → ack`
  transition, shown in the incidents panel. The transition logic and its
  optimistic concurrency stay as they are.

**Not in this phase, deliberately**: N1 (confirm before concluding) and N2
(`device.unreachable`) are the two that matter *when notifications exist*, and
V3 (blast radius) needs an entity-key design decision. All three earn their own
spec rather than being bolted onto this plan. The trigger for starting them is a
notification engine actually being on the table — which is what the roadmap
already says.

V4 (scheduled ARP/MAC collection) waits for the same reason: a scheduler is a
new moving part, and on-demand collection has not yet produced a complaint.

---

## Phase 4 — Documentation debts (S3, D2, D3)

Prose, no code, and the only phase safe to delegate to a small agent.

- **S3** MCP least-privilege: which of the ~40 tools are safe to enable for
  which role, and why the two observability tools ship disabled. Lands in
  `docs/hardening.md`.
- **D2** commented UDP mappings in `docker-compose.yml` (2055, 6343, 5514) with
  the note that ingest is off by default and binds loopback.
- **D3** data-protection note: what personal data the product stores (MAC, IP,
  hostname of identifiable endpoints), where it lives, what the retention prune
  does, what an operator must configure. No legal claims.

Every example address stays RFC 5737 or private, and
`scripts/check_no_private_data.py` runs before the commit as always.

---

## Phase 5 — The two visual leftovers (U1, U2)

Needs the app running and eyes on it; a detector at zero already proved it
cannot see either of these.

- **U1** the 11px `fa-arrow-down-long` clickable-KPI cue: zoom first, then
  decide — it may want a different icon rather than a size change.
- **U2** confirm the hostname/firmware `nowrap` in `devices.js` actually looks
  right in a real table, which no one has seen.

No commit without having looked at the screen. That is the whole point of the
phase.

---

## After each phase

```sh
uv run pyrefly check                            # 0 errors
uv run python scripts/check_frontend.py         # if static/js or templates/ changed
uv run pytest tests -n 4                        # all green
uv run python scripts/check_no_private_data.py
graphify update .
```

Before touching any shared symbol in phase 1 or 3: `graphify affected
"<symbol>()"` — it walks callers, subclasses, importers and tests, which is the
question "grep every caller" is actually asking.

`HANDOFF.md` gets rewritten against this plan at the end of the session that
starts it, not when context runs out.
