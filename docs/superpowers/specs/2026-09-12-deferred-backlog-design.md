# Deferred backlog — triage and design (2026-09-12)

Everything previous sessions postponed, **each entry verified against the tree
at `d145b4d` (0.36.0) before being written here**, because the last two triages
both carried false entries that cost a day each (`HANDOFF.md` §1).

`HANDOFF.md` is a month stale (2026-08-10). It is the input to this document,
not the authority: five of its open items are already closed.

## Method

For every candidate the question was not "is it on a list?" but "does the code
still lack it?". Each row below names the grep or file that settles it. An item
whose evidence is a *product* question is marked as such and gets no code.

---

## Verified CLOSED — do not re-implement

| Item, as previously recorded | Evidence it is closed |
|---|---|
| M-2 default-credentials guard | `user_manager.must_change_password`, `routers/auth.py:147`, consumed at `core.js:477` |
| M-3 per-IP login throttle | WP6 lockout keyed source+account, `routers/auth.py:117-123`, `clear_account_lockouts` |
| Eleven FortiOS paths never exercised | All twelve views answered on FortiOS 7.4.12 — table in `docs/fortigate-management-plan.md` §"Verified against a box". `monitor/system/ha-status` turned out not to exist and `get_ha_status()` now uses `ha-peer` |
| exe smoke test (Phase 6) | `scripts/build.ps1` lines 15-34, and `c0b26b7` fixed it using the production data dir |
| Modal titles 17px vs "Plate Title 21px" | **Not a defect.** DESIGN.md:390 scopes Plate Title to *the login title*, and `.login-card h2` is 21px (`dashboard.css:1217`). Modal `h3` at 17px is the correct ramp step |
| `get_category_assignments()` missing tenant | Keyed by site-plus-node since `da133a8` |
| CSV formula injection in the three exporters | `f9bf15d`, shared `csvCell()` |
| GUI-management Phase 1 / 1b | Fleet versions `routers/settings.py:399-421`, agent logs `routers/sites.py:262` + `site_agent.py:539`, restart `services/self_update.py:102`, self-signed cert with SAN `services/cert_manager.py:50` |

---

## Verified OPEN

### A. Security backlog — the three that never got their commit

| # | Item | Evidence it is missing |
|---|---|---|
| **S1** | **JWT revocation.** A logged-out or stolen token stays valid until expiry — `logout` cleared the cookie and said so in its own docstring. (Disabled and deleted accounts were **already** covered at `routers/deps.py:60-66`; an earlier draft of this row claimed otherwise and was wrong.) | zero occurrences of `jti`, `revok`, or any denylist in `routers/`, `core/`, `app_server.py` |
| **S2** | **Audit tamper-evidence.** The audit log is an append-only text file with nothing binding line *n* to line *n-1*: whoever can write it can rewrite it | no `prev_hash` / `hmac` anywhere outside `.venv` |
| **S3** | **MCP least-privilege docs.** ~40 tools reachable by an LLM, no document saying which are safe to enable for which role | no least-privilege section in `docs/`, nothing on MCP in `docs/hardening.md` |
| **S4** | **The CLI blacklist bypass stops at the relay.** M-1 gave admins an audited bypass of `COMMAND_BLACKLIST`, but `site_agent.py:693` calls `send_custom_command(device, cmd)` with the default `bypass_blacklist=False`. The same admin, the same command, succeeds at central and fails at an agent site — silently, as a job result | `services/site_agent.py:693` |

**S1 design.** A `jti` claim plus a persisted denylist of revoked ids, checked in
`get_current_user`. The denylist is bounded by construction: an entry can be
dropped once the token it names would have expired anyway, so it never grows
without limit. `logout` and "disable user" both write to it. Not a session
table — that would move the source of truth for authentication and is a bigger
change than the hole justifies.

**S2 design.** Each audit line carries the SHA-256 of the previous line. This
proves *modification*, not deletion of the tail, and is honest about that: a
full guarantee needs an external sink, which is a different feature. One
verifier function plus a test that mutates a middle line and expects detection.

**S4 design.** The relay job must carry the authorisation decision made at
central, not re-derive it. `command_jobs` already carries `kind`; it needs the
bypass flag alongside, set only where central already audited the bypass, and
the agent keeps its *independent* allowlist check (the whole point of
ADR-0008) — the flag widens the blacklist, never the allowlist.

### B. RBAC — six tabs cannot be granted to anyone

`ASSIGNABLE_TABS` (`static/js/settings.js:335`) lists 14 tabs. The dashboard has
27, of which 7 are `requires-admin`. That leaves **six tabs a non-admin user can
never be given**: `tab-config-drift`, `tab-interfaces`, `tab-policy-test`,
`tab-redundancy`, `tab-routes`, `tab-wlc`.

`HANDOFF.md` recorded this as "`tab-clientmap` missing, pre-existing gap". The
gap is six times wider than that and grew with every tab shipped since — which
is the actual defect: **a list of tabs maintained by hand drifts the moment
someone adds a tab.** The fix is to derive the list from the template (the tab
bar already declares `data-tab` and `requires-admin`) and keep a test that fails
when a non-admin tab is unreachable. Adding the six by hand fixes today and
guarantees the same bug in a month.

### C. GUI management — Phase 2, unstarted

`docs/superpowers/specs/2026-09-01-gui-management-design.md` §Phase 2. Every
field is already supported by `site_manager.update_site` and reachable at
`POST /api/sites/update`; what is missing is UI. `settings.js` calls that route
three times, for `jump_identity`, `device_identity` and
`central_manages_devices` only.

| # | Item | Today |
|---|---|---|
| **G1** | Edit site name and subnets after creation | creation form only (`newSiteName`, `newSiteSubnets`); the table renders them as text |
| **G2** | Edit bastion host and port after creation | creation form only — a bastion that changes address means a hand-made API call |
| **G3** | Change a site's mode, with guard rails (`central` drops the token, `agent` mints one, `jump` requires bastion fields) | backend supports it, UI does not offer it |
| **G4** | Agent config panel: syslog listener on/off and the resolved data directory (read-only) | the port is settable (`site-agent.js:265`), the listener cannot be disabled and the path is invisible |
| **G5** | Agent enrollment helper: the exact `agent.json` and install commands with the token filled in | the token is shown once, as a bare string |

### D. Observability workflow — `docs/roadmap.md` §1, items 3-5

Ordered there already, and that order is still right. All three are debts that
**explode the day a notification engine exists** and are cheap before it.

| # | Item | Evidence |
|---|---|---|
| **N1** | Confirm before concluding — one rule parameter declaring how many observations are required before evidence is produced | no `min_observations` in the rule catalog |
| **N2** | `device.unreachable` — `_poll_device` returning nothing is silence, not a fact | no `device.unreachable` event kind |
| **N3** | Full acknowledgement — `acknowledged_by`, timestamp, note on the incident | `incidents` (`observability/storage/schema.sql:206`) has `status` and the transitions, but the "who" exists only in the audit log |

### E. Data already collected, no consumer

The roadmap's own ordering criterion is "how much new data does it require?".
These need none.

| # | Item | Note |
|---|---|---|
| **V1** | **MAC → server correlation.** A Linux host in inventory is not matched against `mac_history`, so the map cannot say which switch port it is on | a join; no collector. `docs/roadmap.md` §3 names it the suggested entry point |
| **V2** | **`IFACE_ERRORS_001`.** `ifInErrors`/`ifOutErrors` are collected and *used in the diagnosis*, but no rule fires proactively on them | left undone deliberately on 2026-08-01 |
| **V3** | **Blast radius — "is it just me?"** Needs a `dst:`/`policy:` entity key so evidence can aggregate across clients | the entity key is the whole design question |
| **V4** | **Scheduled ARP/MAC collection.** Both are collected on demand, so the diagnosis answers from whatever happens to be in the DB | no scheduler for either; `core_engine.py:165` notes the absence |

### F. Product decisions — answered 2026-09-12

- **P1 — endpoint inventory KPIs: DECIDED, they stay exact.** The ~875 ms at
  50k is accepted as the honest cost. Do not re-open this with an "approximate
  and label it" proposal: a stated estimate in an inventory is a number
  someone will quote as exact, and the read path is already outside the lock,
  so the remaining cost buys correctness rather than paying for neglect.
- **P2 — FortiGate HA: no cluster available.** `parse_ha_status()` stays
  unverified against a real cluster and the FortiGate plan says so. Nothing to
  build; a standalone unit answers with an empty member list by design.
- **P3 — port bounce: RUN ON REAL HARDWARE, AND IT WORKS** (user,
  2026-09-12). The port came back up and the running-config was otherwise
  unchanged. The last unverified write path in the product is now verified;
  the recipe in the plan stays as the way to re-check it after a change to the
  per-vendor command tables.
- **P4 — Windows: over SSH, not WinRM** (user's call, 2026-09-12, and it is
  the better one). WinRM is the Windows remote-management service — HTTP(S)
  transport, `pywinrm` as the client. But **Windows has shipped an OpenSSH
  server since Windows 10 / Server 2019**, so the netmiko transport this
  product already uses for every other device reaches a Windows host with:
  - **no new dependency** (`pywinrm` plus its auth stack: NTLM, Kerberos, or
    CredSSP, which is the one that forwards credentials to the target);
  - **no second remote-execution path to secure** — the CLI blacklist, the
    audited admin bypass, the identity resolution in
    `core_engine.get_device_credentials` and the jump-host transport all apply
    unchanged;
  - **one artefact format**, so the `--- <section> ---` markers and the
    analyzer follow `drivers/linux.py` instead of being invented again.

  The cost moves to the customer side: the OpenSSH feature has to be installed
  and the service started on each Windows host, where WinRM is on by default
  in a domain. That is a deployment note, not a code problem, and it buys back
  a whole authentication surface. What remains genuinely Windows-specific is
  the command set (`powershell -Command Get-...` instead of `cat /etc/...`)
  and the default shell, which netmiko's `terminal_server` / generic driver
  handles.

  Still a **feature, not a debt**: nothing breaks without it. When it is built
  it gets its own spec, shaped like the Linux one.

Kept for reference:

- **P1 — endpoint inventory KPIs: exact or cheap?** The seven KPIs are not
  expressible in SQL: they depend on `reclassify_sightings()`, the
  `switch_if_macs` MAC filter, `ep_kb.classify_mac()`, the ARP join and
  `_age_days()`. Honest KPIs therefore require materialising every row of the
  tenant — measured **875 ms undiscovered at 50k** synthetic sightings, with the
  read path already outside the lock. The remaining cost is *inherent*. The
  question is whether the KPIs may become approximate and be labelled as such.
  There is no third option, and no amount of SQL invents one.
- **P2 — FortiGate HA member parsing** is unverified: a standalone unit returns
  an empty list, so only a real cluster exercises `parse_ha_status()`.
- **P3 — port bounce has never run against a switch.** `send_config_set` has
  never touched real hardware (`services/port_action.py`).
- **P4 — Windows over WinRM** (`docs/roadmap.md` §3): a driver, an artefact with
  the same `--- <section> ---` markers, an analyzer. Same shape as Linux, but it
  is a feature, not a debt — no `pywinrm` anywhere today.
- **P5 — agent/device plane separation** (`docs/roadmap.md` §2): an
  authenticated agent still receives every pending job for its site. The
  roadmap already states the trigger for un-deferring it — the allowlist growing
  to cover writes, or a second consumer of the relay. Neither has happened.

### G. Small, and the ones only eyes can judge

- **U1 — the clickable-KPI affordance.** `fa-arrow-down-long` at 11px between
  label and value (`dashboard.html:1432`) reads as a dot. Needs a zoom before
  anyone touches it; the fix may be an icon swap, not CSS.
- **U2 — `devices.js` `white-space: nowrap`** on hostname and firmware was
  never looked at on screen; the session expired before reload.
- **D2 — `docker-compose.yml` has no UDP mappings**, not even commented, so
  nothing documents which ports an ingest deployment must publish (2055, 6343,
  5514).
- **D3 — no GDPR / data-protection document** (Phase 6.7), despite the product
  storing MAC addresses, IPs and hostnames of identifiable endpoints.

---

## Out of scope for this document

The Go port (`../sentinelnet-go`) keeps its own living plan and divergence
register. Its open items — AI Assistant units 2b/2c, MCP client-preview, the
embedded dashboard snapshot, Visio export — are tracked there and must not be
mirrored here, or the two lists will disagree.
