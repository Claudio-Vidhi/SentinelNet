# Rename "site" to "probe" everywhere — design (2026-10-09)

Sub-project 0 of the multi-location revamp, done before the data model
([2026-10-09-organizations-locations-design.md](2026-10-09-organizations-locations-design.md)).

## Why

"Site" names the registry of how devices are reached (central, agent, jump
host). The revamp introduces the **location** (Sede) as a separate entity, and
the UI calls the registry **probes** (Sonde). Keeping "site" in code, data or
wire protocol with the meaning *probe* — next to a new `Location` — is the same
two-words-one-concept confusion this revamp removes, moved from the UI into the
code where it keeps producing bugs.

The deployed agents are test installs only: they are deleted and reinstalled
after this change. So there is **no transition** — no dual header, no alias, no
shim.

## Rename map

| Area | Before | After |
|---|---|---|
| Module | `services/site_manager.py` | `services/probe_manager.py` |
| Agent program | `services/site_agent.py`, CLI `--site-id` | `services/probe_agent.py`, `--probe-id` |
| Router | `routers/sites.py`, `/api/sites…`, `/api/sites/{site_id}/…` | `routers/probes.py`, `/api/probes…`, `/api/probes/{probe_id}/…` |
| Wire headers | `X-Site-Id`, `X-Site-Token` | `X-Probe-Id`, `X-Probe-Token` |
| Agent config on disk | `site_id` | `probe_id` |
| Registry file | `sites.json`, `SITES_JSON` | `probes.json`, `PROBES_JSON` |
| Device column | `Site` in `network_hosts.csv` (central and agent) | `Probe` |
| SQLite | `mac_history.site`, jobs `site_id` | `probe`, `probe_id` |
| Device lookup | `get_device_by_ip(...)["site"]` | `["probe"]` |
| Helpers | `is_agent_site`, `has_direct_path(site_id)`, `DEFAULT_SITE_ID` | `is_agent_probe`, `has_direct_path(probe_id)`, `DEFAULT_PROBE_ID` (value stays `"central"`) |
| Frontend | `static/js/site-agent.js`, `tab-sites`, ids/i18n keys with `site`/`Site` | `probe-agent.js`, `tab-probes`, `probe`/`Probe` |
| Docs | `docs/remote-sites.md`, mentions in ADRs, architecture, operations | `docs/probes.md`, mentions updated |

**Not renamed:** "agent" — it is the software (`/api/agent/*` endpoints, the
`sentinelnet-agent` systemd unit); a probe is the registry entry it serves.
`central` keeps its value.

**CSV import aliases** (a system boundary): `probe`, `sonda`, and `site` map to
`Probe`, so an export made before the rename still reimports correctly.
`sede` and `location` are reserved for the Location column of sub-project 1.

## One-shot data migration (startup)

Idempotent; runs when `probes.json` does not exist; backs up the files it
touches; one audit entry.

1. `sites.json` → `probes.json`, entries unchanged.
2. `network_hosts.csv` header `Site` → `Probe`.
3. `mac_history`: `ALTER TABLE … RENAME COLUMN site TO probe`.
4. Jobs table: dropped and recreated with `probe_id` (queued jobs are
   transient; the test probes are reinstalled anyway).
5. Users' allowed-tab lists: `tab-sites` → `tab-probes`, through
   `user_manager`'s own save path.

Sub-project 1's migration runs after this one.

## Keeping it aligned

A test, `tests/test_no_site_identifier.py`, scans tracked code (`*.py`,
`static/js`, `templates`, `types`) for `site` as an identifier or
user-visible key, with a short reviewed allowlist (`website`, third-party
names). A new `site_…` is a red test, not a review comment. Widening the
allowlist is a reviewable diff, the same rule as
`check_no_private_data`.

## Execution

Behaviour-preserving refactor, in reviewable slices, each green before the
next: backend (module, router, agent, migration) → frontend → tests → docs.
The mechanical sweep is delegated to subagents; each router gets a
`TestClient` smoke hit and the agent endpoints an authenticated call with the
new headers. Release notes state that existing agents must be reinstalled.

## Testing

- Migration: the five steps above on a fixture data dir; second run is a no-op.
- Agent auth: `X-Probe-Id`/`X-Probe-Token` accepted; `X-Site-*` rejected (401).
- OpenAPI: no path contains `/sites`.
- `test_no_site_identifier.py` green.
- Gate: pyrefly, `check_frontend`, full suite, `check_no_private_data`,
  `check_i18n_coverage --strict`, `check_a11y --strict`,
  `tests/test_lazy_tab_scripts.py` (the tab id changes).
