# Device decommission and bulk delete — design

Date: 2026-10-09. Status: approved in chat, spec under review.

## Goal

From the inventory, select many devices at once and:

- **decommission** them: they leave monitoring (polling, triage, ping,
  backup, alerts, probe-agent sync, AI/MCP) but are kept, with credentials,
  and can be **reactivated** unchanged;
- **delete** them permanently, active or decommissioned.

Success: a decommissioned device is invisible to every subsystem that reads
the inventory, without editing those subsystems; reactivating it restores
the identical row; nothing is ever lost by an unrelated inventory write.

## Decision: a separate file, not a column

About 75 call sites read `inventory_manager.get_all_devices()`, and about 11
read→rewrite paths go through `safe_write_hosts_csv`. A `Decommissioned`
column would need every reader to filter and every writer to ask for the
full list; one writer that forgets silently deletes the decommissioned rows.

Decommissioned rows therefore move to their own file. Readers and writers
of `network_hosts.csv` never see them, so they need no change.

## Data — `services/inventory_manager.py`

- File `decommissioned_hosts.csv` in the data directory (via
  `data_config.get_path`), same columns as `network_hosts.csv` plus
  `Decommissioned` (ISO-8601 UTC, e.g. `2026-10-09T12:00:00Z`) and
  `Decommissioned By` (username). Credentials stay encrypted exactly as
  they were.
- Identity is `(tenant, ip)` (`Group`, `IP`), as everywhere in the
  inventory: two tenants may own the same IP.
- New functions, all under `_hosts_csv_lock`, taking
  `pairs: list[tuple[str, str]]` of `(tenant, ip)`:
  - `get_decommissioned_devices() -> list[dict]`
  - `decommission(pairs, actor) -> int`
  - `reactivate(pairs) -> int`
  - `delete_devices(pairs) -> int` — removes from whichever file holds the
    pair.
- **Write order: copy first, remove second.** A crash between the two
  writes leaves the row in both files, never in neither.
  - `decommission`: write the row to the decommissioned file (replacing an
    existing row for the same pair), then remove it from the active file.
    Interrupted: the device is still active, and repeating the action
    completes it.
  - `reactivate`: add the row to the active file, then remove it from the
    decommissioned file. Interrupted: repeating it finds the pair already
    active and only removes the leftover.
- **Collision guard, one place.** `safe_write_hosts_csv` is the single
  write path (UI, CSV import, promote, probe-agent inventory save, rename,
  reassign). It raises `ValueError` when a row **new to the active file in
  this write** has the same `(tenant, ip)` as a decommissioned row, e.g.
  "192.0.2.10 is decommissioned in tenant acme: reactivate or delete it
  first." Only new rows are checked, so a leftover from an interrupted
  action never blocks unrelated writes. `reactivate` passes the pairs it
  is restoring as an internal exemption. Callers already turn
  `ValueError` into HTTP 400.
- `core/data_config.py`: add `decommissioned_hosts.csv` to `_STATE_FILES`
  next to `network_hosts.csv`. (Cloud backup mirrors the config-backup
  folder, not the data directory: nothing to add there.)
- The file lives next to `network_hosts.csv` (same directory as
  `get_hosts_csv()`), so tests that point the inventory at a temp dir
  isolate it too, and a probe agent — which has no such file — is
  unaffected.
- Writers that can now hit the guard and did not expect a `ValueError`
  (`/api/reassign-device`, `/api/promote-device`) turn it into 400.
- `data/` is gitignored as a directory: no `.gitignore` change.

## API — `routers/inventory.py`

All `require_tab("tab-devices")` + `require_operator`, like
`/api/delete-device`.

| Route | Body | Effect |
|---|---|---|
| `GET /api/devices/decommissioned` | — | decommissioned rows in the caller's tenant scope, secrets stripped the same way the active list strips them |
| `POST /api/devices/decommission` | `{"devices": [{"ip", "tenant"}]}` | decommission |
| `POST /api/devices/reactivate` | same | reactivate |
| `POST /api/devices/delete` | same | delete, from either file |

- Every pair is checked against the caller's tenant scope **before**
  anything is written: one forbidden pair → 403 and nothing changes. A pair
  not found → 404 naming it, nothing changes. At most 1000 pairs per
  request (422 above).
- One audit line per device, Italian like the existing ones:
  `Dispositivo '<ip>' (gruppo '<tenant>') dismesso|riattivato|eliminato
  dall'utente '<user>'.`
- `/api/delete-device` stays unchanged.

## History — `services/device_history.py`

- New event kinds `decommissioned` and `reactivated`, recorded by the new
  functions in place of the `removed`/`added` the CSV diff would produce.
  Deleting a decommissioned device records `removed`.
- `record` gains a way to relabel the diff's events (a mapping such as
  `{"removed": "decommissioned"}`), so the diff stays the single source of
  the snapshot.
- UI (`static/js/device-history.js`): labels and icons for the two kinds;
  the service-days counter (`dhServiceDays`) also applies to
  `decommissioned`. The kind filter keeps its tabs: `decommissioned`
  counts with removals, `reactivated` with additions. Today `removed` is
  labelled «dismesso»; it becomes «eliminato» / "deleted", and the tab
  «Dismessi» becomes «Rimossi» / "Removed".

## UI — inventory (`templates/dashboard.html`, `static/js/devices.js`)

- A sixth status tab «Dismessi» / "Decommissioned" with its count, after
  «Non misurabile». It loads `GET /api/devices/decommissioned`; rows are
  greyed and show date and actor instead of live status. Decommissioned
  rows never appear in the other tabs (they are not in `globalDevices`).
- The bulk selection is keyed by tenant + IP instead of IP alone, so two
  tenants' identical IPs are distinct rows. Triage, Ping and Commands keep
  receiving the list of IPs, derived from the keys.
- Selection bar (`#invSelectionBar`):
  - active tabs: existing buttons + «Dismetti» + «Elimina»;
  - «Dismessi» tab: «Riattiva» + «Elimina» only.
- Each action opens a confirmation modal through `openModal` listing the
  selected devices (hostname, IP, tenant); «Elimina» states it is
  permanent. On success the selection clears and both lists reload.
- All strings via `tr()`, both languages; delegated listeners on ids that
  exist in the template; accessible names on new controls.

## Tests

- `tests/test_device_decommission.py`:
  - decommission → gone from `get_all_devices()`, present in
    `get_decommissioned_devices()` with timestamp and actor;
  - reactivate → row identical to before (credentials included), extra
    columns gone;
  - delete from active and from decommissioned;
  - same IP in two tenants: only the named pair moves;
  - collision: `add_or_update_device` and CSV import of a decommissioned
    `(tenant, ip)` → `ValueError` / 400;
  - interrupted action (row in both files): unrelated writes still work,
    repeating the action completes it;
  - an unrelated write leaves the decommissioned file untouched;
  - history: `decommissioned` / `reactivated` / `removed` events.
- API: scoped user with one pair outside scope → 403 and nothing changed;
  unknown pair → 404; `TestClient` smoke on each route.
- UI: existing lazy-tab, a11y, i18n, modal and frontend checks green.
- Full gate from AGENTS.md.

## Out of scope

- A reason/note field on decommission.
- Automatic purge of decommissioned devices after N days.
- Tutorials for Probes and Device History: a separate task after this one.
