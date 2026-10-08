# Manual config repository — design (2026-10-08)

## Why

Some devices cannot be reached by SentinelNet: no SSH/Telnet from the
management LAN, no site agent, a customer that hands over a config file and
nothing else. Today those devices are invisible, so their configuration gets
none of the analysis the reachable ones get.

Goal: the operator uploads the config by hand, SentinelNet tells them exactly
which commands to run to obtain it, the device is categorized like any other
(tenant, site, category), and every feature that works from a stored backup
works on it too.

Success: a manually uploaded device appears in the Devices table, the maps and
its tenant like any other device, and Config Analyzer, Config Drift, NetSec
Audit, Policy Test, CVE triage and the route table fall back to its config
without any of them knowing it was uploaded by hand.

## Key fact the design rests on

Every analysis reads the same file:
`backup-config/<tenant>/<vendor>/<name>-<ip>.txt`, keyed by IP and tenant
(`core/backup_store.save_backup`, `ai/config_analyzer._find_freshest_backup`).
An ingest path that writes exactly that file already exists — the site agent's
`POST /api/agent/backup` (`routers/agent.py`): `save_backup` →
`history.record_version` → `update_version_inventory`. A manual upload is the
same ingest with a human instead of an agent as the source.

## 1. Data model: the `manual` transport

- A manual device is a normal `hosts.csv` row with
  `Transports = {"manual": null}`.
- `"manual"` is added to `ALLOWED_TRANSPORTS`; `_validate_transports` rejects
  it combined with any other transport (a device is either reached or not).
- `inventory_manager.is_manual(device) -> bool` is the single test used
  everywhere below.
- No credentials are stored for it: Username/Password/Enable Secret/Profile
  stay empty.

### What skips a manual device

Every loop that opens a session or sends a probe to the device skips it:
central triage/backup run (`core/core_engine`), triage scheduler, ping monitor,
MAC collector, SNMP polling, command execution, provisioning, WLC/FortiGate
live calls. The implementation plan enumerates them with
`graphify affected "parse_transports()"` / `"get_cli_transport()"` /
`"get_all_devices()"` rather than from memory, and each skip is covered by a
test.

`services/route_table.collect_for` goes straight to `routes_from_backup` for a
manual device instead of trying a live session first.

### How it is shown

Status of a manual device is **"Manuale · config del <data>"** (neutral
styling), never red/offline: the morning sweep must not see false alarms. The
config age uses the same backup-age threshold the reachable devices use, so an
old upload reads as stale — that is the truth about it.

## 2. Backend

### The stored text must look like a triage backup

A triage backup is not just the config: it is the config, then
`TRIAGE_MARKER`, then one tagged section per accessory command
(`--- SHOW CDP NEIGHBORS DETAIL ---`, `--- SHOW INVENTORY ---`, …). The map
(CDP/LLDP links), stack detection and the inventory read those sections. A
manual upload that stored only the config would leave the device as an island
on the map.

So the guide asks for the same commands the triage runs, and the upload is
a **terminal session log** (PuTTY/SecureCRT/`script` logging): every command
echo (`switch-01#show running-config`) marks where its output starts. The
server splits the log at those echoes and rebuilds the triage layout. A file
with no recognizable echo of the backup command is a plain config (e.g. a
FortiGate GUI backup) and is stored as uploaded.

To keep one list, the per-vendor accessory commands move out of the
`if/elif` chain in `core_engine._run_backup_and_triage` into module-level data
(`triage_extra_commands(vendor, privileged)`), read by both the triage and
the guide. Version, model and serial come from running the driver's own
`get_version/get_model/get_serial` against the captured outputs (a stand-in
connection that answers `send_command` from the log), so there is no second
parser for `show version`.

### `services/manual_config.py` (pure, no I/O beyond the driver registry)

- `guide() -> dict`: per vendor, `{vendor, paging, commands[], notes[]}`.
  `commands` = driver backup command + the commands the driver's
  `get_version/get_model/get_serial` send (recorded, not hand-listed) + the
  triage accessory commands. `paging` is the vendor's pager-off command.
- `to_backup(vendor, text) -> dict`: `{backup, structured, hostname, version,
  model, serial}` — the triage-format text plus what the captured outputs say.
- `preview(text, vendor="") -> dict`: `to_backup` fields plus `vendor`
  (suggested from `detect_config_type` when not given), `ip_candidates[]`
  (management addresses first when recognizable) and `analyses[]` (§4).
  Extraction failures yield empty fields, never an exception.

### `routers/manual_config.py`

All routes: operator role, `require_tab("tab-import", "tab-devices")` — the
upload also opens from the Devices table.

| Route | Purpose |
|---|---|
| `GET /api/manual-config/guide` | the guide, plus the category list and sites for the review form |
| `POST /api/manual-config/preview` | `{text, vendor}` → `preview()`; writes nothing |
| `POST /api/manual-config/import` | ONE device: `{text, ip, vendor, group, site, hostname, category, subcategory, version, model}` |

One device per call: the UI posts the rows one after another and shows each
outcome as it lands; a list endpoint would only add a second error channel.
Per call, in order:

1. Validate: text non-empty, ≤ 5 MB (`MAX_CONFIG_BYTES`, shared with the
   agent route), valid IP, `group` exists and is inside the caller's
   `user_group_scope`, `site` exists.
2. Refuse (409) if the IP already exists in that tenant as a **non-manual**
   device: the next triage would overwrite the uploaded config.
3. `add_or_update_device(..., transports={"manual": None})`.
4. `to_backup(vendor, text)` — server-side, never trusting a client rebuild.
5. `backup_store.save_backup(device, hostname, backup)`.
6. `history.record_version(device, backup)` — drift between uploaded versions.
7. `update_version_inventory(ip, vendor, version, status="manual", ...)`.
8. `update_device_hostname`, `set_device_meta(category, subcategory)` when given.
9. `log_audit(...)` naming the user, device and size.

The same call serves a new device and a new version of an existing manual
device (upsert).

Uploaded configs are stored exactly like SSH backups: plain text in the
gitignored `data/`, redacted only on egress (LLM, MCP, drift diff) by
`security/redaction.py`. No special case.

Body is JSON; the browser reads files with `FileReader`. No
`python-multipart`, no `UploadFile`, no new dependency.

## 3. UI

Visual authority: `DESIGN.md` (mimic-panel). Surface mode: Operate.

### One wizard, two doors

The flow is a side-sheet wizard built on the existing `ui-wizard.js`
(`createWizard`, same pattern as the site and user wizards), not a new
stepper. It opens from:

- **Tab Import** — a panel "Device non raggiungibili" next to the CSV import,
  with a button *Carica config*;
- **Devices table** — on a manual device's row, an upload button in place of
  ping/triage/CLI: the same wizard, device fields prefilled and locked, one
  file.

Steps:

1. **Vendor e guida** — vendor select; the pager-off command and the command
   list in a code block with a Copy button; how to log the session.
2. **Carica** — the existing dropzone pattern, accepting multiple files or a
   whole folder (`<input multiple>` + `webkitdirectory`).
3. **Revisione** — one row per file: hostname, IP (`ip_candidates` as a
   datalist, or typed), tenant, site, category, plus the analyses that config
   type unlocks. A top "apply to all" row sets tenant/site/category on every
   row (the MSP case). *Importa* is disabled while any row lacks IP or tenant.
4. **Esito** — per-row outcome; links to the tabs of the analyses unlocked.

### Devices table

Status pill "Manuale" (the "not measurable" bucket, never offline) with the
config age as its title.

Frontend rules from AGENTS.md apply: `tr()` for every string (it + en), no
inline handlers, accessible names on every control, modal manager. The module
loads eagerly (`<script>` in `dashboard.html`): it is opened from two tabs, and
a lazy entry for each would buy nothing.

## 4. What each config type unlocks

Derived from the current code; the UI lists only these.

| config_type | Analyzer | NetSec Audit | Policy Test | Drift | Routes (static) | CVE |
|---|---|---|---|---|---|---|
| ios | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ if version |
| fortios | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ if version |
| panos | ✓ | — | — | ✓ | — | ✓ if version |
| wlc-aireos | ✓ | — | — | ✓ | — | ✓ if version |
| linux | ✓ | ✓ | — | ✓ | — | ✓ if version |
| windows | ✓ | — | — | ✓ | — | ✓ if version |
| junos (`display set`) | — | — | — | ✓ | — | ✓ if version |

Junos has a driver but no config_type: `detect_config_type` maps any other
vendor to `ios`, and IOS parsing of `set` lines yields nothing useful. The
review row therefore lists only Drift and CVE for Junos, rather than an
Analyzer that would come back empty. IOS-like CLIs (HP ProCurve, Aruba, Cisco
CBS) keep the `ios` row, as they do for automatic backups today.

Routes from backup use `analyze_device(...)["routing"]["static"]`, filled for
IOS and FortiOS. CVE needs a version: from `preview()` or typed by the user.
Unknown formats fall back to `ios`, as `detect_config_type` does today.

## 5. Tests

- `tests/test_manual_config.py`: `preview()` on fixtures for IOS, FortiOS,
  PAN-OS, Junos (RFC 5737 addresses, placeholder hostnames); `guide()` covers
  every registered driver; `_validate_transports` rejects `manual` + `ssh`.
- Router via `TestClient`: 403 for viewer, 422 on bad body, happy path into a
  temporary data dir (file written where `_find_freshest_backup` finds it,
  history version recorded, inventory row has the manual transport), refusal
  when the IP is already an SSH device, refusal for a tenant outside scope.
- One test per skipping loop: a manual device is never handed to a session or
  probe.
- Frontend gate: `check_frontend.py`, i18n strict, a11y strict,
  `test_lazy_tab_scripts.py`, `test_ui_modal.py`.

## Out of scope

- Server-side zip upload (the browser's folder select covers bulk).
- Devices without an IP (synthetic ids would touch every IP-keyed reader).
- New config parsers: formats `detect_config_type` does not recognize are not
  added here.
- Automatic reminders to re-upload a stale config (the age badge shows it).
