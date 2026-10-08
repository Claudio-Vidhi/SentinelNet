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

### `services/manual_config.py` (pure, no I/O)

- `guide() -> dict`: per vendor, `{label, steps[], command, notes}`.
  The capture command comes from the driver (`get_backup_command()`), so the
  guide and the automatic backup can never ask for different outputs. Steps add
  what a human needs and the driver does implicitly: disable paging
  (`terminal length 0`, FortiOS `config system console` / `set output standard`,
  `set cli pager off` on PAN-OS, `| no-more` on Junos), capture `show version`
  output for the version, save as plain text. Vendors: those with a driver in
  `drivers/registry.py`.
- `preview(text) -> dict`: `config_type` (existing
  `config_analyzer.detect_config_type`), `vendor` suggestion, `hostname`,
  `ip_candidates[]` (interface addresses, management interface first when
  recognizable), `version`, `model` when the text carries them, and
  `analyses[]` (see §4). Extraction failures yield empty fields, never an
  exception: the user fills them in.

### `routers/manual_config.py`

All routes: operator role, `require_tab("tab-import")`.

| Route | Purpose |
|---|---|
| `GET /api/manual-config/guide` | the extraction guide |
| `POST /api/manual-config/preview` | `{text, filename}` → `preview()`; writes nothing |
| `POST /api/manual-config/import` | `{items: [{text, ip, hostname, vendor, group, site, category, subcategory, version, model}]}` |

`import` processes each item independently and returns one outcome per item
(`ok` / `error` + message). Per item, in order:

1. Validate: text non-empty, ≤ 5 MB (`MAX_CONFIG_BYTES`, shared with the
   agent route), valid IP, `group` inside the caller's `user_group_scope`.
2. Refuse if the IP already exists in that tenant as a **non-manual** device:
   the next triage would overwrite the uploaded config.
3. `add_or_update_device(..., transports={"manual": None})`.
4. `backup_store.save_backup(device, hostname or ip, text)`.
5. `history.record_version(device, text)` — drift between uploaded versions.
6. `update_version_inventory(ip, vendor, version, status="manual", model=...)`.
7. `set_device_meta(ip, tenant=group, category=..., subcategory=...)` when given.
8. `log_audit(...)` naming the user, device and size.

The same `import` call serves a new device and a new version of an existing
manual device (upsert).

Uploaded configs are stored exactly like SSH backups: plain text in the
gitignored `data/`, redacted only on egress (LLM, MCP, drift diff) by
`security/redaction.py`. No special case.

Body is JSON; the browser reads files with `FileReader`. No
`python-multipart`, no `UploadFile`, no new dependency.

## 3. UI

Visual authority: `DESIGN.md` (mimic-panel). Surface mode: Operate.

### Tab Import — "Config manuale"

A segmented control at the top of the tab: *Inventario CSV* | *Config manuale*.
The CSV import stays as it is. The manual flow is an in-page stepper, not a
modal:

1. **Vendor e guida** — vendor tabs; numbered steps; the command in a code
   block with a Copy button.
2. **Carica** — the existing dropzone pattern, accepting multiple files or a
   whole folder (`<input multiple>` + `webkitdirectory`).
3. **Revisione** — one row per file: hostname, IP (select from
   `ip_candidates` or type), vendor, tenant, site, category, plus the list of
   analyses that config type unlocks. A top "apply to all" row sets
   tenant/site/category on every row (the MSP case: many devices, one
   customer). Import is disabled while any row lacks IP or tenant.
4. **Esito** — per-row outcome; for each imported device, direct links to the
   analyses it unlocks.

### Device drawer

A manual device's drawer shows "Carica nuova versione": a modal
(`openModal`) running steps 2–3 for one file with the device fields prefilled
and locked.

### Devices table

Badge "Manuale" and the config age in place of reachability.

Frontend rules from AGENTS.md apply: `tr()` for every string (it + en), no
inline handlers, accessible names on every control, modal manager, lazy-tab
entry for any binding that lives in another tab (drawer → devices tab).

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
