# Factory reset — design (2026-10-09)

Status: approved in chat, spec under review.

## Goal

A super-admin can return the installation to its first-run state from the
UI: no inventory, tenants, users, credentials, keys, history, backups or
settings. The old data is **archived, not deleted**: a reset by mistake is
undone by putting the folder back; deleting the archive is the operator's job.

## Why at startup, not in the request

While the app runs it holds the SQLite files, the audit log and in-memory
caches open, and on Windows an open file cannot be moved. The request only
records the intent; the move happens in the next process, before it opens
anything.

## Mechanism

- The request writes `factory-reset.pending` (JSON: `requested_by`,
  `requested_at` ISO-8601 UTC) into the data directory, then restarts through
  `services.self_update.restart()`.
- `core/data_config.py`, at import and **before** `_migrate_legacy_files()`,
  calls `_apply_pending_factory_reset()`: if the marker exists in the active
  data directory, `os.replace(DATA_DIR, f"{DATA_DIR}.wiped-{YYYYmmddTHHMMSS}")`
  and `os.makedirs(DATA_DIR)`. Every module that touches a file imports
  `data_config` first, so nothing is open yet.
- The rename is all-or-nothing. If it raises (antivirus, a file held by
  another program), the app starts on the old data, the marker stays, the
  reset is retried at the next start, and the error goes to stderr.
- The archive keeps the files' restrictive ACLs (rename, not copy). The
  marker travels inside it, so the new directory starts without one.
- stdlib only in that function: it runs before logging is configured.

## API — `routers/settings.py`

| Route | Who | Body | Effect |
|---|---|---|---|
| `GET /api/settings/factory-reset` | super-admin | — | `{"pending": bool, "requested_by", "requested_at", "data_dir"}` |
| `POST /api/settings/factory-reset` | super-admin | `{"password", "confirm"}` | `confirm` must equal `"RESET"`, password must be the caller's; writes the marker, audit line, then restart |
| `DELETE /api/settings/factory-reset` | super-admin | — | removes the marker (cancel) |

- `require_tab("tab-settings")` + `require_super_admin` on all three.
- Wrong password → 403, missing/wrong `confirm` → 400; nothing written.
- Audit line (Italian, like the others): `Reset di fabbrica richiesto da
  '<user>': la data directory sarà archiviata al prossimo avvio.` — also on
  stderr, because the audit log itself moves into the archive.
- Supervised (systemd / Windows service): restart now, response
  `{"status": "restarting"}`. Not supervised (exe started by hand, dev):
  marker written, response `{"status": "pending-restart"}`; the UI says to
  restart the app and offers «Annulla».

## UI — Impostazioni

- A «Zona pericolosa» card, visible to super-admins only.
- Button «Reset di fabbrica» opens a modal (`openModal`):
  - what is lost: inventory, organizations, users, credentials and keys,
    history, configuration backups, settings; probe agents must be
    reinstalled;
  - where the archive goes (`data_dir` + `.wiped-<timestamp>`);
  - HTTPS configured from the UI is lost with the settings; HTTPS set through
    `SENTINELNET_SSL_*` environment variables keeps working;
  - password field, a field where `RESET` must be typed; the confirm button
    is disabled until it matches.
- After `restarting`: «Riavvio in corso…», poll `/api/version`, then reload
  (the first-run wizard appears). After `pending-restart`: the card shows
  «Reset in attesa del riavvio» and an «Annulla» button.
- Strings via `tr()` in both languages; accessible names on the fields.

## Tests

- `data_config._apply_pending_factory_reset()` on a temp dir: marker present
  → archive contains the old files and the marker, data dir exists and is
  empty; no marker → nothing moves; rename failing (patched `os.replace`) →
  old data and marker stay, no exception escapes.
- Routes: admin (not super-admin) → 403; wrong password → 403; `confirm`
  missing → 400; success writes the marker and calls `self_update.restart`
  (patched); unsupervised → `pending-restart`; `DELETE` removes the marker;
  `GET` reports pending.
- UI static test: card, modal and controls exist and are bound.
- Full gate from AGENTS.md.

## Out of scope

- Permanent deletion from the UI.
- Partial resets (per tenant, per data kind).
- Restoring an archive from the UI.
