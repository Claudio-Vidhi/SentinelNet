# Inventory on SQLite and per-location CSV import (sub-project 2) — 2026-10-10

Builds on sub-project 1 (`2026-10-09-organizations-locations-design.md`).
Mockup: canvas "SentinelNet – Sedi e Import", artboard *Import contestuale con
anteprima*.

## Problem

1. The inventory lives in `network_hosts.csv` / `decommissioned_hosts.csv`.
   Reads are cached, but every `add_or_update_device` rewrites the whole file:
   measured on a synthetic inventory, one rewrite is 39 ms at 10,000 devices,
   so importing 10,000 rows (one rewrite per row, plus a re-parse) takes about
   11 minutes. Organizations (`groups.json`) and locations (`locations.json`)
   are JSON files whose invariants ("a location belongs to an existing
   organization", "a location with devices cannot be deleted") are enforced
   only by code.
2. CSV import has no preview, no default destination and no subnet check: a
   wrong file is discovered after it has been written.

## Decisions

| Question | Decision |
|---|---|
| Storage | Hosts, decommissioned hosts, organizations, locations → SQLite in `device_meta.db` (already owned by `inventory_manager`, synchronous connection). Not `observability.db`: its asynchronous write queue (ADR-0004) breaks read-your-write. |
| `probes.json` | Stays JSON: it holds tokens and agent configuration. |
| Public API | `inventory_manager` and `location_manager` keep their functions and return shapes; callers do not change. |
| CSV | Exchange format only: user import, export, template, agent-inventory RPC payload. Never state. |
| Agent | The agent runs the same `inventory_manager`, so its local inventory is SQLite too, migrated at agent start. The read/save RPC keeps CSV text as the wire format (the agent converts at its edge), so a central on this version still talks to agents on the previous one and vice versa. |
| Unknown organization in an imported CSV | Row error («crea prima l'organizzazione»). Import never creates organizations or locations. |
| Missing credentials on import | Not an error. The row is imported; the preview says which fallback applies. |
| Import entry point | The existing Importa tab, with a default destination (organization + location). Each location in the Organizations tab links to it preselected. |
| Preview vs import | Stateless: both endpoints take the same input and run the same pure classification. Import recomputes it and imports `new` + `update` rows, skips the rest. |
| Import write | One transaction per import. |

## Storage

Tables in `device_meta.db` (WAL, `foreign_keys = ON`, `busy_timeout`):

```sql
CREATE TABLE organizations (key TEXT PRIMARY KEY, name TEXT, description TEXT NOT NULL DEFAULT '');
CREATE TABLE locations (
  id TEXT PRIMARY KEY, org TEXT NOT NULL REFERENCES organizations(key) ON DELETE RESTRICT,
  name TEXT NOT NULL, role TEXT NOT NULL, subnets TEXT NOT NULL DEFAULT '[]',
  probe TEXT NOT NULL DEFAULT 'central');
CREATE TABLE hosts (
  ip TEXT NOT NULL, grp TEXT NOT NULL,
  location TEXT REFERENCES locations(id) ON DELETE RESTRICT,
  vendor, profile, username, password, enable_secret, hostname, probe,
  ssh_port, transports, snmp_community, snmp_disabled,   -- TEXT, as in the CSV
  PRIMARY KEY (ip, grp));
CREATE TABLE decommissioned_hosts (
  -- same columns as hosts plus today's decommission columns
  location TEXT REFERENCES locations(id) ON DELETE RESTRICT);
```

- `(ip, grp)` is today's identity (`_same_device`).
- `hosts.location` is nullable at schema level: agent databases have no
  locations. The "every new or moved device needs a location" rule stays in
  the boundaries, as today.
- `hosts.grp` has no foreign key for the same reason (agent databases have no
  organization registry). Deleting an organization with devices stays refused
  by code, with the count.
- Passwords stay encrypted with `crypto_vault`, as in the CSV.
- Every write goes through one function (today `safe_write_hosts_csv`'s role):
  it diffs, feeds `device_history`, invalidates the IP caches. The row cache
  keyed on file stat goes; reads are queries.

## Migration (one shot, at startup, central and agent)

Runs when the tables are empty and the old files exist. Order: after
`probe_migration` and `location_migration`.

1. Back up `groups.json`, `locations.json`, `network_hosts.csv`,
   `decommissioned_hosts.csv` as `*.pre-sqlite`.
2. In one transaction: organizations, locations, hosts, decommissioned hosts.
   A row whose `Location` does not exist is a migration error. It is not
   dropped: the migration stops and logs it, and the files stay
   authoritative.
3. Commit, then rename the old files to `*.migrated`.
4. A second start finds the tables populated and does nothing.

`data_config._STATE_FILES`, the factory reset, `check_no_private_data` and the
`location_migration` / `probe_migration` readers are updated to the new
names. Those migrations run first and still read the old files.

## Import

### Classification — `services/csv_import.py`

`classify(csv_text, default_org, default_location, decisions, scope) -> list[RowResult]`
reads the inventory, locations and probes, and writes nothing.

`RowResult`: `row`, `ip`, `hostname`, `vendor`, `org`, `location`, `probe`,
`status` (`new` | `update` | `error` | `skipped`), `changes`
(`{field: [old, new]}`; credentials only as "changed"), `reason`, `warnings`,
`action` (`{"kind": "move", "location": id}` | `{"kind": "skip"}` | null),
`credentials_note`.

Rules, in order:

1. IP missing or invalid → `error`.
2. Organization = row column, else `default_org`. Missing, unknown or outside
   the user's scope → `error`.
3. Location = decision › row column (id or name) › `default_location`.
   Missing, or not in that organization → `error`.
4. `Probe` column, if present, must exist; otherwise the location's probe.
5. IP repeated in the file within the same organization → `error` on the
   later rows, action `skip`.
6. Location with subnets, IP outside them:
   - inside another location of the same organization → `error`, action
     `move` to it;
   - inside no location → `warning` «fuori dalle subnet della sede»; the row
     keeps its status.
7. Same `(ip, org)` in inventory → `update` with `changes` (empty =
   «nessuna modifica»); else `new`. Empty cells keep existing values, as
   `add_or_update_device` already does.
8. `credentials_note`: own credentials › the probe's `device_identity` › the
   global account › «nessuna: la connessione fallirà finché non assegni
   un'identità» (same chain as `core/device_credentials.py`).

Decisions: `{"<row>": {"skip": true}}` → `skipped`;
`{"<row>": {"location": id}}` → rule 3 uses it.

### API

- `POST /api/import-csv/preview` `{csv_data, org?, location?, decisions?}` →
  `{columns: [{header, field|null}], rows: [RowResult], counts}`.
- `POST /api/import-csv` with the same body → imports `new` + `update` in one
  transaction → `{imported, updated, skipped, failed}`. The current response
  keys `imported`, `failed` keep their meaning.
- Both: `require_tab("tab-import")`, operator, scope as today. One audit entry
  per import with the counts.

### UI (Importa tab)

1. Destination: Organization select → Location select (filtered), both
   required; chips with the location's probe and subnets.
2. File drop zone. Choosing a file runs the preview. «Importa N apparati» is
   disabled until the preview has at least one `new`/`update` row.
3. Recognized columns (`indirizzo → IP ✓`, unknown → «ignorata»).
4. Filter tabs Tutte / Nuovi / Aggiornati / Da sistemare with counts
   (`role="tablist"`).
5. Table: outcome, row, IP, hostname, vendor, location, notes (diff, warnings,
   credentials note). Error rows carry the action button; pressing it adds a
   decision and reruns the preview.
6. Footer: «N apparati pronti · M righe saltate se importi ora» and the
   import button. The result replaces the preview with the counts.
7. Organizations tab: «Importa apparati» on each location →
   `window.openImportFor(org, location)` (declared in `types/globals.d.ts`).

The CSV template gains optional `Organization` / `Location` columns.

## Testing

- Migration: CSV + JSON → tables, identical rows; second run is a no-op;
  orphan `Location` stops it with the files untouched; agent data dir
  (hosts only, no locations) migrates.
- Storage: `get_all_devices` / `add_or_update_device` / decommission / reassign
  behave as before (existing suite green on SQLite); foreign keys refuse a
  location delete with devices; `device_history` still records every change.
- Agent RPC: get returns CSV text from the agent's tables; save accepts CSV
  text and replaces the agent's rows.
- `classify`: one test per rule and per decision; credentials note on each
  level.
- Preview and import agree: same input → import writes exactly the preview's
  `new` + `update` rows.
- Performance: a 10,000-row import is one transaction (asserted by counting
  commits), and a measured run on synthetic data is recorded in the plan.
- `TestClient` smoke for both import routes (incl. 403 out of scope, 422
  malformed body).
- UI: ids exist and are bound; keys in both languages; a11y; lazy-tab entry
  for the Organizations → Importa link.

## Out of scope

`probes.json` to SQLite; observability data; Blueprint (sub-project 3);
assistant (4); maps and routing per location (5).
