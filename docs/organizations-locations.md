# Organizations and locations

Every device belongs to an **organization** and to one of its physical
**locations**. The probe that reaches it is a separate, per-device choice.

## Vocabulary

| Concept | Code / storage | UI (it) | UI (en) |
|---|---|---|---|
| Tenant | `Group` column, `organizations` table in `inventory.db`, `tenant` in SQLite | Organizzazione | Organization |
| Physical location | `Location` column, `locations` table in `inventory.db` | Sede | Location |
| How a device is reached | `Probe` column, `probes.json` | Sonda | Probe |

An organization is the permission boundary: a scoped admin sees and manages
only the organizations, and their locations, in scope. None is special and
there is no default organization.

## Storage

Hosts, decommissioned hosts, organizations and locations live in
`inventory.db`, next to the hosts path in the data directory (never tracked;
SQLite, WAL, `foreign_keys = ON`). Implementation: `services/inventory_store.py`;
`inventory_manager` and `location_manager` keep their public functions.

| Table | Key | Notes |
|---|---|---|
| `organizations` | `key` | `name`, `description` |
| `locations` | `id` | `org` references `organizations(key)` (plain `REFERENCES`, i.e. `NO ACTION`: deleting a referenced organization fails); `name`, `role`, `subnets` (JSON list), `probe` |
| `hosts` | `("IP", "Group")` | CSV column names kept; `"Location"` references `locations(id)`, NULL when empty |
| `decommissioned_hosts` | same | the same columns plus `"Decommissioned"`, `"Decommissioned By"` |

`hosts."Group"` has no foreign key and `"Location"` is nullable: an agent's
database has no organization or location registry. "Every new or moved device
needs a location" and "an organization with devices cannot be deleted" stay
rules of the code (see Boundaries). Passwords stay encrypted with
`crypto_vault`.

Stays JSON: `probes.json` (tokens and agent configuration). CSV is an
exchange format only: import, export, template and the agent inventory RPC.

## Locations

A location row, shown as JSON by `GET /api/locations`:

```json
{"milano": {"org": "acme", "name": "Milano", "role": "hq",
            "subnets": ["10.10.0.0/16"], "probe": "central"}}
```

- The id is a slug of the name, unique across the file and immutable.
- `role` is one of `hq`, `branch`, `datacenter`, `warehouse`, `other`.
- A location belongs to exactly one organization. A probe belongs to none: one
  probe may serve locations of different organizations.
- `probe` is the location's **default** probe. It prefills new devices; the
  device's own `Probe` column is what is used. Editing a location offers
  "apply the probe to every device of the location".

### Where subnets live

Subnets are set on locations, not on probes. A probe's subnets are the union
of the subnets of the locations whose default probe it is; the Probes tab
shows them read-only, and scans and client diagnosis read that union.

## Boundaries

Every entry point that creates or moves a device requires an existing
organization **and** an existing location of that organization: the device
form, `/api/add-device`, `/api/reassign-device`, `/api/reassign-device-probe`,
CSV import (column `Location`/`Sede`, by id or name; missing is a row error),
provisioning, the manual-config wizard, subnet-scan add and map promotion.

Agent inventory push: an existing row keeps its location; a new device goes to
the single location of its organization whose default probe is that agent.
With zero or several candidates the device is dropped, audited and counted on
the probe ("N devices without a location" in the Probes tab) — never assigned
to a guess.

Deleting an organization or a location that still has devices, active **or
decommissioned**, is refused with the count. Move them first.

API (Organizations tab permission; writes need an admin in scope):
`GET /api/locations`, `POST /api/locations`, `POST /api/locations/update`,
`POST /api/locations/delete`, `POST /api/locations/dismiss-review`.

## Upgrade migration

### 1. Locations

Runs once at startup when `locations.json` does not exist
(`core/location_migration.py`), and is skipped once `inventory.db` exists:
after the SQLite migration `locations.json` is gone by design. It backs up `groups.json`, `probes.json`,
`network_hosts.csv`, `decommissioned_hosts.csv` and `device_meta.db` next to
themselves (`*.pre-locations`), then:

1. Rows with an empty `Group` are written as the old implicit tenant
   «Generale», which from then on is an ordinary organization.
2. Each distinct `(organization, probe)` pair becomes a location of that
   organization, named after the probe, with the probe's subnets and that
   probe as default. A probe serving two organizations yields two locations.
3. Every device row, active and decommissioned, gets its `Location`.
4. `subnets` is removed from `probes.json`.
5. The home page shows a banner, "Check the locations created by the
   migration", until an admin dismisses it. If an organization named
   «Generale» still has devices, the banner gives the count: rename it or move
   them.

`locations.json` is written last, so a crash half-way reruns the whole
migration at the next start; a second start does nothing.

### 2. SQLite

Runs once at startup (central and agent) when `inventory.db` does not exist
and at least one old file does (`core/inventory_migration.py`), after the
locations migration, which still reads the old files.

1. It reads `groups.json`, `locations.json`, `network_hosts.csv` and
   `decommissioned_hosts.csv`, and builds the database in a temporary file in
   one transaction.
2. Rows repeating an `(IP, Group)` keep the last one; the count is logged
   (central: audit log; agent: printed to its console as `[inventory] migrazione: ...`).
3. The database is renamed into place, then each source is renamed to
   `*.pre-sqlite`. That file is the backup and the sign it was consumed; a
   crash between the two renames is finished at the next start. An existing
   `*.pre-sqlite` is never overwritten: the source stays in place and the
   start logs a warning naming it.
4. A second start finds `inventory.db` and does nothing.

A row whose `Location` names a location missing from `locations.json` is an
orphan. On central the migration stops, leaves every file untouched and the
server refuses to start with a message naming the rows (an empty inventory
would be worse): fix or remove those rows and restart. In an agent's data
directory there is no `locations.json`, so such `Location` values are blanked
and their count is logged instead.

## Import per location

The Import tab takes a default destination: an organization, then one of its
locations. Each location in the Organizations tab links to the tab with both
preselected. Import **never creates** organizations or locations.

Choosing a file runs a preview (`POST /api/import-csv/preview`), which
classifies every row against the inventory, the locations and the probes and
writes nothing. Outcomes:

- `new` / `update`: will be imported. `update` lists the changed fields
  (credentials only as "changed"); empty cells keep the existing value.
- `error`: IP missing or invalid, organization or location missing, unknown or
  out of scope, unknown probe, IP repeated in the file, IP outside the
  location's subnets but inside another location of the same organization, or
  a **decommissioned** IP (reactivate or delete it first). The other rows
  still import.
- `skipped`: the row was set aside by the user.
- A warning, not an error: IP outside the subnets of every location.

Row actions on an error row: **Sposta in …** (the other location whose subnets
contain the IP) and **Salta**. They are sent back as `decisions`, so preview
and import stay stateless and run the same classification.

Missing credentials are not an error. Each row shows a credentials note: the
fallback that will apply (own credentials, the probe's identity, the global
account) or that none exists and the connection will fail until an identity
is assigned.

`POST /api/import-csv` (same body) imports `new` + `update` rows in **one
inventory write** and returns `{imported, updated, skipped, failed}`; it writes
one audit entry with the counts. Both routes need the Import tab permission.

Links between locations, each location's gateway and the checks against the
observed network live in the [Network Blueprint](network-blueprint.md).
