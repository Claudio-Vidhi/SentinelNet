# Organizations and locations

Every device belongs to an **organization** and to one of its physical
**locations**. The probe that reaches it is a separate, per-device choice.

## Vocabulary

| Concept | Code / storage | UI (it) | UI (en) |
|---|---|---|---|
| Tenant | `Group` column, `groups.json`, `tenant` in SQLite | Organizzazione | Organization |
| Physical location | `Location` column, `locations.json` | Sede | Location |
| How a device is reached | `Probe` column, `probes.json` | Sonda | Probe |

An organization is the permission boundary: a scoped admin sees and manages
only the organizations, and their locations, in scope. None is special and
there is no default organization.

## Locations

`locations.json` (under the data directory, never tracked):

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

Runs once at startup when `locations.json` does not exist
(`core/location_migration.py`). It backs up `groups.json`, `probes.json`,
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
