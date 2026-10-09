# Organizations, locations and probes — data model (2026-10-09)

Sub-project 1 of the multi-location revamp. Each sub-project has its own spec
and builds on the previous ones:

0. Rename "site" to "probe" in code, data and wire protocol
   ([2026-10-09-site-to-probe-rename-design.md](2026-10-09-site-to-probe-rename-design.md))
1. **Data model** (this spec)
2. Per-location CSV import with preview (dry-run)
3. Network Blueprint wizard (presets, canvas, deterministic checks, «Primi passi»)
4. Assistant: "Descrivi la rete", "Ricava dalle configurazioni", AI profile prompt, draft-only MCP tool
5. Maps and routing per location

## Problem

The app has two concepts and one word for both. `Group` is the tenant (RBAC
boundary, the `tenant` of every observability row); `Site` is how a device is
reached (`central`, an agent, a jump host). The UI calls the first «Gestione
Tenant» but describes the default one as «Sede Principale predefinita», the
import says «Sede '…' non consentita» about a Group, and the tab «Sedi» manages
agents. The import tab needs a whole panel to explain the difference.

What is missing is the **physical location** of an organization (HQ, branch,
warehouse). A branch reached directly over VPN has no entity at all: it is
either a separate tenant (splitting the company) or nothing.

`Site` today is also half location: it carries `subnets`, which
[routers/scan.py](../../../routers/scan.py) and the cross-site resolver in
[services/client_diagnosis.py](../../../services/client_diagnosis.py) read.

Already shipped (commit `7b66c7c`): a tenant's key is immutable, renaming sets
`groups.json[key].name`, the UI shows it through `orgLabel()`, deleting a
tenant with devices is refused.

## Vocabulary

| Concept | Code / storage | UI (it) | UI (en) |
|---|---|---|---|
| Tenant | `Group` column, `groups.json`, `tenant` in SQLite | Organizzazione | Organization |
| Physical location | `Location` column (new), `locations.json` (new) | Sede | Location |
| How a device is reached | `Probe` column, `probes.json`, `probe_manager` | — | — |
| ↳ mode `central` | `mode: "central"` | Diretto (server centrale) | Direct (central server) |
| ↳ mode `agent` | `mode: "agent"` | Sonda agente | Agent probe |
| ↳ mode `jump` | `mode: "jump"` | Sonda bastion | Bastion probe |
| The `probes.json` registry, as a tab | `tab-probes` | Sonde | Probes |

Code, data and wire protocol already say "probe" after sub-project 0; this
spec uses those names.

## Decisions

| Question | Decision |
|---|---|
| Location belongs to | Exactly one organization. |
| Probe belongs to | Nobody: one probe may serve locations of different organizations. `central` always exists. |
| Device's probe | Stays the device's own `Probe` column. A location has a **default** probe, used to prefill new devices; changing it offers «applica a tutti i device della sede». No resolver. |
| Subnets | Move from `probes.json` to the location. A probe's subnets = union of the subnets of the locations whose default probe it is, through one helper. |
| Default tenant | None. «Generale» and every `or 'Generale'` fallback go. A device without organization or location is refused at the boundary (ADR-0005 applied to inventory). |
| Delete an organization or location with devices | Refused, with the count. |
| Migration names | Locations created by the migration take the probe's name; a banner «Verifica le sedi create dalla migrazione» links to them (option A). |
| API paths | Unchanged (`/api/groups`, `/api/probes`); new `/api/locations`. |

## Storage

- `groups.json`: `{key: {name?, description}}` — `name` absent means the key.
- `locations.json` (new, under the data dir, already gitignored with `data/`):

  ```json
  {"milano": {"org": "acme", "name": "Milano", "role": "hq",
              "subnets": ["10.10.0.0/16"], "probe": "central"}}
  ```

  `id` is a slug of the name, unique across the file (a clash gets a short
  suffix, as `probe_manager.create_probe` does), immutable (same reason as the
  tenant key). `role` ∈ `hq | branch | datacenter | warehouse | other`.
- `network_hosts.csv`: new column `Location` (location id). `Probe` unchanged.
- `probes.json`: `subnets` removed by the migration.
- Agents' local `network_hosts.csv`: unchanged. Agents do not know locations.

## Migration (one shot, at startup)

Idempotent; runs when `locations.json` does not exist. Backs up `groups.json`,
`probes.json`, `network_hosts.csv` next to themselves first; one audit entry.

1. If `groups.json` has «Generale» **and** hosts.csv has devices in it: stop,
   log and show an error naming the device count. Never invent a tenant.
   Otherwise drop «Generale».
2. For each distinct `(Group, Probe or 'central')` in hosts.csv: create a
   location in `Group`, named after the probe, `probe` = that `Probe`,
   `subnets` copied from the probe. A probe serving two organizations yields
   two locations.
3. Write `Location` on every device row accordingly.
4. Remove `subnets` from `probes.json`.
5. Flag `migration_review_pending` so the UI shows the banner until dismissed.

## Boundaries

Every entry point that creates or moves a device requires an existing
organization **and** an existing location of that organization:

- `/api/add-device`, `/api/reassign-device`, `/api/reassign-device-probe`
- `/api/import-csv` (columns `Location`/`Sede`/`sede` added to the aliases;
  missing → row error; the per-location import of sub-project 2 will prefill it)
- provisioning and the manual-config wizard
- agent inventory push: an existing row (same org + IP) keeps its location; a
  new device goes to the single location of its organization whose probe is
  that agent; zero or several candidates → dropped, audit entry, counter shown
  on the probe in the «Sonde» tab («3 device senza sede»).

## UI (minimal; the Blueprint is sub-project 3)

- «Gestione Tenant» → **«Organizzazioni»**: each row expands to its locations;
  create/edit a location in a modal opened with `openModal` (name, role,
  subnets, default probe). Delete refused with the count.
- The probes tab is labelled **«Sonde»**, mode labels per the vocabulary table.
- Device form and table: Organizzazione → Sede (filtered by organization) →
  Raggiunto tramite (prefilled from the location's probe, editable).
- Post-migration banner.
- Every string through `tr()`, both languages; every control named
  (`check_a11y --strict`).

## Testing

- Migration: hosts + probes → locations and `Location` column; second run is a
  no-op; «Generale» with devices stops it; subnets moved.
- Boundaries: each entry point above refuses a missing/foreign location.
- Agent push: existing row keeps location; single candidate assigned; zero or
  several dropped and counted.
- Location delete refused with devices; succeeds empty.
- Probe subnets helper = union of its locations' subnets; `scan.py` and
  `client_diagnosis` read it.
- `TestClient` smoke per new route (`/api/locations` CRUD).
- Gate: pyrefly, `check_frontend`, full suite, `check_no_private_data`,
  `check_i18n_coverage --strict`, `check_a11y --strict`.

## Out of scope

Blueprint, links between locations, maps and routing per location, the AI
assistant, location-level RBAC. The CSV preview/dry-run is sub-project 2.
