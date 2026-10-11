# Network Blueprint — expected network vs observed network (2026-10-11)

Sub-project 3 of the multi-location revamp
([roadmap](2026-10-09-organizations-locations-design.md)). Builds on 1
(organizations and locations) and 2 (inventory on SQLite, `inventory.db`).
Sub-project 4 (assistant) writes Blueprint **drafts** only; sub-project 5 (maps
and routing per location) reads the links defined here.

## Problem

An organization's locations exist, but nothing says how they are meant to be
connected, which device is a location's gateway, or whether the network
SentinelNet observes matches what the operator intends. The operator wants to
give a rough outline (a preset or a few locations) and let deterministic checks,
fed by data the product already collects, propose what is missing until the
model is complete. Every change to the model must be versioned so the history
is exact and aligned with what was actually applied.

## Decisions

| Question | Decision |
|---|---|
| Purpose | Expected network (model) compared with the observed one. |
| Model | One model: the existing locations plus a new `links` table. No separate Blueprint document. |
| How the model changes in the Blueprint | Through a **draft** (list of operations), reviewed, editable, applied in one transaction. |
| Versioning | Every write to locations or links of an organization, from any path, creates a revision with a full snapshot. |
| Restore | Never rewrites: builds a draft that brings the model back to revision N. |
| Checks | Pure functions `(model, snapshot) -> findings`; never open a connection. |
| Observed data | Stored snapshot: offline sources on every check, live sources only on an explicit «Aggiorna dai gateway». |
| Gaps found | A finding may carry a **proposal** (operations); the user accepts, edits or ignores it. Nothing is written without applying a draft. |
| Rejected proposals | Not remembered: a proposal reappears while its cause persists. |
| Canvas | Lists + modals for editing; vis-network diagram that is live, colored by findings, click opens the modal. Not an editable canvas. |
| Presets | Fixed topological skeletons producing a draft; subnets left empty. |
| Placement | New tab `tab-blueprint`, lazy-loaded; Organizations rows link to it. |
| MCP | None in this sub-project (draft-only tool comes with 4). |

## Storage (`inventory.db`)

Schema added to `services/inventory_store.py`, foreign keys on as for the
existing tables.

- `locations`: new column `gateway TEXT` (nullable) — IP of a device in the
  inventory of the same organization. Checked by the checks, not by a foreign
  key (hosts are keyed `(IP, Group)`).
- `links`:

  ```sql
  CREATE TABLE links (
    id   TEXT PRIMARY KEY,
    org  TEXT NOT NULL REFERENCES organizations(key),
    a    TEXT NOT NULL REFERENCES locations(id),
    b    TEXT NOT NULL REFERENCES locations(id),
    kind TEXT NOT NULL CHECK (kind IN ('vpn','wan','mpls','lan')),
    note TEXT NOT NULL DEFAULT '',
    CHECK (a <> b),
    UNIQUE (org, a, b, kind));
  ```

  `a`/`b` are stored ordered (`a < b`) so A↔B and B↔A are the same link. Both
  locations must belong to `org` (checked on write). Deleting a location with
  links: the draft that deletes it must also remove its links; a direct delete
  through `/api/locations/delete` removes them in the same transaction and the
  revision records it.
- `blueprint_drafts`: `org TEXT PRIMARY KEY REFERENCES organizations(key)`,
  `base_rev INTEGER NOT NULL`, `source TEXT NOT NULL`, `ops TEXT NOT NULL`
  (JSON), `updated_by`, `updated_at`. One open draft per organization; `source`
  is the origin of the first operation (`preset | checks | restore | manual |
  assistant`), each operation also carries its own `source`.
- `blueprint_revisions`: `(org, rev)` primary key, `at`, `by`, `source`
  (`migration | blueprint | locations | import | restore`), `note`, `snapshot`
  (JSON: the organization's locations and links after the write).
- `blueprint_observations`: `org TEXT PRIMARY KEY`, `at`, `data` (JSON: per
  gateway, live routes and IPsec tunnels with their own timestamp and error).
  One snapshot per organization, replaced by each «Aggiorna dai gateway».

### Operations

```json
{"op": "create_location", "ref": "new-1", "name": "Filiale 1", "role": "branch",
 "subnets": [], "probe": "central"}
{"op": "update_location", "id": "roma", "fields": {"subnets": ["10.20.0.0/24"]}}
{"op": "delete_location", "id": "roma"}
{"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"}
{"op": "add_link", "a": "milano", "b": "new-1", "kind": "vpn", "note": ""}
{"op": "remove_link", "id": "milano--roma--vpn"}
```

`ref` lets later operations of the same draft point at a location not created
yet; on apply each `ref` becomes the slug id the location manager assigns.
Operations are validated when added (shape, enums, subnets via the existing
`_clean_subnets`) and again on apply against the current model.

## Revisions

- One write function, `location_manager._save(data, links, by, source, note)`,
  compares old and new state per organization and appends a revision for each
  organization that changed. Every path goes through it: the `/api/locations`
  routes (`source=locations`), draft apply (`blueprint`, or `restore` when
  the draft's source is `restore`), the inventory
  migration (`migration`). The import of sub-project 2 does not create
  locations today; if it ever does it passes `import`.
- At startup, each organization without revisions gets revision 1
  (`source=migration`) with its current snapshot. Idempotent.
- Apply: one transaction. If the organization's latest revision is not the
  draft's `base_rev`, apply is refused with `409` and the UI reruns the checks
  on the new model; the draft stays, and the user realigns it («Allinea alla versione attuale» sets
  `base_rev` to the current one after showing what changed in between).
- Deleting a location that still has devices (active or decommissioned) is
  refused with the count, as today; the whole draft is not applied.
- Restore to N: the diff between the current model and snapshot N, expressed
  as operations, opened as a draft with `source=restore`. A location deleted
  since N comes back as `create_location` with its old id requested; if the id
  is taken, it gets a suffix and the restore says so.
- Diff between two revisions: locations and links added, removed, changed
  (field by field). Computed from the snapshots, no extra storage.

## Observed data

Gathered by `services/blueprint_observe.py`; the checks only read the result.

| Source | When | How |
|---|---|---|
| Inventory devices of the organization | every check | `inventory_store.read_hosts` |
| ARP entries seen by the organization's devices | every check | `arp_entries` |
| Static routes from the latest backup of each gateway | every check | `route_table.routes_from_backup` |
| Full route table of each gateway | «Aggiorna dai gateway» | `route_table.collect_for` |
| IPsec tunnels of each FortiGate gateway | «Aggiorna dai gateway» | `fortigate_service.get_vpn_tunnels` |

«Aggiorna dai gateway» runs per gateway with the existing per-device
collection; an unreachable gateway is a row with its error, not a failed
request. The snapshot age is shown in the UI. Locations without a gateway are
skipped (and produce the «sede senza gateway» finding).

## Checks

`services/blueprint_checks.py`: `run(model, observed) -> list[Finding]`.

```python
Finding = {"code": str, "severity": "error" | "warning" | "info" | "unknown",
           "subject": {"location": id} | {"link": id} | {"device": ip},
           "params": dict,           # for the tr() message
           "proposal": list[op] | None}
```

A check that lacks the data it needs returns `unknown`, never `ok` nor
`error`.

| Group | Code | Finding | Proposal |
|---|---|---|---|
| Model | `subnet_overlap` | two locations' subnets overlap (error) | none |
| | `location_no_subnets` | location without subnets (warning) | subnets seen for it, see `arp_uncovered` |
| | `location_isolated` | branch/warehouse with no path of links to an `hq` or `datacenter` (warning) | `add_link` vpn to the HQ (first `hq`, else first `datacenter`) |
| | `location_no_gateway` | no gateway (warning) | `set_gateway` if exactly one device of the location is a FortiGate or a router with routes/backup; several → listed, no proposal |
| | `gateway_not_in_location` | gateway IP not a device of that location (error) | none |
| Subnets | `device_outside_subnets` | device IP not in its location's subnets (warning) | move it to the location covering the IP if one exists, else add its /24 to its location |
| | `arp_uncovered` | /24 seen in ARP by a location's gateway, covered by no location (warning) | `update_location` adding it to that location |
| | `subnet_unused` | declared subnet with no device nor ARP entry (info) | none |
| Routing | `link_no_route` | gateway of A has no route covering a subnet of B, or vice versa (error); a covering default route → warning «via default» | none |
| | `route_without_link` | route from A's gateway towards B's subnets, no link A↔B (info) | `add_link` (`vpn` if the egress interface is a tunnel, else `wan`) |
| VPN | `vpn_link_down` | `vpn` link with no up tunnel between the two gateways (error); tunnel present but down → error; FortiGate data missing → unknown | none |
| | `tunnel_without_link` | up tunnel between gateways of two locations, no link (info) | `add_link` vpn |

A tunnel matches a link A↔B when its remote gateway is B's gateway, or its
phase-2 selectors cover a subnet of B. Only FortiGate tunnels in this
sub-project; other vendors' VPN links are `unknown`.

## UI (`tab-blueprint`, `static/js/blueprint.js`)

- Top bar: organization selector, current revision (`rev N · when · who`),
  snapshot age, «Verifica», «Aggiorna dai gateway», «Preset…», «Storico».
- «Primi passi» panel, shown until complete, derived from model and findings
  (no stored state): locations defined → every location has subnets → every
  non-HQ location is linked → every location has a gateway → gateway snapshot
  collected → no `error` finding. Each item links to its action. The Home
  checklist gains the item «Disegna il Blueprint di un'organizzazione».
- Left: Locations list (name, role, subnets, gateway, probe) and Links list
  (A, B, kind). Edits open modals (`openModal`) and become draft operations.
- Right: vis-network diagram. Nodes = locations (shape by role), edges = links
  (style by kind), color = worst finding; draft items not yet applied are
  dashed. Click a node/edge → its modal. The diagram mirrors the lists, it is
  not an editor.
- Findings, grouped by check. Each proposal: checkbox and «modifica» (opens
  the operation in its modal); «Aggiungi alla bozza» for the selected ones.
- Draft bar, sticky while a draft exists: «Bozza · N modifiche · da rev M»,
  «Rivedi» (operations list, each editable or removable), «Applica» (optional
  note), «Scarta». On `409`: «Il modello è cambiato» with the in-between diff
  and «Allinea alla versione attuale» (en: «Align to current version»).
- Storico: revisions (n, when, who, source, note); pick two → diff; «Ripristina
  questa revisione» opens a `restore` draft.
- Presets modal: Sede singola; Hub-and-spoke (HQ + N filiali, vpn); Hub-and-spoke
  con DC (HQ + DC + N filiali, each linked to both); Full mesh (N sedi). N in
  1..50. Placeholder names («Filiale 1…N»), roles set, subnets empty. Existing
  locations are kept: the preset only adds; if an `hq` exists it is reused as
  the hub.
- Organizations tab: per-row action «Blueprint» opens the tab on that
  organization.
- Every string through `tr()` in both languages, every control named,
  `LAZY_TAB_SCRIPTS` entry for `tab-blueprint` (and for `tab-groups` if the
  row action calls into `blueprint.js`), `types/globals.d.ts` for anything on
  `window`.

## API

All routes: `require_tab("tab-blueprint")`, `assert_group_allowed(user, org)`.
Writes also `require_admin`, like the locations routes.

| Method | Path | Body / answer |
|---|---|---|
| GET | `/api/blueprint/{org}` | `{locations, links, rev, draft}` |
| GET | `/api/blueprint/{org}/checks` | `{findings, observed_at}` — model **with the draft applied in memory** if a draft exists, so proposals already in the draft disappear |
| POST | `/api/blueprint/{org}/observe` | runs the live collection, returns the snapshot summary |
| POST | `/api/blueprint/{org}/draft` | `{source, ops}` appended (draft created at the current rev if none); `{preset, n}` builds the ops server side; `{restore: N}` builds the restore ops |
| PUT | `/api/blueprint/{org}/draft` | `{ops}` replaces the list (edit/remove) |
| POST | `/api/blueprint/{org}/draft/apply` | `{note}` → `{rev}`; `409` on stale base, `422` on an invalid op (which one, why) |
| POST | `/api/blueprint/{org}/draft/discard` | |
| POST | `/api/blueprint/{org}/draft/align` | sets `base_rev` to the current one |
| GET | `/api/blueprint/{org}/revisions` · `/revisions/{n}` · `/diff?a=&b=` | |

`/api/locations` keeps working and writes through the revisioned `_save`.

## Error handling

- Invalid operation (unknown location, foreign organization, bad subnet, bad
  enum, link to itself): refused when added (`422`, operation index and reason)
  and rechecked on apply.
- Apply is all-or-nothing; a refused delete (devices still there) names the
  location and the count.
- Live collection: per-gateway errors are stored and shown; the request
  succeeds. A FortiGate without REST token falls back as `get_vpn_tunnels`
  already does.
- Checks never raise on missing data: `unknown`.

## Testing

- Store: links schema (ordering, uniqueness, `a<>b`, foreign keys); revisions
  appended per changed organization only; startup revision 1 idempotent.
- Drafts: add/replace/discard; `ref` resolution; apply all-or-nothing; stale
  base → 409; align; delete with devices refused with count.
- Restore: round trip (apply changes, restore rev N, apply → snapshot equals N);
  id clash gets a suffix.
- Diff between revisions.
- Each check: fixtures of plain dicts, one positive and one negative case, plus
  `unknown` when its data is missing; each proposal is a valid draft op.
- Presets: each generates valid ops; reuses an existing `hq`; N bounds.
- Observe: unreachable gateway recorded as error, others collected (collectors
  mocked).
- `/api/locations` writes create revisions.
- `TestClient` smoke per route (401/403/422 fine); tenant isolation: a user of
  org X gets 403 on org Y.
- Frontend: `check_frontend`, `check_i18n_coverage --strict`,
  `check_a11y --strict`, `test_lazy_tab_scripts`, `test_ui_modal`.
- Gate: pyrefly, full suite, `check_no_private_data`. Screenshots regenerated
  (new tab).

## Out of scope

The assistant and its MCP draft tool (4); maps and routing per location (5);
non-FortiGate VPN status; periodic background checks and notifications;
persistent «ignore this finding»; an editable canvas; IP plan generation in
presets.
