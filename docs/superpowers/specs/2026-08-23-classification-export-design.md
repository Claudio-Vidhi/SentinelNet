# Classification Export — Design

**Date:** 2026-08-23
**Status:** approved, ready for implementation planning

## Problem

Two device exports exist and they are not the same tool.

**Network Device Inventory** (`/api/export/devices`) is server-side: a column
registry, a picker modal fed by `/api/export/devices/columns`, saved
preferences, tenant/site/vendor/redundancy filters, and row explosion for
stack and HA members.

**Discovered Devices & Classification** builds its CSV in the browser from
whichever columns happen to be visible in the table. No picker, no registry,
no filters beyond the table's own.

The operator wants the second export to have the first one's capabilities, plus
two columns neither export has today: **serial number** and **neighbour
device**.

The motivating case is access points. They are discovered via CDP/LLDP and
already appear as rows in the classification table, but nothing in the export
tells you an AP's serial or which switch it hangs off.

## What the data already answers

Investigated before designing; each of these changed the shape of the solution.

- **Neighbour is free.** Access points appear in the network map precisely
  because a switch announced them over CDP/LLDP, so every AP node already
  carries a link. `data["links"]` gives the neighbour device *and* the port,
  at no additional cost and with no controller involved.
- **CDP carries no serial.** Neither CDP nor LLDP advertises a serial number,
  so the neighbour path cannot supply it. For an inventoried device the serial
  comes from scan data (`get_detected_versions()`), exactly as the inventory
  export already reads it. For a discovered AP it exists only on the wireless
  controller.
- **`show ap summary` carries no serial either.** It returns name, IP, model,
  ethernet MAC and status. Serial needs a separate inventory command.
- **`/api/device-classification` already assembles the rows we want.** The
  export does not need a second traversal of the map.

## Decisions

| Question | Decision | Why |
|---|---|---|
| Serial acquisition | Bulk command only | A per-AP command is one SSH round-trip each. Where a platform has no bulk form the column exports empty — never a fan-out. |
| Neighbour source | The network map | Already parsed and cached; the controller adds nothing here. |
| Where AP data lands | The classification export | APs sit beside every other device. One export to build, test and learn. |
| Serial delivery | Cached on WLC tab visit | Keeps SSH out of the export request entirely, so an export can never hang on an unreachable controller. |
| Several neighbours | One row per neighbour, opt-in | Follows the `_MEMBER_COLUMNS` precedent, whose comment already argues the case: a concatenated cell cannot be filtered or looked up in a spreadsheet. |

Rejected: a WLC-specific AP export (a second surface for a subset of one
table); live controller queries at export time (puts SSH back inside a
request); a scheduled background pull (a new job to supervise for one column).

## Architecture

### One assembler, two consumers

The node-building loop inside `device_classification()` in `routers/catalog.py`
moves into a shared helper. The tab endpoint and the export both call it, so
they cannot drift apart — the same reasoning that put the inventory column
registry behind `/api/export/devices/columns` instead of a copy in JavaScript.

New endpoints mirroring the inventory pair:

- `GET /api/export/classification/columns` — registry and defaults
- `GET /api/export/classification` — CSV

### Column registry

`_CLASSIFICATION_COLUMNS` in `routers/catalog.py`, same `{key: (header, fn)}`
shape as `_EXPORT_COLUMNS`:

hostname, IP, tenant, category, subcategory, vendor, model, version, status,
discovered, **serial**, **neighbour device**, **neighbour port**.

`_NEIGHBOUR_COLUMNS` mirrors `_MEMBER_COLUMNS`: requesting a neighbour column
means one row per link; omit them and each device stays on a single row. Links
are matched in both directions, since a node may be either end of one.

A device with no links still exports one row, with the neighbour columns empty.
Dropping it would make selecting a column silently shrink the device list,
which is the opposite of what adding a column should do.

### Serial resolution

```
inventoried device  -> get_detected_versions()[ip]["serial"]
discovered AP       -> AP store, matched on AP name
anything else       -> empty
```

### AP store

`/api/wlc/{ip}/overview` gains one bulk inventory command and writes the AP
name to serial map to `data/ap_inventory.json`:

```json
{
  "<ap-name>": {
    "serial": "<serial>",
    "model": "<model>",
    "wlc_ip": "192.0.2.10",
    "tenant": "ACME",
    "seen_at": "2026-08-23T15:07:54Z"
  }
}
```

JSON rather than a table in `observability.db`: this is small keyed state, like
`vendors.json`, and it needs no schema migration. `data/` is already gitignored.

The command is best-effort like every other command in `overview()` — a
controller that will not answer costs the serial column, not the tab. The
export carries `seen_at` so a stale serial is visible rather than silent, and
an AP whose controller nobody has opened exports with an empty serial.

### Frontend

The classification tab gets the column-picker modal, replacing the browser-side
CSV builder in `static/js/topology.js`; that function and its column-visibility
CSV path are deleted rather than left beside the new one. Preferences use their
own localStorage key. Labels get keys in both the `it` and `en` blocks of
`i18n.js`. The button binds through `data-action` and a delegated listener, per
the project's no-inline-handler rule.

## Testing

- Column registry: every key renders, defaults are a subset of the registry.
- Row explosion: a device with two links yields two rows when a neighbour
  column is selected, one row when it is not; a device with no links yields
  one row with the neighbour columns empty.
- Serial join: an inventoried device resolves from scan data; a discovered AP
  resolves from the store; an AP absent from the store exports an empty serial.
- AP name normalisation: a CDP-announced FQDN matches the controller's short
  AP name.
- Tenant scoping: a caller scoped to one tenant cannot export another's rows.
- Router parity: the two new paths go in the `tests/test_router_parity.py`
  allow-list. The OpenAPI golden is never regenerated.

Tests are `unittest.TestCase` classes — bare `test_*` functions are not
collected by `unittest discover`. Fixtures use RFC 5737 addresses
(`192.0.2.x`), `switch-01`, `ACME`, and invented serials.

## To verify during implementation, not assume

- The exact bulk inventory command per platform, and whether IOS-XE offers a
  bulk form at all. No bulk form means the serial column stays empty for that
  platform; it never becomes a per-AP fan-out.
- Whether a CDP-announced AP hostname matches the controller's AP name (case,
  FQDN suffix). Normalise the way `hostname_to_ip` already does in
  `_generate_network_map`.

## Out of scope

- A wifi-only export surface.
- Persisting anything beyond the AP name, serial and model map.
- Backfilling serials for controllers nobody has opened.

## Version

MINOR — new feature. `core/version.py` and `pyproject.toml` move together.
