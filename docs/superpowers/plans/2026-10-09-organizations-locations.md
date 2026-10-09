# Organizations, Locations and Probes — Implementation Plan (sub-project 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every device a physical location (`Sede`) inside its organization, move subnets from probes to locations, and drop the implicit «Generale» tenant.

**Architecture:** A new registry `services/location_manager.py` over `locations.json`; a `Location` column in `network_hosts.csv`; a one-shot startup migration (`core/location_migration.py`) that derives locations from the existing `(Group, Probe)` pairs. Probes keep exposing `subnets`, now computed from the locations whose default probe they are, so the four subnet readers do not change. Every entry point that creates or moves a device requires an existing organization and location. The «Generale» fallbacks go behind a shrinking scanner test, the same ratchet that carried the site → probe rename.

**Tech Stack:** Python 3 / FastAPI / JSON + CSV state files / classic-script JS / unittest via pytest (`uv run pytest tests -n 4`).

**Spec:** `docs/superpowers/specs/2026-10-09-organizations-locations-design.md`

## Decision before Task 2 (spec conflict) — decided: A

The spec says: if «Generale» has devices, the migration **stops**. But while it
is stopped `locations.json` does not exist, every boundary of Task 3 refuses
devices without a location, and `/api/reassign-device` — the only way to move
the devices out of «Generale» — needs a location in the target organization.
The installation would be stuck.

- **A (recommended):** «Generale» with devices is migrated like any other
  organization (it gets its locations); it simply stops being special — no
  code falls back to it any more. The post-migration banner says «L'organizzazione
  Generale contiene N apparati: rinominala o spostali».
- **B:** keep the stop, and while `locations.json` is missing the boundaries
  accept devices without a location (a migration-pending mode).

The plan below is written for **A**. Choosing B changes Task 2 Step 3 and adds
a `migration_pending()` bypass in Task 3.

## Global Constraints

- Location ids: slug of the name, unique across the file, immutable (`probe_manager._slugify`, clash → `-2`, `-3`…).
- `role` ∈ `hq | branch | datacenter | warehouse | other`.
- A location belongs to exactly one organization; a probe belongs to none; `central` always exists.
- A device's `Probe` stays its own column; the location's `probe` only prefills new devices.
- Subnets live on locations; `probe_manager` exposes `subnets` = union of its locations' subnets.
- No fallback tenant anywhere (ADR-0005 extended to the inventory).
- Delete of an organization or location with devices (active **or decommissioned**) is refused with the count.
- API paths unchanged (`/api/groups`, `/api/probes`); new `/api/locations`.
- New comments in English; Italian user/audit strings like the existing ones; UI strings via `tr()` in both languages; `openModal`/`closeModal`; accessible names.
- Example data only (`192.0.2.x`, `acme`, `milano`, private ranges such as `10.10.0.0/16`).
- Gate before each commit: `uv run pyrefly check`, `uv run python scripts/check_frontend.py` (JS/templates), `uv run pytest tests -n 4`, `uv run python scripts/check_no_private_data.py`; UI tasks also `check_i18n_coverage.py --strict` and `check_a11y.py --strict`.

## Review Focus

1. **Upgrade of an install where some rows have an empty `Group`** → they belong to «Generale» (today's read default) and migrate with it, never silently dropped. Test in Task 2.
2. **A probe serving two organizations** → two locations, each with the probe's subnets; a scan in that subnet still finds the probe. Tests in Tasks 1–2.
3. **Decommissioned devices** (`decommissioned_hosts.csv`) → get their `Location` from the same migration, and count when deleting a location. Tests in Tasks 1–2.
4. **Agent push of a brand-new device** with zero or several candidate locations → dropped, audited, counted on the probe — never assigned to a guess. Test in Task 3.
5. **Scoped admin** → manages locations only of the organizations in scope (`assert_group_allowed`). Test in Task 4.

---

## File map

| File | Change |
|---|---|
| `services/location_manager.py` (new) | registry, validation, `probe_subnets`, `apply_probe_to_devices` |
| `services/probe_manager.py` | `_public` adds computed `subnets`; `create/update_probe` stop storing them |
| `core/location_migration.py` (new) | one-shot migration |
| `app_server.py` | run it in `lifespan` after `probe_migration` |
| `services/inventory_manager.py` | `Location` in `_HOSTS_FIELDS`, `add_or_update_device(..., location=)`, CSV aliases, `delete_group` counts locations |
| `routers/inventory.py`, `routers/manual_config.py`, `routers/provisioner.py`, `routers/agent.py` | boundaries |
| `routers/locations.py` (new) | `/api/locations` CRUD, dismiss-review |
| `routers/catalog.py` | org delete refuses with locations |
| `routers/probes.py` | `subnets` field removed from create/update |
| ~44 Python files, ~26 JS/HTML lines | «Generale» fallbacks, behind `tests/test_no_generale_fallback.py` |
| `templates/dashboard.html`, `static/js/devices.js`, `static/js/i18n.js`, banner module | Organizzazioni tab with locations, device form, banner |
| Tests | `test_location_manager.py`, `test_location_migration.py`, `test_location_boundaries.py`, `test_locations_api.py`, `test_no_generale_fallback.py`, `test_locations_ui.py` |

---

### Task 1: Location registry; probes expose subnets from locations

**Model:** sonnet

**Files:**
- Create: `services/location_manager.py`
- Modify: `services/probe_manager.py` (`_public` at ~98, `create_probe` at ~185, `update_probe` at ~237)
- Modify: `core/data_config.py` (`locations.json` in `_STATE_FILES`)
- Test: `tests/test_location_manager.py`

**Interfaces — Produces:**
- `location_manager.ROLES: tuple[str, ...]`
- `list_locations(org: str | None = None) -> list[dict]` (each with `id`)
- `get_location(loc_id: str) -> dict | None`
- `create_location(org, name, role="branch", subnets=None, probe="central") -> dict` — `ValueError` on unknown org/probe, bad role, bad CIDR, empty name
- `update_location(loc_id, name=None, role=None, subnets=None, probe=None) -> dict`
- `devices_in(loc_id) -> int` (active + decommissioned)
- `delete_location(loc_id) -> None` — `ValueError("La sede contiene N apparati…")` when devices reference it
- `probe_subnets(probe_id) -> list[str]` — sorted union
- `apply_probe_to_devices(loc_id) -> int` — sets `Probe` of the location's devices to the location's probe
- `probe_manager.list_probes()/get_probe()` keep returning `subnets`, now computed

- [ ] **Step 1: Write the failing tests** — `tests/test_location_manager.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Locations: one organization each, subnets owned here, probes derive theirs."""
import os
import tempfile
import unittest
from unittest.mock import patch

from core import data_config
from services import inventory_manager, location_manager, probe_manager


class _Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="loc_")
        files = {"locations.json": os.path.join(tmp, "locations.json")}
        real_get_path = data_config.get_path
        for p in (
            patch.object(data_config, "get_path", lambda n: files.get(n) or real_get_path(n)),
            patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv")),
            patch.object(inventory_manager, "GROUPS_JSON", os.path.join(tmp, "groups.json")),
            patch.object(probe_manager, "PROBES_JSON", os.path.join(tmp, "probes.json")),
        ):
            p.start()
            self.addCleanup(p.stop)
        inventory_manager.save_groups({"acme": {"description": ""}, "beta": {"description": ""}})


class TestRegistry(_Base):
    def test_create_slugs_and_validates(self):
        loc = location_manager.create_location("acme", "Milano", "hq", ["10.10.0.0/16"])
        self.assertEqual(loc["id"], "milano")
        self.assertEqual(loc["org"], "acme")
        self.assertEqual(loc["probe"], "central")
        again = location_manager.create_location("beta", "Milano")
        self.assertNotEqual(again["id"], "milano")
        for bad in (dict(org="nope", name="X"), dict(org="acme", name=""),
                    dict(org="acme", name="X", role="castle"),
                    dict(org="acme", name="X", subnets=["10.0.0.0/33"]),
                    dict(org="acme", name="X", probe="ghost")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                location_manager.create_location(**bad)

    def test_probe_subnets_are_the_union_of_its_locations(self):
        probe, _ = probe_manager.create_probe("Lab", "agent")
        location_manager.create_location("acme", "A", subnets=["10.1.0.0/16"], probe=probe["id"])
        location_manager.create_location("beta", "B", subnets=["10.2.0.0/16", "10.1.0.0/16"],
                                         probe=probe["id"])
        location_manager.create_location("acme", "C", subnets=["10.3.0.0/16"])
        self.assertEqual(location_manager.probe_subnets(probe["id"]),
                         ["10.1.0.0/16", "10.2.0.0/16"])
        self.assertEqual(probe_manager.get_probe(probe["id"])["subnets"],
                         ["10.1.0.0/16", "10.2.0.0/16"])

    @unittest.skip("Task 3: add_or_update_device(location=)")
    def test_delete_refused_while_devices_reference_it(self):
        loc = location_manager.create_location("acme", "Milano")
        inventory_manager.add_or_update_device("192.0.2.10", "cisco", "custom", "u", "p", "",
                                               "acme", location=loc["id"])
        with self.assertRaisesRegex(ValueError, "1"):
            location_manager.delete_location(loc["id"])
        inventory_manager.delete_devices([("acme", "192.0.2.10")])
        location_manager.delete_location(loc["id"])
        self.assertIsNone(location_manager.get_location(loc["id"]))

    @unittest.skip("Task 3: add_or_update_device(location=)")
    def test_apply_probe_to_devices(self):
        probe, _ = probe_manager.create_probe("Lab", "agent")
        loc = location_manager.create_location("acme", "Milano")
        inventory_manager.add_or_update_device("192.0.2.10", "cisco", "custom", "u", "p", "",
                                               "acme", location=loc["id"])
        location_manager.update_location(loc["id"], probe=probe["id"])
        self.assertEqual(location_manager.apply_probe_to_devices(loc["id"]), 1)
        self.assertEqual(inventory_manager.get_all_devices()[0]["Probe"], probe["id"])
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_location_manager.py -q`
Expected: FAIL, `ImportError: cannot import name 'location_manager'`.

- [ ] **Step 3: Implement `services/location_manager.py`**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Physical locations of an organization (spec 2026-10-09
organizations-locations). A location belongs to exactly one organization (the
tenant key), owns the subnets that probes used to carry, and names a default
probe that prefills new devices. Ids are immutable slugs, like tenant keys."""
import ipaddress
import json
import threading

from core import data_config

ROLES = ("hq", "branch", "datacenter", "warehouse", "other")
_lock = threading.RLock()


def _path() -> str:
    return data_config.get_path("locations.json")


def _load() -> dict:
    try:
        with open(_path(), encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def _save(data: dict) -> None:
    data_config.atomic_write(_path(), data)


def _clean_subnets(subnets) -> list:
    out = []
    for raw in subnets or []:
        raw = str(raw).strip()
        if not raw:
            continue
        try:
            out.append(str(ipaddress.ip_network(raw, strict=False)))
        except ValueError:
            raise ValueError(f"Subnet non valida: {raw}")
    return sorted(set(out))


def _check(org=None, role=None, probe=None) -> None:
    # Local imports: probe_manager._public calls back into this module.
    from services import inventory_manager, probe_manager
    if org is not None and org not in inventory_manager.get_all_groups():
        raise ValueError(f"Organizzazione '{org}' inesistente.")
    if role is not None and role not in ROLES:
        raise ValueError(f"Ruolo non valido: {role}")
    if probe is not None and not probe_manager.get_probe(probe):
        raise ValueError(f"Sonda '{probe}' inesistente.")


def list_locations(org=None) -> list:
    with _lock:
        data = _load()
    return [dict(v, id=k) for k, v in sorted(data.items())
            if org is None or v.get("org") == org]


def get_location(loc_id: str):
    with _lock:
        v = _load().get(loc_id)
    return dict(v, id=loc_id) if v else None


def create_location(org, name, role="branch", subnets=None, probe="central") -> dict:
    from services.probe_manager import _slugify
    name = (name or "").strip()
    if not name:
        raise ValueError("Il nome della sede è obbligatorio.")
    _check(org=org, role=role, probe=probe)
    clean = _clean_subnets(subnets)
    with _lock:
        data = _load()
        base = _slugify(name)
        loc_id, n = base, 2
        while loc_id in data:
            loc_id, n = f"{base}-{n}", n + 1
        data[loc_id] = {"org": org, "name": name, "role": role,
                        "subnets": clean, "probe": probe}
        _save(data)
    return dict(data[loc_id], id=loc_id)


def update_location(loc_id, name=None, role=None, subnets=None, probe=None) -> dict:
    _check(role=role, probe=probe)
    with _lock:
        data = _load()
        if loc_id not in data:
            raise ValueError(f"Sede '{loc_id}' inesistente.")
        loc = data[loc_id]
        if name is not None:
            if not name.strip():
                raise ValueError("Il nome della sede è obbligatorio.")
            loc["name"] = name.strip()
        if role is not None:
            loc["role"] = role
        if subnets is not None:
            loc["subnets"] = _clean_subnets(subnets)
        if probe is not None:
            loc["probe"] = probe
        _save(data)
    return dict(loc, id=loc_id)


def devices_in(loc_id: str) -> int:
    from services import inventory_manager
    rows = inventory_manager.get_all_devices() + inventory_manager.get_decommissioned_devices()
    return sum(1 for d in rows if d.get("Location") == loc_id)


def delete_location(loc_id: str) -> None:
    n = devices_in(loc_id)
    if n:
        raise ValueError(f"La sede contiene {n} apparati: spostali o eliminali prima.")
    with _lock:
        data = _load()
        data.pop(loc_id, None)
        _save(data)


def probe_subnets(probe_id: str) -> list:
    with _lock:
        data = _load()
    return sorted({s for v in data.values() if v.get("probe") == probe_id
                   for s in v.get("subnets") or []})


def apply_probe_to_devices(loc_id: str) -> int:
    """«Applica a tutti i device della sede»: the location's probe onto its
    devices. Explicit, never implicit — a device's probe is its own column."""
    from services import inventory_manager
    loc = get_location(loc_id)
    if not loc:
        raise ValueError(f"Sede '{loc_id}' inesistente.")
    with inventory_manager._io_lock:
        rows = inventory_manager.get_all_devices()
        n = 0
        for d in rows:
            if d.get("Location") == loc_id and d.get("Probe") != loc["probe"]:
                d["Probe"] = loc["probe"]
                n += 1
        if n:
            inventory_manager.safe_write_hosts_csv(rows)
    return n
```

- [ ] **Step 4: Probes derive subnets** — in `services/probe_manager.py`:

```python
def _public(probe: dict) -> dict:
    """Copia del sito senza l'hash del token (aggiunge has_token)."""
    from services import location_manager  # local: location_manager imports us
    d = {k: v for k, v in probe.items() if k != "token_hash"}
    d["has_token"] = bool(probe.get("token_hash"))
    # Subnets belong to locations now; a probe's are those of the locations
    # whose default probe it is (spec 2026-10-09 organizations-locations).
    d["subnets"] = location_manager.probe_subnets(probe.get("id"))
    return d
```

In `create_probe` stop writing `"subnets": subnets` into the record (keep the
parameter for now, ignored; Task 4 removes it from callers). In `update_probe`
delete the `if subnets is not None:` branch. The readers
`routers/scan.py:46`, `services/client_diagnosis.py:278,752` and
`routers/agent.py:152` stay unchanged.

- [ ] **Step 5: State file list** — add `"locations.json"` to `_STATE_FILES` in `core/data_config.py`.

- [ ] **Step 6: Run, gate, commit**

```bash
uv run pytest tests/test_location_manager.py tests/test_probes.py tests/test_client_diagnosis.py -q
uv run pyrefly check && uv run pytest tests -n 4 -q && uv run python scripts/check_no_private_data.py
git add services/location_manager.py services/probe_manager.py core/data_config.py tests/test_location_manager.py
git commit -m "feat(locations): location registry; probes derive subnets from their locations"
```

Existing tests that create probes with `subnets` and then read them back
(grep `subnets` under `tests/`) now need a location instead; update them to
create one with `location_manager.create_location(...)`.

---

### Task 2: One-shot migration

**Model:** sonnet

**Files:**
- Create: `core/location_migration.py`
- Modify: `app_server.py` (`lifespan`, right after the `probe_migration` loop)
- Test: `tests/test_location_migration.py`

**Interfaces — Produces:** `location_migration.migrate(data_dir: str) -> list[str]` (steps done; `[]` = nothing to do). Sets `locations_review_pending: true` in `app_settings.json` when it created locations.

- [ ] **Step 1: Write the failing tests** — `tests/test_location_migration.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""(Group, Probe) pairs become locations; subnets move from probes to them."""
import csv
import json
import os
import tempfile
import unittest

from core import location_migration

HDR = "IP,Vendor,Group,Hostname,Probe\n"


class TestLocationMigration(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="locmig_")

    def _w(self, name, obj):
        with open(os.path.join(self.d, name), "w", encoding="utf-8", newline="") as f:
            f.write(obj if isinstance(obj, str) else json.dumps(obj))

    def _r(self, name):
        with open(os.path.join(self.d, name), encoding="utf-8") as f:
            return json.load(f)

    def _rows(self, name="network_hosts.csv"):
        with open(os.path.join(self.d, name), encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def test_pairs_become_locations_and_rows_get_them(self):
        self._w("groups.json", {"acme": {}, "beta": {}})
        self._w("probes.json", {"central": {"id": "central", "name": "Centrale", "mode": "central",
                                            "subnets": []},
                                "lab": {"id": "lab", "name": "Lab", "mode": "agent",
                                        "subnets": ["10.1.0.0/16"]}})
        self._w("network_hosts.csv", HDR + "192.0.2.1,cisco,acme,sw-01,central\n"
                                           "192.0.2.2,cisco,acme,sw-02,lab\n"
                                           "192.0.2.3,cisco,beta,sw-03,lab\n")
        self.assertTrue(location_migration.migrate(self.d))
        locs = self._r("locations.json")
        pairs = sorted((v["org"], v["probe"]) for v in locs.values())
        self.assertEqual(pairs, [("acme", "central"), ("acme", "lab"), ("beta", "lab")])
        lab = [v for v in locs.values() if v["probe"] == "lab"]
        self.assertTrue(all(v["subnets"] == ["10.1.0.0/16"] for v in lab))
        self.assertTrue(all(r["Location"] in locs for r in self._rows()))
        self.assertNotIn("subnets", self._r("probes.json")["lab"])
        self.assertTrue(self._r("app_settings.json")["locations_review_pending"])

    def test_second_run_is_a_noop(self):
        self._w("groups.json", {"acme": {}})
        self._w("network_hosts.csv", HDR + "192.0.2.1,cisco,acme,sw-01,central\n")
        location_migration.migrate(self.d)
        self.assertEqual(location_migration.migrate(self.d), [])

    def test_empty_group_rows_migrate_with_generale(self):
        # Decision A: «Generale» is migrated like any organization.
        self._w("groups.json", {"Generale": {}})  # check-generale: ok
        self._w("network_hosts.csv", HDR + "192.0.2.1,cisco,,sw-01,central\n")
        location_migration.migrate(self.d)
        (row,) = self._rows()
        self.assertEqual(row["Group"], "Generale")  # check-generale: ok
        self.assertIn(row["Location"], self._r("locations.json"))

    def test_decommissioned_rows_get_a_location_too(self):
        self._w("groups.json", {"acme": {}})
        self._w("network_hosts.csv", HDR)
        self._w("decommissioned_hosts.csv",
                "IP,Vendor,Group,Hostname,Probe,Decommissioned,Decommissioned By\n"
                "192.0.2.9,cisco,acme,old,central,2026-10-09T12:00:00Z,op\n")
        location_migration.migrate(self.d)
        (row,) = self._rows("decommissioned_hosts.csv")
        self.assertIn(row["Location"], self._r("locations.json"))


class TestWiring(unittest.TestCase):
    def test_lifespan_runs_it_after_the_probe_migration(self):
        import inspect
        import app_server
        src = inspect.getsource(app_server.lifespan)
        self.assertLess(src.index("probe_migration.migrate"),
                        src.index("location_migration.migrate"))
        self.assertLess(src.index("location_migration.migrate"), src.index("db.start_writer"))
```

- [ ] **Step 2: Run to verify failure** — `uv run pytest tests/test_location_migration.py -q` → `ImportError`.

- [ ] **Step 3: Implement `core/location_migration.py`** — same shape as `core/probe_migration.py` (stdlib and direct file access, no service imports at module level), in this order:

1. Return `[]` if `locations.json` exists.
2. Back up `groups.json`, `probes.json`, `network_hosts.csv`, `decommissioned_hosts.csv` to `*.pre-locations` when present (never overwrite an existing backup).
3. Read both CSVs; an empty `Group` becomes `"Generale"` (today's read default; mark the line `check-generale: ok`) and is written back.
4. For each distinct `(Group, Probe or "central")` across both files, create a location: `name` = the probe's `name` (or its id), `role` = `"hq"` for `central`, else `"branch"`, `subnets` = the probe's `subnets`, `probe` = the probe id; id = `probe_manager._slugify(name)` re-implemented locally (lowercase, non-alnum → `-`), `-2`, `-3`… on clash.
5. Write `Location` on every row of both CSVs (header: `Location` right after `Probe`); write each file via temp + `os.replace`.
6. Remove `subnets` from every probe in `probes.json`.
7. Set `locations_review_pending: true` in `app_settings.json` (read, merge, write).
8. Write `locations.json` **last**: it is the done-flag, so a crash before it reruns everything.
9. Return the steps (Italian, like `probe_migration`).

- [ ] **Step 4: Wire it** — in `app_server.lifespan`, right after the `probe_migration` loop:

```python
    from core import location_migration
    for step in location_migration.migrate(data_dir):
        log_audit(f"Migrazione sedi: {step}.")
```

- [ ] **Step 5: Run, gate, commit** — `git commit -m "feat(migration): derive locations from (organization, probe) pairs"`.

---

### Task 3: `Location` column and the boundaries

**Model:** sonnet

**Files:**
- Modify: `services/inventory_manager.py` (`_HOSTS_FIELDS` + `'Location'` after `'Probe'`, `add_or_update_device(..., location=None)`, `_CSV_ALIASES`, `delete_group`)
- Modify: `routers/inventory.py` (`DeviceSchema.location`, add / reassign / reassign-probe / import / promote), `routers/manual_config.py`, `routers/provisioner.py`, `routers/agent.py`, `routers/catalog.py`
- Modify: `services/probe_manager.py` (`unlocated_devices` counter)
- Modify: `tests/conftest.py` (helper `make_location`)
- Test: `tests/test_location_boundaries.py`

**Rules:**
- `add_or_update_device(..., location)`: a **new** device requires `location`, which must exist and belong to `group` → else `ValueError`. An existing device keeps its location when `location` is `None`.
- `/api/add-device`: `location: str = ""` in `DeviceSchema`; empty on a new device → 400 (via the `ValueError`).
- `/api/reassign-device`: body gains `new_location` (required, must belong to `new_group`).
- `/api/reassign-device-probe`: unchanged.
- `/api/import-csv`: aliases `"location": "Location", "sede": "Location"` (and the canonical `Location`); a row without it, or with a location of another organization → row error.
- `/api/promote-device`: body gains `location`.
- Manual-config wizard and provisioner: pass the location chosen in their forms.
- Agent push (`routers/agent.py`): existing row (same org + IP) keeps its location; a new device goes to the **single** location of its organization whose `probe` is this agent; zero or several → skipped, one audit line, and `probe_manager` records `unlocated_devices` on the probe (exposed by `list_probes()`).
- `/api/groups/delete` and `delete_group`: also refuse while the organization has locations (count in the message).

- [ ] **Step 1: Write the failing tests** (`tests/test_location_boundaries.py`, `_Isolated` pattern from `tests/test_device_decommission_api.py`, with `locations.json` patched as in Task 1):
  - add-device without `location` → 400; with a location of another org → 400; with the right one → 200 and the row's `Location` set.
  - reassign-device to another org without `new_location` → 400; with one of that org → 200.
  - import-csv with columns `IP,Vendor,Group,Sede`: a valid row imports; a row without location and one with a foreign location fail with their row numbers.
  - agent push: existing row keeps its location; a new device with exactly one candidate is assigned; with zero candidates it is skipped and `get_probe(id)["unlocated_devices"] == 1`.
  - `/api/groups/delete` on an organization with a location → 400.
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement the rules.**
- [ ] **Step 4: Existing tests** — every test that adds a **new** device needs a location: add `make_location(org, name="Sede", probe="central") -> str` to `tests/conftest.py` and use it. Do not weaken the boundary to make old tests pass.
- [ ] **Step 5: Full suite green.**
- [ ] **Step 6: Remove the two `@unittest.skip("Task 3 …")` markers in `tests/test_location_manager.py`; gate; commit** — `git commit -m "feat(locations): every new or moved device needs an organization and a location"`.

---

### Task 4: `/api/locations`; probe form without subnets

**Model:** sonnet

**Files:**
- Create: `routers/locations.py`; include it in `app_server.py`
- Modify: `routers/probes.py` (drop `subnets` from create/update schemas and calls), `services/probe_manager.py` (drop the ignored `subnets` parameter), `tests/test_router_parity.py` (allow `/api/locations` and the new schemas, as done for `/api/devices/`)
- Test: `tests/test_locations_api.py`

| Route | Guard | Body | Effect |
|---|---|---|---|
| `GET /api/locations` | `get_current_user` + scope filter | `?org=` | locations in scope, each with `devices` (count) |
| `POST /api/locations` | `require_admin` + `assert_group_allowed(org)` | `{org, name, role, subnets, probe}` | create |
| `POST /api/locations/update` | same | `{id, name?, role?, subnets?, probe?, apply_probe_to_devices?: bool}` | update; optional «applica a tutti» |
| `POST /api/locations/delete` | same | `{id}` | delete; 400 with count if devices |
| `POST /api/locations/dismiss-review` | `require_admin` | — | clears `locations_review_pending` |

All with `require_tab("tab-groups")`. One audit line per write (Italian).

- [ ] **Step 1: Failing tests:** CRUD round trip as admin; scoped admin cannot create in a foreign org (403) and does not see foreign locations; delete with devices → 400 with the count; `apply_probe_to_devices` flag updates device probes; one `TestClient` call per route.
- [ ] **Step 2–4:** implement, run, parity allow-list.
- [ ] **Step 5: Gate, commit** — `git commit -m "feat(locations): /api/locations CRUD; probes no longer take subnets"`.

---

### Task 5: Drop the «Generale» fallback (ratchet)

**Model:** sonnet for the sweep; the final whole-branch review on the most capable model must look hard at `routers/deps.py`, `core/core_engine.py`, `observability/*`, `collectors/*` (tenant attribution).

**Files:**
- Create: `tests/test_no_generale_fallback.py` — same structure as the site scanner at `git show 9e0bc03^:tests/test_no_site_identifier.py` (a `PENDING` set that only shrinks; a listed file that no longer offends fails too)
- Modify: the files it lists (today: 131 occurrences in 44 Python files, 26 in JS/HTML)

**Scanner:** flags `'Generale'` / `"Generale"` in tracked `*.py|*.js|*.html` outside `docs/` and `tests/`; a line that must keep it carries `check-generale: ok` (the migration's empty-Group rule only).

| Pattern | Replace with |
|---|---|
| `d.get('Group') or 'Generale'` on an inventory row | `d['Group']` — after the migration every row has one |
| `device_pair`, `_same_device`, `delete_device(..., group or 'Generale')` | require the group; no default |
| Pydantic `group: str = "Generale"` | `group: str` (required) |
| Tenant of an observability / MAC / ARP record whose IP is not in the inventory | drop the record per ADR-0005 (count it), never a fallback tenant |
| UI preselecting `'Generale'` (`static/js/devices.js:1024`) | no preselection; the select starts on a «Scegli…» placeholder |
| `== "Generale"` guards (cannot delete/rename it) | remove: no organization is special |

- [ ] **Step 1:** write the scanner, run it, fill `PENDING`, commit (`test: scanner for Generale fallbacks, with a shrinking pending list`).
- [ ] **Steps 2..n:** one commit per area (inventory core; routers; observability + collectors; UI), each shrinking `PENDING`, full suite green each time.
- [ ] **Last step:** empty `PENDING`, delete `test_pending_only_shrinks`, commit.

---

### Task 6: UI

**Model:** sonnet

**Files:** `templates/dashboard.html`; `static/js/devices.js` (`renderGroupsTable` ~45, device form, table «where» line); the home banner (`static/js/home.js`); `static/js/i18n.js`; `static/css/dashboard.css`; `tests/test_locations_ui.py`; the ui-revamp / i18n / a11y tests that count panels or keys.

- [ ] «Gestione Tenant» → **«Organizzazioni»** (nav label, page title, both languages). Each organization row expands to its locations (name, role, subnets, default probe, device count) with «Nuova sede» / edit / delete; the form is a modal opened with `openModal` (name, role select, subnets textarea one CIDR per line, default-probe select, «Applica la sonda a tutti i device della sede» checkbox on edit). Delete shows the server's count message.
- [ ] Sonde tab: subnets field removed from the probe wizard; each probe row shows its derived subnets read-only and «N device senza sede» when `unlocated_devices > 0`.
- [ ] Device form: Organizzazione → **Sede** (select filtered by organization, required) → **Raggiunto tramite** (prefilled from the location's probe, editable). Inventory row «where» line: `Organizzazione · Sede · Sonda`. Decommissioned rows show the same.
- [ ] Home banner while `locations_review_pending`: «Verifica le sedi create dalla migrazione» → opens Organizzazioni; «Ho verificato» calls `dismiss-review`. If an organization literally named «Generale» still has devices, the banner adds the count.
- [ ] `tests/test_locations_ui.py`: ids exist and are bound; every new key in both dictionaries.
- [ ] Gate incl. `check_i18n_coverage --strict`, `check_a11y --strict`; browser check on a throwaway instance (create org, location, device; move a device; delete refused with count); commit.

---

### Task 7: Docs, tour, gate, build

**Model:** session model.

- [ ] `docs/probes.md`: subnets now live on locations. New `docs/organizations-locations.md` (vocabulary table from the spec, boundaries, migration and banner); link it from `docs/README.md`.
- [ ] Tutorials: a «Organizzazioni e sedi» tour (3 steps); update the Sonde tour text about subnets. `tests/test_tutorials.py` checks the targets.
- [ ] Full gate, `graphify update .`, screenshots (`scripts/dev/capture_screenshots.py`), `uv run pyinstaller SentinelNet.spec --noconfirm`.
- [ ] Upgrade check on a **copy** of a real data dir (run by the user): every device keeps organization and probe and has a location; probes' subnets equal before/after; second start logs nothing.

---

## After this plan: sub-projects 2–5 (no spec yet)

Each needs its own brainstorming → spec → plan, and builds on the `Location` column and `/api/locations`.

| # | Sub-project | Depends on | First questions to settle |
|---|---|---|---|
| 2 | Per-location CSV import with preview (dry-run) | 1 | preview granularity (row / location); what «apply» does on conflicts |
| 3 | Network Blueprint wizard (presets, canvas, deterministic checks, «Primi passi») | 1, 2 | which presets; canvas on the existing vis-network or not; what the checks verify |
| 4 | Assistant: «Descrivi la rete», «Ricava dalle configurazioni», draft-only MCP tool | 3 | output is always a Blueprint draft, never a direct write |
| 5 | Maps and routing per location | 1 (3 for links) | map grouping by location; source of inter-location links (Blueprint vs discovered) |
