# Inventory on SQLite and per-location CSV import — Implementation Plan (sub-project 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the inventory, organizations and locations from CSV/JSON files to SQLite, then give CSV import a default destination, a stateless preview and a single-write apply.

**Architecture:** A stdlib-only module `services/inventory_store.py` owns the schema and the row ↔ table conversion of `inventory.db`. Its path is derived from `get_hosts_csv()`'s directory, so the agent and every test that pins that path get their own database for free. `inventory_manager` and `location_manager` keep their public functions and return shapes and swap their file I/O for store calls. A one-shot startup migration (`core/inventory_migration.py`) builds the database in a temp file and renames it into place. On top of that, `services/csv_import.py` holds one pure `classify()` shared by `/api/import-csv/preview` and `/api/import-csv`.

**Tech Stack:** Python 3 / FastAPI / sqlite3 (stdlib) / classic-script JS / unittest via pytest (`uv run pytest tests -n 4`).

**Spec:** `docs/superpowers/specs/2026-10-10-inventory-sqlite-import-design.md`

## Global Constraints

- Database file: `inventory.db` in `os.path.dirname(inventory_manager.get_hosts_csv())`.
- Host columns keep the CSV names, quoted: `IP, Vendor, Profile, Username, Password, Enable Secret, Group, Hostname, Probe, Location, SSH Port, Transports, SNMP Community, SNMP Disabled`; decommissioned adds `Decommissioned, Decommissioned By`.
- Identity of a device: `("IP", "Group")`. `"Location"` is `NULL` in the table and `''` in the dicts callers see.
- Foreign keys: `locations.org → organizations.key`, `hosts."Location"` / `decommissioned_hosts."Location"` → `locations.id`. No FK on `"Group"`.
- `probes.json` stays JSON. CSV stays only as an exchange format (import, export, template, agent RPC payload).
- Agent RPC wire format unchanged (CSV text both ways).
- Import never creates organizations or locations.
- One inventory write per import.
- New comments in English; Italian user/audit strings like the existing ones; UI strings via `tr()` in both languages; `openModal`/`closeModal`; accessible names.
- Example data only (`192.0.2.x`, `10.20.0.0/16`, `acme`, `roma`, `bologna`).
- Gate before each commit: `uv run pyrefly check`, `uv run python scripts/check_frontend.py` (JS/templates), `uv run pytest tests -n 4`, `uv run python scripts/check_no_private_data.py`; UI tasks also `check_i18n_coverage.py --strict` and `check_a11y.py --strict`.

## Review Focus

1. **An install whose CSV has two rows with the same `(IP, Group)`** (possible with hand edits) → the migration keeps the last one and reports the count, never fails on the primary key. Test in Task 4.
2. **A device written with `Location=''`** (agent push, legacy rows, `require_location=False`) → stored as `NULL`, read back as `''`, no FK error. Test in Task 1.
3. **Import of an IP that is decommissioned in the same organization** → that row is an `error`, the rest of the file still imports (today `_refuse_decommissioned` would fail the whole batch). Test in Task 6.
4. **Deleting a location that a decommissioned device still references** → refused with the count (code), and the FK refuses it even if the count were bypassed. Tests in Tasks 1 and 3.
5. **Server restarted after a crash between the DB rename and the sources' rename** → no second migration, no duplicate rows, the sources get renamed then. Test in Task 4.

---

## File map

| File | Change |
|---|---|
| `services/inventory_store.py` (new) | schema, `connect`, `read_hosts`/`write_hosts`, `read_orgs`/`write_orgs`, `read_locations`/`write_locations` |
| `services/inventory_manager.py` | `inventory_db_path`, `_db`, `inventory_version`; groups, hosts, decommissioned through the store; `safe_write_hosts_csv` → `write_devices`; `upsert_devices`; CSV aliases for Organization; `_csv_columns` |
| `services/location_manager.py` | `_load`/`_save` through the store |
| `core/core_engine.py:1943` | netmap signature uses `inventory_version()` |
| `core/inventory_migration.py` (new) | one-shot migration |
| `core/location_migration.py` | skip when `inventory.db` exists |
| `app_server.py` | run the migration after `location_migration` |
| `services/probe_agent.py` | migration at config load; RPC get/save through the store |
| `core/data_config.py` | `_STATE_FILES`, `_SENSITIVE_FILES` |
| `routers/inventory.py`, `routers/catalog.py`, `services/device_history.py` docstring | `write_devices` rename |
| `services/csv_import.py` (new) | `classify`, `public`, `apply` |
| `routers/inventory.py` | `/api/import-csv/preview`, `/api/import-csv` on `csv_import` |
| `templates/dashboard.html`, `static/js/devices.js`, `static/js/core.js`, `static/js/i18n.js`, `types/globals.d.ts`, `static/css/dashboard.css` | Importa tab, Organizations link |
| `tests/conftest.py` | `seed_inventory` helper |
| Tests | `test_inventory_store.py`, `test_inventory_sqlite_orgs.py`, `test_inventory_sqlite_hosts.py`, `test_inventory_migration.py`, `test_inventory_batch.py`, `test_csv_import.py`, `test_csv_import_api.py`, `test_import_ui.py`, plus fixture conversions |
| Docs | `docs/organizations-locations.md`, `docs/probes.md`, `docs/README.md` |

Task order matters: organizations and locations move (Task 2) before hosts (Task 3), because the hosts table's foreign key checks `locations` in the database.

---

### Task 1: `inventory_store` — schema and row conversion

**Model:** sonnet

**Files:**
- Create: `services/inventory_store.py`
- Test: `tests/test_inventory_store.py`

**Interfaces:**
- Produces:
  - `HOST_FIELDS: list[str]`, `DECOM_FIELDS: list[str]`, `_ready: set` (paths whose schema is ensured)
  - `connect(path: str) -> sqlite3.Connection` (schema ensured, `foreign_keys=ON`, WAL, `row_factory=Row`)
  - `read_hosts(conn, table: str) -> list[dict]` — `table` ∈ `"hosts"`, `"decommissioned_hosts"`; values `str`, `Location` `''` when NULL, `Probe` `'central'` and `SSH Port` `'22'` when empty (today's read defaults)
  - `write_hosts(conn, table: str, old: list[dict], new: list[dict]) -> None` — one transaction, deletes keys missing from `new`, upserts changed/new rows, untouched rows keep their position
  - `read_orgs(conn) -> dict` (`{key: {"description": str, "name"?: str}}`), `write_orgs(conn, groups: dict) -> None`
  - `read_locations(conn) -> dict` (`{id: {"org","name","role","subnets": list,"probe"}}`), `write_locations(conn, data: dict) -> None`

- [ ] **Step 1: Write the failing tests** — `tests/test_inventory_store.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import os
import sqlite3
import tempfile
import unittest

from services import inventory_store as st


def _host(ip, group="acme", **kw):
    row = {f: "" for f in st.HOST_FIELDS}
    row.update({"IP": ip, "Group": group, "Vendor": "cisco", "Probe": "central", "SSH Port": "22"})
    row.update(kw)
    return row


class TestInventoryStore(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.conn = st.connect(os.path.join(self.dir, "inventory.db"))
        st.write_orgs(self.conn, {"acme": {"description": ""}})
        st.write_locations(self.conn, {"roma": {"org": "acme", "name": "Roma", "role": "branch",
                                                 "subnets": ["10.20.0.0/16"], "probe": "central"}})

    def tearDown(self):
        self.conn.close()

    def test_round_trip_keeps_dict_shape(self):
        st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.1", Location="roma")])
        [row] = st.read_hosts(self.conn, "hosts")
        self.assertEqual(set(row), set(st.HOST_FIELDS))
        self.assertEqual(row["Location"], "roma")

    def test_empty_location_is_null_and_reads_back_empty(self):
        st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.2", Location="")])
        self.assertEqual(st.read_hosts(self.conn, "hosts")[0]["Location"], "")
        (raw,) = self.conn.execute('SELECT "Location" FROM hosts').fetchone()
        self.assertIsNone(raw)

    def test_read_defaults(self):
        st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.3", Probe="", **{"SSH Port": ""})])
        row = st.read_hosts(self.conn, "hosts")[0]
        self.assertEqual((row["Probe"], row["SSH Port"]), ("central", "22"))

    def test_unknown_location_is_refused(self):
        with self.assertRaises(sqlite3.IntegrityError):
            st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.4", Location="nowhere")])
        self.assertEqual(st.read_hosts(self.conn, "hosts"), [])

    def test_diff_write_deletes_updates_and_keeps_order(self):
        st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.1"), _host("192.0.2.2"), _host("192.0.2.3")])
        old = st.read_hosts(self.conn, "hosts")
        st.write_hosts(self.conn, "hosts", old, [old[0], dict(old[1], Hostname="sw-02")])
        rows = st.read_hosts(self.conn, "hosts")
        self.assertEqual([r["IP"] for r in rows], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(rows[1]["Hostname"], "sw-02")

    def test_same_ip_two_orgs_are_two_rows(self):
        st.write_orgs(self.conn, {"acme": {"description": ""}, "beta": {"description": ""}})
        st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.1"), _host("192.0.2.1", group="beta")])
        self.assertEqual(len(st.read_hosts(self.conn, "hosts")), 2)

    def test_duplicate_key_in_new_list_last_wins(self):
        st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.1", Hostname="a"),
                                                _host("192.0.2.1", Hostname="b")])
        self.assertEqual([r["Hostname"] for r in st.read_hosts(self.conn, "hosts")], ["b"])

    def test_decommissioned_table_has_extra_columns(self):
        row = dict(_host("192.0.2.9"), Decommissioned="2026-10-10T00:00:00Z",
                   **{"Decommissioned By": "admin"})
        st.write_hosts(self.conn, "decommissioned_hosts", [], [row])
        self.assertEqual(st.read_hosts(self.conn, "decommissioned_hosts")[0]["Decommissioned By"], "admin")

    def test_location_with_decommissioned_device_cannot_be_deleted(self):
        st.write_hosts(self.conn, "decommissioned_hosts", [],
                       [dict(_host("192.0.2.9", Location="roma"), Decommissioned="x",
                             **{"Decommissioned By": "a"})])
        with self.assertRaises(sqlite3.IntegrityError):
            st.write_locations(self.conn, {})

    def test_orgs_and_locations_round_trip(self):
        st.write_orgs(self.conn, {"acme": {"description": "d", "name": "Acme S.p.A."}})
        self.assertEqual(st.read_orgs(self.conn), {"acme": {"description": "d", "name": "Acme S.p.A."}})
        self.assertEqual(st.read_locations(self.conn)["roma"]["subnets"], ["10.20.0.0/16"])

    def test_org_with_locations_cannot_be_deleted(self):
        with self.assertRaises(sqlite3.IntegrityError):
            st.write_orgs(self.conn, {})


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify failure** — `uv run pytest tests/test_inventory_store.py -q` → `ImportError`.

- [ ] **Step 3: Implement `services/inventory_store.py`**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""SQLite storage of the inventory: organizations, locations, active and
decommissioned hosts (spec 2026-10-10 inventory-sqlite-import).

Host rows keep the CSV-era shape — dicts keyed by the column names below — so
callers of inventory_manager read what they always read. stdlib only and no
data paths at import: the startup migration imports it before any service."""
import json
import sqlite3
import threading

HOST_FIELDS = ['IP', 'Vendor', 'Profile', 'Username', 'Password', 'Enable Secret', 'Group',
               'Hostname', 'Probe', 'Location', 'SSH Port', 'Transports', 'SNMP Community',
               'SNMP Disabled']
DECOM_FIELDS = ['Decommissioned', 'Decommissioned By']
_FIELDS = {"hosts": HOST_FIELDS, "decommissioned_hosts": HOST_FIELDS + DECOM_FIELDS}


def _host_table(name: str, fields: list) -> str:
    cols = []
    for f in fields:
        if f in ("IP", "Group"):
            cols.append(f'"{f}" TEXT NOT NULL')
        elif f == "Location":
            cols.append('"Location" TEXT REFERENCES locations(id)')
        else:
            cols.append(f'"{f}" TEXT NOT NULL DEFAULT \'\'')
    return (f'CREATE TABLE IF NOT EXISTS {name} ({", ".join(cols)}, '
            f'PRIMARY KEY ("IP", "Group"));')


_SCHEMA = "\n".join([
    "CREATE TABLE IF NOT EXISTS organizations (key TEXT PRIMARY KEY, name TEXT, "
    "description TEXT NOT NULL DEFAULT '');",
    "CREATE TABLE IF NOT EXISTS locations (id TEXT PRIMARY KEY, "
    "org TEXT NOT NULL REFERENCES organizations(key), name TEXT NOT NULL, "
    "role TEXT NOT NULL, subnets TEXT NOT NULL DEFAULT '[]', "
    "probe TEXT NOT NULL DEFAULT 'central');",
    _host_table("hosts", _FIELDS["hosts"]),
    _host_table("decommissioned_hosts", _FIELDS["decommissioned_hosts"]),
])
_ready: set = set()
_ready_lock = threading.Lock()


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    with _ready_lock:
        if path not in _ready:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(_SCHEMA)
            _ready.add(path)
    return conn


def _quoted(fields) -> str:
    return ", ".join(f'"{f}"' for f in fields)


def read_hosts(conn, table: str) -> list:
    fields = _FIELDS[table]
    rows = []
    for r in conn.execute(f"SELECT {_quoted(fields)} FROM {table} ORDER BY rowid"):
        row = {f: (r[f] or "") for f in fields}
        # Read defaults the CSV reader applied to legacy rows.
        row["Probe"] = row["Probe"] or "central"
        row["SSH Port"] = row["SSH Port"] or "22"
        rows.append(row)
    return rows


def _values(row: dict, fields) -> tuple:
    out = []
    for f in fields:
        v = row.get(f)
        v = "" if v is None else str(v)
        out.append((v or None) if f == "Location" else v)
    return tuple(out)


def write_hosts(conn, table: str, old: list, new: list) -> None:
    """Turn the table from ``old`` into ``new`` touching only the rows that
    differ. One transaction: a refused row (unknown location) leaves the table
    as it was."""
    fields = _FIELDS[table]
    before = {(r.get("IP"), r.get("Group")): _values(r, fields) for r in old}
    after = {}
    for r in new:
        after[(r.get("IP"), r.get("Group"))] = _values(r, fields)   # duplicate key: last wins
    gone = [k for k in before if k not in after]
    changed = [v for k, v in after.items() if before.get(k) != v]
    sets = ", ".join(f'"{f}" = excluded."{f}"' for f in fields if f not in ("IP", "Group"))
    with conn:
        conn.executemany(f'DELETE FROM {table} WHERE "IP" = ? AND "Group" = ?', gone)
        conn.executemany(
            f"INSERT INTO {table} ({_quoted(fields)}) VALUES ({', '.join('?' * len(fields))}) "
            f'ON CONFLICT ("IP", "Group") DO UPDATE SET {sets}', changed)


def read_orgs(conn) -> dict:
    out = {}
    for r in conn.execute("SELECT key, name, description FROM organizations ORDER BY rowid"):
        entry = {"description": r["description"]}
        if r["name"]:
            entry["name"] = r["name"]
        out[r["key"]] = entry
    return out


def write_orgs(conn, groups: dict) -> None:
    keep = list(groups)
    with conn:
        conn.execute(f"DELETE FROM organizations WHERE key NOT IN ({', '.join('?' * len(keep))})", keep)
        conn.executemany(
            "INSERT INTO organizations (key, name, description) VALUES (?, ?, ?) "
            "ON CONFLICT (key) DO UPDATE SET name = excluded.name, description = excluded.description",
            [(k, v.get("name"), v.get("description") or "") for k, v in groups.items()])


def read_locations(conn) -> dict:
    return {r["id"]: {"org": r["org"], "name": r["name"], "role": r["role"],
                      "subnets": json.loads(r["subnets"]), "probe": r["probe"]}
            for r in conn.execute("SELECT * FROM locations ORDER BY id")}


def write_locations(conn, data: dict) -> None:
    keep = list(data)
    with conn:
        conn.execute(f"DELETE FROM locations WHERE id NOT IN ({', '.join('?' * len(keep))})", keep)
        conn.executemany(
            "INSERT INTO locations (id, org, name, role, subnets, probe) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (id) DO UPDATE SET org = excluded.org, name = excluded.name, "
            "role = excluded.role, subnets = excluded.subnets, probe = excluded.probe",
            [(k, v["org"], v["name"], v["role"], json.dumps(v.get("subnets") or []),
              v.get("probe") or "central") for k, v in data.items()])
```

- [ ] **Step 4: Run** — `uv run pytest tests/test_inventory_store.py -q` → all pass.
- [ ] **Step 5: Gate, commit** — `git commit -m "feat(inventory): SQLite store for organizations, locations and hosts"`.

---

### Task 2: Organizations and locations on the store

**Model:** sonnet

**Files:**
- Modify: `services/inventory_manager.py:19-36` (drop `_DEFAULT_GROUPS_JSON`, `GROUPS_JSON`, `get_groups_json`), `:127-146` (`get_all_groups`, `save_groups`); add `inventory_db_path`, `_db`
- Modify: `services/location_manager.py:14-29` (`_load`, `_save`; drop `LOCATIONS_JSON`)
- Modify: `tests/conftest.py:60` (comment on the `location_manager` import), tests patching `GROUPS_JSON` / `LOCATIONS_JSON` or writing those files
- Test: `tests/test_inventory_sqlite_orgs.py`

**Interfaces:**
- Consumes: `inventory_store.connect/read_orgs/write_orgs/read_locations/write_locations` (Task 1).
- Produces:
  - `inventory_manager.inventory_db_path() -> str`
  - `inventory_manager._db()` → context manager yielding a connection (closed on exit)
  - unchanged public functions: `get_all_groups`, `save_groups`, `add_group`, `update_group`, `delete_group`, `resolve_group`, `location_manager.*`

- [ ] **Step 1: Failing tests** — `tests/test_inventory_sqlite_orgs.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import os
import tempfile
import unittest
from unittest.mock import patch

from services import inventory_manager as im, location_manager as lm


class TestOrgsLocationsOnSqlite(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        p = patch.object(im, "HOSTS_CSV", os.path.join(self.dir, "network_hosts.csv"))
        p.start()
        self.addCleanup(p.stop)

    def test_db_lives_next_to_the_hosts_path(self):
        self.assertEqual(im.inventory_db_path(), os.path.join(self.dir, "inventory.db"))

    def test_groups_live_in_the_database(self):
        im.add_group("acme")
        self.assertIn("acme", im.get_all_groups())
        self.assertFalse(os.path.exists(os.path.join(self.dir, "groups.json")))

    def test_rename_keeps_key(self):
        im.add_group("acme")
        im.update_group("acme", "Acme S.p.A.")
        self.assertEqual(im.resolve_group("Acme S.p.A."), "acme")

    def test_location_round_trip(self):
        im.add_group("acme")
        loc = lm.create_location("acme", "Roma", subnets=["10.20.0.0/16"])
        self.assertEqual(lm.get_location(loc["id"])["subnets"], ["10.20.0.0/16"])
        self.assertFalse(os.path.exists(os.path.join(self.dir, "locations.json")))

    def test_org_with_locations_is_refused(self):
        im.add_group("acme")
        lm.create_location("acme", "Roma")
        with self.assertRaises(ValueError):
            im.delete_group("acme")
        self.assertIn("acme", im.get_all_groups())
```

- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement:**
  - In `inventory_manager`, after `get_hosts_csv`:

```python
def inventory_db_path() -> str:
    # ponytail: derived from the hosts path instead of its own constant. The
    # agent and ~170 test files already pin get_hosts_csv() to a directory;
    # they get their own database there without a second thing to patch.
    return os.path.join(os.path.dirname(get_hosts_csv()), "inventory.db")


def _db():
    return contextlib.closing(inventory_store.connect(inventory_db_path()))
```

    with `import contextlib` and `from services import inventory_store`.
  - `get_all_groups()` → `with _db() as conn: return inventory_store.read_orgs(conn)`; `save_groups(d)` → `with _db() as conn: inventory_store.write_orgs(conn, d)`. Drop the legacy-list conversion: the list format predates every supported version, and the migration reads `groups.json` itself.
  - `location_manager._load()` → `with inventory_manager._db() as conn: return inventory_store.read_locations(conn)`; `_save(data)` → `with inventory_manager._db() as conn: inventory_store.write_locations(conn, data)` (local imports, as `_check` already does). Keep `_lock`.
- [ ] **Step 4: Fix tests** patching `GROUPS_JSON` / `LOCATIONS_JSON` (`grep -rlE "GROUPS_JSON|LOCATIONS_JSON|groups.json|locations.json" tests`): replace with the `HOSTS_CSV` patch, which isolates the whole database. Full suite green.
- [ ] **Step 5: Gate, commit** — `git commit -m "refactor(inventory): organizations and locations on SQLite, with foreign keys"`.

---

### Task 3: Hosts and decommissioned devices on the store

**Model:** session model (Step 6's fixture conversion may be delegated to sonnet subagents, one per batch of test files).

**Files:**
- Modify: `services/inventory_manager.py` (lines 245–373 hosts I/O, 564–662 decommissioned, every `safe_write_hosts_csv` call)
- Modify: `routers/inventory.py:614,648`, `routers/catalog.py` (if it calls the writer), `services/location_manager.py:150`, `services/probe_agent.py:575-610`, `services/device_history.py:7` (docstring), `core/core_engine.py:1943-1948`
- Modify: `tests/conftest.py` (helper); tests that write or read the hosts CSV directly
- Test: `tests/test_inventory_sqlite_hosts.py`

**Interfaces:**
- Consumes: Task 1 store, Task 2 `_db()`.
- Produces:
  - `inventory_manager.inventory_version() -> int` (bumped by every write)
  - `inventory_manager.write_devices(devices, exempt=frozenset(), relabel=None) -> None` (replaces `safe_write_hosts_csv`, same semantics: refuse decommissioned clashes, history, cache invalidation)
  - unchanged: `get_all_devices`, `get_decommissioned_devices`, `decommission`, `reactivate`, `delete_devices`, `add_or_update_device`, `delete_device`, `update_device_hostname`, `bulk_assign_profile`
  - `tests/conftest.py: seed_inventory(hosts=(), decommissioned=(), orgs=(), locations=None) -> None`

- [ ] **Step 1: Write the failing tests** — `tests/test_inventory_sqlite_hosts.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import os
import tempfile
import unittest
from unittest.mock import patch

from services import inventory_manager as im, location_manager as lm
from tests.conftest import make_location, seed_inventory


class TestHostsOnSqlite(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        p = patch.object(im, "HOSTS_CSV", os.path.join(self.dir, "network_hosts.csv"))
        p.start()
        self.addCleanup(p.stop)
        im.add_group("acme")
        self.loc = make_location("acme", "Roma")

    def _add(self, ip):
        im.add_or_update_device(ip, "cisco", "custom", "u", "p", "", "acme", location=self.loc)

    def test_add_then_read_without_any_csv(self):
        self._add("192.0.2.1")
        self.assertEqual([d["IP"] for d in im.get_all_devices()], ["192.0.2.1"])
        self.assertFalse(os.path.exists(os.path.join(self.dir, "network_hosts.csv")))

    def test_version_bumps_on_write(self):
        v = im.inventory_version()
        self._add("192.0.2.1")
        self.assertGreater(im.inventory_version(), v)

    def test_decommission_round_trip(self):
        self._add("192.0.2.1")
        self.assertEqual(im.decommission([("acme", "192.0.2.1")], "admin"), 1)
        self.assertEqual(im.get_all_devices(), [])
        self.assertEqual(im.get_decommissioned_devices()[0]["Decommissioned By"], "admin")
        self.assertEqual(im.reactivate([("acme", "192.0.2.1")]), 1)
        self.assertEqual(len(im.get_all_devices()), 1)

    def test_returned_rows_are_copies(self):
        self._add("192.0.2.1")
        im.get_all_devices()[0]["Hostname"] = "poisoned"
        self.assertEqual(im.get_all_devices()[0]["Hostname"], "")

    def test_location_referenced_by_decommissioned_device_cannot_go(self):
        seed_inventory(decommissioned=[{"IP": "192.0.2.9", "Group": "acme", "Location": self.loc,
                                        "Decommissioned": "x", "Decommissioned By": "a"}])
        with self.assertRaisesRegex(ValueError, "1 apparati"):
            lm.delete_location(self.loc)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify failure** — `AttributeError: inventory_version`.

- [ ] **Step 3: Implement in `services/inventory_manager.py`**
  - `_HOSTS_FIELDS = inventory_store.HOST_FIELDS`, `_DECOM_COLS = inventory_store.DECOM_FIELDS`.
  - Add:

```python
_version = 0


def inventory_version() -> int:
    """Changes on every inventory write; a cache signature for readers that
    join against the inventory (core_engine's netmap)."""
    return _version
```

  - Replace `_read_hosts_csv`, the stat-keyed cache (`_rows_cache_key`, `_invalidate_rows_cache`) and `get_all_devices` with:

```python
# ponytail: in-process cache invalidated by write_devices. A second process
# writing the same inventory.db (none today: central and each agent own
# theirs) would need PRAGMA data_version here.
_rows_cache: dict = {}


def get_all_devices():
    """L'inventario come lista di dict, uno per apparato. Always new dicts:
    callers modify them before writing back."""
    path = inventory_db_path()
    with _hosts_csv_lock:
        rows = _rows_cache.get(path)
        if rows is None:
            with _db() as conn:
                rows = _rows_cache[path] = inventory_store.read_hosts(conn, "hosts")
        return [dict(r) for r in rows]
```

  - Rename `safe_write_hosts_csv` → `write_devices`; body:

```python
def write_devices(devices, exempt=frozenset(), relabel=None):
    global _version
    invalidate_device_ip_cache()
    from ai import config_analyzer
    config_analyzer._analyze_device_at.cache_clear()
    with _hosts_csv_lock:
        old_rows = get_all_devices()
        _refuse_decommissioned(devices, old_rows, exempt)
        with _db() as conn:
            inventory_store.write_hosts(conn, "hosts", old_rows, devices)
        _rows_cache.pop(inventory_db_path(), None)
        _version += 1
        # Diffed against the rows as re-read, so both sides carry the same
        # read defaults. The inventory is already saved: a failing history
        # append must not turn it into an error for the caller.
        try:
            from services import device_history
            device_history.record(old_rows, get_all_devices(), relabel)
        except Exception:
            logger.exception("Storico dispositivi non aggiornato")
```

  - `get_decommissioned_devices()`:

```python
def get_decommissioned_devices() -> list:
    with _hosts_csv_lock, _db() as conn:
        return inventory_store.read_hosts(conn, "decommissioned_hosts")


def _write_decommissioned(rows: list) -> None:
    global _version
    with _hosts_csv_lock, _db() as conn:
        current = inventory_store.read_hosts(conn, "decommissioned_hosts")
        inventory_store.write_hosts(conn, "decommissioned_hosts", current, rows)
        _version += 1
```

    Delete `get_decommissioned_csv`. Update the comment block above `_DECOM_COLS` ("leaves network_hosts.csv for its own file" → "its own table").
  - `_hosts_csv_lock` keeps its name; rewrite its comment: it serializes inventory reads and writes in this process.
  - `grep -rl safe_write_hosts_csv services routers core tests | xargs sed -i 's/safe_write_hosts_csv/write_devices/g'`; fix the docstring in `services/device_history.py:7`.
  - `core/core_engine.py:1943-1948`: replace the `os.stat(get_hosts_csv())` block with

```python
    from services.inventory_manager import inventory_version
    inv = inventory_version()
```

  - `services/probe_agent.py` `_agent_get_inventory`:

```python
                from services import inventory_manager
                buf = io.StringIO()
                w = csv.DictWriter(buf, fieldnames=inventory_manager._HOSTS_FIELDS,
                                   extrasaction="ignore", lineterminator="\n")
                w.writeheader()
                w.writerows(inventory_manager.get_all_devices())
                return {"status": "done", "result": buf.getvalue()}
```

    and in `_agent_save_inventory` replace the `os.makedirs(... get_hosts_csv() ...)` line with `os.makedirs(os.path.dirname(inventory_manager.inventory_db_path()), exist_ok=True)`. Add `import csv, io` at the top if missing.

- [ ] **Step 4: `seed_inventory` helper** in `tests/conftest.py`:

```python
def seed_inventory(hosts=(), decommissioned=(), orgs=(), locations=None):
    """Write rows straight into the inventory database under the current
    get_hosts_csv() directory. Organizations named by rows or `orgs`, and
    locations named by rows, are created; `locations` overrides their data."""
    from services import inventory_store
    rows = [dict({f: "" for f in inventory_store.HOST_FIELDS}, **h) for h in hosts]
    dec = [dict({f: "" for f in inventory_store.HOST_FIELDS + inventory_store.DECOM_FIELDS}, **h)
           for h in decommissioned]
    with inventory_manager._db() as conn:
        groups = inventory_store.read_orgs(conn)
        for g in set(orgs) | {r["Group"] for r in rows + dec if r["Group"]} | \
                {v["org"] for v in (locations or {}).values()}:
            groups.setdefault(g, {"description": ""})
        inventory_store.write_orgs(conn, groups)
        locs = inventory_store.read_locations(conn)
        locs.update(locations or {})
        for r in rows + dec:
            if r["Location"] and r["Location"] not in locs:
                locs[r["Location"]] = {"org": r["Group"], "name": r["Location"],
                                       "role": "branch", "subnets": [], "probe": "central"}
        inventory_store.write_locations(conn, locs)
        inventory_store.write_hosts(conn, "hosts", inventory_store.read_hosts(conn, "hosts"), rows)
        inventory_store.write_hosts(conn, "decommissioned_hosts",
                                    inventory_store.read_hosts(conn, "decommissioned_hosts"), dec)
    inventory_manager._rows_cache.clear()
    inventory_manager.invalidate_device_ip_cache()
```

- [ ] **Step 5: Run the new test, then the full suite** — `uv run pytest tests -n 4 -q 2>&1 | tail -40`. Expected failures: tests that write `network_hosts.csv` / `decommissioned_hosts.csv` with `csv`/`open` (≈22 files) or read them back (≈17 files). List: `grep -rlE "HOSTS_CSV|get_hosts_csv|network_hosts.csv|decommissioned_hosts" tests`.
- [ ] **Step 6: Convert those tests** — writes → `seed_inventory(hosts=[...])` (keep the patch of `HOSTS_CSV`/`get_hosts_csv` that isolates them); reads → `inventory_manager.get_all_devices()` / `get_decommissioned_devices()`. A test that asserted on CSV text asserts on the rows. Do not delete assertions; do not weaken the boundaries. Rerun until green.
- [ ] **Step 7: Gate, commit** — `git commit -m "refactor(inventory): hosts and decommissioned devices on SQLite"`.

---

### Task 4: One-shot migration, central and agent

**Model:** session model

**Files:**
- Create: `core/inventory_migration.py`
- Modify: `app_server.py:82-84`, `core/location_migration.py:64-68`, `services/probe_agent.py:180-184`, `core/data_config.py:23-35`
- Test: `tests/test_inventory_migration.py`

**Interfaces:**
- Consumes: `inventory_store.connect/_ready/write_orgs/write_locations/write_hosts/HOST_FIELDS/DECOM_FIELDS`.
- Produces: `inventory_migration.migrate(data_dir: str) -> list[str]` (steps done; `[]` = nothing to do); raises `inventory_migration.MigrationError` naming orphan rows.

Behaviour: each source is **renamed** to `*.pre-sqlite` after the database is in place — that file is the backup and the sign the source was consumed (the spec's separate backup + `.migrated` collapse into this one move).

- [ ] **Step 1: Failing tests** — `tests/test_inventory_migration.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import csv
import json
import os
import tempfile
import unittest

from core import inventory_migration as mig
from services import inventory_store as st

HDR = st.HOST_FIELDS


def _csv(path, rows, extra=()):
    fields = HDR + list(extra)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({**{h: "" for h in fields}, **r})


def _json(path, value):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(value, f)


class TestInventoryMigration(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        _json(os.path.join(self.d, "groups.json"), {"acme": {"description": "", "name": "Acme"}})
        _json(os.path.join(self.d, "locations.json"),
              {"roma": {"org": "acme", "name": "Roma", "role": "branch",
                        "subnets": ["10.20.0.0/16"], "probe": "central"}})
        _csv(os.path.join(self.d, "network_hosts.csv"),
             [{"IP": "192.0.2.1", "Group": "acme", "Location": "roma", "Vendor": "cisco"},
              {"IP": "192.0.2.2", "Group": "acme", "Location": "roma", "Vendor": "hp"}])
        _csv(os.path.join(self.d, "decommissioned_hosts.csv"),
             [{"IP": "192.0.2.9", "Group": "acme", "Location": "roma",
               "Decommissioned": "2026-10-10T00:00:00Z", "Decommissioned By": "admin"}],
             extra=st.DECOM_FIELDS)

    def _db(self):
        return st.connect(os.path.join(self.d, "inventory.db"))

    def test_migrates_everything_and_renames_sources(self):
        self.assertTrue(mig.migrate(self.d))
        with self._db() as c:
            self.assertEqual(len(st.read_hosts(c, "hosts")), 2)
            self.assertEqual(st.read_hosts(c, "decommissioned_hosts")[0]["Decommissioned By"], "admin")
            self.assertEqual(st.read_orgs(c)["acme"]["name"], "Acme")
            self.assertEqual(st.read_locations(c)["roma"]["subnets"], ["10.20.0.0/16"])
        for n in ("groups.json", "locations.json", "network_hosts.csv", "decommissioned_hosts.csv"):
            self.assertFalse(os.path.exists(os.path.join(self.d, n)), n)
            self.assertTrue(os.path.exists(os.path.join(self.d, n + ".pre-sqlite")), n)

    def test_second_run_is_a_noop(self):
        mig.migrate(self.d)
        self.assertEqual(mig.migrate(self.d), [])

    def test_orphan_location_stops_and_leaves_files(self):
        _csv(os.path.join(self.d, "network_hosts.csv"),
             [{"IP": "192.0.2.1", "Group": "acme", "Location": "nowhere"}])
        with self.assertRaisesRegex(mig.MigrationError, "192.0.2.1"):
            mig.migrate(self.d)
        self.assertFalse(os.path.exists(os.path.join(self.d, "inventory.db")))
        self.assertTrue(os.path.exists(os.path.join(self.d, "network_hosts.csv")))

    def test_duplicate_key_keeps_last_and_reports(self):
        _csv(os.path.join(self.d, "network_hosts.csv"),
             [{"IP": "192.0.2.1", "Group": "acme", "Location": "roma", "Hostname": "a"},
              {"IP": "192.0.2.1", "Group": "acme", "Location": "roma", "Hostname": "b"}])
        steps = mig.migrate(self.d)
        self.assertTrue(any("duplicate" in s for s in steps))
        with self._db() as c:
            self.assertEqual([r["Hostname"] for r in st.read_hosts(c, "hosts")], ["b"])

    def test_crash_after_db_rename_finishes_renames(self):
        mig.migrate(self.d)
        for n in ("network_hosts.csv", "groups.json"):   # as if the renames never ran
            os.replace(os.path.join(self.d, n + ".pre-sqlite"), os.path.join(self.d, n))
        self.assertEqual(mig.migrate(self.d), [])
        self.assertFalse(os.path.exists(os.path.join(self.d, "network_hosts.csv")))
        with self._db() as c:
            self.assertEqual(len(st.read_hosts(c, "hosts")), 2)

    def test_agent_dir_hosts_only(self):
        for n in ("groups.json", "locations.json", "decommissioned_hosts.csv"):
            os.remove(os.path.join(self.d, n))
        _csv(os.path.join(self.d, "network_hosts.csv"), [{"IP": "192.0.2.1", "Group": "acme"}])
        mig.migrate(self.d)
        with self._db() as c:
            self.assertEqual(st.read_hosts(c, "hosts")[0]["Location"], "")

    def test_fresh_install_does_nothing(self):
        d = tempfile.mkdtemp()
        self.assertEqual(mig.migrate(d), [])
        self.assertFalse(os.path.exists(os.path.join(d, "inventory.db")))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement `core/inventory_migration.py`:**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""One-shot migration of the inventory files to inventory.db (spec 2026-10-10
inventory-sqlite-import). Runs on central (lifespan) and on each agent (config
load). The database is built in a temp file and renamed into place after the
commit, so a crash half-way reruns the whole thing; each source is then
renamed to *.pre-sqlite, which is both its backup and the sign it was
consumed."""
import csv
import json
import os

from services import inventory_store   # stdlib-only module, no data paths

_SOURCES = ("groups.json", "locations.json", "network_hosts.csv", "decommissioned_hosts.csv")


class MigrationError(RuntimeError):
    pass


def _rows(path, fields):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as f:
        return [{k: (r.get(k) or "") for k in fields} for r in csv.DictReader(f)]


def _json(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _consume(data_dir):
    for name in _SOURCES:
        src = os.path.join(data_dir, name)
        if os.path.exists(src):
            os.replace(src, src + ".pre-sqlite")


def migrate(data_dir: str) -> list:
    db = os.path.join(data_dir, "inventory.db")
    if os.path.exists(db):
        _consume(data_dir)   # a crash between the two renames left sources behind
        return []
    if not any(os.path.exists(os.path.join(data_dir, n)) for n in _SOURCES):
        return []
    groups = _json(os.path.join(data_dir, "groups.json"))
    locations = _json(os.path.join(data_dir, "locations.json"))
    hosts = _rows(os.path.join(data_dir, "network_hosts.csv"), inventory_store.HOST_FIELDS)
    dec = _rows(os.path.join(data_dir, "decommissioned_hosts.csv"),
                inventory_store.HOST_FIELDS + inventory_store.DECOM_FIELDS)
    orphans = [f"{r['IP']} ({r['Group']}) -> {r['Location']}" for r in hosts + dec
               if r["Location"] and r["Location"] not in locations]
    if orphans:
        raise MigrationError("Migrazione inventario interrotta: righe con sede inesistente: "
                             + "; ".join(orphans))
    steps = []
    dupes = len(hosts) - len({(r["IP"], r["Group"]) for r in hosts})
    if dupes:
        steps.append(f"network_hosts.csv: {dupes} righe duplicate (IP, organizzazione), tenuta l'ultima")
    for v in locations.values():
        groups.setdefault(v["org"], {"description": ""})
    tmp = db + ".tmp"
    for leftover in (tmp, tmp + "-wal", tmp + "-shm"):
        if os.path.exists(leftover):
            os.remove(leftover)
    inventory_store._ready.discard(tmp)   # a previous attempt's schema flag
    conn = inventory_store.connect(tmp)
    try:
        inventory_store.write_orgs(conn, groups)
        inventory_store.write_locations(conn, locations)
        inventory_store.write_hosts(conn, "hosts", [], hosts)
        inventory_store.write_hosts(conn, "decommissioned_hosts", [], dec)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    inventory_store._ready.discard(tmp)
    os.replace(tmp, db)
    _consume(data_dir)
    steps.insert(0, f"inventario su SQLite: {len(groups)} organizzazioni, {len(locations)} sedi, "
                    f"{len(hosts)} apparati, {len(dec)} dismessi")
    return steps
```

- [ ] **Step 4: Wire it:**
  - `core/location_migration.py`, first lines of `migrate`:

```python
    # After the SQLite migration (spec 2026-10-10) locations.json is gone by
    # design; without this guard its absence would rerun this migration.
    if os.path.exists(os.path.join(data_dir, "inventory.db")):
        return []
```

  - `app_server.lifespan`, after the `location_migration` loop:

```python
    # Inventory, organizations and locations to SQLite (spec 2026-10-10);
    # reads the files the two migrations above just wrote. An orphan row stops
    # the server: running on an empty inventory would be worse.
    from core import inventory_migration
    try:
        for step in inventory_migration.migrate(data_dir):
            log_audit(f"Migrazione inventario: {step}.")
    except inventory_migration.MigrationError as e:
        print(f"ERRORE: {e}", file=sys.stderr)
        raise
```

  - `services/probe_agent.py`: `from core import core_engine, inventory_migration, probe_migration`; after `probe_migration._hosts_header(cfg["data_dir"])` add `inventory_migration.migrate(cfg["data_dir"])`.
  - `core/data_config.py`: `_STATE_FILES` += `"inventory.db", "inventory.db-wal", "inventory.db-shm"`; `_SENSITIVE_FILES` += `"inventory.db"` (it holds the encrypted device credentials).
- [ ] **Step 5: Run, full suite, gate, commit** — `git commit -m "feat(migration): inventory, organizations and locations to SQLite at startup"`.

---

### Task 5: Batch upsert and CSV helpers

**Model:** sonnet

**Files:**
- Modify: `services/inventory_manager.py` (`add_or_update_device` 441–545, `_CSV_ALIASES` 158, `_read_inventory_csv` 195)
- Test: `tests/test_inventory_batch.py`

**Interfaces:**
- Consumes: `write_devices` (Task 3).
- Produces:
  - `inventory_manager.upsert_devices(entries: list[dict]) -> None` — each entry carries `add_or_update_device`'s keyword arguments (`ip, vendor, profile, username, password, enable_secret, group, probe, ssh_port, transports, snmp_community, snmp_disabled, location, require_location`) plus optional `hostname`; all are validated, then one `write_devices` call. A `ValueError` on any entry writes nothing.
  - `add_or_update_device(...)` → `upsert_devices([entry])`, same signature as today.
  - `inventory_manager._csv_columns(raw: str) -> list[tuple[str, str | None]]` — `(header as written, canonical field or None)`.
  - Aliases `"organization"`, `"organizzazione"`, `"org"` → `"Group"`.

- [ ] **Step 1: Failing tests** — `tests/test_inventory_batch.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import os
import tempfile
import unittest
from unittest.mock import patch

from services import inventory_manager as im
from tests.conftest import make_location


class TestBatch(unittest.TestCase):
    def setUp(self):
        p = patch.object(im, "HOSTS_CSV", os.path.join(tempfile.mkdtemp(), "network_hosts.csv"))
        p.start()
        self.addCleanup(p.stop)
        im.add_group("acme")
        self.loc = make_location("acme", "Roma")

    def _e(self, ip, **kw):
        return dict(ip=ip, vendor="cisco", profile="custom", username="u", password="p",
                    enable_secret="", group="acme", location=self.loc, **kw)

    def test_one_write_for_many_devices(self):
        with patch.object(im, "write_devices", wraps=im.write_devices) as w:
            im.upsert_devices([self._e(f"192.0.2.{i}") for i in range(1, 201)])
        self.assertEqual(w.call_count, 1)
        self.assertEqual(len(im.get_all_devices()), 200)

    def test_one_bad_entry_writes_nothing(self):
        with self.assertRaises(ValueError):
            im.upsert_devices([self._e("192.0.2.1"), self._e("999.0.2.1")])
        self.assertEqual(im.get_all_devices(), [])

    def test_hostname_in_entry(self):
        im.upsert_devices([self._e("192.0.2.1", hostname="rm-fw-01")])
        self.assertEqual(im.get_all_devices()[0]["Hostname"], "rm-fw-01")

    def test_single_add_still_works(self):
        im.add_or_update_device("192.0.2.1", "cisco", "custom", "u", "p", "", "acme", location=self.loc)
        self.assertEqual(len(im.get_all_devices()), 1)

    def test_csv_columns_and_org_alias(self):
        cols = im._csv_columns("indirizzo;organizzazione;note\n192.0.2.1;acme;x\n")
        self.assertEqual(cols, [("indirizzo", "IP"), ("organizzazione", "Group"), ("note", None)])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement:**
  - Extract `_delimiter(header_line: str) -> str` from `_read_inventory_csv` (the `max((",", ";", "\t", "|"), key=header_line.count)` choice and the `,` fallback); `_read_inventory_csv` calls it. Add:

```python
def _csv_columns(raw: str) -> list:
    """Headers as written, with the canonical field each maps to (None =
    ignored): what the import preview shows as «colonne riconosciute»."""
    text = (raw or "").lstrip("﻿").strip()
    if not text:
        return []
    header_line = text.splitlines()[0]
    headers = next(csv.reader([header_line], delimiter=_delimiter(header_line)))
    return [(h.strip(), _canonical_header(h)) for h in headers]
```

  - Move the body of `add_or_update_device`, from the IP check to the construction of `new_device` (including `existing_hostname`), into

```python
def _merged_row(devices, ip, vendor, profile, username, password, enable_secret, group,
                probe=None, ssh_port=None, transports=None, snmp_community=None,
                snmp_disabled=None, location=None, require_location=True, hostname=None) -> dict:
```

    It looks `existing` up in `devices` and returns `new_device`; a non-empty `hostname` wins over `existing_hostname`. Then:

```python
def upsert_devices(entries: list) -> None:
    """Add or update many devices with one inventory write: an import of N rows
    used to rewrite the whole inventory N times. Every entry is validated
    before anything is written."""
    with _io_lock:
        devices = get_all_devices()
        for e in entries:
            row = _merged_row(devices, **e)
            devices = [d for d in devices if not _same_device(d, row["IP"], row["Group"])]
            devices.append(row)
        write_devices(devices)


def add_or_update_device(ip, vendor, profile, username, password, enable_secret, group,
                         probe=None, ssh_port=None, transports=None, snmp_community=None,
                         snmp_disabled=None, location=None, require_location=True):
    upsert_devices([dict(ip=ip, vendor=vendor, profile=profile, username=username,
                         password=password, enable_secret=enable_secret, group=group,
                         probe=probe, ssh_port=ssh_port, transports=transports,
                         snmp_community=snmp_community, snmp_disabled=snmp_disabled,
                         location=location, require_location=require_location)])
```

  - Add `"organization": "Group", "organizzazione": "Group", "org": "Group",` to `_CSV_ALIASES` next to `"group"`.
- [ ] **Step 4: Run, full suite, gate, commit** — `git commit -m "feat(inventory): batch upsert in one write; CSV column map and organization aliases"`.

---

### Task 6: `csv_import.classify` and `apply`

**Model:** session model

**Files:**
- Create: `services/csv_import.py`
- Test: `tests/test_csv_import.py`

**Interfaces:**
- Consumes: `inventory_manager._read_inventory_csv`, `_csv_columns`, `get_all_devices`, `get_decommissioned_devices`, `resolve_group`, `normalize_vendor`, `upsert_devices`, `IP_PATTERN`; `location_manager.list_locations`; `probe_manager.get_probe`; `identity_manager.get_identity_credentials`; `core.device_credentials.DEFAULT_USERNAME/DEFAULT_PASSWORD`.
- Produces:
  - `classify(csv_text, default_org, default_location, decisions: dict, scope: set | None) -> dict` → `{"columns": [{"header","field"}], "rows": [RowResult], "counts": {"new","update","error","skipped"}}`; `ValueError` for an unreadable file.
  - `public(result) -> dict` — same without keys starting with `_` (raw records carry passwords).
  - `apply(...)` same arguments → `{"imported": [ip], "updated": [ip], "skipped": [row], "failed": [{"row","ip","error"}], "preview": public(result)}`.
  - `RowResult` public keys: `row, ip, hostname, vendor, org, location, probe, status, changes, reason, warnings, action, credentials_note`.

- [ ] **Step 1: Failing tests** — `tests/test_csv_import.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import os
import tempfile
import unittest
from unittest.mock import patch

from services import csv_import, inventory_manager as im
from tests.conftest import seed_inventory

LOCS = {"roma": {"org": "acme", "name": "Roma", "role": "branch", "subnets": ["10.20.0.0/16"], "probe": "central"},
        "bologna": {"org": "acme", "name": "Bologna", "role": "warehouse", "subnets": ["10.30.0.0/16"], "probe": "central"},
        "nosub": {"org": "acme", "name": "Senza subnet", "role": "other", "subnets": [], "probe": "central"}}


class TestClassify(unittest.TestCase):
    def setUp(self):
        p = patch.object(im, "HOSTS_CSV", os.path.join(tempfile.mkdtemp(), "network_hosts.csv"))
        p.start()
        self.addCleanup(p.stop)
        seed_inventory(orgs=["acme", "beta"], locations=LOCS,
                       hosts=[{"IP": "10.20.1.11", "Group": "acme", "Location": "roma",
                               "Hostname": "rm-sw-02", "Vendor": "hp", "Probe": "central"}],
                       decommissioned=[{"IP": "10.20.1.99", "Group": "acme", "Location": "roma",
                                        "Decommissioned": "x", "Decommissioned By": "a"}])

    def run_(self, text, org="acme", loc="roma", decisions=None, scope=None):
        return csv_import.classify(text, org, loc, decisions or {}, scope)

    def row(self, text, n=0, **kw):
        return self.run_(text, **kw)["rows"][n]

    def test_new_row_goes_to_default_location(self):
        r = self.row("ip,hostname\n10.20.1.1,rm-fw-01\n")
        self.assertEqual((r["status"], r["org"], r["location"]), ("new", "acme", "roma"))

    def test_row_columns_override_default(self):
        self.assertEqual(self.row("ip,sede\n10.30.1.1,Bologna\n")["location"], "bologna")

    def test_missing_ip(self):
        self.assertEqual(self.row("ip,hostname\n,x\n")["status"], "error")

    def test_invalid_ip(self):
        self.assertEqual(self.row("ip\n999.1.1.1\n")["status"], "error")

    def test_unknown_org_is_error(self):
        r = self.row("ip,organizzazione\n10.20.1.1,ghost\n")
        self.assertEqual(r["status"], "error")
        self.assertIn("crea prima", r["reason"])

    def test_org_out_of_scope(self):
        self.assertEqual(self.row("ip\n10.20.1.1\n", scope={"beta"})["status"], "error")

    def test_no_destination_and_no_column(self):
        self.assertEqual(self.row("ip\n10.20.1.1\n", org=None, loc=None)["status"], "error")

    def test_location_of_another_org(self):
        self.assertEqual(self.row("ip,organizzazione,sede\n10.20.1.1,beta,roma\n")["status"], "error")

    def test_unknown_probe(self):
        self.assertEqual(self.row("ip,sonda\n10.20.1.1,ghost\n")["status"], "error")

    def test_duplicate_ip_in_file(self):
        rows = self.run_("ip\n10.20.1.1\n10.20.1.1\n")["rows"]
        self.assertEqual([r["status"] for r in rows], ["new", "error"])
        self.assertEqual(rows[1]["action"], {"kind": "skip"})

    def test_ip_in_other_location_suggests_move(self):
        r = self.row("ip\n10.30.4.20\n")
        self.assertEqual((r["status"], r["action"]), ("error", {"kind": "move", "location": "bologna"}))

    def test_ip_outside_every_subnet_is_only_a_warning(self):
        r = self.row("ip\n192.0.2.50\n")
        self.assertEqual(r["status"], "new")
        self.assertTrue(r["warnings"])

    def test_location_without_subnets_has_no_check(self):
        r = self.row("ip\n192.0.2.50\n", loc="nosub")
        self.assertEqual((r["status"], r["warnings"]), ("new", []))

    def test_decommissioned_ip_is_error_and_rest_imports(self):
        out = csv_import.apply("ip\n10.20.1.99\n10.20.1.1\n", "acme", "roma", {}, None)
        self.assertEqual(out["imported"], ["10.20.1.1"])
        self.assertIn("dismesso", out["preview"]["rows"][0]["reason"])

    def test_update_shows_diff(self):
        r = self.row("ip,hostname\n10.20.1.11,rm-sw-p2\n")
        self.assertEqual(r["status"], "update")
        self.assertEqual(r["changes"]["Hostname"], ["rm-sw-02", "rm-sw-p2"])

    def test_update_without_changes(self):
        self.assertEqual(self.row("ip\n10.20.1.11\n")["changes"], {})

    def test_update_without_vendor_keeps_vendor(self):
        csv_import.apply("ip,hostname\n10.20.1.11,x\n", "acme", "roma", {}, None)
        self.assertEqual(im.get_all_devices()[0]["Vendor"], "hp")

    def test_password_change_is_flagged_not_shown(self):
        r = self.row("ip,username,password\n10.20.1.11,u,secret\n")
        self.assertEqual(r["changes"]["Password"], ["", "changed"])
        self.assertNotIn("secret", str(csv_import.public(self.run_("ip,password\n10.20.1.11,secret\n"))))

    def test_decision_skip(self):
        self.assertEqual(self.row("ip\n10.20.1.1\n", decisions={"2": {"skip": True}})["status"], "skipped")

    def test_decision_move(self):
        r = self.row("ip\n10.30.4.20\n", decisions={"2": {"location": "bologna"}})
        self.assertEqual((r["status"], r["location"]), ("new", "bologna"))

    def test_credentials_note_levels(self):
        self.assertIn("proprie", self.row("ip,username,password\n10.20.1.1,u,p\n")["credentials_note"])
        self.assertIn("nessuna", self.row("ip\n10.20.1.1\n")["credentials_note"])
        with patch("core.device_credentials.DEFAULT_USERNAME", "a"), \
             patch("core.device_credentials.DEFAULT_PASSWORD", "b"):
            self.assertIn("globale", self.row("ip\n10.20.1.1\n")["credentials_note"])

    def test_preview_and_apply_agree(self):
        text = "ip,hostname\n10.20.1.1,a\n10.20.1.11,b\n10.30.4.20,c\n"
        pre = self.run_(text)
        out = csv_import.apply(text, "acme", "roma", {}, None)
        self.assertEqual(out["imported"], [r["ip"] for r in pre["rows"] if r["status"] == "new"])
        self.assertEqual(out["updated"], [r["ip"] for r in pre["rows"] if r["status"] == "update"])

    def test_apply_is_one_write(self):
        text = "ip\n" + "".join(f"10.20.{i // 250}.{i % 250 + 1}\n" for i in range(2000))
        with patch.object(im, "write_devices", wraps=im.write_devices) as w:
            out = csv_import.apply(text, "acme", "roma", {}, None)
        self.assertEqual((len(out["imported"]), w.call_count), (2000, 1))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement `services/csv_import.py`:**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""CSV import with preview (spec 2026-10-10 inventory-sqlite-import).

classify() is pure: it reads the inventory and writes nothing. The preview
endpoint returns it; the import endpoint recomputes it on the same input and
writes its new + update rows in one go, so the two cannot disagree."""
import ipaddress

from services import inventory_manager, location_manager, probe_manager

_SECRET = ("Password", "Enable Secret")
_COMPARED = ("Hostname", "Vendor", "Username", "Password", "Enable Secret", "Probe", "Location")


def _credentials_note(username, password, probe_id) -> str:
    from core import device_credentials
    from security import identity_manager
    if username and password:
        return "credenziali proprie della riga"
    identity = (probe_manager.get_probe(probe_id) or {}).get("device_identity")
    if identity and identity_manager.get_identity_credentials(identity):
        return f"userà l'identità della sonda {probe_id}"
    if device_credentials.DEFAULT_USERNAME and device_credentials.DEFAULT_PASSWORD:
        return "userà l'account globale"
    return "nessuna: la connessione fallirà finché non assegni un'identità"


def _find_location(org, value, locs):
    if not value:
        return None
    if value in locs and locs[value]["org"] == org:
        return value
    return next((i for i, l in locs.items()
                 if l["org"] == org and l["name"].casefold() == value.casefold()), None)


def _in(ip, subnets) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(s) for s in subnets)


def _valid_ip(ip) -> bool:
    m = inventory_manager.IP_PATTERN.match(ip)
    return bool(m) and all(0 <= int(o) <= 255 for o in m.groups())


def classify(csv_text, default_org, default_location, decisions, scope) -> dict:
    parsed = inventory_manager._read_inventory_csv(csv_text)   # ValueError: unreadable file
    locs = {l["id"]: l for l in location_manager.list_locations()}
    active = {(d["Group"], d["IP"]): d for d in inventory_manager.get_all_devices()}
    retired = {(d["Group"], d["IP"]) for d in inventory_manager.get_decommissioned_devices()}
    seen, rows = set(), []
    for line, rec in parsed:
        dec = (decisions or {}).get(str(line)) or {}
        ip = (rec.get("IP") or "").strip()
        r = {"row": line, "ip": ip, "hostname": rec.get("Hostname", ""),
             "vendor": inventory_manager.normalize_vendor(rec.get("Vendor") or "cisco"),
             "org": None, "location": None, "probe": None, "status": "new", "changes": {},
             "reason": "", "warnings": [], "action": None, "credentials_note": "",
             "_rec": rec, "_existing_vendor": None}
        rows.append(r)

        def fail(reason, action=None):
            r.update(status="error", reason=reason, action=action)

        if dec.get("skip"):
            r["status"] = "skipped"
            continue
        if not _valid_ip(ip):
            fail("IP mancante o non valido")
            continue
        raw_org = (rec.get("Group") or "").strip() or default_org
        if not raw_org:
            fail("Organizzazione mancante: scegli una destinazione o aggiungi la colonna")
            continue
        org = inventory_manager.resolve_group(raw_org)
        if org is None:
            fail(f"Organizzazione '{raw_org}' inesistente: crea prima l'organizzazione")
            continue
        if scope is not None and org not in scope:
            fail(f"Organizzazione '{org}' non consentita per il tuo profilo")
            continue
        r["org"] = org
        loc_value = dec.get("location") or (rec.get("Location") or "").strip() or \
            (default_location if org == default_org else None)
        loc_id = _find_location(org, loc_value, locs)
        if not loc_id:
            fail(f"Sede '{loc_value or ''}' inesistente o non appartenente a '{org}'")
            continue
        r["location"] = loc_id
        probe = (rec.get("Probe") or "").strip()
        if probe and not probe_manager.get_probe(probe):
            fail(f"Sonda '{probe}' inesistente")
            continue
        r["probe"] = probe or locs[loc_id]["probe"]
        if (org, ip) in seen:
            fail("IP già presente in una riga precedente del file", {"kind": "skip"})
            continue
        seen.add((org, ip))
        subnets = locs[loc_id]["subnets"]
        if subnets and not _in(ip, subnets) and "location" not in dec:
            other = next((i for i, l in locs.items() if l["org"] == org and i != loc_id
                          and l["subnets"] and _in(ip, l["subnets"])), None)
            if other:
                fail(f"Fuori dalle subnet di {locs[loc_id]['name']}: rientra in {locs[other]['name']}",
                     {"kind": "move", "location": other})
                continue
            r["warnings"].append("fuori dalle subnet della sede")
        if (org, ip) in retired:
            fail("Apparato dismesso: riattivalo o eliminalo prima")
            continue
        existing = active.get((org, ip))
        username, password = rec.get("Username", ""), rec.get("Password", "")
        if existing:
            r["status"] = "update"
            r["_existing_vendor"] = existing.get("Vendor")
            incoming = {"Hostname": r["hostname"], "Vendor": r["vendor"] if rec.get("Vendor") else "",
                        "Username": username, "Password": password,
                        "Enable Secret": rec.get("Enable Secret", ""), "Probe": probe,
                        "Location": loc_id}
            for f in _COMPARED:
                new = incoming[f]
                if not new:
                    continue                      # empty cell keeps the stored value
                if f in _SECRET:
                    r["changes"][f] = ["", "changed"]
                elif new != existing.get(f, ""):
                    r["changes"][f] = [existing.get(f, ""), new]
            username = username or existing.get("Username", "")
            password = password or existing.get("Password", "")
        r["credentials_note"] = _credentials_note(username, password, r["probe"])
    counts = {k: sum(1 for r in rows if r["status"] == k) for k in ("new", "update", "error", "skipped")}
    columns = [{"header": h, "field": f} for h, f in inventory_manager._csv_columns(csv_text)]
    return {"columns": columns, "rows": rows, "counts": counts}


def public(result: dict) -> dict:
    """The classification without the private keys (raw records carry passwords)."""
    return dict(result, rows=[{k: v for k, v in r.items() if not k.startswith("_")}
                              for r in result["rows"]])


def apply(csv_text, default_org, default_location, decisions, scope) -> dict:
    result = classify(csv_text, default_org, default_location, decisions, scope)
    todo = [r for r in result["rows"] if r["status"] in ("new", "update")]
    entries = []
    for r in todo:
        rec = r["_rec"]
        # An update without a Vendor column keeps the stored vendor; only a
        # new device falls back to today's default.
        vendor = r["vendor"] if (rec.get("Vendor") or r["status"] == "new") else r["_existing_vendor"]
        entries.append(dict(ip=r["ip"], vendor=vendor, profile="custom",
                            username=rec.get("Username", ""), password=rec.get("Password", ""),
                            enable_secret=rec.get("Enable Secret", ""), group=r["org"],
                            probe=(rec.get("Probe") or "").strip() or None,
                            location=r["location"], hostname=r["hostname"] or None))
    if entries:
        inventory_manager.upsert_devices(entries)
    return {"imported": [r["ip"] for r in todo if r["status"] == "new"],
            "updated": [r["ip"] for r in todo if r["status"] == "update"],
            "skipped": [r["row"] for r in result["rows"] if r["status"] == "skipped"],
            "failed": [{"row": r["row"], "ip": r["ip"] or "?", "error": r["reason"]}
                       for r in result["rows"] if r["status"] == "error"],
            "preview": public(result)}
```

- [ ] **Step 4: Run, full suite, gate, commit** — `git commit -m "feat(import): classify CSV rows against inventory, locations and subnets"`.

---

### Task 7: Import endpoints

**Model:** sonnet

**Files:**
- Modify: `routers/inventory.py:55-57` (`CSVImportRequest`), `:442-530` (`import_csv` and the aliases above it)
- Test: `tests/test_csv_import_api.py`; `tests/test_router_parity.py` allow-list if it lists routes

**Interfaces:**
- Consumes: `csv_import.classify/apply/public` (Task 6), `user_group_scope`.
- Produces: `POST /api/import-csv/preview` and `POST /api/import-csv`, body `{csv_data: str, org: str | None, location: str | None, decisions: dict[str, dict] = {}}`.

- [ ] **Step 1: Failing tests** — `tests/test_csv_import_api.py`, `_Isolated` + `TestClient` pattern of `tests/test_device_decommission_api.py`, with `seed_inventory(orgs=["acme", "beta"], locations={"roma": …})`:
  - preview as operator → 200, keys `columns`, `rows`, `counts`; `get_all_devices()` unchanged;
  - preview of `"ip,password\n10.20.1.1,secret\n"` → response text contains neither `secret` nor `_rec`;
  - import → 200 with `imported`, `updated`, `skipped`, `failed`; the IP is in `get_all_devices()`;
  - operator scoped to `beta`, destination `acme` → 200, every row `error` (a file may target several organizations, so it is not a 403);
  - body without `csv_data` → 422; file `"hostname\nx\n"` → 400 whose detail mentions `IP`;
  - viewer → 403 on both routes.
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement** (`from typing import Any, Dict, Optional` and `from services import csv_import` if missing):

```python
class CSVImportRequest(BaseModel):
    csv_data: str
    org: Optional[str] = None
    location: Optional[str] = None
    decisions: Dict[str, Dict[str, Any]] = {}


@router.post("/api/import-csv/preview", dependencies=[Depends(require_tab("tab-import"))])
def import_csv_preview(payload: CSVImportRequest, current_user = Depends(require_operator)):
    try:
        result = csv_import.classify(payload.csv_data, payload.org, payload.location,
                                     payload.decisions, user_group_scope(current_user))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return csv_import.public(result)


@router.post("/api/import-csv", dependencies=[Depends(require_tab("tab-import"))])
def import_csv(payload: CSVImportRequest, current_user = Depends(require_operator)):
    try:
        out = csv_import.apply(payload.csv_data, payload.org, payload.location,
                               payload.decisions, user_group_scope(current_user))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    log_audit(f"Importazione CSV da '{current_user.get('sub')}': {len(out['imported'])} nuovi, "
              f"{len(out['updated'])} aggiornati, {len(out['skipped'])} saltati, "
              f"{len(out['failed'])} con errori.")
    return out
```

  Delete the old per-row loop. Delete the `_CSV_ALIASES` / `_canonical_header` / `_read_inventory_csv` module aliases above it only if `grep -n "_read_inventory_csv\|_canonical_header\|_CSV_ALIASES" routers/` shows no other user (`routers/probes.py` calls `inventory_manager._read_inventory_csv` directly).
- [ ] **Step 4: Run, full suite, gate, commit** — `git commit -m "feat(import): preview endpoint; import applies the same classification in one write"`.

---

### Task 8: Importa tab UI and the Organizations link

**Model:** sonnet

**Files:**
- Modify: `templates/dashboard.html` (`#tab-import`, ~2780–2810), `static/js/devices.js:1950-2060` (template download, drop zone, upload, `renderCsvImportResult`), `static/js/devices.js` (`renderGroupsTable` location rows), `static/js/core.js` (`LAZY_TAB_SCRIPTS`), `static/js/i18n.js`, `types/globals.d.ts`, `static/css/dashboard.css`
- Test: `tests/test_import_ui.py`

**Interfaces:**
- Consumes: Task 7 endpoints; `GET /api/locations`; `GET /api/groups`.
- Produces: `window.openImportFor(org: string, location: string): void`.

- [ ] **Step 1: Failing test** `tests/test_import_ui.py` (pattern of `tests/test_locations_ui.py`):
  - ids `importOrgSelect`, `importLocationSelect`, `importDestChips`, `importColumns`, `importFilterTabs`, `importPreviewBody`, `importSummary`, `btnUploadCsv` exist in `dashboard.html` and each appears in `devices.js`;
  - `window.openImportFor =` in `devices.js` and `openImportFor` in `types/globals.d.ts`;
  - every `tr('import…')` / `tr('btnImportDevices')` / `tr('locImportDevices')` key used in `devices.js` exists in both dictionaries;
  - `id="importFilterTabs"` carries `role="tablist"`; both selects have a `<label for>`.
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Template** — inside `#tab-import`, before the drop zone: a «Destinazione» panel with `<label for="importOrgSelect" data-i18n="importOrgLabel">` + `<select id="importOrgSelect">`, `<label for="importLocationSelect" data-i18n="importLocationLabel">` + `<select id="importLocationSelect">`, `<div id="importDestChips">`. After the drop zone: `<div id="importColumns">`, `<div id="importFilterTabs" role="tablist">` with four `<button role="tab" data-filter="all|new|update|error">`, a `.table-container` with `<tbody id="importPreviewBody">`, a footer with `<span id="importSummary">` and the existing `#btnUploadCsv`. Keep `#csvImportResult` for the final counts.
- [ ] **Step 4: JS (`devices.js`)**:
  - `loadImportDestinations()` fills both selects from `/api/groups` and `/api/locations` (location select filtered by the chosen organization; chips show the chosen location's probe and subnets).
  - `importState = { text: '', decisions: {}, filter: 'all', preview: null }`.
  - On file choose/drop and on select change: read the file into `importState.text`, `POST /api/import-csv/preview` with `{csv_data, org, location, decisions}`, render.
  - Render: columns as chips (`field === null` → `tr('importColIgnored')`); tab labels with counts; rows filtered by `importState.filter` (the error tab shows `error` and `skipped`); a status pill per status; notes = `reason`, each change as `field: old → new` (`changed` → `tr('importPwdChanged')`, no changes on an update → `tr('importNoChanges')`), `warnings`, `credentials_note`; action button with `data-action="import-move"` + `data-row` + `data-location`, or `data-action="import-skip"` + `data-row`. Every value through `escapeHtml`.
  - Delegated click on `#importPreviewBody`: `importState.decisions[row] = {location}` or `{skip: true}`, rerun the preview.
  - `#btnUploadCsv`: disabled unless `counts.new + counts.update > 0`; text `tr('btnImportDevices', {n})`; click → `POST /api/import-csv` with the same body → `renderCsvImportResult(result)` (now shows `imported`, `updated`, `skipped`, `failed`) → `refreshInventory()` → clear the preview.
  - `window.openImportFor = (org, loc) => { switchTab('tab-import'); …select both, refresh chips… }`.
  - CSV template: header gains `Organization,Location`; the sample row uses `acme,roma`.
- [ ] **Step 5: Organizations tab** — in each location row's actions, `<button data-action="loc-import" data-org="…" data-loc="…">` with `tr('locImportDevices')` → `openImportFor(org, loc)`. If the import code is only lazy-loaded for `tab-import`, add it to the `tab-groups` entry of `LAZY_TAB_SCRIPTS` (AGENTS.md rule; `tests/test_lazy_tab_scripts.py` checks it).
- [ ] **Step 6: i18n** — keys in both dictionaries: `importDestTitle`, `importOrgLabel`, `importLocationLabel`, `importPickDestination`, `importColIgnored`, `importTabAll`, `importTabNew`, `importTabUpdate`, `importTabError`, `importStNew`, `importStUpdate`, `importStError`, `importStSkipped`, `importPwdChanged`, `importNoChanges`, `importActionMove` (`Sposta in {name}`), `importActionSkip`, `importSummary` (`{n} apparati pronti · {m} righe saltate se importi ora`), `btnImportDevices` (`Importa {n} apparati`), `importResult`, `locImportDevices`.
- [ ] **Step 7: Gate incl. `check_i18n_coverage --strict`, `check_a11y --strict`; browser check on a throwaway instance** (two locations with subnets; a file with a new row, an update, an IP of the other location → «Sposta» → becomes new, a duplicate → «Salta»; import; the inventory shows them); commit `git commit -m "feat(import): destination, preview with row actions, import in one step"`.

---

### Task 9: Docs, gate, build

**Model:** session model

- [ ] `docs/organizations-locations.md`: storage section → `inventory.db` (tables, foreign keys, what stays JSON); the migration section gains the SQLite step (`*.pre-sqlite`, refusal to start on orphan rows); new "Import per location" section (destination, preview outcomes, row actions, credentials note, one write).
- [ ] `docs/probes.md`: the agent's local inventory is `inventory.db`, migrated at agent start; the get/save RPC still exchanges CSV text, so mixed versions keep working.
- [ ] `docs/README.md`: update the organizations-locations row description.
- [ ] `docs/superpowers/plans/2026-10-09-organizations-locations.md` roadmap: row 2 → this plan.
- [ ] Full gate, `graphify update .`, screenshots (`uv run python scripts/dev/capture_screenshots.py`), `uv run pyinstaller SentinelNet.spec --noconfirm`.
- [ ] Upgrade check on a **copy** of a real data dir (run by the user): the server starts; device, organization and location counts equal before/after; `*.pre-sqlite` files present; second start logs nothing; one updated agent and one old agent both still sync.
- [ ] Commit `git commit -m "docs(inventory): SQLite storage and per-location import"`.

### Measured

Synthetic data, final review run: 10,000 rows — preview 0.09 s, new import
0.57 s, update import 0.60 s; single add on a 10k inventory 0.34 s; cached
`get_all_devices` 3 ms.

---

## After this plan

Sub-projects 3 (Network Blueprint), 4 (assistant), 5 (maps and routing per location) — each its own brainstorming → spec → plan. 3 stores the links between locations in `inventory.db`.
