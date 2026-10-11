# Network Blueprint — Implementation Plan (sub-project 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each organization an expected network — locations, links between them, a gateway per location — edited through reviewable drafts, versioned on every write, and compared by deterministic checks with what SentinelNet observes, the checks proposing the missing pieces.

**Architecture:** The model stays where it is: `locations` in `inventory.db`, plus a new `links` table and a `gateway` column. `services/blueprint_store.py` holds drafts, revisions (full per-organization snapshots) and the observation snapshot; `services/blueprint_model.py` is pure (apply draft operations to the tables, diff, restore and preset operations); `services/blueprint_checks.py` is pure (`(view, observed) -> findings`); `services/blueprint_observe.py` gathers the observed data (offline sources always, live routes and IPsec tunnels only on demand); `services/blueprint.py` composes them and `routers/blueprint.py` exposes them. Every write to locations — the existing `/api/locations` routes included — records a revision in the same transaction. The UI is a new lazy-loaded tab `tab-blueprint` (`static/js/blueprint.js`) with lists, modals, a vis-network diagram, findings with proposals, a draft bar and the history.

**Tech Stack:** Python 3 / FastAPI / sqlite3 (stdlib) / classic-script JS + vis-network (already vendored) / unittest via pytest (`uv run pytest tests -n 4`).

**Spec:** `docs/superpowers/specs/2026-10-11-network-blueprint-design.md`

## Global Constraints

- Storage: `inventory.db` (`inventory_manager.inventory_db_path()`), opened with `inventory_manager._db()`; foreign keys on.
- `links.a < links.b` (stored ordered); link id = `f"{a}--{b}--{kind}"` with `a, b = sorted(...)`; `kind` ∈ `vpn | wan | mpls | lan`.
- Draft refs of locations not created yet start with `+` (`"+1"`); location slugs never contain `+`.
- Operations: `create_location`, `update_location`, `add_subnet`, `set_gateway`, `delete_location`, `add_link`, `remove_link`.
- Revision sources: `migration | blueprint | locations | import | restore`. Draft sources: `preset | checks | restore | manual | assistant`.
- Checks never open a connection; missing data → severity `unknown`.
- Live collection only in `blueprint_observe.observe()` (route «Aggiorna dai gateway»).
- API: every route `require_tab("tab-blueprint")` + `assert_group_allowed(user, org)`; writes `require_admin`. Op errors → `422` with `detail = {"message", "index"}`; stale draft → `409`.
- New comments in English; Italian user/audit strings like the existing ones; UI strings via `tr()` in both languages; `openModal`/`closeModal`; accessible names; no inline handlers.
- Example data only (`10.10.0.0/16`, `10.20.0.0/16`, `192.0.2.x`, `acme`, `beta`, `milano`, `roma`).
- Gate before each commit: `uv run pyrefly check`, `uv run python scripts/check_frontend.py` (JS/templates), `uv run pytest tests -n 4`, `uv run python scripts/check_no_private_data.py`; UI task also `uv run python scripts/check_i18n_coverage.py --strict` and `uv run python scripts/check_a11y.py --strict`; `graphify update .` after code changes.

## Spec adjustments (made while planning, written back into the spec in Task 1)

- **`device_outside_subnets`**: when another location covers the device's IP the finding names that location but carries **no proposal** — moving a device is an inventory write, not a model operation, and a draft that also wrote hosts could not be applied in one transaction with the model. When no location covers it, the proposal adds its /24 to the device's location.
- **`add_subnet` operation** (new): ARP proposals add one subnet each. Two `update_location` proposals for the same location would each carry the full list and the second would drop the first one's subnet.
- **Home checklist**: the spec says the Home «Primi passi» gains an item; that checklist is no longer in the code (grep `firstRunSteps`/`chkTitle`: nothing). The item is dropped; the Blueprint's own «Primi passi» panel stays.

## Review Focus

1. **Accepting two ARP proposals for the same location** → both subnets end up on the location (not only the last one). Test in Task 4 (`add_subnet` twice) and Task 6.
2. **Routes known only from the config backup** (static routes, no connected/dynamic) → a missing route is a `warning` saying «solo statiche», never an `error`. Test in Task 7.
3. **ARP entries for public addresses** (the ISP side of a WAN interface) → never proposed as a location subnet. Test in Task 6.
4. **A restore whose deleted location's id was taken meanwhile by another organization** → the location comes back with a suffixed id, its links follow it, and the apply answer lists the rename. Tests in Task 5 and Task 9.
5. **Apply racing a direct location edit** (`/api/locations/update` between draft creation and apply) → `409`, nothing written; after «Allinea» the apply succeeds. Test in Task 9.

---

## File map

| File | Change |
|---|---|
| `services/inventory_store.py` | schema: `locations.gateway`, `links`, `blueprint_drafts`, `blueprint_revisions`, `blueprint_observations`; `put_locations`, `read_links`, `put_links`, `write_links`; gateway column added to old databases |
| `services/blueprint_store.py` (new) | `snapshot`, `latest_rev`, `record_revisions`, `revisions`, `revision`, drafts, observations |
| `services/location_manager.py` | `_save` records revisions; `by` on create/update/delete |
| `routers/locations.py` | passes `by=who` |
| `app_server.py` | revision 1 for every organization at startup; include `routers.blueprint` |
| `services/blueprint_model.py` (new) | `OpError`, `link_id`, `org_view`, `apply_ops`, `diff`, `restore_ops`, `preset_ops` |
| `services/blueprint_checks.py` (new) | `run(view, observed)` and the twelve checks |
| `services/blueprint_observe.py` (new) | `gateways`, `observe`, `gather` |
| `services/blueprint.py` (new) | `state`, `checks`, `add_ops`, `replace_ops`, `discard`, `align`, `apply`, `restore`, `preset`, `diff`, `revisions`, `revision`, `observe`, `Conflict` |
| `routers/blueprint.py` (new) | `/api/blueprint/{org}...` |
| `templates/dashboard.html` | nav button, `tab-blueprint` panel, five modals |
| `static/js/blueprint.js` (new) | the tab |
| `static/js/core.js` | `LAZY_TAB_SCRIPTS`, `switchTab` dispatch, command palette entry |
| `static/js/settings.js` | `ADMIN_GROUP_TABS` |
| `static/js/devices.js` | «Blueprint» action on each organization row |
| `static/js/i18n.js`, `types/globals.d.ts`, `static/css/dashboard.css` | strings, globals, styles |
| Tests | `test_blueprint_schema.py`, `test_blueprint_store.py`, `test_location_revisions.py`, `test_blueprint_model.py`, `test_blueprint_checks.py`, `test_blueprint_observe.py`, `test_blueprint_api.py`, `test_blueprint_tab.py`; one line in `test_tab_enforcement.py` |
| Docs | `docs/network-blueprint.md` (new), `docs/README.md`, `docs/organizations-locations.md`, spec adjustments |

---

### Task 1: Schema — gateway, links, Blueprint tables

**Model:** sonnet

**Files:**
- Modify: `services/inventory_store.py`
- Modify: `docs/superpowers/specs/2026-10-11-network-blueprint-design.md` (the three adjustments above)
- Test: `tests/test_blueprint_schema.py`

**Interfaces:**
- Produces:
  - `read_locations(conn)` entries gain `"gateway": str` (`''` when NULL); `write_locations` stores it (`NULL` when empty)
  - `put_locations(conn, data: dict) -> None` — `write_locations` without its own transaction
  - `read_links(conn) -> dict` — `{id: {"org", "a", "b", "kind", "note"}}`
  - `put_links(conn, links: dict) -> None`, `write_links(conn, links: dict) -> None`
  - Tables `blueprint_drafts`, `blueprint_revisions`, `blueprint_observations` (used by Task 2)

- [ ] **Step 1: Write the failing tests** — `tests/test_blueprint_schema.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Blueprint schema: location gateway, links between locations (spec 2026-10-11)."""
import os
import sqlite3
import tempfile
import unittest

from services import inventory_store

LOC = {"org": "acme", "name": "Milano", "role": "hq", "subnets": ["10.10.0.0/16"], "probe": "central"}
LINK = {"org": "acme", "a": "milano", "b": "roma", "kind": "vpn", "note": ""}


class _Base(unittest.TestCase):
    def setUp(self):
        path = os.path.join(tempfile.mkdtemp(prefix="bp_schema_"), "inventory.db")
        self.conn = inventory_store.connect(path)
        self.addCleanup(self.conn.close)
        inventory_store.write_orgs(self.conn, {"acme": {"description": ""}})
        inventory_store.write_locations(self.conn, {
            "milano": dict(LOC),
            "roma": dict(LOC, name="Roma", role="branch", subnets=["10.20.0.0/16"]),
        })


class TestGateway(_Base):
    def test_gateway_defaults_empty_and_round_trips(self):
        locs = inventory_store.read_locations(self.conn)
        self.assertEqual(locs["milano"]["gateway"], "")
        locs["milano"]["gateway"] = "10.10.0.1"
        inventory_store.write_locations(self.conn, locs)
        self.assertEqual(inventory_store.read_locations(self.conn)["milano"]["gateway"], "10.10.0.1")

    def test_database_from_before_gets_the_column(self):
        path = os.path.join(tempfile.mkdtemp(prefix="bp_old_"), "inventory.db")
        raw = sqlite3.connect(path)
        raw.executescript(
            "CREATE TABLE organizations (key TEXT PRIMARY KEY, name TEXT, description TEXT NOT NULL DEFAULT '');"
            "CREATE TABLE locations (id TEXT PRIMARY KEY, org TEXT NOT NULL REFERENCES organizations(key), "
            "name TEXT NOT NULL, role TEXT NOT NULL, subnets TEXT NOT NULL DEFAULT '[]', "
            "probe TEXT NOT NULL DEFAULT 'central');"
            "INSERT INTO organizations VALUES ('acme', NULL, '');"
            "INSERT INTO locations VALUES ('milano', 'acme', 'Milano', 'hq', '[]', 'central');")
        raw.commit()
        raw.close()
        conn = inventory_store.connect(path)
        self.addCleanup(conn.close)
        self.assertEqual(inventory_store.read_locations(conn)["milano"]["gateway"], "")


class TestLinks(_Base):
    def test_round_trip(self):
        inventory_store.write_links(self.conn, {"milano--roma--vpn": dict(LINK)})
        self.assertEqual(inventory_store.read_links(self.conn), {"milano--roma--vpn": LINK})

    def test_unordered_self_unknown_kind_or_location_refused(self):
        for bad in (dict(LINK, a="roma", b="milano"), dict(LINK, b="milano"),
                    dict(LINK, kind="carrier-pigeon"), dict(LINK, b="zara")):
            with self.subTest(bad=bad), self.assertRaises(sqlite3.IntegrityError):
                inventory_store.write_links(self.conn, {"x": bad})
        self.assertEqual(inventory_store.read_links(self.conn), {})

    def test_deleting_a_location_drops_its_links(self):
        inventory_store.write_links(self.conn, {"milano--roma--vpn": dict(LINK)})
        locs = inventory_store.read_locations(self.conn)
        del locs["roma"]
        inventory_store.write_locations(self.conn, locs)
        self.assertEqual(inventory_store.read_links(self.conn), {})

    def test_draft_and_observation_go_with_their_organization(self):
        with self.conn:
            self.conn.execute("INSERT INTO blueprint_drafts (org, base_rev, source, ops, updated_at) "
                              "VALUES ('acme', 0, 'manual', '[]', 'now')")
            self.conn.execute("INSERT INTO blueprint_observations (org, at, data) VALUES ('acme', 'now', '{}')")
            self.conn.execute("INSERT INTO blueprint_revisions (org, rev, at, source, snapshot) "
                              "VALUES ('acme', 1, 'now', 'migration', '{}')")
        inventory_store.write_locations(self.conn, {})
        inventory_store.write_orgs(self.conn, {})
        for table, left in (("blueprint_drafts", 0), ("blueprint_observations", 0),
                            ("blueprint_revisions", 1)):   # history outlives the organization
            with self.subTest(table=table):
                self.assertEqual(self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], left)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_schema.py -v`
Expected: FAIL — `KeyError: 'gateway'`, `AttributeError: ... no attribute 'write_links'`.

- [ ] **Step 3: Implement** — in `services/inventory_store.py`:

Replace the `locations` line of `_SCHEMA` and add the new tables after it (before the two `_host_table(...)` entries):

```python
    "CREATE TABLE IF NOT EXISTS locations (id TEXT PRIMARY KEY, "
    "org TEXT NOT NULL REFERENCES organizations(key), name TEXT NOT NULL, "
    "role TEXT NOT NULL, subnets TEXT NOT NULL DEFAULT '[]', "
    "probe TEXT NOT NULL DEFAULT 'central', gateway TEXT);",
    # Links between two locations of one organization (spec 2026-10-11
    # network-blueprint). Stored ordered, so A-B and B-A are one row; a deleted
    # location takes its links with it.
    "CREATE TABLE IF NOT EXISTS links (id TEXT PRIMARY KEY, "
    "org TEXT NOT NULL REFERENCES organizations(key), "
    "a TEXT NOT NULL REFERENCES locations(id) ON DELETE CASCADE, "
    "b TEXT NOT NULL REFERENCES locations(id) ON DELETE CASCADE, "
    "kind TEXT NOT NULL CHECK (kind IN ('vpn', 'wan', 'mpls', 'lan')), "
    "note TEXT NOT NULL DEFAULT '', CHECK (a < b), UNIQUE (a, b, kind));",
    "CREATE TABLE IF NOT EXISTS blueprint_drafts (org TEXT PRIMARY KEY "
    "REFERENCES organizations(key) ON DELETE CASCADE, base_rev INTEGER NOT NULL, "
    "source TEXT NOT NULL, ops TEXT NOT NULL, updated_by TEXT NOT NULL DEFAULT '', "
    "updated_at TEXT NOT NULL);",
    # No foreign key: the history of an organization outlives it.
    "CREATE TABLE IF NOT EXISTS blueprint_revisions (org TEXT NOT NULL, rev INTEGER NOT NULL, "
    "at TEXT NOT NULL, by TEXT NOT NULL DEFAULT '', source TEXT NOT NULL, "
    "note TEXT NOT NULL DEFAULT '', snapshot TEXT NOT NULL, PRIMARY KEY (org, rev));",
    "CREATE TABLE IF NOT EXISTS blueprint_observations (org TEXT PRIMARY KEY "
    "REFERENCES organizations(key) ON DELETE CASCADE, at TEXT NOT NULL, data TEXT NOT NULL);",
```

In `connect`, right after `conn.executescript(_SCHEMA)`:

```python
            # Databases created before the Blueprint lack the column;
            # CREATE TABLE IF NOT EXISTS does not add it.
            if "gateway" not in {r["name"] for r in conn.execute("PRAGMA table_info(locations)")}:
                conn.execute("ALTER TABLE locations ADD COLUMN gateway TEXT")
```

Replace `read_locations` / `write_locations` and add the link functions:

```python
def read_locations(conn) -> dict:
    return {r["id"]: {"org": r["org"], "name": r["name"], "role": r["role"],
                      "subnets": json.loads(r["subnets"]), "probe": r["probe"],
                      "gateway": r["gateway"] or ""}
            for r in conn.execute("SELECT * FROM locations ORDER BY id")}


def put_locations(conn, data: dict) -> None:
    """write_locations inside the caller's transaction."""
    keep = list(data)
    conn.execute(f"DELETE FROM locations WHERE id NOT IN ({', '.join('?' * len(keep))})", keep)
    conn.executemany(
        "INSERT INTO locations (id, org, name, role, subnets, probe, gateway) VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (id) DO UPDATE SET org = excluded.org, name = excluded.name, "
        "role = excluded.role, subnets = excluded.subnets, probe = excluded.probe, "
        "gateway = excluded.gateway",
        [(k, v["org"], v["name"], v["role"], json.dumps(v.get("subnets") or []),
          v.get("probe") or "central", v.get("gateway") or None) for k, v in data.items()])


def write_locations(conn, data: dict) -> None:
    with conn:
        put_locations(conn, data)


def read_links(conn) -> dict:
    return {r["id"]: {"org": r["org"], "a": r["a"], "b": r["b"], "kind": r["kind"], "note": r["note"]}
            for r in conn.execute("SELECT * FROM links ORDER BY id")}


def put_links(conn, links: dict) -> None:
    """Replace the links table with ``links``, inside the caller's transaction."""
    keep = list(links)
    conn.execute(f"DELETE FROM links WHERE id NOT IN ({', '.join('?' * len(keep))})", keep)
    conn.executemany(
        "INSERT INTO links (id, org, a, b, kind, note) VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (id) DO UPDATE SET org = excluded.org, a = excluded.a, b = excluded.b, "
        "kind = excluded.kind, note = excluded.note",
        [(k, v["org"], v["a"], v["b"], v["kind"], v.get("note") or "") for k, v in links.items()])


def write_links(conn, links: dict) -> None:
    with conn:
        put_links(conn, links)
```

- [ ] **Step 4: Write the spec adjustments** — in `docs/superpowers/specs/2026-10-11-network-blueprint-design.md`:
  - in the operations block add `{"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"}`;
  - `device_outside_subnets` row, proposal column: `none when another location covers the IP (the message names it: moving a device is an inventory write); else add_subnet with its /24`;
  - `arp_uncovered` row, proposal: `add_subnet to that location`;
  - in UI, delete the sentence «The Home checklist gains the item «Disegna il Blueprint di un'organizzazione».» and add after the «Primi passi» bullet: `(The Home checklist the earlier draft mentioned no longer exists.)`

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/test_blueprint_schema.py tests/test_inventory_store.py tests/test_location_manager.py -v`
Expected: PASS.

- [ ] **Step 6: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add services/inventory_store.py tests/test_blueprint_schema.py docs/superpowers/specs/2026-10-11-network-blueprint-design.md
git commit -m "feat(blueprint): links, location gateway and Blueprint tables in inventory.db"
```

---

### Task 2: `blueprint_store` — revisions, drafts, observations

**Model:** sonnet

**Files:**
- Create: `services/blueprint_store.py`
- Test: `tests/test_blueprint_store.py`

**Interfaces:**
- Consumes: Task 1 tables, `inventory_store.read_locations`, `read_links`.
- Produces (none of the writers commits: callers wrap them in `with conn:`):
  - `snapshot(conn, org) -> {"locations": {id: loc}, "links": {id: link}}` (entries as `read_locations`/`read_links` return them, `org` included)
  - `latest_rev(conn, org) -> int` (0 when none)
  - `record_revisions(conn, by: str, source: str, note: str = "") -> list[tuple[str, int]]`
  - `revisions(conn, org) -> list[dict]` newest first, keys `rev, at, by, source, note`
  - `revision(conn, org, rev) -> dict | None` (same keys + `snapshot`)
  - `get_draft(conn, org) -> dict | None` — `{"base_rev", "source", "ops", "updated_by", "updated_at"}`
  - `put_draft(conn, org, base_rev: int, source: str, ops: list, by: str) -> None`
  - `delete_draft(conn, org) -> None`
  - `get_observation(conn, org) -> dict | None` — `{"at", "data"}`
  - `put_observation(conn, org, data: dict) -> str` (returns `at`)

- [ ] **Step 1: Write the failing tests** — `tests/test_blueprint_store.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Blueprint storage: revisions per organization, drafts, observations."""
import os
import tempfile
import unittest

from services import blueprint_store, inventory_store

LOC = {"org": "acme", "name": "Milano", "role": "hq", "subnets": ["10.10.0.0/16"], "probe": "central"}


class _Base(unittest.TestCase):
    def setUp(self):
        path = os.path.join(tempfile.mkdtemp(prefix="bp_store_"), "inventory.db")
        self.conn = inventory_store.connect(path)
        self.addCleanup(self.conn.close)
        inventory_store.write_orgs(self.conn, {"acme": {"description": ""}, "beta": {"description": ""}})
        inventory_store.write_locations(self.conn, {
            "milano": dict(LOC), "roma": dict(LOC, name="Roma", role="branch", subnets=["10.20.0.0/16"]),
            "zurigo": dict(LOC, org="beta", name="Zurigo")})

    def record(self, by="mario", source="locations", note=""):
        with self.conn:
            return blueprint_store.record_revisions(self.conn, by, source, note)


class TestRevisions(_Base):
    def test_first_record_then_only_on_change(self):
        self.assertEqual(self.record(), [("acme", 1), ("beta", 1)])
        self.assertEqual(self.record(), [])
        locs = inventory_store.read_locations(self.conn)
        locs["roma"]["subnets"] = ["10.21.0.0/16"]
        inventory_store.write_locations(self.conn, locs)
        self.assertEqual(self.record("anna", "blueprint", "nuova subnet"), [("acme", 2)])
        revs = blueprint_store.revisions(self.conn, "acme")
        self.assertEqual([(r["rev"], r["by"], r["source"], r["note"]) for r in revs],
                         [(2, "anna", "blueprint", "nuova subnet"), (1, "mario", "locations", "")])
        self.assertEqual(blueprint_store.latest_rev(self.conn, "acme"), 2)
        rev2 = blueprint_store.revision(self.conn, "acme", 2)
        self.assertEqual(rev2["snapshot"]["locations"]["roma"]["subnets"], ["10.21.0.0/16"])
        self.assertNotIn("zurigo", rev2["snapshot"]["locations"])
        self.assertIsNone(blueprint_store.revision(self.conn, "acme", 9))
        self.assertEqual(blueprint_store.latest_rev(self.conn, "nobody"), 0)

    def test_snapshot_holds_the_links(self):
        self.record()
        inventory_store.write_links(self.conn, {"milano--roma--vpn": {
            "org": "acme", "a": "milano", "b": "roma", "kind": "vpn", "note": ""}})
        self.assertEqual(self.record(), [("acme", 2)])
        snap = blueprint_store.revision(self.conn, "acme", 2)["snapshot"]
        self.assertEqual(list(snap["links"]), ["milano--roma--vpn"])


class TestDrafts(_Base):
    def test_put_get_delete(self):
        self.assertIsNone(blueprint_store.get_draft(self.conn, "acme"))
        ops = [{"op": "delete_location", "id": "roma", "source": "manual"}]
        with self.conn:
            blueprint_store.put_draft(self.conn, "acme", 3, "manual", ops, "mario")
        d = blueprint_store.get_draft(self.conn, "acme")
        self.assertEqual((d["base_rev"], d["source"], d["ops"], d["updated_by"]), (3, "manual", ops, "mario"))
        with self.conn:
            blueprint_store.put_draft(self.conn, "acme", 4, "manual", [], "anna")
        self.assertEqual(blueprint_store.get_draft(self.conn, "acme")["base_rev"], 4)
        with self.conn:
            blueprint_store.delete_draft(self.conn, "acme")
        self.assertIsNone(blueprint_store.get_draft(self.conn, "acme"))


class TestObservations(_Base):
    def test_replaced_each_time(self):
        self.assertIsNone(blueprint_store.get_observation(self.conn, "acme"))
        with self.conn:
            blueprint_store.put_observation(self.conn, "acme", {"10.10.0.1": {"routes": {"rows": [], "error": "x"}}})
            at = blueprint_store.put_observation(self.conn, "acme", {})
        obs = blueprint_store.get_observation(self.conn, "acme")
        self.assertEqual((obs["at"], obs["data"]), (at, {}))
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_store.py -v`
Expected: FAIL — `ImportError: cannot import name 'blueprint_store'`.

- [ ] **Step 3: Implement** — `services/blueprint_store.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Storage of the Network Blueprint (spec 2026-10-11 network-blueprint):
revisions of each organization's locations and links, the open draft, the
last observation of its gateways. Tables live in inventory.db
(inventory_store). No writer commits: callers group a model write and its
revision in one ``with conn:``."""
import json
from datetime import datetime, timezone

from services import inventory_store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def snapshot(conn, org: str) -> dict:
    return {"locations": {k: v for k, v in inventory_store.read_locations(conn).items() if v["org"] == org},
            "links": {k: v for k, v in inventory_store.read_links(conn).items() if v["org"] == org}}


def latest_rev(conn, org: str) -> int:
    return conn.execute("SELECT MAX(rev) FROM blueprint_revisions WHERE org = ?", (org,)).fetchone()[0] or 0


def record_revisions(conn, by: str, source: str, note: str = "") -> list:
    """Append a revision for every organization whose locations or links
    differ from its latest snapshot. Comparing snapshots instead of trusting
    each caller to say what changed is what keeps the history aligned: a
    cascade (a deleted location takes its links) is recorded too."""
    # ponytail: re-reads both tables per organization; per-org queries if an
    # install ever has thousands of organizations.
    made = []
    for (org,) in conn.execute("SELECT key FROM organizations ORDER BY key").fetchall():
        snap = snapshot(conn, org)
        rev = latest_rev(conn, org)
        if rev:
            last = conn.execute("SELECT snapshot FROM blueprint_revisions WHERE org = ? AND rev = ?",
                                (org, rev)).fetchone()[0]
            if json.loads(last) == snap:
                continue
        conn.execute("INSERT INTO blueprint_revisions (org, rev, at, by, source, note, snapshot) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (org, rev + 1, _now(), by or "", source, note or "", json.dumps(snap, sort_keys=True)))
        made.append((org, rev + 1))
    return made


def revisions(conn, org: str) -> list:
    return [dict(r) for r in conn.execute(
        "SELECT rev, at, by, source, note FROM blueprint_revisions WHERE org = ? ORDER BY rev DESC", (org,))]


def revision(conn, org: str, rev: int):
    r = conn.execute("SELECT rev, at, by, source, note, snapshot FROM blueprint_revisions "
                     "WHERE org = ? AND rev = ?", (org, rev)).fetchone()
    if not r:
        return None
    out = dict(r)
    out["snapshot"] = json.loads(out["snapshot"])
    return out


def get_draft(conn, org: str):
    r = conn.execute("SELECT base_rev, source, ops, updated_by, updated_at FROM blueprint_drafts "
                     "WHERE org = ?", (org,)).fetchone()
    if not r:
        return None
    out = dict(r)
    out["ops"] = json.loads(out["ops"])
    return out


def put_draft(conn, org: str, base_rev: int, source: str, ops: list, by: str) -> None:
    conn.execute("INSERT INTO blueprint_drafts (org, base_rev, source, ops, updated_by, updated_at) "
                 "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (org) DO UPDATE SET base_rev = excluded.base_rev, "
                 "source = excluded.source, ops = excluded.ops, updated_by = excluded.updated_by, "
                 "updated_at = excluded.updated_at",
                 (org, base_rev, source, json.dumps(ops), by or "", _now()))


def delete_draft(conn, org: str) -> None:
    conn.execute("DELETE FROM blueprint_drafts WHERE org = ?", (org,))


def get_observation(conn, org: str):
    r = conn.execute("SELECT at, data FROM blueprint_observations WHERE org = ?", (org,)).fetchone()
    return {"at": r["at"], "data": json.loads(r["data"])} if r else None


def put_observation(conn, org: str, data: dict) -> str:
    at = _now()
    conn.execute("INSERT INTO blueprint_observations (org, at, data) VALUES (?, ?, ?) "
                 "ON CONFLICT (org) DO UPDATE SET at = excluded.at, data = excluded.data",
                 (org, at, json.dumps(data)))
    return at
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_blueprint_store.py -v`
Expected: PASS.

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add services/blueprint_store.py tests/test_blueprint_store.py
git commit -m "feat(blueprint): revisions, drafts and observations store"
```

---

### Task 3: Every location write records a revision

**Model:** sonnet

**Files:**
- Modify: `services/location_manager.py` (`_save`, `create_location`, `update_location`, `delete_location`)
- Modify: `routers/locations.py` (pass `by=who`)
- Modify: `app_server.py` (after the inventory migration, ~line 93)
- Test: `tests/test_location_revisions.py`

**Interfaces:**
- Consumes: `blueprint_store.record_revisions`, `inventory_store.put_locations`, `inventory_store.put_links`.
- Produces: `location_manager._save(data, by="", source="locations")`; `create_location(..., by="")`, `update_location(..., by="")`, `delete_location(loc_id, by="")`.

- [ ] **Step 1: Write the failing tests** — `tests/test_location_revisions.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Every write to locations records a revision (spec 2026-10-11 network-blueprint)."""
import os
import tempfile
import unittest
from unittest.mock import patch

from services import blueprint_store, inventory_manager, inventory_store, location_manager, probe_manager


class TestRevisionedWrites(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="loc_rev_")
        for p in (patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv")),
                  patch.object(probe_manager, "PROBES_JSON", os.path.join(tmp, "probes.json"))):
            p.start()
            self.addCleanup(p.stop)
        inventory_manager.save_groups({"acme": {"description": ""}, "beta": {"description": ""}})

    def revs(self, org="acme"):
        with inventory_manager._db() as conn:
            return [(r["rev"], r["by"], r["source"]) for r in blueprint_store.revisions(conn, org)]

    def test_create_update_delete_each_make_one_revision(self):
        location_manager.create_location("acme", "Milano", "hq", by="mario")
        location_manager.create_location("acme", "Roma", by="mario")
        location_manager.update_location("roma", subnets=["10.20.0.0/16"], by="anna")
        location_manager.update_location("roma", subnets=["10.20.0.0/16"], by="anna")   # no change
        location_manager.delete_location("roma", by="anna")
        self.assertEqual(self.revs(), [(4, "anna", "locations"), (3, "anna", "locations"),
                                       (2, "mario", "locations"), (1, "mario", "locations")])

    def test_other_organization_untouched(self):
        location_manager.create_location("acme", "Milano", "hq", by="mario")
        location_manager.create_location("beta", "Zurigo", "hq", by="mario")
        before = self.revs("beta")
        location_manager.update_location("milano", name="Milano HQ", by="mario")
        self.assertEqual(self.revs("beta"), before)

    def test_delete_takes_the_links_and_the_revision_shows_it(self):
        location_manager.create_location("acme", "Milano", "hq")
        location_manager.create_location("acme", "Roma")
        with inventory_manager._db() as conn, conn:
            inventory_store.put_links(conn, {"milano--roma--vpn": {
                "org": "acme", "a": "milano", "b": "roma", "kind": "vpn", "note": ""}})
            blueprint_store.record_revisions(conn, "", "blueprint")
        location_manager.delete_location("roma")
        with inventory_manager._db() as conn:
            snap = blueprint_store.revision(conn, "acme", blueprint_store.latest_rev(conn, "acme"))["snapshot"]
        self.assertEqual((list(snap["locations"]), snap["links"]), (["milano"], {}))

    def test_gateway_survives_an_edit_from_the_organizations_tab(self):
        location_manager.create_location("acme", "Milano", "hq")
        with inventory_manager._db() as conn:
            locs = inventory_store.read_locations(conn)
        locs["milano"]["gateway"] = "10.10.0.1"
        location_manager._save(locs)
        location_manager.update_location("milano", subnets=["10.10.0.0/16"])
        self.assertEqual(location_manager.get_location("milano")["gateway"], "10.10.0.1")
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_location_revisions.py -v`
Expected: FAIL — `TypeError: create_location() got an unexpected keyword argument 'by'`.

- [ ] **Step 3: Implement** — `services/location_manager.py`:

```python
def _save(data: dict, by: str = "", source: str = "locations") -> None:
    from services import blueprint_store, inventory_manager, inventory_store
    # The write and its revision commit together (spec 2026-10-11
    # network-blueprint): a revision that could miss a write would make the
    # history lie about what was applied.
    with inventory_manager._db() as conn, conn:
        inventory_store.put_locations(conn, data)
        blueprint_store.record_revisions(conn, by, source)
```

Add `by: str = ""` as the last parameter of `create_location`, `update_location`, `delete_location` and change their `_save(data)` calls to `_save(data, by=by)`. In `create_location` the new entry also carries the column: `data[loc_id] = {"org": org, "name": name, "role": role, "subnets": clean, "probe": probe, "gateway": ""}`.

`routers/locations.py`: pass `by=who` in the three calls:

```python
        loc = location_manager.create_location(
            payload.org, payload.name, role=payload.role,
            subnets=payload.subnets, probe=payload.probe, by=who,
        )
...
        updated = location_manager.update_location(
            payload.id, name=payload.name, role=payload.role,
            subnets=payload.subnets, probe=payload.probe, by=who,
        )
...
        location_manager.delete_location(payload.id, by=who)
```

`app_server.py`, right after the `inventory_migration` `try/except` block:

```python
    # Revision 1 of every organization's Blueprint (spec 2026-10-11): the
    # history starts from the model as it is at the first start with it.
    # Idempotent: nothing is recorded when nothing changed.
    from services import blueprint_store, inventory_manager as _inv
    with _inv._db() as _conn, _conn:
        blueprint_store.record_revisions(_conn, "", "migration")
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_location_revisions.py tests/test_location_manager.py tests/test_locations_api.py tests/test_location_boundaries.py -v`
Expected: PASS.

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add services/location_manager.py routers/locations.py app_server.py tests/test_location_revisions.py
git commit -m "feat(blueprint): every location write records a revision"
```

---

### Task 4: `blueprint_model` — operations

**Model:** opus

**Files:**
- Create: `services/blueprint_model.py`
- Test: `tests/test_blueprint_model.py`

**Interfaces:**
- Consumes: `location_manager.ROLES`, `location_manager._clean_subnets`, `probe_manager._slugify`.
- Produces:
  - `KINDS`, `FIELDS = ("name", "role", "subnets", "probe", "gateway")`, `PRESETS`, `MAX_PRESET = 50`
  - `class OpError(ValueError)` with `.index: int`; message `"Modifica {index+1}: {reason}"`
  - `link_id(a, b, kind) -> str`
  - `org_view(locations: dict, links: dict, org) -> {"locations", "links"}` (same shape as `blueprint_store.snapshot`)
  - `apply_ops(org, locations: dict, links: dict, ops: list, probes: set | None = None) -> (locations, links, refs)` — whole tables in, whole tables out (copies); `refs` maps each `+ref` to the id it got

- [ ] **Step 1: Write the failing tests** — `tests/test_blueprint_model.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Draft operations applied to the locations and links tables (pure)."""
import unittest

from services import blueprint_model as bm


def loc(name, org="acme", role="branch", subnets=(), gateway=""):
    return {"org": org, "name": name, "role": role, "subnets": list(subnets), "probe": "central", "gateway": gateway}


LOCS = {"milano": loc("Milano", role="hq", subnets=["10.10.0.0/16"]), "roma": loc("Roma"),
        "zurigo": loc("Zurigo", org="beta")}
LINKS = {"milano--roma--vpn": {"org": "acme", "a": "milano", "b": "roma", "kind": "vpn", "note": ""}}
PROBES = {"central"}


def apply(ops, locs=LOCS, links=LINKS):
    return bm.apply_ops("acme", locs, links, ops, PROBES)


class TestApplyOps(unittest.TestCase):
    def test_create_with_ref_then_link_to_it(self):
        locs, links, refs = apply([
            {"op": "create_location", "ref": "+1", "name": "Torino"},
            {"op": "add_link", "a": "+1", "b": "milano", "kind": "wan"}])
        self.assertEqual(refs, {"+1": "torino"})
        self.assertEqual(locs["torino"], loc("Torino"))
        self.assertEqual(links["milano--torino--wan"]["a"], "milano")
        self.assertNotIn("torino", LOCS)                      # inputs untouched

    def test_slug_clash_gets_a_suffix_and_wanted_id_is_used_when_free(self):
        locs, _, refs = apply([{"op": "create_location", "ref": "+1", "name": "Roma"},
                               {"op": "create_location", "ref": "+2", "name": "X", "id": "napoli"},
                               {"op": "create_location", "ref": "+3", "name": "Y", "id": "zurigo"}])
        self.assertEqual(refs, {"+1": "roma-2", "+2": "napoli", "+3": "zurigo-2"})

    def test_update_gateway_add_subnet(self):
        locs, _, _ = apply([
            {"op": "update_location", "id": "roma", "fields": {"name": "Roma Est", "subnets": ["10.20.0.0/24"]}},
            {"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"},
            {"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"},
            {"op": "add_subnet", "id": "roma", "subnet": "10.20.2.0/24"}])
        self.assertEqual(locs["roma"]["name"], "Roma Est")
        self.assertEqual(locs["roma"]["gateway"], "10.20.0.1")
        self.assertEqual(locs["roma"]["subnets"], ["10.20.0.0/24", "10.20.1.0/24", "10.20.2.0/24"])

    def test_delete_drops_links_and_remove_link(self):
        locs, links, _ = apply([{"op": "delete_location", "id": "roma"}])
        self.assertNotIn("roma", locs)
        self.assertEqual(links, {})
        _, links, _ = apply([{"op": "remove_link", "id": "milano--roma--vpn"}])
        self.assertEqual(links, {})

    def test_errors_name_the_operation(self):
        bad = [
            [{"op": "update_location", "id": "zurigo", "fields": {"name": "X"}}],   # other org
            [{"op": "update_location", "id": "roma", "fields": {"color": "red"}}],
            [{"op": "update_location", "id": "roma", "fields": {}}],
            [{"op": "update_location", "id": "roma", "fields": {"role": "castle"}}],
            [{"op": "update_location", "id": "roma", "fields": {"probe": "ghost"}}],
            [{"op": "set_gateway", "id": "roma", "ip": "not-an-ip"}],
            [{"op": "add_subnet", "id": "roma", "subnet": "10.0.0.0/33"}],
            [{"op": "create_location", "name": " "}],
            [{"op": "create_location", "ref": "1", "name": "X"}],
            [{"op": "add_link", "a": "roma", "b": "roma", "kind": "vpn"}],
            [{"op": "add_link", "a": "roma", "b": "milano", "kind": "vpn"}],          # exists
            [{"op": "add_link", "a": "roma", "b": "milano", "kind": "smoke"}],
            [{"op": "add_link", "a": "roma", "b": "+9", "kind": "wan"}],
            [{"op": "remove_link", "id": "nope"}],
            [{"op": "teleport"}],
        ]
        for ops in bad:
            with self.subTest(ops=ops):
                with self.assertRaises(bm.OpError) as cm:
                    apply([{"op": "set_gateway", "id": "milano", "ip": "10.10.0.1"}] + ops)
                self.assertEqual(cm.exception.index, 1)
                self.assertTrue(str(cm.exception).startswith("Modifica 2: "))

    def test_link_id_is_ordered(self):
        self.assertEqual(bm.link_id("roma", "milano", "vpn"), "milano--roma--vpn")

    def test_org_view(self):
        view = bm.org_view(LOCS, LINKS, "beta")
        self.assertEqual((list(view["locations"]), view["links"]), (["zurigo"], {}))
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_model.py -v`
Expected: FAIL — `ImportError: cannot import name 'blueprint_model'`.

- [ ] **Step 3: Implement** — `services/blueprint_model.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure logic of the Network Blueprint (spec 2026-10-11 network-blueprint):
draft operations applied to the locations and links tables, revision diffs,
restore and preset operations. No I/O: callers pass the tables in and
persist what comes out."""
import copy
import ipaddress
from itertools import combinations

from services.location_manager import ROLES, _clean_subnets

KINDS = ("vpn", "wan", "mpls", "lan")
FIELDS = ("name", "role", "subnets", "probe", "gateway")
PRESETS = ("single", "hub_spoke", "hub_spoke_dc", "full_mesh")
MAX_PRESET = 50


class OpError(ValueError):
    """A draft operation that cannot be applied; ``index`` is its position."""

    def __init__(self, index: int, message: str):
        super().__init__(f"Modifica {index + 1}: {message}")
        self.index = index


def link_id(a: str, b: str, kind: str) -> str:
    a, b = sorted((a, b))
    return f"{a}--{b}--{kind}"


def org_view(locations: dict, links: dict, org: str) -> dict:
    return {"locations": {k: v for k, v in locations.items() if v["org"] == org},
            "links": {k: v for k, v in links.items() if v["org"] == org}}


def _free_id(base: str, taken) -> str:
    lid, n = base, 2
    while lid in taken:
        lid, n = f"{base}-{n}", n + 1
    return lid


def _clean_fields(fields: dict, probes) -> dict:
    out = {}
    for k, v in fields.items():
        if k not in FIELDS:
            raise ValueError(f"campo sconosciuto: {k}")
        if k == "name":
            v = str(v or "").strip()
            if not v:
                raise ValueError("il nome della sede è obbligatorio")
        elif k == "role" and v not in ROLES:
            raise ValueError(f"ruolo non valido: {v}")
        elif k == "subnets":
            v = _clean_subnets(v)
        elif k == "probe" and probes is not None and v not in probes:
            raise ValueError(f"sonda '{v}' inesistente")
        elif k == "gateway":
            v = str(v or "").strip()
            if v:
                try:
                    ipaddress.ip_address(v)
                except ValueError:
                    raise ValueError(f"gateway non valido: {v}")
        out[k] = v
    return out


def apply_ops(org: str, locations: dict, links: dict, ops: list, probes=None):
    """Apply draft operations to copies of the whole locations and links
    tables (whole, because a new location's id must be unique across every
    organization). Returns (locations, links, refs); refs maps the «+…» ref
    of each created location to the id it got."""
    from services.probe_manager import _slugify
    locs, lnks, refs = copy.deepcopy(locations), copy.deepcopy(links), {}

    def loc_id(i, x):
        lid = refs.get(x, x)
        if lid not in locs or locs[lid]["org"] != org:
            raise OpError(i, f"sede '{x}' inesistente in questa organizzazione")
        return lid

    for i, op in enumerate(ops):
        kind = op.get("op")
        try:
            if kind == "create_location":
                fields = _clean_fields({"name": op.get("name"), "role": op.get("role") or "branch",
                                        "subnets": op.get("subnets") or [],
                                        "probe": op.get("probe") or "central",
                                        "gateway": op.get("gateway") or ""}, probes)
                ref = op.get("ref")
                if ref is not None and (not str(ref).startswith("+") or ref in refs):
                    raise ValueError(f"riferimento non valido: {ref}")
                wanted = op.get("id")
                lid = wanted if wanted and wanted not in locs else _free_id(wanted or _slugify(fields["name"]), locs)
                locs[lid] = dict(fields, org=org)
                if ref:
                    refs[ref] = lid
            elif kind in ("update_location", "set_gateway", "add_subnet"):
                lid = loc_id(i, op.get("id"))
                if kind == "update_location":
                    fields = op.get("fields")
                    if not isinstance(fields, dict) or not fields:
                        raise ValueError("nessun campo da modificare")
                elif kind == "set_gateway":
                    fields = {"gateway": op.get("ip")}
                else:
                    fields = {"subnets": locs[lid]["subnets"] + [op.get("subnet")]}
                locs[lid].update(_clean_fields(fields, probes))
            elif kind == "delete_location":
                lid = loc_id(i, op.get("id"))
                del locs[lid]
                lnks = {k: v for k, v in lnks.items() if lid not in (v["a"], v["b"])}
            elif kind == "add_link":
                a, b = loc_id(i, op.get("a")), loc_id(i, op.get("b"))
                if a == b:
                    raise ValueError("un collegamento unisce due sedi diverse")
                if op.get("kind") not in KINDS:
                    raise ValueError(f"tipo di collegamento non valido: {op.get('kind')}")
                k = link_id(a, b, op["kind"])
                if k in lnks:
                    raise ValueError("collegamento già presente")
                a, b = sorted((a, b))
                lnks[k] = {"org": org, "a": a, "b": b, "kind": op["kind"], "note": str(op.get("note") or "")}
            elif kind == "remove_link":
                k = op.get("id")
                if k not in lnks or lnks[k]["org"] != org:
                    raise ValueError(f"collegamento '{k}' inesistente")
                del lnks[k]
            else:
                raise ValueError(f"operazione sconosciuta: {kind}")
        except OpError:
            raise
        except ValueError as e:
            raise OpError(i, str(e))
    return locs, lnks, refs
```

(`combinations` is used by `preset_ops` in Task 5; keep the import.)

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_blueprint_model.py -v`
Expected: PASS.

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add services/blueprint_model.py tests/test_blueprint_model.py
git commit -m "feat(blueprint): draft operations applied to locations and links"
```

---

### Task 5: `blueprint_model` — diff, restore, presets

**Model:** opus

**Files:**
- Modify: `services/blueprint_model.py`
- Test: `tests/test_blueprint_model.py` (append)

**Interfaces:**
- Produces:
  - `diff(old: dict, new: dict) -> {"locations": part, "links": part}`, `part = {"added": [dict+id], "removed": [dict+id], "changed": [{"id", "label", "fields": {f: [old, new]}}]}`
  - `restore_ops(current: dict, target: dict) -> list` — views/snapshots in, ops out; created locations carry `"id"` (wanted) and `"ref": "+" + id`
  - `preset_ops(kind: str, n: int, view: dict) -> list` — raises `ValueError` on unknown kind or `n` outside `1..MAX_PRESET` (ignored for `single`)

- [ ] **Step 1: Write the failing tests** — append to `tests/test_blueprint_model.py`:

```python
class TestDiff(unittest.TestCase):
    def test_added_removed_changed(self):
        old = bm.org_view(LOCS, LINKS, "acme")
        locs, links, _ = apply([{"op": "delete_location", "id": "roma"},
                                {"op": "create_location", "ref": "+1", "name": "Torino"},
                                {"op": "set_gateway", "id": "milano", "ip": "10.10.0.1"}])
        d = bm.diff(old, bm.org_view(locs, links, "acme"))
        self.assertEqual([x["id"] for x in d["locations"]["added"]], ["torino"])
        self.assertEqual([x["id"] for x in d["locations"]["removed"]], ["roma"])
        self.assertEqual(d["locations"]["changed"],
                         [{"id": "milano", "label": "Milano", "fields": {"gateway": ["", "10.10.0.1"]}}])
        self.assertEqual([x["id"] for x in d["links"]["removed"]], ["milano--roma--vpn"])


class TestRestore(unittest.TestCase):
    def test_round_trip_back_to_the_target(self):
        target = bm.org_view(LOCS, LINKS, "acme")
        locs, links, _ = apply([{"op": "delete_location", "id": "roma"},
                                {"op": "create_location", "ref": "+1", "name": "Torino"},
                                {"op": "add_link", "a": "+1", "b": "milano", "kind": "wan"},
                                {"op": "update_location", "id": "milano", "fields": {"name": "HQ"}}])
        ops = bm.restore_ops(bm.org_view(locs, links, "acme"), target)
        back, back_links, _ = bm.apply_ops("acme", locs, links, ops, PROBES)
        self.assertEqual(bm.org_view(back, back_links, "acme"), target)

    def test_taken_id_comes_back_suffixed_with_its_links(self):
        target = bm.org_view(LOCS, LINKS, "acme")
        locs, links, _ = apply([{"op": "delete_location", "id": "roma"}])
        locs["roma"] = loc("Roma", org="beta")                # another org took the id meanwhile
        ops = bm.restore_ops(bm.org_view(locs, links, "acme"), target)
        back, back_links, refs = bm.apply_ops("acme", locs, links, ops, PROBES)
        self.assertEqual(refs["+roma"], "roma-2")
        self.assertIn("milano--roma-2--vpn", back_links)

    def test_nothing_to_do(self):
        view = bm.org_view(LOCS, LINKS, "acme")
        self.assertEqual(bm.restore_ops(view, view), [])


class TestPresets(unittest.TestCase):
    EMPTY = {"locations": {}, "links": {}}

    def run_preset(self, kind, n, view=None):
        view = view or self.EMPTY
        ops = bm.preset_ops(kind, n, view)
        locs, links, _ = bm.apply_ops("acme", dict(view["locations"]), dict(view["links"]), ops, PROBES)
        return locs, links

    def test_single(self):
        locs, _ = self.run_preset("single", 1)
        self.assertEqual([l["role"] for l in locs.values()], ["hq"])
        self.assertEqual(bm.preset_ops("single", 1, bm.org_view(LOCS, LINKS, "acme")), [])

    def test_hub_spoke_reuses_the_existing_hq(self):
        locs, links = self.run_preset("hub_spoke", 2, bm.org_view(LOCS, LINKS, "acme"))
        self.assertEqual(sum(1 for l in locs.values() if l["role"] == "hq"), 1)
        self.assertIn("filiale-2", locs)                       # Roma is branch 1
        self.assertEqual(set(links), {"milano--roma--vpn", "filiale-2--milano--vpn", "filiale-3--milano--vpn"})

    def test_hub_spoke_dc(self):
        locs, links = self.run_preset("hub_spoke_dc", 2)
        self.assertEqual(sorted(l["role"] for l in locs.values()), ["branch", "branch", "datacenter", "hq"])
        self.assertEqual(len(links), 1 + 2 * 2)

    def test_full_mesh(self):
        locs, links = self.run_preset("full_mesh", 4)
        self.assertEqual(len(locs), 4)
        self.assertEqual(len(links), 6)
        self.assertEqual(sum(1 for l in locs.values() if l["role"] == "hq"), 1)

    def test_bounds_and_unknown(self):
        for kind, n in (("hub_spoke", 0), ("hub_spoke", bm.MAX_PRESET + 1), ("ring", 3)):
            with self.subTest(kind=kind, n=n), self.assertRaises(ValueError):
                bm.preset_ops(kind, n, self.EMPTY)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_model.py -v`
Expected: FAIL — `AttributeError: module ... has no attribute 'diff'`.

- [ ] **Step 3: Implement** — append to `services/blueprint_model.py`:

```python
def diff(old: dict, new: dict) -> dict:
    def part(a, b, label):
        changed = []
        for k in sorted(set(a) & set(b)):
            fields = {f: [a[k].get(f), b[k].get(f)] for f in sorted(set(a[k]) | set(b[k]))
                      if f != "org" and a[k].get(f) != b[k].get(f)}
            if fields:
                changed.append({"id": k, "label": b[k].get(label) or k, "fields": fields})
        return {"added": [dict(b[k], id=k) for k in sorted(set(b) - set(a))],
                "removed": [dict(a[k], id=k) for k in sorted(set(a) - set(b))],
                "changed": changed}
    return {"locations": part(old["locations"], new["locations"], "name"),
            "links": part(old["links"], new["links"], "kind")}


def restore_ops(current: dict, target: dict) -> list:
    """The operations that turn ``current`` back into ``target``. A location
    deleted since asks for its old id; if another organization took it, it
    gets a suffix and its links follow it through the ref."""
    cur_l, tgt_l = current["locations"], target["locations"]
    cur_k, tgt_k = current["links"], target["links"]
    ops = [{"op": "remove_link", "id": k} for k in sorted(cur_k) if cur_k[k] != tgt_k.get(k)]
    ops += [{"op": "delete_location", "id": lid} for lid in sorted(set(cur_l) - set(tgt_l))]
    created = {}
    for lid in sorted(set(tgt_l) - set(cur_l)):
        created[lid] = "+" + lid
        ops.append(dict({f: tgt_l[lid].get(f, "") for f in FIELDS},
                        op="create_location", ref="+" + lid, id=lid))
    for lid in sorted(set(cur_l) & set(tgt_l)):
        fields = {f: tgt_l[lid].get(f, "") for f in FIELDS if cur_l[lid].get(f, "") != tgt_l[lid].get(f, "")}
        if fields:
            ops.append({"op": "update_location", "id": lid, "fields": fields})
    for k in sorted(tgt_k):
        if cur_k.get(k) != tgt_k[k]:
            t = tgt_k[k]
            ops.append({"op": "add_link", "a": created.get(t["a"], t["a"]), "b": created.get(t["b"], t["b"]),
                        "kind": t["kind"], "note": t.get("note") or ""})
    return ops


def preset_ops(kind: str, n: int, view: dict) -> list:
    """Topological skeleton as draft operations. Existing locations stay: an
    existing hq is the hub, an existing datacenter the DC; subnets are left
    empty for the checks to fill in."""
    if kind not in PRESETS:
        raise ValueError(f"Preset sconosciuto: {kind}")
    if kind != "single" and not 1 <= n <= MAX_PRESET:
        raise ValueError(f"Il numero di sedi va da 1 a {MAX_PRESET}.")
    locs, links = view["locations"], view["links"]
    ops = []

    def first(role):
        return next((lid for lid, l in sorted(locs.items()) if l["role"] == role), None)

    def new(name, role):
        ref = f"+{sum(1 for o in ops if o['op'] == 'create_location') + 1}"
        ops.append({"op": "create_location", "ref": ref, "name": name, "role": role,
                    "subnets": [], "probe": "central"})
        return ref

    def link(a, b, kind_):
        if not (a.startswith("+") or b.startswith("+")) and link_id(a, b, kind_) in links:
            return
        ops.append({"op": "add_link", "a": a, "b": b, "kind": kind_, "note": ""})

    if kind == "single":
        if not locs:
            new("Sede principale", "hq")
        return ops
    if kind == "full_mesh":
        members = sorted(locs)
        for i in range(n):
            members.append(new(f"Sede {len(locs) + i + 1}",
                               "hq" if i == 0 and first("hq") is None else "branch"))
        for a, b in combinations(members, 2):
            link(a, b, "vpn")
        return ops
    hub = first("hq") or new("Sede centrale", "hq")
    dc = None
    if kind == "hub_spoke_dc":
        dc = first("datacenter") or new("Datacenter", "datacenter")
        link(hub, dc, "wan")
    start = sum(1 for l in locs.values() if l["role"] == "branch")
    for i in range(n):
        b = new(f"Filiale {start + i + 1}", "branch")
        link(hub, b, "vpn")
        if dc:
            link(dc, b, "vpn")
    return ops
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_blueprint_model.py -v`
Expected: PASS.

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add services/blueprint_model.py tests/test_blueprint_model.py
git commit -m "feat(blueprint): revision diff, restore and preset operations"
```

---

### Task 6: Checks — model and subnets

**Model:** opus

**Files:**
- Create: `services/blueprint_checks.py`
- Test: `tests/test_blueprint_checks.py`

**Interfaces:**
- Consumes: `blueprint_model.apply_ops` (tests only: every proposal must apply).
- Produces:
  - `run(view: dict, observed: dict) -> list[Finding]` sorted by severity (`error, warning, unknown, info`) then code; `SEVERITY_ORDER`
  - `Finding = {"code", "severity", "subject": {"location"|"link"|"device": id}, "params": dict, "proposal": list[op] | None}`
  - `observed = {"devices": [host rows of the org], "arp": [{"ip", "source_ip"}], "routes": {gw_ip: {"rows": [{"network", "interface", "gateway"}], "error": str, "from_backup": bool}}, "tunnels": {gw_ip: {"tunnels": [{"name", "remote_gw", "up", "dst": [cidr]}], "error": str}}, "observed_at": str | None}`
  - Codes in this task: `subnet_overlap`, `location_no_subnets`, `location_isolated`, `location_no_gateway`, `gateway_not_in_location`, `device_outside_subnets`, `arp_uncovered`, `subnet_unused`

- [ ] **Step 1: Write the failing tests** — `tests/test_blueprint_checks.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Blueprint checks: plain dicts in, findings out, no network."""
import unittest

from services import blueprint_checks as bc
from services import blueprint_model as bm


def loc(name, role="branch", subnets=(), gateway=""):
    return {"org": "acme", "name": name, "role": role, "subnets": list(subnets), "probe": "central",
            "gateway": gateway}


def link(a, b, kind="vpn"):
    a, b = sorted((a, b))
    return {bm.link_id(a, b, kind): {"org": "acme", "a": a, "b": b, "kind": kind, "note": ""}}


def dev(ip, location, vendor="cisco"):
    return {"IP": ip, "Location": location, "Vendor": vendor, "Group": "acme", "Hostname": ""}


def obs(**kw):
    base = {"devices": [], "arp": [], "routes": {}, "tunnels": {}, "observed_at": None}
    base.update(kw)
    return base


def view(locations, links=None):
    return {"locations": locations, "links": links or {}}


def found(findings, code):
    return [f for f in findings if f["code"] == code]


class _Proposals(unittest.TestCase):
    def assertProposalsApply(self, v, findings):
        for f in findings:
            if f["proposal"]:
                bm.apply_ops("acme", v["locations"], v["links"], f["proposal"], {"central"})


class TestModelChecks(_Proposals):
    def test_overlap(self):
        v = view({"milano": loc("Milano", "hq", ["10.10.0.0/16"]), "roma": loc("Roma", subnets=["10.10.5.0/24"])})
        self.assertEqual(len(found(bc.run(v, obs()), "subnet_overlap")), 1)
        v["locations"]["roma"]["subnets"] = ["10.20.0.0/16"]
        self.assertEqual(found(bc.run(v, obs()), "subnet_overlap"), [])

    def test_no_subnets(self):
        v = view({"roma": loc("Roma")})
        self.assertEqual([f["subject"] for f in found(bc.run(v, obs()), "location_no_subnets")],
                         [{"location": "roma"}])

    def test_isolated_branch_proposes_a_vpn_to_the_hq(self):
        v = view({"milano": loc("Milano", "hq"), "roma": loc("Roma"), "torino": loc("Torino"),
                  "napoli": loc("Napoli")}, {**link("milano", "roma"), **link("roma", "torino")})
        fs = found(bc.run(v, obs()), "location_isolated")
        self.assertEqual([f["subject"]["location"] for f in fs], ["napoli"])   # torino reaches via roma
        self.assertEqual(fs[0]["proposal"], [{"op": "add_link", "a": "milano", "b": "napoli", "kind": "vpn", "note": ""}])
        self.assertProposalsApply(v, fs)

    def test_gateway_missing_one_candidate_or_several(self):
        v = view({"roma": loc("Roma", subnets=["10.20.0.0/16"])})
        one = obs(devices=[dev("10.20.0.1", "roma", "fortinet"), dev("10.20.0.9", "roma", "hp")])
        f = found(bc.run(v, one), "location_no_gateway")[0]
        self.assertEqual(f["proposal"], [{"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"}])
        self.assertProposalsApply(v, [f])
        two = obs(devices=[dev("10.20.0.1", "roma", "fortinet"), dev("10.20.0.2", "roma", "cisco")])
        f = found(bc.run(v, two), "location_no_gateway")[0]
        self.assertIsNone(f["proposal"])
        self.assertEqual(f["params"]["candidates"], ["10.20.0.1", "10.20.0.2"])

    def test_gateway_not_in_location(self):
        v = view({"roma": loc("Roma", subnets=["10.20.0.0/16"], gateway="10.20.0.1")})
        self.assertEqual(len(found(bc.run(v, obs(devices=[dev("10.20.0.1", "milano")])), "gateway_not_in_location")), 1)
        self.assertEqual(found(bc.run(v, obs(devices=[dev("10.20.0.1", "roma")])), "gateway_not_in_location"), [])


class TestSubnetChecks(_Proposals):
    def setUp(self):
        self.v = view({"milano": loc("Milano", "hq", ["10.10.0.0/16"], gateway="10.10.0.1"),
                       "roma": loc("Roma", subnets=["10.20.0.0/16"], gateway="10.20.0.1")})

    def test_device_outside_its_subnets(self):
        fs = found(bc.run(self.v, obs(devices=[dev("10.20.9.9", "milano")])), "device_outside_subnets")
        self.assertEqual((fs[0]["params"]["owner"], fs[0]["proposal"]), ("Roma", None))
        fs = found(bc.run(self.v, obs(devices=[dev("10.30.1.5", "milano")])), "device_outside_subnets")
        self.assertEqual(fs[0]["proposal"], [{"op": "add_subnet", "id": "milano", "subnet": "10.30.1.0/24"}])
        self.assertProposalsApply(self.v, fs)
        self.assertEqual(found(bc.run(self.v, obs(devices=[dev("10.10.1.5", "milano")])), "device_outside_subnets"), [])

    def test_arp_uncovered_private_only_and_both_proposals_apply(self):
        arp = [{"ip": "10.30.1.5", "source_ip": "10.20.0.1"}, {"ip": "10.30.1.6", "source_ip": "10.20.0.1"},
               {"ip": "10.31.0.7", "source_ip": "10.20.0.1"},
               {"ip": "203.0.113.9", "source_ip": "10.20.0.1"},      # ISP side: never proposed
               {"ip": "10.20.4.4", "source_ip": "10.20.0.1"},        # covered
               {"ip": "10.40.0.1", "source_ip": "192.0.2.77"}]       # not a gateway
        fs = found(bc.run(self.v, obs(arp=arp)), "arp_uncovered")
        self.assertEqual([(f["params"]["subnet"], f["params"]["count"]) for f in fs],
                         [("10.30.1.0/24", 2), ("10.31.0.0/24", 1)])
        ops = [op for f in fs for op in f["proposal"]]
        locs, _, _ = bm.apply_ops("acme", self.v["locations"], {}, ops, {"central"})
        self.assertEqual(locs["roma"]["subnets"], ["10.20.0.0/16", "10.30.1.0/24", "10.31.0.0/24"])

    def test_subnet_unused(self):
        fs = found(bc.run(self.v, obs(devices=[dev("10.10.0.1", "milano")])), "subnet_unused")
        self.assertEqual([f["params"]["subnet"] for f in fs], ["10.20.0.0/16"])

    def test_sorted_by_severity(self):
        v = view({"milano": loc("Milano", "hq", ["10.10.0.0/16"]), "roma": loc("Roma", subnets=["10.10.5.0/24"])})
        sev = [f["severity"] for f in bc.run(v, obs())]
        self.assertEqual(sev, sorted(sev, key=lambda s: bc.SEVERITY_ORDER[s]))
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_checks.py -v`
Expected: FAIL — `ImportError: cannot import name 'blueprint_checks'`.

- [ ] **Step 3: Implement** — `services/blueprint_checks.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic checks of the Network Blueprint (spec 2026-10-11
network-blueprint): the expected model against the observed snapshot.
Pure: no connection is ever opened here, the same inputs give the same
findings. A check that lacks its data says «unknown», never ok or error.

A finding may carry a proposal: draft operations that close the gap, which
the user accepts, edits or ignores."""
import ipaddress
from itertools import combinations

SEVERITY_ORDER = {"error": 0, "warning": 1, "unknown": 2, "info": 3}
HUB_ROLES = ("hq", "datacenter")
SPOKE_ROLES = ("branch", "warehouse")
# Vendors whose route table SentinelNet reads (route_table.ROUTE_SOURCES):
# the ones that can be a location's gateway for these checks.
GATEWAY_VENDORS = ("fortinet", "cisco")
# Spelled out: ip_address.is_private also says True for the documentation
# ranges (RFC 5737) and others that are never a location's LAN.
_LAN_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _f(code, severity, subject, proposal=None, **params) -> dict:
    return {"code": code, "severity": severity, "subject": subject, "params": params, "proposal": proposal}


def _net(text):
    try:
        return ipaddress.ip_network(str(text or "").strip().replace(" ", "/"), strict=False)
    except ValueError:
        return None


def _nets(subnets) -> list:
    return [n for n in (_net(s) for s in subnets or []) if n is not None]


def _addr(ip):
    try:
        return ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return None


def _covers(nets, ip) -> bool:
    # ip_address in ip_network does not compare versions: guard it.
    return any(n.version == ip.version and ip in n for n in nets)


def _slash24(ip) -> str:
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def _model_checks(locs: dict, links: dict, devices: list) -> list:
    out = []
    items = sorted(locs.items())
    for (ida, la), (idb, lb) in combinations(items, 2):
        for na in _nets(la["subnets"]):
            for nb in _nets(lb["subnets"]):
                if na.version == nb.version and na.overlaps(nb):
                    out.append(_f("subnet_overlap", "error", {"location": ida}, a=la["name"], b=lb["name"],
                                  subnet_a=str(na), subnet_b=str(nb)))
    for lid, l in items:
        if not l["subnets"]:
            out.append(_f("location_no_subnets", "warning", {"location": lid}, name=l["name"]))

    hubs = {lid for lid, l in items if l["role"] in HUB_ROLES}
    adj = {lid: set() for lid in locs}
    for k in links.values():
        adj[k["a"]].add(k["b"])
        adj[k["b"]].add(k["a"])
    reach, todo = set(hubs), list(hubs)
    while todo:
        for nxt in adj[todo.pop()] - reach:
            reach.add(nxt)
            todo.append(nxt)
    hub = next((lid for lid, l in items if l["role"] == "hq"), None) or next(iter(sorted(hubs)), None)
    for lid, l in items:
        if l["role"] in SPOKE_ROLES and lid not in reach:
            prop = [{"op": "add_link", "a": hub, "b": lid, "kind": "vpn", "note": ""}] if hub else None
            out.append(_f("location_isolated", "warning", {"location": lid}, prop, name=l["name"]))

    for lid, l in items:
        gw = l.get("gateway") or ""
        mine = [d for d in devices if d.get("Location") == lid]
        if not gw:
            cands = sorted(d["IP"] for d in mine if (d.get("Vendor") or "").lower() in GATEWAY_VENDORS)
            prop = [{"op": "set_gateway", "id": lid, "ip": cands[0]}] if len(cands) == 1 else None
            out.append(_f("location_no_gateway", "warning", {"location": lid}, prop,
                          name=l["name"], candidates=cands))
        elif not any(d.get("IP") == gw for d in mine):
            out.append(_f("gateway_not_in_location", "error", {"location": lid}, name=l["name"], ip=gw))
    return out


def _subnet_checks(locs: dict, devices: list, arp: list) -> list:
    out = []
    nets = {lid: _nets(l["subnets"]) for lid, l in locs.items()}
    all_nets = [n for ns in nets.values() for n in ns]

    for d in devices:
        lid, ip = d.get("Location"), _addr(d.get("IP"))
        if lid not in locs or ip is None or not nets[lid] or _covers(nets[lid], ip):
            continue
        owner = next((o for o, ns in sorted(nets.items()) if o != lid and _covers(ns, ip)), None)
        # Moving a device is an inventory write, not a model operation: when
        # another location owns the address the finding names it, no proposal.
        prop = None if owner or ip.version != 4 else \
            [{"op": "add_subnet", "id": lid, "subnet": _slash24(d["IP"])}]
        out.append(_f("device_outside_subnets", "warning", {"device": d["IP"]}, prop,
                      ip=d["IP"], name=locs[lid]["name"], owner=locs[owner]["name"] if owner else ""))

    gw_loc = {l["gateway"]: lid for lid, l in locs.items() if l.get("gateway")}
    seen = {}
    for e in arp:
        lid, ip = gw_loc.get(e.get("source_ip")), _addr(e.get("ip"))
        # RFC 1918 only: the ISP side of a WAN interface shows up in ARP too,
        # and a public /24 is never a location's subnet.
        if lid is None or ip is None or not _covers(_LAN_NETS, ip) or _covers(all_nets, ip):
            continue
        key = (lid, _slash24(str(ip)))
        seen[key] = seen.get(key, 0) + 1
    for (lid, net), count in sorted(seen.items()):
        out.append(_f("arp_uncovered", "warning", {"location": lid},
                      [{"op": "add_subnet", "id": lid, "subnet": net}],
                      name=locs[lid]["name"], subnet=net, count=count))

    used = [a for a in (_addr(x) for x in [d.get("IP") for d in devices] + [e.get("ip") for e in arp]) if a]
    for lid, ns in sorted(nets.items()):
        for n in ns:
            if not any(a.version == n.version and a in n for a in used):
                out.append(_f("subnet_unused", "info", {"location": lid}, name=locs[lid]["name"], subnet=str(n)))
    return out


def run(view: dict, observed: dict) -> list:
    locs, links = view["locations"], view["links"]
    devices = observed.get("devices") or []
    findings = _model_checks(locs, links, devices) + _subnet_checks(locs, devices, observed.get("arp") or [])
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["code"]))
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_blueprint_checks.py -v`
Expected: PASS.

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add services/blueprint_checks.py tests/test_blueprint_checks.py
git commit -m "feat(blueprint): model and subnet checks with proposals"
```

---

### Task 7: Checks — routing and VPN

**Model:** opus

**Files:**
- Modify: `services/blueprint_checks.py`
- Test: `tests/test_blueprint_checks.py` (append)

**Interfaces:**
- Produces: codes `link_no_route` (params `src, dst, subnet, via ∈ {"", "default"}, backup_only: bool`; `reason` for unknown), `route_without_link` (`src, dst, network, interface`), `vpn_link_down` (`side, other, state ∈ {"missing", "down", "unknown"}, tunnel`), `tunnel_without_link` (`src, dst, tunnel`). `run()` includes them.

- [ ] **Step 1: Write the failing tests** — append to `tests/test_blueprint_checks.py`:

```python
def routes(*rows, backup=False, error=""):
    return {"rows": [{"network": n, "interface": i, "gateway": ""} for n, i in rows],
            "error": error, "from_backup": backup}


class TestRoutingChecks(_Proposals):
    def setUp(self):
        self.v = view({"milano": loc("Milano", "hq", ["10.10.0.0/16"], gateway="10.10.0.1"),
                       "roma": loc("Roma", subnets=["10.20.0.0/16"], gateway="10.20.0.1")},
                      link("milano", "roma"))

    def test_route_present_both_ways(self):
        r = {"10.10.0.1": routes(("10.20.0.0/16", "vpn-roma")), "10.20.0.1": routes(("10.0.0.0/8", "vpn-mi"))}
        self.assertEqual(found(bc.run(self.v, obs(routes=r)), "link_no_route"), [])

    def test_missing_live_is_error_backup_is_warning_default_is_warning(self):
        r = {"10.10.0.1": routes(("10.99.0.0/16", "port1")), "10.20.0.1": routes(("10.10.0.0/16", "x"))}
        f = found(bc.run(self.v, obs(routes=r)), "link_no_route")
        self.assertEqual([(x["severity"], x["params"]["src"]) for x in f], [("error", "Milano")])
        r["10.10.0.1"] = routes(("10.99.0.0/16", "port1"), backup=True)
        f = found(bc.run(self.v, obs(routes=r)), "link_no_route")[0]
        self.assertEqual((f["severity"], f["params"]["backup_only"]), ("warning", True))
        r["10.10.0.1"] = routes(("0.0.0.0/0", "wan1"))
        f = found(bc.run(self.v, obs(routes=r)), "link_no_route")[0]
        self.assertEqual((f["severity"], f["params"]["via"]), ("warning", "default"))

    def test_unknown_without_routes_or_gateway(self):
        f = found(bc.run(self.v, obs()), "link_no_route")
        self.assertEqual({x["severity"] for x in f}, {"unknown"})
        self.assertEqual(len(f), 2)

    def test_route_without_link_proposes_once_per_pair(self):
        v = view(self.v["locations"])                             # no links
        r = {"10.10.0.1": routes(("10.20.0.0/16", "vpn-roma")), "10.20.0.1": routes(("10.10.0.0/16", "wan1"))}
        t = {"10.10.0.1": {"tunnels": [{"name": "vpn-roma", "remote_gw": "", "up": True, "dst": []}], "error": ""}}
        fs = found(bc.run(v, obs(routes=r, tunnels=t)), "route_without_link")
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["proposal"][0]["kind"], "vpn")
        self.assertProposalsApply(v, fs)


class TestVpnChecks(_Proposals):
    def setUp(self):
        self.v = view({"milano": loc("Milano", "hq", ["10.10.0.0/16"], gateway="10.10.0.1"),
                       "roma": loc("Roma", subnets=["10.20.0.0/16"], gateway="10.20.0.1")},
                      link("milano", "roma"))
        self.devs = [dev("10.10.0.1", "milano", "fortinet"), dev("10.20.0.1", "roma", "cisco")]

    def tunnels(self, *ts):
        return {"10.10.0.1": {"tunnels": list(ts), "error": ""}}

    def test_up_by_selector(self):
        t = self.tunnels({"name": "to-roma", "remote_gw": "198.51.100.7", "up": True, "dst": ["10.20.0.0/16"]})
        self.assertEqual(found(bc.run(self.v, obs(devices=self.devs, tunnels=t)), "vpn_link_down"), [])

    def test_down_missing_unknown(self):
        t = self.tunnels({"name": "to-roma", "remote_gw": "", "up": False, "dst": ["10.20.0.0/16"]})
        f = found(bc.run(self.v, obs(devices=self.devs, tunnels=t)), "vpn_link_down")
        self.assertEqual([(x["severity"], x["params"]["state"]) for x in f], [("error", "down")])
        f = found(bc.run(self.v, obs(devices=self.devs, tunnels=self.tunnels())), "vpn_link_down")
        self.assertEqual([x["params"]["state"] for x in f], ["missing"])
        f = found(bc.run(self.v, obs(devices=self.devs)), "vpn_link_down")
        self.assertEqual([(x["severity"], x["params"]["state"]) for x in f], [("unknown", "unknown")])

    def test_tunnel_without_link(self):
        v = view(self.v["locations"])
        t = self.tunnels({"name": "to-roma", "remote_gw": "", "up": True, "dst": ["10.20.0.0/24"]})
        fs = found(bc.run(v, obs(devices=self.devs, tunnels=t)), "tunnel_without_link")
        self.assertEqual(fs[0]["proposal"], [{"op": "add_link", "a": "milano", "b": "roma", "kind": "vpn", "note": ""}])
        self.assertProposalsApply(v, fs)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_checks.py -v`
Expected: FAIL — the new classes find no findings.

- [ ] **Step 3: Implement** — add to `services/blueprint_checks.py` (before `run`) and extend `run`:

```python
def _route_nets(entry) -> list:
    return [(n, row) for n, row in ((_net(r.get("network")), r) for r in entry.get("rows") or []) if n is not None]


def _routing_checks(locs: dict, links: dict, routes: dict, tunnels: dict) -> list:
    out = []
    for lkid, k in sorted(links.items()):
        for src, dst in ((k["a"], k["b"]), (k["b"], k["a"])):
            gw = locs[src].get("gateway")
            entry = routes.get(gw) if gw else None
            names = {"src": locs[src]["name"], "dst": locs[dst]["name"]}
            if not entry or not entry.get("rows"):
                out.append(_f("link_no_route", "unknown", {"link": lkid},
                              reason="no_gateway" if not gw else "no_routes", **names))
                continue
            nets = _route_nets(entry)
            for s in _nets(locs[dst]["subnets"]):
                if any(n.version == s.version and n.prefixlen > 0 and s.subnet_of(n) for n, _ in nets):
                    continue
                if any(n.version == s.version and n.prefixlen == 0 for n, _ in nets):
                    sev, via = "warning", "default"
                else:
                    # The backup only has static routes: a dynamic route may
                    # well exist, so a gap there is a warning, not an error.
                    sev, via = ("warning" if entry.get("from_backup") else "error"), ""
                out.append(_f("link_no_route", sev, {"link": lkid}, subnet=str(s), via=via,
                              backup_only=bool(entry.get("from_backup")), **names))

    linked = {frozenset((k["a"], k["b"])) for k in links.values()}
    proposed = set()
    for src, l in sorted(locs.items()):
        gw = l.get("gateway")
        entry = routes.get(gw) if gw else None
        if not entry:
            continue
        tnames = {t["name"] for t in (tunnels.get(gw) or {}).get("tunnels") or []}
        nets = _route_nets(entry)
        for dst, m in sorted(locs.items()):
            pair = frozenset((src, dst))
            if dst == src or pair in linked or pair in proposed:
                continue
            dnets = _nets(m["subnets"])
            hit = next((row for n, row in nets if n.prefixlen > 0
                        and any(n.version == s.version and n.overlaps(s) for s in dnets)), None)
            if hit:
                proposed.add(pair)
                kind = "vpn" if hit.get("interface") in tnames else "wan"
                out.append(_f("route_without_link", "info", {"location": src},
                              [{"op": "add_link", "a": src, "b": dst, "kind": kind, "note": ""}],
                              src=l["name"], dst=m["name"], network=hit.get("network") or "",
                              interface=hit.get("interface") or ""))
    return out


def _tunnel_matches(t: dict, other: dict) -> bool:
    gw = other.get("gateway") or ""
    if gw and t.get("remote_gw") == gw:
        return True
    dnets = _nets(other["subnets"])
    return any(any(n.version == s.version and n.overlaps(s) for s in dnets) for n in _nets(t.get("dst")))


def _vpn_checks(locs: dict, links: dict, tunnels: dict, devices: list) -> list:
    out = []
    vendor = {d.get("IP"): (d.get("Vendor") or "").lower() for d in devices}

    def side_tunnels(loc_id):
        """The location's gateway tunnels, or None when they are not known
        (no FortiGate gateway, or never collected)."""
        gw = locs[loc_id].get("gateway")
        data = tunnels.get(gw) if gw else None
        if not gw or vendor.get(gw) != "fortinet" or data is None:
            return None
        if data.get("error") and not data.get("tunnels"):
            return None
        return data.get("tunnels") or []

    for lkid, k in sorted(links.items()):
        if k["kind"] != "vpn":
            continue
        known = False
        for side, other in ((k["a"], k["b"]), (k["b"], k["a"])):
            ts = side_tunnels(side)
            if ts is None:
                continue
            known = True
            match = [t for t in ts if _tunnel_matches(t, locs[other])]
            names = {"side": locs[side]["name"], "other": locs[other]["name"]}
            if not match:
                out.append(_f("vpn_link_down", "error", {"link": lkid}, state="missing", tunnel="", **names))
            elif not any(t.get("up") for t in match):
                out.append(_f("vpn_link_down", "error", {"link": lkid}, state="down",
                              tunnel=match[0].get("name") or "", **names))
        if not known:
            out.append(_f("vpn_link_down", "unknown", {"link": lkid}, state="unknown", tunnel="",
                          side=locs[k["a"]]["name"], other=locs[k["b"]]["name"]))

    linked = {frozenset((k["a"], k["b"])) for k in links.values() if k["kind"] == "vpn"}
    proposed = set()
    for src, l in sorted(locs.items()):
        for t in side_tunnels(src) or []:
            if not t.get("up"):
                continue
            for dst, m in sorted(locs.items()):
                pair = frozenset((src, dst))
                if dst == src or pair in linked or pair in proposed or not _tunnel_matches(t, m):
                    continue
                proposed.add(pair)
                out.append(_f("tunnel_without_link", "info", {"location": src},
                              [{"op": "add_link", "a": src, "b": dst, "kind": "vpn", "note": ""}],
                              src=l["name"], dst=m["name"], tunnel=t.get("name") or ""))
    return out
```

`run` becomes:

```python
def run(view: dict, observed: dict) -> list:
    locs, links = view["locations"], view["links"]
    devices = observed.get("devices") or []
    routes, tunnels = observed.get("routes") or {}, observed.get("tunnels") or {}
    findings = (_model_checks(locs, links, devices)
                + _subnet_checks(locs, devices, observed.get("arp") or [])
                + _routing_checks(locs, links, routes, tunnels)
                + _vpn_checks(locs, links, tunnels, devices))
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["code"]))
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_blueprint_checks.py -v`
Expected: PASS.

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add services/blueprint_checks.py tests/test_blueprint_checks.py
git commit -m "feat(blueprint): routing and VPN checks"
```

---

### Task 8: Observed data — gather and live collection

**Model:** sonnet

**Files:**
- Create: `services/blueprint_observe.py`
- Test: `tests/test_blueprint_observe.py`

**Interfaces:**
- Consumes: `inventory_manager.get_all_devices`, `mac_history.search_arp`, `route_table.collect_for`, `route_table.routes_from_backup`, `route_table._cidr`, `fortigate_service.get_vpn_tunnels`, `probe_manager.is_agent_probe`, `blueprint_store.get_observation`/`put_observation`.
- Produces:
  - `gateways(org, view) -> list[tuple[str, dict]]` — `(location id, device row)` for each location whose gateway is a device of the organization
  - `observe(org, view) -> {"at": str, "gateways": {ip: {"routes": int, "routes_error": str, "tunnels": int | None, "tunnels_error": str}}}` — live, stores the snapshot
  - `gather(org, view) -> observed` (shape in Task 6)

- [ ] **Step 1: Write the failing tests** — `tests/test_blueprint_observe.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Observed data for the Blueprint checks: offline always, live on demand."""
import os
import tempfile
import unittest
from unittest.mock import patch

from services import blueprint_observe, fortigate_service, inventory_manager, probe_manager
from tests.conftest import seed_inventory

LOCS = {"milano": {"org": "acme", "name": "Milano", "role": "hq", "subnets": ["10.10.0.0/16"],
                   "probe": "central", "gateway": "10.10.0.1"},
        "roma": {"org": "acme", "name": "Roma", "role": "branch", "subnets": ["10.20.0.0/16"],
                 "probe": "central", "gateway": "10.20.0.1"}}
VIEW = {"locations": LOCS, "links": {}}
ROW = {"network": "10.20.0.0/16", "interface": "to-roma", "gateway": "", "from_backup": False}


class _Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="bp_obs_")
        for p in (patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv")),
                  patch.object(probe_manager, "PROBES_JSON", os.path.join(tmp, "probes.json"))):
            p.start()
            self.addCleanup(p.stop)
        seed_inventory(hosts=[
            {"IP": "10.10.0.1", "Group": "acme", "Vendor": "fortinet", "Location": "milano"},
            {"IP": "10.20.0.1", "Group": "acme", "Vendor": "cisco", "Location": "roma"},
            {"IP": "10.30.0.1", "Group": "beta", "Vendor": "cisco"}], locations=LOCS)
        p = patch("collectors.mac_history.search_arp", return_value=[
            {"ip": "10.30.1.5", "source_ip": "10.20.0.1", "mac": "aa:bb:cc:dd:ee:ff"}])
        self.search_arp = p.start()
        self.addCleanup(p.stop)


class TestObserve(_Base):
    def test_live_routes_and_tunnels_one_gateway_failing(self):
        def collect(dev):
            if dev["IP"] == "10.20.0.1":
                return {"device_ip": dev["IP"], "error": "timeout"}
            return {"device_ip": dev["IP"], "rows": [dict(ROW, device="x", vrf="")]}
        tunnels = {"source": "api", "data": [{"name": "to-roma", "rgwy": "198.51.100.7", "proxyid": [
            {"status": "up", "proxy_dst": [{"subnet": "10.20.0.0/255.255.0.0"}]}]}]}
        with patch("services.route_table.collect_for", side_effect=collect), \
                patch.object(fortigate_service, "get_vpn_tunnels", return_value=tunnels):
            summary = blueprint_observe.observe("acme", VIEW)
        self.assertEqual(summary["gateways"]["10.10.0.1"],
                         {"routes": 1, "routes_error": "", "tunnels": 1, "tunnels_error": ""})
        self.assertEqual(summary["gateways"]["10.20.0.1"]["routes_error"], "timeout")
        with patch("services.route_table.routes_from_backup", return_value=None):
            observed = blueprint_observe.gather("acme", VIEW)
        self.assertEqual(observed["tunnels"]["10.10.0.1"]["tunnels"],
                         [{"name": "to-roma", "remote_gw": "198.51.100.7", "up": True, "dst": ["10.20.0.0/16"]}])
        self.assertEqual(observed["routes"]["10.10.0.1"]["from_backup"], False)
        self.assertEqual(observed["observed_at"], summary["at"])

    def test_tunnel_error_is_kept(self):
        with patch("services.route_table.collect_for", return_value={"rows": []}), \
                patch.object(fortigate_service, "get_vpn_tunnels",
                             side_effect=fortigate_service.FortiGateError("401")):
            summary = blueprint_observe.observe("acme", VIEW)
        self.assertEqual(summary["gateways"]["10.10.0.1"]["tunnels_error"], "401")


class TestGather(_Base):
    def test_offline_sources_only_the_org(self):
        backup = {"rows": [dict(ROW, from_backup=True)]}
        with patch("services.route_table.routes_from_backup", return_value=backup):
            observed = blueprint_observe.gather("acme", VIEW)
        self.assertEqual(sorted(d["IP"] for d in observed["devices"]), ["10.10.0.1", "10.20.0.1"])
        self.assertEqual(observed["arp"], [{"ip": "10.30.1.5", "source_ip": "10.20.0.1"}])
        self.assertEqual(self.search_arp.call_args.kwargs["tenants"], ["acme"])
        self.assertEqual(observed["routes"]["10.10.0.1"]["from_backup"], True)
        self.assertEqual((observed["tunnels"], observed["observed_at"]), ({}, None))
```

(`198.51.100.7` is RFC 5737, which `check_no_private_data.py` accepts.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_observe.py -v`
Expected: FAIL — `ImportError: cannot import name 'blueprint_observe'`.

- [ ] **Step 3: Implement** — `services/blueprint_observe.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""What the Blueprint checks compare the model with (spec 2026-10-11
network-blueprint). gather() reads only what the product already has —
inventory, ARP, the stored snapshot, static routes from backups — and opens
no connection. observe() is the explicit «Aggiorna dai gateway»: live routes
and IPsec tunnels of each location's gateway, stored as the snapshot."""
from services import blueprint_store, fortigate_service, inventory_manager, probe_manager, route_table


def _slim(rows) -> list:
    return [{"network": r.get("network") or "", "interface": r.get("interface") or "",
             "gateway": r.get("gateway") or "", "from_backup": bool(r.get("from_backup"))} for r in rows or []]


def gateways(org: str, view: dict) -> list:
    devs = {d["IP"]: d for d in inventory_manager.get_all_devices() if d.get("Group") == org}
    return [(lid, devs[l["gateway"]]) for lid, l in sorted(view["locations"].items())
            if l.get("gateway") in devs]


def _tunnels(device) -> dict:
    if probe_manager.is_agent_probe(device.get("Probe") or "central"):
        return {"tunnels": [], "error": "sede in modalita' agent: il centrale non raggiunge l'apparato"}
    try:
        data = fortigate_service.get_vpn_tunnels(device).get("data")
    except fortigate_service.FortiGateError as e:
        return {"tunnels": [], "error": str(e)}
    if not isinstance(data, list):
        return {"tunnels": [], "error": "solo testo CLI: tunnel non leggibili"}
    out = []
    for t in data:
        if not isinstance(t, dict) or not t.get("name"):
            continue
        proxies = [p for p in t.get("proxyid") or [] if isinstance(p, dict)]
        dst = sorted({route_table._cidr(s.get("subnet")) for p in proxies
                      for s in p.get("proxy_dst") or [] if isinstance(s, dict) and s.get("subnet")})
        # Up when at least one phase-2 selector is, as route_table reads it.
        out.append({"name": t["name"], "remote_gw": t.get("rgwy") or "",
                    "up": any(p.get("status") == "up" for p in proxies), "dst": dst})
    return {"tunnels": out, "error": ""}


def observe(org: str, view: dict) -> dict:
    data, summary = {}, {}
    for _lid, dev in gateways(org, view):
        answer = route_table.collect_for(dev)
        entry = {"routes": {"rows": _slim(answer.get("rows")), "error": answer.get("error") or ""}}
        if (dev.get("Vendor") or "").lower() == "fortinet":
            entry["tunnels"] = _tunnels(dev)
        data[dev["IP"]] = entry
        t = entry.get("tunnels")
        summary[dev["IP"]] = {"routes": len(entry["routes"]["rows"]), "routes_error": entry["routes"]["error"],
                              "tunnels": len(t["tunnels"]) if t else None,
                              "tunnels_error": t["error"] if t else ""}
    with inventory_manager._db() as conn, conn:
        at = blueprint_store.put_observation(conn, org, data)
    return {"at": at, "gateways": summary}


def gather(org: str, view: dict) -> dict:
    from collectors import mac_history
    devices = [d for d in inventory_manager.get_all_devices() if d.get("Group") == org]
    # ponytail: the 5000 most recent bindings (search_arp's ceiling); a paged
    # read if an organization ever has more live endpoints than that.
    arp = [{"ip": e.get("ip"), "source_ip": e.get("source_ip")}
           for e in mac_history.search_arp(tenants=[org], limit=5000)]
    with inventory_manager._db() as conn:
        obs = blueprint_store.get_observation(conn, org)
    live = obs["data"] if obs else {}
    routes, tunnels = {}, {}
    for _lid, dev in gateways(org, view):
        ip = dev["IP"]
        if ip in live:
            r = live[ip]["routes"]
            routes[ip] = {"rows": r["rows"], "error": r["error"],
                          "from_backup": bool(r["rows"]) and all(x["from_backup"] for x in r["rows"])}
            if "tunnels" in live[ip]:
                tunnels[ip] = live[ip]["tunnels"]
        else:
            backup = route_table.routes_from_backup(dev)
            if backup and backup.get("rows"):
                routes[ip] = {"rows": _slim(backup["rows"]), "error": "", "from_backup": True}
    return {"devices": devices, "arp": arp, "routes": routes, "tunnels": tunnels,
            "observed_at": obs["at"] if obs else None}
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_blueprint_observe.py -v`
Expected: PASS.

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add services/blueprint_observe.py tests/test_blueprint_observe.py
git commit -m "feat(blueprint): observed data, offline and from the gateways"
```

---

### Task 9: Service and API

**Model:** opus

**Files:**
- Create: `services/blueprint.py`, `routers/blueprint.py`
- Modify: `app_server.py` (include the router next to `_locations_router`)
- Modify: `tests/test_tab_enforcement.py` (one `TAB_GET_ROUTES` line)
- Test: `tests/test_blueprint_api.py`

**Interfaces:**
- Consumes: Tasks 2–8.
- Produces (`services/blueprint.py`):
  - `class Conflict(Exception)`
  - `state(org) -> {"org", "locations", "links", "rev", "rev_info", "draft", "preview", "draft_error", "probes": [{"id", "name"}]}`
  - `checks(org) -> {"findings", "observed_at"}`
  - `add_ops(org, ops, source, by)`, `replace_ops(org, ops, by)`, `align(org, by)`, `preset(org, kind, n, by)`, `restore(org, rev, by)` → `state(org)`; `discard(org) -> None`
  - `apply(org, by, note) -> {"rev": int, "renamed": {wanted: actual}}`
  - `diff(org, a, b)`, `revisions(org)`, `revision(org, rev)`, `observe(org)`
  - Errors: `blueprint_model.OpError`/`ValueError` → 422, `LookupError` → 404, `Conflict` → 409.
- Produces (HTTP): the table in the spec (`/api/blueprint/{org}`, `/checks`, `/observe`, `/draft` POST/PUT, `/draft/apply`, `/draft/discard`, `/draft/align`, `/revisions`, `/revisions/{n}`, `/diff?a=&b=`).

- [ ] **Step 1: Write the failing tests** — `tests/test_blueprint_api.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""/api/blueprint: drafts, apply, revisions, restore (spec 2026-10-11)."""
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from routers.deps import CSRF_HEADER
from security import security_manager, user_manager
from services import blueprint_observe, blueprint_store, inventory_manager, location_manager, probe_manager
from tests.conftest import seed_inventory

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"
LOCS = {"milano": {"org": "acme", "name": "Milano", "role": "hq", "subnets": ["10.10.0.0/16"], "probe": "central"},
        "roma": {"org": "acme", "name": "Roma", "role": "branch", "subnets": ["10.20.0.0/16"], "probe": "central"}}
EMPTY_OBS = {"devices": [], "arp": [], "routes": {}, "tunnels": {}, "observed_at": None}


class _Api(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="bp_api_")
        for p in (patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv")),
                  patch.object(probe_manager, "PROBES_JSON", os.path.join(tmp, "probes.json")),
                  patch.object(user_manager, "USERS_JSON", os.path.join(tmp, "users.json")),
                  patch.object(blueprint_observe, "gather", return_value=EMPTY_OBS)):
            p.start()
            self.addCleanup(p.stop)
        security_manager._failed_attempts.clear()
        seed_inventory(orgs=["acme", "beta"], locations=LOCS)
        with inventory_manager._db() as conn, conn:
            blueprint_store.record_revisions(conn, "", "migration")
        user_manager.create_user("adm", PW, role="admin")
        user_manager.create_user("admbeta", PW, role="admin", groups=["beta"])
        user_manager.create_user("view", PW, role="viewer")
        self.c = self._as("adm")

    def _as(self, name):
        c = TestClient(app_server.app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", json={"username": name, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        c.headers.update(H)
        return c

    def draft(self, body):
        return self.c.post("/api/blueprint/acme/draft", json=body)


class TestAccess(_Api):
    def test_state_checks_and_gates(self):
        r = self.c.get("/api/blueprint/acme")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((sorted(r.json()["locations"]), r.json()["rev"], r.json()["draft"]),
                         (["milano", "roma"], 1, None))
        self.assertEqual(self.c.get("/api/blueprint/acme/checks").status_code, 200)
        self.assertEqual(self._as("admbeta").get("/api/blueprint/acme").status_code, 403)
        self.assertEqual(self._as("view").post("/api/blueprint/acme/draft", json={"ops": []}).status_code, 403)
        self.assertEqual(self.c.get("/api/blueprint/nobody").status_code, 404)


class TestDraftFlow(_Api):
    def test_preset_apply_revisions_diff(self):
        r = self.draft({"preset": "hub_spoke", "n": 2})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(len(r.json()["draft"]["ops"]), 4)                    # 2 branches + 2 links
        self.assertIn("filiale-3", r.json()["preview"]["locations"])
        r = self.c.post("/api/blueprint/acme/draft/apply", json={"note": "prime filiali"})
        self.assertEqual(r.json(), {"rev": 2, "renamed": {}})
        revs = self.c.get("/api/blueprint/acme/revisions").json()["revisions"]
        self.assertEqual((revs[0]["rev"], revs[0]["source"], revs[0]["note"]), (2, "blueprint", "prime filiali"))
        d = self.c.get("/api/blueprint/acme/diff", params={"a": 1, "b": 2}).json()
        self.assertEqual([x["id"] for x in d["locations"]["added"]], ["filiale-2", "filiale-3"])
        self.assertIsNone(self.c.get("/api/blueprint/acme").json()["draft"])

    def test_invalid_op_is_422_with_its_index(self):
        r = self.draft({"ops": [{"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"},
                                {"op": "add_link", "a": "roma", "b": "roma", "kind": "vpn"}]})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.json()["detail"]["index"], 1)
        self.assertIsNone(self.c.get("/api/blueprint/acme").json()["draft"])

    def test_replace_and_discard(self):
        self.draft({"ops": [{"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"},
                            {"op": "add_subnet", "id": "roma", "subnet": "10.21.0.0/24"}]})
        r = self.c.put("/api/blueprint/acme/draft", json={"ops": [{"op": "set_gateway", "id": "roma", "ip": "10.20.0.2"}]})
        self.assertEqual(len(r.json()["draft"]["ops"]), 1)
        self.assertEqual(self.c.post("/api/blueprint/acme/draft/discard").status_code, 200)
        self.assertIsNone(self.c.get("/api/blueprint/acme").json()["draft"])

    def test_stale_draft_is_409_until_aligned(self):
        self.draft({"ops": [{"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"}]})
        location_manager.update_location("milano", name="Milano HQ", by="anna")
        r = self.c.post("/api/blueprint/acme/draft/apply", json={})
        self.assertEqual(r.status_code, 409)
        self.assertEqual(location_manager.get_location("roma")["gateway"], "")
        self.assertEqual(self.c.post("/api/blueprint/acme/draft/align").status_code, 200)
        r = self.c.post("/api/blueprint/acme/draft/apply", json={})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(location_manager.get_location("roma")["gateway"], "10.20.0.1")

    def test_delete_with_devices_refused_with_count(self):
        seed_inventory(hosts=[{"IP": "10.20.0.5", "Group": "acme", "Location": "roma"}], locations=LOCS)
        self.draft({"ops": [{"op": "delete_location", "id": "roma"}]})
        r = self.c.post("/api/blueprint/acme/draft/apply", json={})
        self.assertEqual(r.status_code, 422)
        self.assertIn("1 apparati", r.json()["detail"]["message"])
        self.assertIsNotNone(location_manager.get_location("roma"))

    def test_restore_round_trip_and_renamed_id(self):
        self.draft({"ops": [{"op": "delete_location", "id": "roma"},
                            {"op": "update_location", "id": "milano", "fields": {"name": "HQ"}}]})
        self.c.post("/api/blueprint/acme/draft/apply", json={})
        location_manager.create_location("beta", "Roma", by="x")         # takes the id «roma»
        r = self.draft({"restore": 1})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["draft"]["source"], "restore")
        r = self.c.post("/api/blueprint/acme/draft/apply", json={})
        self.assertEqual(r.json()["renamed"], {"roma": "roma-2"})
        state = self.c.get("/api/blueprint/acme").json()
        self.assertEqual(sorted(l["name"] for l in state["locations"].values()), ["Milano", "Roma"])
        revs = self.c.get("/api/blueprint/acme/revisions").json()["revisions"]
        self.assertEqual(revs[0]["source"], "restore")

    def test_observe_runs_the_live_collection(self):
        with patch.object(blueprint_observe, "observe", return_value={"at": "now", "gateways": {}}) as obs:
            r = self.c.post("/api/blueprint/acme/observe")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(obs.call_args.args[0], "acme")
```

In `tests/test_tab_enforcement.py`, add to `TAB_GET_ROUTES`:

```python
    ("/api/blueprint/acme", "tab-blueprint"),
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_api.py -v`
Expected: FAIL — 404 on every `/api/blueprint` route.

- [ ] **Step 3: Implement** — `services/blueprint.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Network Blueprint (spec 2026-10-11 network-blueprint): drafts over an
organization's locations and links, applied in one transaction, every write
versioned. Storage in blueprint_store, pure logic in blueprint_model, checks
in blueprint_checks, observed data in blueprint_observe."""
from services import (blueprint_checks, blueprint_model, blueprint_observe, blueprint_store,
                      inventory_manager, inventory_store, location_manager, probe_manager)


class Conflict(Exception):
    """The model changed after the draft was made from it."""


def _probes() -> set:
    return {p["id"] for p in probe_manager.list_probes()}


def _tables(conn):
    return inventory_store.read_locations(conn), inventory_store.read_links(conn)


def _preview(org, locs, links, draft):
    if not draft:
        return None, ""
    try:
        new_locs, new_links, _ = blueprint_model.apply_ops(org, locs, links, draft["ops"], _probes())
    except blueprint_model.OpError as e:
        return None, str(e)
    return blueprint_model.org_view(new_locs, new_links, org), ""


def state(org: str) -> dict:
    with inventory_manager._db() as conn:
        locs, links = _tables(conn)
        draft = blueprint_store.get_draft(conn, org)
        revs = blueprint_store.revisions(conn, org)
    preview, error = _preview(org, locs, links, draft)
    view = blueprint_model.org_view(locs, links, org)
    return {"org": org, "locations": view["locations"], "links": view["links"],
            "rev": revs[0]["rev"] if revs else 0, "rev_info": revs[0] if revs else None,
            "draft": draft, "preview": preview, "draft_error": error,
            "probes": [{"id": p["id"], "name": p.get("name") or p["id"]} for p in probe_manager.list_probes()]}


def checks(org: str) -> dict:
    """Findings on the model with the draft applied in memory: a proposal
    already in the draft does not come back."""
    st = state(org)
    view = st["preview"] or {"locations": st["locations"], "links": st["links"]}
    observed = blueprint_observe.gather(org, view)
    return {"findings": blueprint_checks.run(view, observed), "observed_at": observed.get("observed_at")}


def _with_unique_refs(existing: list, new: list) -> list:
    """Rename the refs the new operations define when the draft already uses
    them (two presets both start at «+1»)."""
    used = {o["ref"] for o in existing if o.get("ref")}
    mapping = {}
    for o in new:
        r = o.get("ref")
        if not r:
            continue
        fresh, n = r, 2
        while fresh in used:
            fresh, n = f"{r}.{n}", n + 1
        used.add(fresh)
        mapping[r] = fresh
    return [dict(o, **{k: mapping.get(o[k], o[k]) for k in ("ref", "id", "a", "b") if k in o}) for o in new]


def add_ops(org: str, ops: list, source: str, by: str) -> dict:
    with location_manager._lock, inventory_manager._db() as conn:
        locs, links = _tables(conn)
        draft = blueprint_store.get_draft(conn, org)
        old = draft["ops"] if draft else []
        new = _with_unique_refs(old, [dict(o, source=source) for o in ops])
        if not new:
            raise ValueError("Nessuna modifica da aggiungere.")
        blueprint_model.apply_ops(org, locs, links, old + new, _probes())
        base = draft["base_rev"] if draft else blueprint_store.latest_rev(conn, org)
        with conn:
            blueprint_store.put_draft(conn, org, base, draft["source"] if draft else source, old + new, by)
    return state(org)


def replace_ops(org: str, ops: list, by: str) -> dict:
    with location_manager._lock, inventory_manager._db() as conn:
        draft = blueprint_store.get_draft(conn, org)
        if not draft:
            raise LookupError("Nessuna bozza aperta.")
        locs, links = _tables(conn)
        blueprint_model.apply_ops(org, locs, links, ops, _probes())
        with conn:
            if ops:
                blueprint_store.put_draft(conn, org, draft["base_rev"], draft["source"], ops, by)
            else:
                blueprint_store.delete_draft(conn, org)
    return state(org)


def discard(org: str) -> None:
    with location_manager._lock, inventory_manager._db() as conn, conn:
        blueprint_store.delete_draft(conn, org)


def align(org: str, by: str) -> dict:
    with location_manager._lock, inventory_manager._db() as conn:
        draft = blueprint_store.get_draft(conn, org)
        if not draft:
            raise LookupError("Nessuna bozza aperta.")
        with conn:
            blueprint_store.put_draft(conn, org, blueprint_store.latest_rev(conn, org),
                                      draft["source"], draft["ops"], by)
    return state(org)


def apply(org: str, by: str, note: str) -> dict:
    with location_manager._lock, inventory_manager._db() as conn:
        draft = blueprint_store.get_draft(conn, org)
        if not draft:
            raise LookupError("Nessuna bozza aperta.")
        current = blueprint_store.latest_rev(conn, org)
        if draft["base_rev"] != current:
            raise Conflict(f"Il modello è cambiato dopo la bozza: revisione {draft['base_rev']} → {current}.")
        locs, links = _tables(conn)
        new_locs, new_links, refs = blueprint_model.apply_ops(org, locs, links, draft["ops"], _probes())
        for lid in sorted(set(locs) - set(new_locs)):
            n = location_manager.devices_in(lid)
            if n:
                raise ValueError(f"La sede '{locs[lid]['name']}' contiene {n} apparati: spostali o eliminali prima.")
        source = "restore" if draft["source"] == "restore" else "blueprint"
        with conn:
            inventory_store.put_locations(conn, new_locs)
            inventory_store.put_links(conn, new_links)
            blueprint_store.record_revisions(conn, by, source, note)
            blueprint_store.delete_draft(conn, org)
        rev = blueprint_store.latest_rev(conn, org)
    renamed = {r[1:]: lid for r, lid in refs.items() if source == "restore" and r[1:] != lid}
    return {"rev": rev, "renamed": renamed}


def restore(org: str, rev: int, by: str) -> dict:
    with location_manager._lock, inventory_manager._db() as conn:
        if blueprint_store.get_draft(conn, org):
            raise ValueError("C'è già una bozza aperta: applicala o scartala prima del ripristino.")
        target = blueprint_store.revision(conn, org, rev)
        if not target:
            raise LookupError(f"Revisione {rev} inesistente.")
        locs, links = _tables(conn)
        ops = blueprint_model.restore_ops(blueprint_model.org_view(locs, links, org), target["snapshot"])
        if not ops:
            raise ValueError(f"Il modello è già uguale alla revisione {rev}.")
        ops = [dict(o, source="restore") for o in ops]
        blueprint_model.apply_ops(org, locs, links, ops, _probes())
        with conn:
            blueprint_store.put_draft(conn, org, blueprint_store.latest_rev(conn, org), "restore", ops, by)
    return state(org)


def preset(org: str, kind: str, n: int, by: str) -> dict:
    st = state(org)
    view = st["preview"] or {"locations": st["locations"], "links": st["links"]}
    ops = blueprint_model.preset_ops(kind, n, view)
    if not ops:
        raise ValueError("Il preset non aggiunge nulla a questo modello.")
    return add_ops(org, ops, "preset", by)


def diff(org: str, a: int, b: int) -> dict:
    with inventory_manager._db() as conn:
        ra, rb = blueprint_store.revision(conn, org, a), blueprint_store.revision(conn, org, b)
    if not ra or not rb:
        raise LookupError("Revisione inesistente.")
    return blueprint_model.diff(ra["snapshot"], rb["snapshot"])


def revisions(org: str) -> list:
    with inventory_manager._db() as conn:
        return blueprint_store.revisions(conn, org)


def revision(org: str, rev: int) -> dict:
    with inventory_manager._db() as conn:
        r = blueprint_store.revision(conn, org, rev)
    if not r:
        raise LookupError(f"Revisione {rev} inesistente.")
    return r


def observe(org: str) -> dict:
    st = state(org)
    return blueprint_observe.observe(org, {"locations": st["locations"], "links": st["links"]})
```

`routers/blueprint.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router Network Blueprint (spec 2026-10-11 network-blueprint)."""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers.deps import assert_group_allowed, get_current_user, require_admin, require_tab
from security.security_manager import log_audit
from services import blueprint, inventory_manager

router = APIRouter(tags=["Blueprint"])
_TAB = [Depends(require_tab("tab-blueprint"))]
# Sources a client may name; «preset» and «restore» are set by the server.
_CLIENT_SOURCES = ("manual", "checks")


class DraftAddSchema(BaseModel):
    ops: List[dict] = []
    source: str = "manual"
    preset: Optional[str] = None
    n: int = 1
    restore: Optional[int] = None


class DraftReplaceSchema(BaseModel):
    ops: List[dict]


class ApplySchema(BaseModel):
    note: str = ""


def _org(org: str, user) -> None:
    assert_group_allowed(user, org)
    if org not in inventory_manager.get_all_groups():
        raise HTTPException(status_code=404, detail={"message": f"Organizzazione '{org}' inesistente."})


def _call(fn, *args):
    try:
        return fn(*args)
    except blueprint.Conflict as e:
        raise HTTPException(status_code=409, detail={"message": str(e)})
    except LookupError as e:
        raise HTTPException(status_code=404, detail={"message": str(e)})
    except ValueError as e:
        raise HTTPException(status_code=422, detail={"message": str(e), "index": getattr(e, "index", None)})


@router.get("/api/blueprint/{org}", dependencies=_TAB)
def state_ep(org: str, current_user=Depends(get_current_user)):
    _org(org, current_user)
    return blueprint.state(org)


@router.get("/api/blueprint/{org}/checks", dependencies=_TAB)
def checks_ep(org: str, current_user=Depends(get_current_user)):
    _org(org, current_user)
    return blueprint.checks(org)


@router.post("/api/blueprint/{org}/observe", dependencies=_TAB)
def observe_ep(org: str, current_user=Depends(require_admin)):
    _org(org, current_user)
    out = blueprint.observe(org)
    log_audit(f"Blueprint '{org}': dati raccolti da {len(out['gateways'])} gateway "
              f"dall'utente '{current_user.get('sub')}'.")
    return out


@router.post("/api/blueprint/{org}/draft", dependencies=_TAB)
def draft_add_ep(org: str, payload: DraftAddSchema, current_user=Depends(require_admin)):
    _org(org, current_user)
    who = current_user.get("sub")
    if payload.restore is not None:
        out = _call(blueprint.restore, org, payload.restore, who)
        log_audit(f"Blueprint '{org}': bozza di ripristino alla revisione {payload.restore} "
                  f"aperta dall'utente '{who}'.")
        return out
    if payload.preset is not None:
        return _call(blueprint.preset, org, payload.preset, payload.n, who)
    if payload.source not in _CLIENT_SOURCES:
        raise HTTPException(status_code=422, detail={"message": f"Origine non valida: {payload.source}", "index": None})
    return _call(blueprint.add_ops, org, payload.ops, payload.source, who)


@router.put("/api/blueprint/{org}/draft", dependencies=_TAB)
def draft_replace_ep(org: str, payload: DraftReplaceSchema, current_user=Depends(require_admin)):
    _org(org, current_user)
    return _call(blueprint.replace_ops, org, payload.ops, current_user.get("sub"))


@router.post("/api/blueprint/{org}/draft/apply", dependencies=_TAB)
def draft_apply_ep(org: str, payload: ApplySchema, current_user=Depends(require_admin)):
    _org(org, current_user)
    who = current_user.get("sub")
    out = _call(blueprint.apply, org, who, payload.note)
    log_audit(f"Blueprint '{org}': bozza applicata (revisione {out['rev']}) dall'utente '{who}'.")
    return out


@router.post("/api/blueprint/{org}/draft/discard", dependencies=_TAB)
def draft_discard_ep(org: str, current_user=Depends(require_admin)):
    _org(org, current_user)
    blueprint.discard(org)
    log_audit(f"Blueprint '{org}': bozza scartata dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}


@router.post("/api/blueprint/{org}/draft/align", dependencies=_TAB)
def draft_align_ep(org: str, current_user=Depends(require_admin)):
    _org(org, current_user)
    return _call(blueprint.align, org, current_user.get("sub"))


@router.get("/api/blueprint/{org}/revisions", dependencies=_TAB)
def revisions_ep(org: str, current_user=Depends(get_current_user)):
    _org(org, current_user)
    return {"revisions": blueprint.revisions(org)}


@router.get("/api/blueprint/{org}/revisions/{rev}", dependencies=_TAB)
def revision_ep(org: str, rev: int, current_user=Depends(get_current_user)):
    _org(org, current_user)
    return _call(blueprint.revision, org, rev)


@router.get("/api/blueprint/{org}/diff", dependencies=_TAB)
def diff_ep(org: str, a: int, b: int, current_user=Depends(get_current_user)):
    _org(org, current_user)
    return _call(blueprint.diff, org, a, b)
```

`app_server.py`, next to the locations router:

```python
from routers import blueprint as _blueprint_router
app.include_router(_blueprint_router.router)
```

(`_call` maps `OpError` to 422 because it subclasses `ValueError`.)

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_blueprint_api.py tests/test_tab_enforcement.py -v`
Expected: PASS.

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add services/blueprint.py routers/blueprint.py app_server.py tests/test_blueprint_api.py tests/test_tab_enforcement.py
git commit -m "feat(blueprint): drafts, apply, restore and history API"
```

---

### Task 10: The Blueprint tab

**Model:** opus

**Files:**
- Modify: `templates/dashboard.html` (nav button after `tab-groups`'s, panel after `#tab-groups`, modals after `#locationModal`)
- Create: `static/js/blueprint.js`
- Modify: `static/js/core.js` (`LAZY_TAB_SCRIPTS`, `switchTab` dispatch, command palette list)
- Modify: `static/js/settings.js` (`ADMIN_GROUP_TABS`)
- Modify: `static/js/devices.js` (`renderGroupsTable` action + `groupsTableBody` listener)
- Modify: `static/js/i18n.js`, `types/globals.d.ts`, `static/css/dashboard.css`
- Test: `tests/test_blueprint_tab.py`

**Interfaces:**
- Consumes: the API of Task 9; globals `globalGroups`, `orgLabel`, `apiFetch`, `tr`, `escapeHtml`, `showToast`, `openModal`, `closeModal`, `switchTab`, `canOpenTab`, `vis`.
- Produces: `window.loadBlueprintTab` (called by `switchTab`), `window.bpPendingOrg` (set by the Organizations row action).

- [ ] **Step 1: Write the failing test** — `tests/test_blueprint_tab.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The Blueprint tab must be wired, translated and lazily loaded."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
IDS = ("bpOrgSelect", "bpRevInfo", "bpObsInfo", "btnBpCheck", "btnBpObserve", "btnBpPreset", "btnBpHistory",
       "bpSteps", "bpStepsList", "bpDraftBar", "bpDraftInfo", "btnBpDraftReview", "btnBpDraftApply",
       "btnBpDraftDiscard", "bpLocationsBody", "bpLinksBody", "btnBpAddLocation", "btnBpAddLink",
       "bpDiagram", "bpFindings", "btnBpAcceptSelected",
       "bpLocationModal", "bpLocName", "bpLocRole", "bpLocSubnets", "bpLocProbe", "bpLocGateway",
       "bpLocError", "btnBpLocSave", "bpLinkModal", "bpLinkA", "bpLinkB", "bpLinkKind", "bpLinkNote",
       "bpLinkError", "btnBpLinkSave", "bpPresetModal", "bpPresetKind", "bpPresetN", "bpPresetError",
       "btnBpPresetCreate", "bpDraftModal", "bpDraftOps", "bpApplyNote", "bpDraftError", "bpConflict",
       "bpConflictDiff", "btnBpAlign", "btnBpDraftApplyConfirm", "bpHistoryModal", "bpRevisionsBody",
       "bpDiffA", "bpDiffB", "btnBpDiff", "bpDiffOut")


class TheTabIsWired(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
        self.core = (ROOT / "static/js/core.js").read_text(encoding="utf-8")
        self.js = (ROOT / "static/js/blueprint.js").read_text(encoding="utf-8")
        self.i18n = (ROOT / "static/js/i18n.js").read_text(encoding="utf-8")

    def test_nav_button_and_panel(self):
        self.assertRegex(self.html, r'class="nav-item requires-admin" data-tab="tab-blueprint"')
        self.assertIn('id="tab-blueprint"', self.html)

    def test_lazy_loaded_with_vis_and_dispatched(self):
        self.assertIn("'tab-blueprint': ['/static/vendor/vis/vis-network.min.js', '/static/js/blueprint.js']", self.core)
        self.assertIn("else if (tabId === 'tab-blueprint') loadBlueprintTab();", self.core)
        self.assertIn("window.loadBlueprintTab = loadBlueprintTab;", self.js)

    def test_admin_tab(self):
        settings = (ROOT / "static/js/settings.js").read_text(encoding="utf-8")
        self.assertRegex(settings, r"ADMIN_GROUP_TABS = \[[^\]]*'tab-blueprint'")

    def test_every_control_exists(self):
        for element_id in IDS:
            self.assertIn(f'id="{element_id}"', self.html, element_id)

    def test_finding_keys_in_both_languages(self):
        it, en = self.i18n.split("\n    en: {", 1)
        for key in ("bpf_subnet_overlap", "bpf_location_no_subnets", "bpf_location_isolated",
                    "bpf_location_no_gateway", "bpf_gateway_not_in_location", "bpf_device_outside_subnets",
                    "bpf_device_outside_subnets_owner", "bpf_arp_uncovered", "bpf_subnet_unused",
                    "bpf_link_no_route", "bpf_link_no_route_backup", "bpf_link_no_route_default",
                    "bpf_link_no_route_unknown", "bpf_route_without_link", "bpf_vpn_link_down_missing",
                    "bpf_vpn_link_down_down", "bpf_vpn_link_down_unknown", "bpf_tunnel_without_link"):
            with self.subTest(key=key):
                self.assertRegex(it, rf"\n\s+{key}:")
                self.assertRegex(en, rf"\n\s+{key}:")

    def test_no_inline_handlers_in_the_new_markup(self):
        start = self.html.index('id="tab-blueprint"')
        self.assertNotRegex(self.html[start:self.html.index("<!-- End #tab-blueprint -->")], r"\bon[a-z]+=")
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_tab.py -v`
Expected: FAIL — `FileNotFoundError: static/js/blueprint.js`.

- [ ] **Step 3: Markup** — `templates/dashboard.html`.

Nav, right after the `data-tab="tab-groups"` button:

```html
        <button id="navBlueprint" class="nav-item requires-admin" data-tab="tab-blueprint" role="tab" aria-controls="tab-blueprint" aria-selected="false" tabindex="-1">
          <span class="nav-left"><i class="fa-solid fa-diagram-project"></i> <span data-i18n="tabBlueprint">Blueprint di rete</span></span>
        </button>
```

Panel, right after the closing `</div>` of `#tab-groups`:

```html
    <div id="tab-blueprint" class="tab-content" role="tabpanel" tabindex="0">
      <div class="page-head">
        <div class="page-head-text">
          <h2 data-i18n="tabBlueprint">Blueprint di rete</h2>
          <p data-i18n="descBlueprint">La rete come deve essere, confrontata con quella che SentinelNet osserva.</p>
        </div>
      </div>

      <div class="panel bp-bar">
        <label for="bpOrgSelect" data-i18n="lblBpOrg">Organizzazione</label>
        <select id="bpOrgSelect"></select>
        <span id="bpRevInfo" class="bp-meta"></span>
        <span id="bpObsInfo" class="bp-meta"></span>
        <span class="bp-bar-actions">
          <button type="button" class="btn btn-secondary btn-small" id="btnBpCheck" data-i18n="btnBpCheck">Verifica</button>
          <button type="button" class="btn btn-secondary btn-small" id="btnBpObserve" data-i18n="btnBpObserve">Aggiorna dai gateway</button>
          <button type="button" class="btn btn-secondary btn-small" id="btnBpPreset" data-i18n="btnBpPreset">Preset…</button>
          <button type="button" class="btn btn-secondary btn-small" id="btnBpHistory" data-i18n="btnBpHistory">Storico</button>
        </span>
      </div>

      <section id="bpSteps" class="panel" hidden>
        <h3 data-i18n="bpStepsTitle">Primi passi</h3>
        <ol id="bpStepsList" class="bp-steps"></ol>
      </section>

      <div id="bpDraftBar" class="panel bp-draft-bar" hidden>
        <span id="bpDraftInfo"></span>
        <span class="bp-bar-actions">
          <button type="button" class="btn btn-secondary btn-small" id="btnBpDraftReview" data-i18n="btnBpDraftReview">Rivedi</button>
          <button type="button" class="btn btn-primary btn-small" id="btnBpDraftApply" data-i18n="btnBpDraftApply">Applica</button>
          <button type="button" class="btn btn-secondary btn-small" id="btnBpDraftDiscard" data-i18n="btnBpDraftDiscard">Scarta</button>
        </span>
      </div>

      <div class="bp-grid">
        <section class="panel panel-flush">
          <div class="panel-head">
            <h3 data-i18n="bpLocations">Sedi</h3>
            <button type="button" class="btn btn-secondary btn-small" id="btnBpAddLocation" style="width:auto;"><i class="fa-solid fa-plus"></i> <span data-i18n="btnBpAddLocation">Nuova sede</span></button>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr>
                <th data-i18n="thBpLocName">Sede</th><th data-i18n="thBpRole">Ruolo</th><th data-i18n="thBpSubnets">Subnet</th>
                <th data-i18n="thBpGateway">Gateway</th><th data-i18n="thBpProbe">Sonda</th><th data-i18n="thBpActions">Azioni</th>
              </tr></thead>
              <tbody id="bpLocationsBody"></tbody>
            </table>
          </div>
          <div class="panel-head">
            <h3 data-i18n="bpLinks">Collegamenti</h3>
            <button type="button" class="btn btn-secondary btn-small" id="btnBpAddLink" style="width:auto;"><i class="fa-solid fa-plus"></i> <span data-i18n="btnBpAddLink">Nuovo collegamento</span></button>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr>
                <th data-i18n="thBpLinkA">Sede A</th><th data-i18n="thBpLinkB">Sede B</th><th data-i18n="thBpKind">Tipo</th><th data-i18n="thBpActions">Azioni</th>
              </tr></thead>
              <tbody id="bpLinksBody"></tbody>
            </table>
          </div>
        </section>
        <section class="panel">
          <div id="bpDiagram" class="bp-diagram" role="img" aria-label="Diagramma delle sedi e dei collegamenti" data-i18n-aria-label="bpDiagramAria"></div>
        </section>
      </div>

      <section class="panel">
        <div class="panel-head">
          <h3 data-i18n="bpFindingsTitle">Verifiche</h3>
          <button type="button" class="btn btn-primary btn-small" id="btnBpAcceptSelected" style="width:auto;" data-i18n="btnBpAcceptSelected">Aggiungi alla bozza</button>
        </div>
        <div id="bpFindings"></div>
      </section>
    </div> <!-- End #tab-blueprint -->
```

Modals, right after `#locationModal`:

```html
  <div class="modal-overlay" id="bpLocationModal">
    <div class="modal" style="width: 520px; max-width: 95%;">
      <div class="modal-header">
        <h3><i class="fa-solid fa-map-pin"></i> <span data-i18n="bpLocModalTitle">Sede</span></h3>
        <button type="button" class="modal-close" data-close-modal="bpLocationModal" aria-label="Chiudi" data-i18n-aria-label="btnClose"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="form-group"><label for="bpLocName" data-i18n="lblBpLocName">Nome</label><input id="bpLocName" type="text" style="padding-left:12px;"></div>
      <div class="form-group">
        <label for="bpLocRole" data-i18n="lblBpLocRole">Ruolo</label>
        <select id="bpLocRole">
          <option value="hq" data-i18n="locRole_hq">Sede centrale</option>
          <option value="branch" data-i18n="locRole_branch">Filiale</option>
          <option value="datacenter" data-i18n="locRole_datacenter">Datacenter</option>
          <option value="warehouse" data-i18n="locRole_warehouse">Magazzino</option>
          <option value="other" data-i18n="locRole_other">Altro</option>
        </select>
      </div>
      <div class="form-group"><label for="bpLocSubnets" data-i18n="lblBpLocSubnets">Subnet (una per riga, CIDR)</label><textarea id="bpLocSubnets" rows="4" placeholder="10.10.0.0/16" style="width:100%; font-family:var(--font-code); font-size:12px; padding:8px;"></textarea></div>
      <div class="form-group"><label for="bpLocProbe" data-i18n="lblBpLocProbe">Sonda predefinita</label><select id="bpLocProbe"></select></div>
      <div class="form-group"><label for="bpLocGateway" data-i18n="lblBpLocGateway">Gateway (IP di un apparato della sede)</label><input id="bpLocGateway" type="text" placeholder="10.10.0.1" style="padding-left:12px;"></div>
      <p id="bpLocError" class="form-hint" role="alert" style="color:var(--danger);"></p>
      <div class="modal-actions">
        <button type="button" class="btn btn-secondary" data-close-modal="bpLocationModal" data-i18n="uiCancel">Annulla</button>
        <button type="button" class="btn btn-primary" id="btnBpLocSave" data-i18n="btnBpSaveToDraft">Salva nella bozza</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="bpLinkModal">
    <div class="modal" style="width: 460px; max-width: 95%;">
      <div class="modal-header">
        <h3><i class="fa-solid fa-link"></i> <span data-i18n="bpLinkModalTitle">Collegamento</span></h3>
        <button type="button" class="modal-close" data-close-modal="bpLinkModal" aria-label="Chiudi" data-i18n-aria-label="btnClose"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="form-group"><label for="bpLinkA" data-i18n="thBpLinkA">Sede A</label><select id="bpLinkA"></select></div>
      <div class="form-group"><label for="bpLinkB" data-i18n="thBpLinkB">Sede B</label><select id="bpLinkB"></select></div>
      <div class="form-group">
        <label for="bpLinkKind" data-i18n="thBpKind">Tipo</label>
        <select id="bpLinkKind">
          <option value="vpn" data-i18n="bpKind_vpn">VPN</option>
          <option value="wan" data-i18n="bpKind_wan">WAN</option>
          <option value="mpls" data-i18n="bpKind_mpls">MPLS</option>
          <option value="lan" data-i18n="bpKind_lan">LAN</option>
        </select>
      </div>
      <div class="form-group"><label for="bpLinkNote" data-i18n="lblBpLinkNote">Nota</label><input id="bpLinkNote" type="text" style="padding-left:12px;"></div>
      <p id="bpLinkError" class="form-hint" role="alert" style="color:var(--danger);"></p>
      <div class="modal-actions">
        <button type="button" class="btn btn-secondary" data-close-modal="bpLinkModal" data-i18n="uiCancel">Annulla</button>
        <button type="button" class="btn btn-primary" id="btnBpLinkSave" data-i18n="btnBpSaveToDraft">Salva nella bozza</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="bpPresetModal">
    <div class="modal" style="width: 480px; max-width: 95%;">
      <div class="modal-header">
        <h3><i class="fa-solid fa-shapes"></i> <span data-i18n="bpPresetModalTitle">Preset</span></h3>
        <button type="button" class="modal-close" data-close-modal="bpPresetModal" aria-label="Chiudi" data-i18n-aria-label="btnClose"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <p class="form-hint" data-i18n="bpPresetHint">Crea una bozza: le sedi esistenti restano, le subnet si completano con le verifiche.</p>
      <div class="form-group">
        <label for="bpPresetKind" data-i18n="lblBpPresetKind">Topologia</label>
        <select id="bpPresetKind">
          <option value="single" data-i18n="bpPreset_single">Sede singola</option>
          <option value="hub_spoke" data-i18n="bpPreset_hub_spoke">Hub-and-spoke (sede centrale + N filiali via VPN)</option>
          <option value="hub_spoke_dc" data-i18n="bpPreset_hub_spoke_dc">Hub-and-spoke con datacenter</option>
          <option value="full_mesh" data-i18n="bpPreset_full_mesh">Full mesh (N sedi)</option>
        </select>
      </div>
      <div class="form-group"><label for="bpPresetN" data-i18n="lblBpPresetN">Numero di sedi (1–50)</label><input id="bpPresetN" type="number" min="1" max="50" value="3" style="padding-left:12px;"></div>
      <p id="bpPresetError" class="form-hint" role="alert" style="color:var(--danger);"></p>
      <div class="modal-actions">
        <button type="button" class="btn btn-secondary" data-close-modal="bpPresetModal" data-i18n="uiCancel">Annulla</button>
        <button type="button" class="btn btn-primary" id="btnBpPresetCreate" data-i18n="btnBpPresetCreate">Crea bozza</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="bpDraftModal">
    <div class="modal" style="width: 640px; max-width: 95%;">
      <div class="modal-header">
        <h3><i class="fa-solid fa-list-check"></i> <span data-i18n="bpDraftModalTitle">Bozza</span></h3>
        <button type="button" class="modal-close" data-close-modal="bpDraftModal" aria-label="Chiudi" data-i18n-aria-label="btnClose"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <ol id="bpDraftOps" class="bp-ops"></ol>
      <div id="bpConflict" class="bp-conflict" hidden>
        <p data-i18n="bpConflict">Il modello è cambiato dopo la creazione della bozza. Ecco cosa è cambiato:</p>
        <div id="bpConflictDiff"></div>
        <button type="button" class="btn btn-secondary btn-small" id="btnBpAlign" data-i18n="btnBpAlign">Allinea alla versione attuale</button>
      </div>
      <div class="form-group"><label for="bpApplyNote" data-i18n="lblBpApplyNote">Nota della revisione (facoltativa)</label><input id="bpApplyNote" type="text" style="padding-left:12px;"></div>
      <p id="bpDraftError" class="form-hint" role="alert" style="color:var(--danger);"></p>
      <div class="modal-actions">
        <button type="button" class="btn btn-secondary" data-close-modal="bpDraftModal" data-i18n="uiCancel">Annulla</button>
        <button type="button" class="btn btn-primary" id="btnBpDraftApplyConfirm" data-i18n="btnBpDraftApplyConfirm">Applica la bozza</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="bpHistoryModal">
    <div class="modal" style="width: 760px; max-width: 95%;">
      <div class="modal-header">
        <h3><i class="fa-solid fa-clock-rotate-left"></i> <span data-i18n="bpHistoryModalTitle">Storico revisioni</span></h3>
        <button type="button" class="modal-close" data-close-modal="bpHistoryModal" aria-label="Chiudi" data-i18n-aria-label="btnClose"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="table-wrap" style="max-height:280px; overflow:auto;">
        <table>
          <thead><tr>
            <th data-i18n="thBpRev">Rev</th><th data-i18n="thBpAt">Quando</th><th data-i18n="thBpBy">Chi</th>
            <th data-i18n="thBpSource">Origine</th><th data-i18n="thBpNote">Nota</th><th data-i18n="thBpActions">Azioni</th>
          </tr></thead>
          <tbody id="bpRevisionsBody"></tbody>
        </table>
      </div>
      <div class="bp-bar" style="margin-top:12px;">
        <label for="bpDiffA" data-i18n="lblBpDiffA">Da</label><select id="bpDiffA"></select>
        <label for="bpDiffB" data-i18n="lblBpDiffB">A</label><select id="bpDiffB"></select>
        <button type="button" class="btn btn-secondary btn-small" id="btnBpDiff" data-i18n="btnBpDiff">Confronta</button>
      </div>
      <div id="bpDiffOut"></div>
    </div>
  </div>
```

- [ ] **Step 4: Wiring** —

`static/js/core.js`, in `LAZY_TAB_SCRIPTS` after `'tab-config-drift'`:

```js
    'tab-blueprint': ['/static/vendor/vis/vis-network.min.js', '/static/js/blueprint.js'],
```

in the `switchTab` dispatch, after the `tab-config-drift` line:

```js
    else if (tabId === 'tab-blueprint') loadBlueprintTab();
```

in the command palette list, after the `tab-groups` entry:

```js
        { id: 'tab-blueprint', title: tr('tabBlueprint'), desc: tr('descBlueprint'), group: tr('coreViews') },
```

`static/js/settings.js`:

```js
    const ADMIN_GROUP_TABS = ['tab-users', 'tab-groups', 'tab-blueprint', 'tab-probes', 'tab-mcp', 'tab-settings'];
```

`static/js/devices.js`, in `renderGroupsTable`, the actions cell becomes:

```js
                <td>${currentRole === 'viewer'
                    ? '<span style="color:var(--text-muted)">—</span>'
                    : `${canOpenTab('tab-blueprint') ? `<button data-action="open-blueprint" data-g="${escapeHtml(g)}" style="color:var(--primary); background:none; border:none; cursor:pointer; margin-right:12px;">${escapeHtml(tr('btnOpenBlueprint'))}</button>` : ''}${renameBtn}<button data-action="delete-group" data-g="${escapeHtml(g)}" style="color:var(--danger); background:none; border:none; cursor:pointer;">${btnText}</button>`}</td>
```

and in the `groupsTableBody` listener, after `loc-import`:

```js
        else if (action === 'open-blueprint') { window.bpPendingOrg = g; switchTab('tab-blueprint'); }
```

`types/globals.d.ts`: next to `declare var loadConfigDriftTab: any;` add `declare var loadBlueprintTab: any;`; in `interface Window` add:

```ts
    loadBlueprintTab: any;   // blueprint.js, called by switchTab
    bpPendingOrg: any;       // devices.js -> blueprint.js: organization to open
```

- [ ] **Step 5: Module** — `static/js/blueprint.js`:

```js
// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// static/js/blueprint.js
// ===== Network Blueprint (spec 2026-10-11 network-blueprint) =====
// The expected network of one organization, compared with the observed one.
// Every edit made here becomes a draft operation: nothing reaches the model
// until the draft is applied. The diagram mirrors the lists; it is not an
// editor.

(function () {
    let bpOrg = '';
    let bpState = null;       // GET /api/blueprint/{org}
    let bpFindings = [];      // GET /api/blueprint/{org}/checks
    let bpObservedAt = null;
    let bpNetwork = null;     // vis.Network of the diagram
    let bpLocSave = null;     // save callback of the open location modal
    let bpLinkSave = null;    // save callback of the open link modal

    const ROLE_SHAPES = { hq: 'star', datacenter: 'database', branch: 'dot', warehouse: 'square', other: 'triangle' };
    const KIND_COLORS = { vpn: '--primary', wan: '--text-muted', mpls: '--warning', lan: '--success' };
    const SEV_RANK = { error: 0, warning: 1, unknown: 2, info: 3 };
    const SEV_COLORS = { error: '--danger', warning: '--warning', unknown: '--text-muted', info: '--primary' };
    const CODE_GROUP = {
        subnet_overlap: 'model', location_no_subnets: 'model', location_isolated: 'model',
        location_no_gateway: 'model', gateway_not_in_location: 'model',
        device_outside_subnets: 'subnets', arp_uncovered: 'subnets', subnet_unused: 'subnets',
        link_no_route: 'routing', route_without_link: 'routing',
        vpn_link_down: 'vpn', tunnel_without_link: 'vpn',
    };
    const EDITABLE = ['create_location', 'update_location', 'add_subnet', 'set_gateway', 'add_link'];

    const $ = (id) => document.getElementById(id);
    const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const api = (path) => `/api/blueprint/${encodeURIComponent(bpOrg)}${path}`;
    const roleLabel = (role) => tr('locRole_' + (role || 'other'));

    async function errorText(res) {
        if (!res) return tr('uiError');
        const body = await res.json().catch(() => ({}));
        const d = body.detail;
        return (d && typeof d === 'object' ? d.message : d) || tr('uiError');
    }

    function send(path, method, body) {
        const opts = { method };
        if (body !== undefined) opts.body = JSON.stringify(body);
        return apiFetch(api(path), opts);
    }

    function draftOps() { return (bpState && bpState.draft && bpState.draft.ops) || []; }
    function model() { return bpState.preview || { locations: bpState.locations, links: bpState.links }; }
    function probeName(id) { const p = (bpState.probes || []).find((x) => x.id === id); return p ? p.name : id; }

    // Name of a location id, of a draft ref («+1»), or of a location only the draft has.
    function locName(id) {
        if (String(id).startsWith('+')) {
            const op = draftOps().find((o) => o.ref === id);
            return op ? op.name : id;
        }
        const l = bpState.locations[id] || model().locations[id];
        return l ? l.name : id;
    }

    // ---- loading -----------------------------------------------------------

    async function loadBlueprintTab() {
        const sel = $('bpOrgSelect');
        const orgs = Object.keys(globalGroups || {});
        sel.replaceChildren(...orgs.map((g) => new Option(orgLabel(g), g)));
        const wanted = window.bpPendingOrg;
        window.bpPendingOrg = null;
        bpOrg = wanted && orgs.includes(wanted) ? wanted : (orgs.includes(bpOrg) ? bpOrg : (orgs[0] || ''));
        sel.value = bpOrg;
        await refresh();
    }
    window.loadBlueprintTab = loadBlueprintTab;

    async function refresh() {
        if (!bpOrg) return;
        const res = await apiFetch(api(''));
        if (!res || !res.ok) { showToast(await errorText(res), 'error'); return; }
        bpState = await res.json();
        await runChecks();
    }

    async function runChecks() {
        const res = await apiFetch(api('/checks'));
        if (res && res.ok) {
            const body = await res.json();
            bpFindings = body.findings || [];
            bpObservedAt = body.observed_at;
        } else {
            bpFindings = [];
            showToast(await errorText(res), 'error');
        }
        render();
    }

    // ---- rendering ---------------------------------------------------------

    function render() {
        renderBar();
        renderSteps();
        renderDraftBar();
        renderLocations();
        renderLinks();
        renderDiagram();
        renderFindings();
    }

    function renderBar() {
        const info = bpState.rev_info;
        $('bpRevInfo').textContent = info ? tr('bpRevInfo', { rev: info.rev, at: info.at, by: info.by || '—' }) : tr('bpRevNone');
        $('bpObsInfo').textContent = bpObservedAt ? tr('bpObsInfo', { at: bpObservedAt }) : tr('bpObsNone');
    }

    function renderSteps() {
        const locs = Object.values(model().locations);
        const any = locs.length > 0;
        const has = (code) => bpFindings.some((f) => f.code === code);
        const steps = [
            ['bpStep1', any, 'preset'],
            ['bpStep2', any && locs.every((l) => (l.subnets || []).length), 'findings'],
            ['bpStep3', any && !has('location_isolated'), 'findings'],
            ['bpStep4', any && locs.every((l) => l.gateway), 'findings'],
            ['bpStep5', !!bpObservedAt, 'observe'],
            ['bpStep6', any && !bpFindings.some((f) => f.severity === 'error'), 'findings'],
        ];
        const label = { preset: 'btnBpPreset', observe: 'btnBpObserve', findings: 'btnBpSeeFindings' };
        $('bpSteps').hidden = steps.every((s) => s[1]);
        $('bpStepsList').innerHTML = steps.map(([key, done, action]) => `<li class="${done ? 'is-done' : ''}">
            ${done ? '<i class="fa-solid fa-check" aria-hidden="true"></i> ' : ''}${escapeHtml(tr(key))}
            ${done ? '' : ` <button type="button" class="bp-link-btn" data-bp-step="${action}">${escapeHtml(tr(label[action]))}</button>`}</li>`).join('');
    }

    function renderDraftBar() {
        const draft = bpState.draft;
        $('bpDraftBar').hidden = !draft;
        if (!draft) return;
        const text = tr('bpDraftInfo', { n: draft.ops.length, rev: draft.base_rev });
        $('bpDraftInfo').textContent = bpState.draft_error
            ? `${text} — ${tr('bpDraftInvalid', { error: bpState.draft_error })}` : text;
    }

    function iconBtn(action, id, icon, key, danger) {
        return `<button type="button" class="inv-icon-btn${danger ? ' danger' : ''}" data-action="${action}" data-id="${escapeHtml(id)}" title="${escapeHtml(tr(key))}" aria-label="${escapeHtml(tr(key))}"><i class="fa-solid ${icon}"></i></button>`;
    }

    function renderLocations() {
        const m = model();
        const ids = Object.keys(m.locations).sort((a, b) => m.locations[a].name.localeCompare(m.locations[b].name));
        $('bpLocationsBody').innerHTML = ids.map((id) => {
            const l = m.locations[id];
            const actions = id in bpState.locations
                ? iconBtn('bp-edit-loc', id, 'fa-pen', 'btnBpEditOp') + iconBtn('bp-del-loc', id, 'fa-trash-can', 'btnBpRemoveOp', true)
                : `<span class="bp-draft-tag">${escapeHtml(tr('bpInDraft'))}</span>`;
            return `<tr><td><strong>${escapeHtml(l.name)}</strong></td><td>${escapeHtml(roleLabel(l.role))}</td>
                <td class="bp-mono">${(l.subnets || []).map(escapeHtml).join('<br>') || '—'}</td>
                <td class="bp-mono">${escapeHtml(l.gateway || '—')}</td><td>${escapeHtml(probeName(l.probe))}</td>
                <td style="white-space:nowrap;">${actions}</td></tr>`;
        }).join('') || `<tr><td colspan="6" class="inv-muted">${escapeHtml(tr('bpNoLocations'))}</td></tr>`;
    }

    function renderLinks() {
        const m = model();
        $('bpLinksBody').innerHTML = Object.entries(m.links).map(([id, k]) => {
            const actions = id in bpState.links
                ? iconBtn('bp-edit-link', id, 'fa-pen', 'btnBpEditOp') + iconBtn('bp-del-link', id, 'fa-trash-can', 'btnBpRemoveOp', true)
                : `<span class="bp-draft-tag">${escapeHtml(tr('bpInDraft'))}</span>`;
            return `<tr><td>${escapeHtml(locName(k.a))}</td><td>${escapeHtml(locName(k.b))}</td>
                <td>${escapeHtml(tr('bpKind_' + k.kind))}</td><td style="white-space:nowrap;">${actions}</td></tr>`;
        }).join('') || `<tr><td colspan="4" class="inv-muted">${escapeHtml(tr('bpNoLinks'))}</td></tr>`;
    }

    function worstBy(kind) {
        const out = {};
        bpFindings.forEach((f) => {
            const id = (f.subject || {})[kind];
            if (id !== undefined && (out[id] === undefined || SEV_RANK[f.severity] < SEV_RANK[out[id]])) out[id] = f.severity;
        });
        return out;
    }

    function renderDiagram() {
        if (typeof vis === 'undefined') return;
        const m = model();
        const worstLoc = worstBy('location');
        const worstLink = worstBy('link');
        const text = cssVar('--text');
        const nodes = Object.entries(m.locations).map(([id, l]) => ({
            id, label: l.name, shape: ROLE_SHAPES[l.role] || 'dot', size: 18, borderWidth: 2,
            color: { background: cssVar(worstLoc[id] ? SEV_COLORS[worstLoc[id]] : '--surface'), border: cssVar('--border') },
            shapeProperties: { borderDashes: id in bpState.locations ? false : [4, 4] },
            font: { color: text },
        }));
        const edges = Object.entries(m.links).map(([id, k]) => ({
            id, from: k.a, to: k.b, label: tr('bpKind_' + k.kind), width: 2,
            color: cssVar(worstLink[id] ? SEV_COLORS[worstLink[id]] : KIND_COLORS[k.kind]),
            dashes: !(id in bpState.links), font: { color: text, strokeWidth: 0, size: 11 },
        }));
        if (bpNetwork) bpNetwork.destroy();
        bpNetwork = new vis.Network($('bpDiagram'), { nodes, edges },
            { physics: { stabilization: { iterations: 150 } }, interaction: { hover: true } });
        bpNetwork.on('click', (p) => {
            if (p.nodes.length && p.nodes[0] in bpState.locations) editLocation(p.nodes[0]);
            else if (p.edges.length && p.edges[0] in bpState.links) editLink(p.edges[0]);
        });
    }

    function findingKey(f) {
        const p = f.params || {};
        if (f.code === 'link_no_route') {
            if (f.severity === 'unknown') return 'bpf_link_no_route_unknown';
            if (p.via === 'default') return 'bpf_link_no_route_default';
            return p.backup_only ? 'bpf_link_no_route_backup' : 'bpf_link_no_route';
        }
        if (f.code === 'vpn_link_down') return 'bpf_vpn_link_down_' + p.state;
        if (f.code === 'device_outside_subnets' && p.owner) return 'bpf_device_outside_subnets_owner';
        return 'bpf_' + f.code;
    }

    function findingText(f) {
        const vars = {};
        Object.entries(f.params || {}).forEach(([k, v]) => {
            vars[k] = escapeHtml(Array.isArray(v) ? v.join(', ') : String(v));
        });
        return tr(findingKey(f), vars);
    }

    // HTML: every variable part is escaped here.
    function describeOp(op) {
        const n = (id) => escapeHtml(locName(id));
        switch (op.op) {
            case 'create_location': return tr('bpOpCreate', { name: escapeHtml(op.name), role: escapeHtml(roleLabel(op.role)) });
            case 'update_location': return tr('bpOpUpdate', { name: n(op.id), fields: escapeHtml(Object.entries(op.fields || {})
                .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`).join('; ')) });
            case 'add_subnet': return tr('bpOpAddSubnet', { name: n(op.id), subnet: escapeHtml(op.subnet) });
            case 'set_gateway': return tr('bpOpGateway', { name: n(op.id), ip: escapeHtml(op.ip) });
            case 'delete_location': return tr('bpOpDelete', { name: n(op.id) });
            case 'add_link': return tr('bpOpLink', { a: n(op.a), b: n(op.b), kind: escapeHtml(tr('bpKind_' + op.kind)) });
            case 'remove_link': return tr('bpOpUnlink', { id: escapeHtml(op.id) });
        }
        return escapeHtml(op.op);
    }

    function renderFindings() {
        const box = $('bpFindings');
        if (!bpFindings.length) { box.innerHTML = `<p class="inv-muted">${escapeHtml(tr('bpNoFindings'))}</p>`; return; }
        box.innerHTML = ['model', 'subnets', 'routing', 'vpn'].map((g) => {
            const items = bpFindings.map((f, i) => [f, i]).filter(([f]) => CODE_GROUP[f.code] === g);
            if (!items.length) return '';
            return `<h4 class="bp-group">${escapeHtml(tr('bpGroup_' + g))}</h4><ul class="bp-findings">${items.map(([f, i]) => `
                <li><span class="bp-sev bp-sev-${escapeHtml(f.severity)}">${escapeHtml(tr('bpSev_' + f.severity))}</span> ${findingText(f)}
                ${(f.proposal || []).map((op, j) => `<div class="bp-proposal">
                    <label><input type="checkbox" data-f="${i}" data-o="${j}" aria-label="${escapeHtml(tr('bpAcceptProposal'))}"> ${describeOp(op)}</label>
                    ${EDITABLE.includes(op.op) ? `<button type="button" class="bp-link-btn" data-action="bp-edit-proposal" data-f="${i}" data-o="${j}">${escapeHtml(tr('btnBpEditOp'))}</button>` : ''}
                </div>`).join('')}</li>`).join('')}</ul>`;
        }).join('');
    }

    function renderDiff(d) {
        const fmt = (v) => (Array.isArray(v) ? v.join(', ') : v) || '—';
        const part = (title, p, label) => {
            const rows = [
                ...p.added.map((x) => `<li class="bp-diff-add">+ ${escapeHtml(label(x))}</li>`),
                ...p.removed.map((x) => `<li class="bp-diff-del">− ${escapeHtml(label(x))}</li>`),
                ...p.changed.map((x) => `<li>~ ${escapeHtml(x.label)}: ${escapeHtml(Object.entries(x.fields)
                    .map(([f, [a, b]]) => `${f}: ${fmt(a)} → ${fmt(b)}`).join('; '))}</li>`),
            ];
            return rows.length ? `<h4>${escapeHtml(title)}</h4><ul class="bp-diff">${rows.join('')}</ul>` : '';
        };
        const html = part(tr('bpLocations'), d.locations, (x) => x.name)
            + part(tr('bpLinks'), d.links, (x) => `${locName(x.a)} ↔ ${locName(x.b)} (${tr('bpKind_' + x.kind)})`);
        return html || `<p class="inv-muted">${escapeHtml(tr('bpDiffNone'))}</p>`;
    }

    // ---- draft -------------------------------------------------------------

    async function addOps(ops, source = 'manual') {
        const res = await send('/draft', 'POST', { source, ops });
        if (!res || !res.ok) { showToast(await errorText(res), 'error'); return false; }
        await refresh();
        return true;
    }

    async function replaceOps(ops) {
        const res = await send('/draft', 'PUT', { ops });
        if (!res || !res.ok) { showToast(await errorText(res), 'error'); return false; }
        await refresh();
        return true;
    }

    // `id` set: the location exists and saving yields update_location with
    // the fields that changed. `op` prefills from a proposal or a draft op.
    function openLocationModal(id, op, onSave) {
        const base = id ? bpState.locations[id] : { name: '', role: 'branch', subnets: [], probe: 'central', gateway: '' };
        const v = Object.assign({}, base, { subnets: [...(base.subnets || [])] });
        if (op && op.op === 'create_location') Object.assign(v, op);
        if (op && op.op === 'update_location') Object.assign(v, op.fields);
        if (op && op.op === 'add_subnet') v.subnets = [...v.subnets, op.subnet];
        if (op && op.op === 'set_gateway') v.gateway = op.ip;
        $('bpLocName').value = v.name || '';
        $('bpLocRole').value = v.role || 'branch';
        $('bpLocSubnets').value = (v.subnets || []).join('\n');
        $('bpLocProbe').replaceChildren(...(bpState.probes || []).map((p) => new Option(p.name, p.id)));
        $('bpLocProbe').value = v.probe || 'central';
        $('bpLocGateway').value = v.gateway || '';
        $('bpLocError').textContent = '';
        bpLocSave = async () => {
            const val = {
                name: $('bpLocName').value.trim(), role: $('bpLocRole').value,
                subnets: $('bpLocSubnets').value.split(/\s+/).filter(Boolean),
                probe: $('bpLocProbe').value, gateway: $('bpLocGateway').value.trim(),
            };
            let next;
            if (id) {
                const fields = {};
                Object.keys(val).forEach((k) => {
                    const was = k === 'subnets' ? (base.subnets || []) : (base[k] || '');
                    if (JSON.stringify(val[k]) !== JSON.stringify(was)) fields[k] = val[k];
                });
                if (!Object.keys(fields).length) { closeModal('bpLocationModal'); return; }
                next = { op: 'update_location', id, fields };
            } else {
                next = Object.assign({ op: 'create_location', ref: (op && op.ref) || '+1' }, val);
            }
            if (await onSave(next)) closeModal('bpLocationModal');
        };
        openModal('bpLocationModal');
    }

    function linkEndpoints() {
        const out = Object.entries(bpState.locations).map(([id, l]) => [id, l.name]);
        draftOps().filter((o) => o.op === 'create_location' && o.ref)
            .forEach((o) => out.push([o.ref, `${o.name} (${tr('bpInDraft')})`]));
        return out;
    }

    function openLinkModal(op, onSave) {
        const opts = linkEndpoints();
        ['bpLinkA', 'bpLinkB'].forEach((sid) => $(sid).replaceChildren(...opts.map(([id, name]) => new Option(name, id))));
        $('bpLinkA').value = (op && op.a) || (opts[0] || [''])[0];
        $('bpLinkB').value = (op && op.b) || (opts[1] || opts[0] || [''])[0];
        $('bpLinkKind').value = (op && op.kind) || 'vpn';
        $('bpLinkNote').value = (op && op.note) || '';
        $('bpLinkError').textContent = '';
        bpLinkSave = async () => {
            const next = { op: 'add_link', a: $('bpLinkA').value, b: $('bpLinkB').value,
                kind: $('bpLinkKind').value, note: $('bpLinkNote').value.trim() };
            if (next.a === next.b) { $('bpLinkError').textContent = tr('bpLinkSame'); return; }
            if (await onSave(next)) closeModal('bpLinkModal');
        };
        openModal('bpLinkModal');
    }

    function openOpEditor(op, onSave) {
        if (op.op === 'add_link') openLinkModal(op, onSave);
        else if (op.op === 'create_location') openLocationModal(null, op, onSave);
        else openLocationModal(op.id, op, onSave);
    }

    function editLocation(id) { openLocationModal(id, null, (next) => addOps([next])); }
    function editLink(id) { openLinkModal(bpState.links[id], (next) => addOps([{ op: 'remove_link', id }, next])); }

    async function acceptSelected() {
        const ops = [...$('bpFindings').querySelectorAll('input[type=checkbox][data-f]:checked')]
            .map((c) => bpFindings[+c.dataset.f].proposal[+c.dataset.o]);
        if (!ops.length) return;
        if (await addOps(ops, 'checks')) showToast(tr('bpAddedToDraft', { n: ops.length }), 'success');
    }

    function renderDraftOps() {
        $('bpDraftOps').innerHTML = draftOps().map((op, i) => `<li>${describeOp(op)}
            ${EDITABLE.includes(op.op) ? `<button type="button" class="bp-link-btn" data-action="bp-op-edit" data-i="${i}">${escapeHtml(tr('btnBpEditOp'))}</button>` : ''}
            <button type="button" class="bp-link-btn danger" data-action="bp-op-remove" data-i="${i}">${escapeHtml(tr('btnBpRemoveOp'))}</button></li>`).join('');
    }

    function openDraftModal() {
        renderDraftOps();
        $('bpApplyNote').value = '';
        $('bpDraftError').textContent = '';
        $('bpConflict').hidden = true;
        openModal('bpDraftModal');
    }

    async function showConflict() {
        await refresh();
        const res = await apiFetch(api(`/diff?a=${bpState.draft.base_rev}&b=${bpState.rev}`));
        $('bpConflictDiff').innerHTML = res && res.ok ? renderDiff(await res.json()) : '';
        $('bpConflict').hidden = false;
    }

    async function applyDraft() {
        const res = await send('/draft/apply', 'POST', { note: $('bpApplyNote').value.trim() });
        if (res && res.status === 409) { await showConflict(); return; }
        if (!res || !res.ok) { $('bpDraftError').textContent = await errorText(res); return; }
        const body = await res.json();
        closeModal('bpDraftModal');
        showToast(tr('bpApplied', { rev: body.rev }), 'success');
        const renamed = Object.entries(body.renamed || {});
        if (renamed.length) showToast(tr('bpRenamed', { list: renamed.map(([a, b]) => `${a} → ${b}`).join(', ') }), 'warning');
        await refresh();
    }

    async function align() {
        const res = await send('/draft/align', 'POST', {});
        if (!res || !res.ok) { $('bpDraftError').textContent = await errorText(res); return; }
        $('bpConflict').hidden = true;
        await refresh();
        renderDraftOps();
    }

    // ---- history, presets, observation --------------------------------------

    async function openHistory() {
        const res = await apiFetch(api('/revisions'));
        if (!res || !res.ok) { showToast(await errorText(res), 'error'); return; }
        const revs = (await res.json()).revisions;
        $('bpRevisionsBody').innerHTML = revs.map((r) => `<tr><td>${r.rev}</td><td>${escapeHtml(r.at)}</td>
            <td>${escapeHtml(r.by || '—')}</td><td>${escapeHtml(tr('bpSource_' + r.source))}</td><td>${escapeHtml(r.note || '')}</td>
            <td>${r.rev === bpState.rev ? '' : `<button type="button" class="btn btn-secondary btn-small" data-action="bp-restore" data-rev="${r.rev}">${escapeHtml(tr('btnBpRestore'))}</button>`}</td></tr>`).join('');
        ['bpDiffA', 'bpDiffB'].forEach((sid) => $(sid).replaceChildren(...revs.map((r) => new Option(`rev ${r.rev}`, String(r.rev)))));
        if (revs.length) {
            $('bpDiffB').value = String(revs[0].rev);
            $('bpDiffA').value = String((revs[1] || revs[0]).rev);
        }
        $('bpDiffOut').innerHTML = '';
        openModal('bpHistoryModal');
    }

    async function compare() {
        const res = await apiFetch(api(`/diff?a=${$('bpDiffA').value}&b=${$('bpDiffB').value}`));
        $('bpDiffOut').innerHTML = res && res.ok ? renderDiff(await res.json()) : escapeHtml(await errorText(res));
    }

    async function restore(rev) {
        const res = await send('/draft', 'POST', { restore: rev });
        if (!res || !res.ok) { showToast(await errorText(res), 'error'); return; }
        closeModal('bpHistoryModal');
        showToast(tr('bpRestoreOpened', { rev }), 'success');
        await refresh();
    }

    async function createPreset() {
        const res = await send('/draft', 'POST', { preset: $('bpPresetKind').value, n: parseInt($('bpPresetN').value, 10) || 1 });
        if (!res || !res.ok) { $('bpPresetError').textContent = await errorText(res); return; }
        closeModal('bpPresetModal');
        await refresh();
    }

    async function observe() {
        const btn = $('btnBpObserve');
        btn.disabled = true;
        try {
            const res = await send('/observe', 'POST', {});
            if (!res || !res.ok) { showToast(await errorText(res), 'error'); return; }
            const body = await res.json();
            showToast(tr('bpObserved', { n: Object.keys(body.gateways || {}).length }), 'success');
            await runChecks();
        } finally {
            btn.disabled = false;
        }
    }

    function openPreset() {
        $('bpPresetError').textContent = '';
        openModal('bpPresetModal');
    }

    // ---- bindings (the module loads once, with its tab) ----------------------

    $('bpOrgSelect').addEventListener('change', () => { bpOrg = $('bpOrgSelect').value; refresh(); });
    $('btnBpCheck').addEventListener('click', () => refresh());
    $('btnBpObserve').addEventListener('click', observe);
    $('btnBpPreset').addEventListener('click', openPreset);
    $('btnBpHistory').addEventListener('click', openHistory);
    $('btnBpAddLocation').addEventListener('click', () => openLocationModal(null, null, (next) => addOps([next])));
    $('btnBpAddLink').addEventListener('click', () => openLinkModal(null, (next) => addOps([next])));
    $('btnBpAcceptSelected').addEventListener('click', acceptSelected);
    $('btnBpDraftReview').addEventListener('click', openDraftModal);
    $('btnBpDraftApply').addEventListener('click', openDraftModal);
    $('btnBpDraftDiscard').addEventListener('click', async () => {
        if (!confirm(tr('bpConfirmDiscard'))) return;
        const res = await send('/draft/discard', 'POST', {});
        if (!res || !res.ok) { showToast(await errorText(res), 'error'); return; }
        await refresh();
    });
    $('btnBpDraftApplyConfirm').addEventListener('click', applyDraft);
    $('btnBpAlign').addEventListener('click', align);
    $('btnBpLocSave').addEventListener('click', () => bpLocSave && bpLocSave());
    $('btnBpLinkSave').addEventListener('click', () => bpLinkSave && bpLinkSave());
    $('btnBpPresetCreate').addEventListener('click', createPreset);
    $('btnBpDiff').addEventListener('click', compare);

    $('bpSteps').addEventListener('click', (e) => {
        const b = e.target.closest('[data-bp-step]');
        if (!b) return;
        if (b.dataset.bpStep === 'preset') openPreset();
        else if (b.dataset.bpStep === 'observe') observe();
        else $('bpFindings').scrollIntoView({ behavior: 'smooth' });
    });
    $('bpLocationsBody').addEventListener('click', (e) => {
        const b = e.target.closest('[data-action]');
        if (!b) return;
        const id = b.dataset.id;
        if (b.dataset.action === 'bp-edit-loc') editLocation(id);
        else if (b.dataset.action === 'bp-del-loc' && confirm(tr('bpConfirmDeleteLoc', { name: locName(id) }))) {
            addOps([{ op: 'delete_location', id }]);
        }
    });
    $('bpLinksBody').addEventListener('click', (e) => {
        const b = e.target.closest('[data-action]');
        if (!b) return;
        if (b.dataset.action === 'bp-edit-link') editLink(b.dataset.id);
        else if (b.dataset.action === 'bp-del-link') addOps([{ op: 'remove_link', id: b.dataset.id }]);
    });
    $('bpFindings').addEventListener('click', (e) => {
        const b = e.target.closest('[data-action="bp-edit-proposal"]');
        if (!b) return;
        const f = bpFindings[+b.dataset.f];
        const j = +b.dataset.o;
        openOpEditor(f.proposal[j], (next) => { f.proposal[j] = next; renderFindings(); return true; });
    });
    $('bpDraftOps').addEventListener('click', (e) => {
        const b = e.target.closest('[data-action]');
        if (!b) return;
        const i = +b.dataset.i;
        const ops = draftOps().slice();
        if (b.dataset.action === 'bp-op-remove') {
            ops.splice(i, 1);
            replaceOps(ops).then(renderDraftOps);
        } else if (b.dataset.action === 'bp-op-edit') {
            // One modal at a time: the draft list reopens after the edit.
            closeModal('bpDraftModal');
            openOpEditor(ops[i], async (next) => {
                ops[i] = Object.assign({}, next, { source: ops[i].source });
                const ok = await replaceOps(ops);
                if (ok) openDraftModal();
                return ok;
            });
        }
    });
    $('bpRevisionsBody').addEventListener('click', (e) => {
        const b = e.target.closest('[data-action="bp-restore"]');
        if (b) restore(+b.dataset.rev);
    });
})();
```

- [ ] **Step 6: Strings** — `static/js/i18n.js`. Insert right after `    it: {`:

```js
        // Network Blueprint (blueprint.js)
        tabBlueprint: "Blueprint di rete",
        descBlueprint: "La rete come deve essere, confrontata con quella che SentinelNet osserva.",
        btnOpenBlueprint: "Blueprint",
        lblBpOrg: "Organizzazione",
        btnBpCheck: "Verifica",
        btnBpObserve: "Aggiorna dai gateway",
        btnBpPreset: "Preset…",
        btnBpHistory: "Storico",
        bpRevInfo: "rev {rev} · {at} · {by}",
        bpRevNone: "nessuna revisione",
        bpObsInfo: "dati gateway: {at}",
        bpObsNone: "dati gateway: mai raccolti",
        bpStepsTitle: "Primi passi",
        bpStep1: "Definisci le sedi",
        bpStep2: "Ogni sede ha le sue subnet",
        bpStep3: "Ogni filiale è collegata alla sede centrale",
        bpStep4: "Ogni sede ha un gateway",
        bpStep5: "Raccogli i dati dai gateway",
        bpStep6: "Nessun errore nelle verifiche",
        btnBpSeeFindings: "Vedi le verifiche",
        bpDraftInfo: "Bozza · {n} modifiche · da rev {rev}",
        bpDraftInvalid: "la bozza non è più valida: {error}",
        btnBpDraftReview: "Rivedi",
        btnBpDraftApply: "Applica",
        btnBpDraftDiscard: "Scarta",
        bpConfirmDiscard: "Scartare la bozza?",
        bpLocations: "Sedi",
        bpLinks: "Collegamenti",
        btnBpAddLocation: "Nuova sede",
        btnBpAddLink: "Nuovo collegamento",
        thBpLocName: "Sede",
        thBpRole: "Ruolo",
        thBpSubnets: "Subnet",
        thBpGateway: "Gateway",
        thBpProbe: "Sonda",
        thBpActions: "Azioni",
        thBpLinkA: "Sede A",
        thBpLinkB: "Sede B",
        thBpKind: "Tipo",
        bpInDraft: "in bozza",
        bpNoLocations: "Nessuna sede: parti da un preset.",
        bpNoLinks: "Nessun collegamento.",
        bpDiagramAria: "Diagramma delle sedi e dei collegamenti",
        bpFindingsTitle: "Verifiche",
        btnBpAcceptSelected: "Aggiungi alla bozza",
        bpAddedToDraft: "{n} modifiche aggiunte alla bozza.",
        bpNoFindings: "Nessuna segnalazione.",
        bpAcceptProposal: "Accetta la proposta",
        btnBpEditOp: "modifica",
        btnBpRemoveOp: "rimuovi",
        bpGroup_model: "Coerenza del modello",
        bpGroup_subnets: "Subnet e inventario",
        bpGroup_routing: "Routing",
        bpGroup_vpn: "VPN",
        bpSev_error: "errore",
        bpSev_warning: "avviso",
        bpSev_info: "info",
        bpSev_unknown: "sconosciuto",
        bpf_subnet_overlap: "Subnet sovrapposte: {a} ({subnet_a}) e {b} ({subnet_b}).",
        bpf_location_no_subnets: "{name}: nessuna subnet dichiarata.",
        bpf_location_isolated: "{name}: nessun collegamento verso la sede centrale o un datacenter.",
        bpf_location_no_gateway: "{name}: gateway non indicato.",
        bpf_gateway_not_in_location: "{name}: il gateway {ip} non è un apparato di questa sede.",
        bpf_device_outside_subnets: "{ip} è in {name} ma fuori dalle sue subnet.",
        bpf_device_outside_subnets_owner: "{ip} è in {name} ma il suo indirizzo è nelle subnet di {owner}: spostalo dall'inventario.",
        bpf_arp_uncovered: "{name}: {subnet} visto in ARP dal gateway ({count} indirizzi), non coperto da nessuna sede.",
        bpf_subnet_unused: "{name}: {subnet} senza apparati né voci ARP.",
        bpf_link_no_route: "Il gateway di {src} non ha una rotta verso {subnet} ({dst}).",
        bpf_link_no_route_backup: "Nelle rotte statiche del backup del gateway di {src} manca {subnet} ({dst}): le dinamiche non sono note, aggiorna dai gateway.",
        bpf_link_no_route_default: "{src} raggiunge {subnet} ({dst}) solo con la rotta di default.",
        bpf_link_no_route_unknown: "{src} → {dst}: rotte non disponibili (gateway mancante o senza dati).",
        bpf_route_without_link: "Il gateway di {src} ha la rotta {network} verso {dst} ({interface}) ma manca il collegamento.",
        bpf_vpn_link_down_missing: "{side} → {other}: nessun tunnel IPsec verso l'altra sede.",
        bpf_vpn_link_down_down: "{side} → {other}: il tunnel {tunnel} è giù.",
        bpf_vpn_link_down_unknown: "{side} ↔ {other}: stato dei tunnel sconosciuto (serve un FortiGate come gateway e «Aggiorna dai gateway»).",
        bpf_tunnel_without_link: "Tunnel {tunnel} attivo fra {src} e {dst} senza collegamento VPN nel modello.",
        bpOpCreate: "Crea la sede {name} ({role})",
        bpOpUpdate: "Modifica {name}: {fields}",
        bpOpAddSubnet: "Aggiungi {subnet} a {name}",
        bpOpGateway: "Gateway di {name}: {ip}",
        bpOpDelete: "Elimina la sede {name}",
        bpOpLink: "Collega {a} e {b} ({kind})",
        bpOpUnlink: "Rimuovi il collegamento {id}",
        bpConfirmDeleteLoc: "Eliminare la sede {name}? Diventa una modifica della bozza.",
        bpLocModalTitle: "Sede",
        lblBpLocName: "Nome",
        lblBpLocRole: "Ruolo",
        lblBpLocSubnets: "Subnet (una per riga, CIDR)",
        lblBpLocProbe: "Sonda predefinita",
        lblBpLocGateway: "Gateway (IP di un apparato della sede)",
        btnBpSaveToDraft: "Salva nella bozza",
        bpLinkModalTitle: "Collegamento",
        lblBpLinkNote: "Nota",
        bpLinkSame: "Scegli due sedi diverse.",
        bpKind_vpn: "VPN",
        bpKind_wan: "WAN",
        bpKind_mpls: "MPLS",
        bpKind_lan: "LAN",
        bpPresetModalTitle: "Preset",
        bpPresetHint: "Crea una bozza: le sedi esistenti restano, le subnet si completano con le verifiche.",
        lblBpPresetKind: "Topologia",
        bpPreset_single: "Sede singola",
        bpPreset_hub_spoke: "Hub-and-spoke (sede centrale + N filiali via VPN)",
        bpPreset_hub_spoke_dc: "Hub-and-spoke con datacenter",
        bpPreset_full_mesh: "Full mesh (N sedi)",
        lblBpPresetN: "Numero di sedi (1–50)",
        btnBpPresetCreate: "Crea bozza",
        bpDraftModalTitle: "Bozza",
        lblBpApplyNote: "Nota della revisione (facoltativa)",
        btnBpDraftApplyConfirm: "Applica la bozza",
        bpConflict: "Il modello è cambiato dopo la creazione della bozza. Ecco cosa è cambiato:",
        btnBpAlign: "Allinea alla versione attuale",
        bpApplied: "Bozza applicata: revisione {rev}.",
        bpRenamed: "Sedi ripristinate con un id diverso: {list}",
        bpHistoryModalTitle: "Storico revisioni",
        thBpRev: "Rev",
        thBpAt: "Quando",
        thBpBy: "Chi",
        thBpSource: "Origine",
        thBpNote: "Nota",
        btnBpRestore: "Ripristina",
        lblBpDiffA: "Da",
        lblBpDiffB: "A",
        btnBpDiff: "Confronta",
        bpDiffNone: "Nessuna differenza.",
        bpRestoreOpened: "Bozza di ripristino alla revisione {rev} aperta: rivedila e applicala.",
        bpSource_migration: "migrazione",
        bpSource_blueprint: "blueprint",
        bpSource_locations: "sedi",
        bpSource_import: "import",
        bpSource_restore: "ripristino",
        bpObserved: "Dati raccolti da {n} gateway.",
```

Insert right after `    en: {`:

```js
        // Network Blueprint (blueprint.js)
        tabBlueprint: "Network Blueprint",
        descBlueprint: "The network as it should be, compared with what SentinelNet observes.",
        btnOpenBlueprint: "Blueprint",
        lblBpOrg: "Organization",
        btnBpCheck: "Check",
        btnBpObserve: "Refresh from gateways",
        btnBpPreset: "Presets…",
        btnBpHistory: "History",
        bpRevInfo: "rev {rev} · {at} · {by}",
        bpRevNone: "no revision",
        bpObsInfo: "gateway data: {at}",
        bpObsNone: "gateway data: never collected",
        bpStepsTitle: "First steps",
        bpStep1: "Define the locations",
        bpStep2: "Every location has its subnets",
        bpStep3: "Every branch is linked to the headquarters",
        bpStep4: "Every location has a gateway",
        bpStep5: "Collect data from the gateways",
        bpStep6: "No errors in the checks",
        btnBpSeeFindings: "See the checks",
        bpDraftInfo: "Draft · {n} changes · from rev {rev}",
        bpDraftInvalid: "the draft is no longer valid: {error}",
        btnBpDraftReview: "Review",
        btnBpDraftApply: "Apply",
        btnBpDraftDiscard: "Discard",
        bpConfirmDiscard: "Discard the draft?",
        bpLocations: "Locations",
        bpLinks: "Links",
        btnBpAddLocation: "New location",
        btnBpAddLink: "New link",
        thBpLocName: "Location",
        thBpRole: "Role",
        thBpSubnets: "Subnets",
        thBpGateway: "Gateway",
        thBpProbe: "Probe",
        thBpActions: "Actions",
        thBpLinkA: "Location A",
        thBpLinkB: "Location B",
        thBpKind: "Type",
        bpInDraft: "in draft",
        bpNoLocations: "No locations: start from a preset.",
        bpNoLinks: "No links.",
        bpDiagramAria: "Diagram of locations and links",
        bpFindingsTitle: "Checks",
        btnBpAcceptSelected: "Add to draft",
        bpAddedToDraft: "{n} changes added to the draft.",
        bpNoFindings: "No findings.",
        bpAcceptProposal: "Accept the proposal",
        btnBpEditOp: "edit",
        btnBpRemoveOp: "remove",
        bpGroup_model: "Model consistency",
        bpGroup_subnets: "Subnets and inventory",
        bpGroup_routing: "Routing",
        bpGroup_vpn: "VPN",
        bpSev_error: "error",
        bpSev_warning: "warning",
        bpSev_info: "info",
        bpSev_unknown: "unknown",
        bpf_subnet_overlap: "Overlapping subnets: {a} ({subnet_a}) and {b} ({subnet_b}).",
        bpf_location_no_subnets: "{name}: no subnet declared.",
        bpf_location_isolated: "{name}: no link to the headquarters or a datacenter.",
        bpf_location_no_gateway: "{name}: no gateway set.",
        bpf_gateway_not_in_location: "{name}: gateway {ip} is not a device of this location.",
        bpf_device_outside_subnets: "{ip} is in {name} but outside its subnets.",
        bpf_device_outside_subnets_owner: "{ip} is in {name} but its address is in the subnets of {owner}: move it from the inventory.",
        bpf_arp_uncovered: "{name}: {subnet} seen in ARP by the gateway ({count} addresses), covered by no location.",
        bpf_subnet_unused: "{name}: {subnet} has no device and no ARP entry.",
        bpf_link_no_route: "The gateway of {src} has no route to {subnet} ({dst}).",
        bpf_link_no_route_backup: "The static routes in the backup of the {src} gateway miss {subnet} ({dst}): dynamic routes are unknown, refresh from the gateways.",
        bpf_link_no_route_default: "{src} reaches {subnet} ({dst}) only through the default route.",
        bpf_link_no_route_unknown: "{src} → {dst}: routes unavailable (no gateway or no data).",
        bpf_route_without_link: "The gateway of {src} routes {network} to {dst} ({interface}) but the link is missing.",
        bpf_vpn_link_down_missing: "{side} → {other}: no IPsec tunnel to the other location.",
        bpf_vpn_link_down_down: "{side} → {other}: tunnel {tunnel} is down.",
        bpf_vpn_link_down_unknown: "{side} ↔ {other}: tunnel state unknown (needs a FortiGate gateway and «Refresh from gateways»).",
        bpf_tunnel_without_link: "Tunnel {tunnel} up between {src} and {dst} with no VPN link in the model.",
        bpOpCreate: "Create location {name} ({role})",
        bpOpUpdate: "Change {name}: {fields}",
        bpOpAddSubnet: "Add {subnet} to {name}",
        bpOpGateway: "Gateway of {name}: {ip}",
        bpOpDelete: "Delete location {name}",
        bpOpLink: "Link {a} and {b} ({kind})",
        bpOpUnlink: "Remove link {id}",
        bpConfirmDeleteLoc: "Delete location {name}? It becomes a draft change.",
        bpLocModalTitle: "Location",
        lblBpLocName: "Name",
        lblBpLocRole: "Role",
        lblBpLocSubnets: "Subnets (one per line, CIDR)",
        lblBpLocProbe: "Default probe",
        lblBpLocGateway: "Gateway (IP of a device of the location)",
        btnBpSaveToDraft: "Save to draft",
        bpLinkModalTitle: "Link",
        lblBpLinkNote: "Note",
        bpLinkSame: "Pick two different locations.",
        bpKind_vpn: "VPN",
        bpKind_wan: "WAN",
        bpKind_mpls: "MPLS",
        bpKind_lan: "LAN",
        bpPresetModalTitle: "Presets",
        bpPresetHint: "Creates a draft: existing locations stay, subnets get filled in by the checks.",
        lblBpPresetKind: "Topology",
        bpPreset_single: "Single location",
        bpPreset_hub_spoke: "Hub-and-spoke (headquarters + N branches over VPN)",
        bpPreset_hub_spoke_dc: "Hub-and-spoke with datacenter",
        bpPreset_full_mesh: "Full mesh (N locations)",
        lblBpPresetN: "Number of locations (1–50)",
        btnBpPresetCreate: "Create draft",
        bpDraftModalTitle: "Draft",
        lblBpApplyNote: "Revision note (optional)",
        btnBpDraftApplyConfirm: "Apply the draft",
        bpConflict: "The model changed after the draft was created. Here is what changed:",
        btnBpAlign: "Align to current version",
        bpApplied: "Draft applied: revision {rev}.",
        bpRenamed: "Locations restored with a different id: {list}",
        bpHistoryModalTitle: "Revision history",
        thBpRev: "Rev",
        thBpAt: "When",
        thBpBy: "Who",
        thBpSource: "Source",
        thBpNote: "Note",
        btnBpRestore: "Restore",
        lblBpDiffA: "From",
        lblBpDiffB: "To",
        btnBpDiff: "Compare",
        bpDiffNone: "No differences.",
        bpRestoreOpened: "Restore draft to revision {rev} opened: review and apply it.",
        bpSource_migration: "migration",
        bpSource_blueprint: "blueprint",
        bpSource_locations: "locations",
        bpSource_import: "import",
        bpSource_restore: "restore",
        bpObserved: "Data collected from {n} gateways.",
```

- [ ] **Step 7: Styles** — append to `static/css/dashboard.css`:

```css
/* Network Blueprint (blueprint.js) */
.bp-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; }
.bp-bar select { width: auto; min-width: 180px; }
.bp-bar-actions { display: flex; flex-wrap: wrap; gap: 6px; margin-left: auto; }
.bp-meta { font-size: 12px; color: var(--text-muted); }
.bp-draft-bar { position: sticky; top: 0; z-index: 5; display: flex; flex-wrap: wrap; align-items: center; gap: 8px; border-left: 3px solid var(--warning); }
.bp-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 16px; }
@media (max-width: 1100px) { .bp-grid { grid-template-columns: minmax(0, 1fr); } }
.bp-diagram { height: 440px; }
.bp-mono { font-family: var(--font-code); font-size: 12px; }
.bp-steps { margin: 0; padding-left: 20px; }
.bp-steps li { margin: 4px 0; }
.bp-steps li.is-done { color: var(--text-muted); }
.bp-steps li.is-done .fa-check { color: var(--success); }
.bp-group { margin: 14px 0 6px; font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em; }
.bp-findings, .bp-ops, .bp-diff { margin: 0; padding-left: 18px; }
.bp-findings li, .bp-ops li { margin: 6px 0; }
.bp-proposal { display: flex; align-items: center; gap: 10px; margin: 4px 0 0 4px; font-size: 13px; }
.bp-sev { display: inline-block; min-width: 72px; padding: 1px 6px; border: 1px solid currentColor; font-size: 11px; text-align: center; }
.bp-sev-error { color: var(--danger); }
.bp-sev-warning { color: var(--warning); }
.bp-sev-info { color: var(--primary); }
.bp-sev-unknown { color: var(--text-muted); }
.bp-draft-tag { font-size: 11px; color: var(--warning); }
.bp-link-btn { background: none; border: none; color: var(--primary); cursor: pointer; padding: 0 4px; font-size: 13px; }
.bp-link-btn.danger { color: var(--danger); }
.bp-diff-add { color: var(--success); }
.bp-diff-del { color: var(--danger); }
.bp-conflict { margin: 12px 0; padding: 10px; border: 1px solid var(--warning); }
```

- [ ] **Step 8: Run tests and checks**

Run:
```bash
uv run pytest tests/test_blueprint_tab.py tests/test_lazy_tab_scripts.py tests/test_ui_modal.py tests/test_i18n_keys.py tests/test_a11y_dashboard.py tests/test_tab_enforcement.py -v
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
node tests/js/test_assignable_tabs.mjs
```
Expected: all PASS / zero findings. If `check_i18n_coverage` reports the dynamic keys (`'bpf_' + f.code`, `'bpKind_' + k.kind`, …) as unknown, follow what the script already accepts for dynamic lookups in other modules (e.g. `'locRole_' + role`) rather than widening it.

- [ ] **Step 9: Run it** — `uv run python app_server.py`, log in as admin, open «Blueprint di rete»: pick an organization, Preset → Hub-and-spoke 2 → draft bar appears, diagram shows dashed nodes; «Rivedi» → «Applica la bozza» → toast with the revision; «Storico» → compare the last two revisions → the diff lists the two branches; «Ripristina» the earlier one → apply → back to the original. The browser console shows no error.

- [ ] **Step 10: Gate and commit**

```bash
uv run pyrefly check && uv run python scripts/check_frontend.py && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add templates/dashboard.html static/js/blueprint.js static/js/core.js static/js/settings.js static/js/devices.js static/js/i18n.js types/globals.d.ts static/css/dashboard.css tests/test_blueprint_tab.py
git commit -m "feat(blueprint): the Blueprint tab"
```

---

### Task 11: Docs, screenshots, graph

**Model:** sonnet

**Files:**
- Create: `docs/network-blueprint.md`
- Modify: `docs/README.md` (one row after `organizations-locations.md`), `docs/organizations-locations.md` (one line pointing to the Blueprint)
- Regenerate: `docs/images/` via `scripts/dev/capture_screenshots.py` (the nav gained a button)

- [ ] **Step 1: Write `docs/network-blueprint.md`** — for an admin who knows the Organizations tab. Sections: what the Blueprint is (expected vs observed); drafts (every edit is a draft operation, apply is all-or-nothing, «Allinea alla versione attuale» when someone changed the model meanwhile); revisions (every write from any path, an organization's history survives its deletion, restore = a draft); presets (the four, existing locations kept, subnets left empty); the checks table (code, what it compares, when it is «sconosciuto»), with the backup-only caveat for routes and the FortiGate-only caveat for tunnels; «Aggiorna dai gateway» (live, per gateway; agent-probe gateways are not reachable from the central server); «Primi passi». Example data only (`10.10.0.0/16`, `milano`, `roma`).

- [ ] **Step 2: Index rows**

`docs/README.md`, after the organizations-locations row:

```markdown
| [network-blueprint.md](network-blueprint.md) | Network Blueprint: expected network per organization (locations, links, gateways), drafts, revisions and restore, presets, deterministic checks against observed routes, ARP and IPsec tunnels |
```

`docs/organizations-locations.md`, at the end:

```markdown
Links between locations, each location's gateway and the checks against the observed network live in the [Network Blueprint](network-blueprint.md).
```

- [ ] **Step 3: Screenshots and graph**

```bash
uv run python scripts/dev/capture_screenshots.py
graphify update .
```

If `graphify update .` refuses with «fewer nodes», do not pass `--force` before checking what shrank (AGENTS.md).

- [ ] **Step 4: Gate and commit**

```bash
uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add docs/network-blueprint.md docs/README.md docs/organizations-locations.md docs/images
git commit -m "docs(blueprint): Network Blueprint guide, screenshots"
```

---

## After this plan

Sub-project 4 (assistant: «Descrivi la rete», «Ricava dalle configurazioni», draft-only MCP tool) writes drafts through `blueprint.add_ops(org, ops, "assistant", by)` — its own route or tool passes `"assistant"`; `_CLIENT_SOURCES` stays as it is. Sub-project 5 (maps and routing per location) reads `inventory_store.read_links`. Each gets its own brainstorming → spec → plan. Version bump at release time (`scripts/dev/release.py`, MINOR: new tab).
