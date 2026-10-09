# Site → Probe Rename Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove "site" (meaning *probe*) from code, data files, SQLite, HTTP API, wire protocol, frontend and living docs, replacing it with "probe", with no behaviour change other than the renamed names.

**Architecture:** A scanning test (`tests/test_no_site_identifier.py`) is added first with a `PENDING` set of files still allowed to offend; each task renames one layer, keeps the suite green and shrinks `PENDING`; the last task empties it. A one-shot startup migration renames the persisted names (files, CSV header, SQLite columns, user tab ids).

**Tech Stack:** Python 3 / FastAPI / SQLite / classic-script JS (no bundler) / unittest run by pytest (`uv run pytest tests -n 4`).

**Spec:** `docs/superpowers/specs/2026-10-09-site-to-probe-rename-design.md`

## Global Constraints

- No transition: `X-Site-Id`/`X-Site-Token` are **rejected** after Task 4 (test agents are reinstalled). No dual header, no alias in code paths.
- The only "site" spellings accepted after the plan: CSV import alias `site` → `Probe` (a system boundary, so old exports reimport), the 401 assertion for old headers in tests, the migration's old names, the scanner's own patterns — each such line carries the marker `check-site-name: ok`.
- `central` keeps its value. "agent" (the software, `/api/agent/*`, `sentinelnet-agent` unit) is not renamed.
- `audit_engagements.site_id` means a *location*, not a probe: it becomes `location_id` (Task 3).
- New/rewritten comments in English; existing Italian comments are edited only where they contain a renamed identifier (AGENTS.md).
- Historical documents (`docs/superpowers/plans/*`, `docs/superpowers/specs/*` other than the 2026-10-09 ones) are **not** edited: they record what was true then.
- Every user-facing string through `tr()`; both languages; the dictionary keys renamed too.
- Gate before each commit (AGENTS.md): `uv run pyrefly check` (0 errors), `uv run python scripts/check_frontend.py` (when JS/templates change), `uv run pytest tests -n 4`, `uv run python scripts/check_no_private_data.py`.
- Never edit `users.json` / key stores by hand; the migration goes through `user_manager`'s save path.
- Subagent models: **haiku** for pure mechanical renames with a table to follow (Task 6), **sonnet** for anything that needs judgment (Tasks 1–5). Final whole-branch review on the most capable model.

## Review Focus

1. **An agent still sending `X-Site-*`** → must get 401 with a message saying the probe agent must be reinstalled, not a 500. Test in Task 4.
2. **Upgrading an install whose `network_hosts.csv` has `Site` but no `sites.json`** (never opened the Sites tab) → header still renamed, devices keep `central`. Test in Task 2.
3. **Migration run twice / restarted mid-way** → second run is a no-op, nothing duplicated, no backup overwritten. Test in Task 2.
4. **A user restricted to `tab-sites`** → after upgrade they still see the Probes tab (`tab-probes`). Test in Task 2.
5. **Reimporting a CSV exported before the rename** (column `Site`) → devices keep their probe. Test in Task 3.

---

## File map

| Layer | Before | After |
|---|---|---|
| Registry module | `services/site_manager.py` | `services/probe_manager.py` |
| Agent program | `services/site_agent.py` | `services/probe_agent.py` |
| Router | `routers/sites.py` | `routers/probes.py` |
| Migration (new) | — | `core/probe_migration.py` |
| Agent JS | `static/js/site-agent.js` | `static/js/probe-agent.js` |
| Living docs | `docs/remote-sites.md` | `docs/probes.md` |
| Tests renamed | `tests/test_sites.py`, `test_jump_site.py`, `test_remote_site.py`, `test_site_editing.py`, `test_site_verified.py`, `test_site_wizard_api.py`, `test_site_wizard_ui.py`, `test_device_site_gui.py`, `tests/js/test_site_enrollment.mjs` | `test_probes.py`, `test_bastion_probe.py`, `test_agent_probe.py`, `test_probe_editing.py`, `test_probe_verified.py`, `test_probe_wizard_api.py`, `test_probe_wizard_ui.py`, `test_device_probe_gui.py`, `tests/js/test_probe_enrollment.mjs` |

### Identifier rename table (used by Tasks 3–6)

| Before | After |
|---|---|
| `site_manager` | `probe_manager` |
| `SITES_JSON`, `"sites.json"` | `PROBES_JSON`, `"probes.json"` |
| `DEFAULT_SITE_ID` | `DEFAULT_PROBE_ID` (value `"central"`) |
| `_default_sites`, `list_sites`, `get_site`, `create_site`, `update_site`, `delete_site`, `set_site_flow_status` | `_default_probes`, `list_probes`, `get_probe`, `create_probe`, `update_probe`, `delete_probe`, `set_probe_flow_status` |
| `is_agent_site`, `_is_agent_site` | `is_agent_probe`, `_is_agent_probe` |
| `site_id` (params, vars, SQL column, JSON keys) | `probe_id` |
| `site` / `sites` (local vars holding registry entries) | `probe` / `probes` |
| device column `'Site'` | `'Probe'` |
| `get_device_by_ip(...)["site"]` | `["probe"]` |
| `mac_sightings.site` | `mac_sightings.probe` |
| `command_jobs.site_id`, index `ix_jobs_site` | `probe_id`, `ix_jobs_probe` |
| `net_ssh.invalidate_site`, `jump_site_for` | `invalidate_probe`, `bastion_probe_for` |
| `routers/agent.py` `get_agent_site`, `_devices_for_site` | `get_agent_probe`, `_devices_for_probe` |
| `routers/scan.py` `_site_for_network` | `_probe_for_network` |
| `routers/inventory.py` `reassign_device_site`, `/api/reassign-device-site` | `reassign_device_probe`, `/api/reassign-device-probe` |
| `client_diagnosis._across_sites` | `_across_probes` |
| `routers/sites.py` `*_site_*_ep`, `/api/sites…`, `{site_id}` | `routers/probes.py` `*_probe_*_ep`, `/api/probes…`, `{probe_id}` |
| headers `X-Site-Id`, `X-Site-Token` | `X-Probe-Id`, `X-Probe-Token` |
| agent CLI `--site-id`, config key `site_id` | `--probe-id`, `probe_id` |
| tab id `tab-sites` | `tab-probes` |
| `static/js/site-agent.js`, JS `loadSites`, `site*`/`Site*` ids and i18n keys | `probe-agent.js`, `loadProbes`, `probe*`/`Probe*` |
| `audit_engagements.site_id`, request field `site_id` | `location_id` |

---

### Task 1: Scanning test with a shrinking PENDING set

**Model:** sonnet

**Files:**
- Create: `tests/test_no_site_identifier.py`

**Interfaces:**
- Produces: `PENDING: frozenset[str]` (repo-relative POSIX paths) inside the test file; every later task deletes its files from it. `offending(text) -> list[tuple[int, list[str]]]`.

- [ ] **Step 1: Write the scanner**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
""""site" meant *probe* and is gone: one name per concept (spec
2026-10-09-site-to-probe-rename-design.md). A new site_... is a red test.

A line that must keep the spelling (the CSV alias for old exports, the test
asserting old headers are refused, the migration's old names) carries the
marker below; adding one is a reviewable diff, the same rule as
check_no_private_data.

PENDING lists files not renamed yet. It only shrinks: a listed file that no
longer offends fails too, so the list cannot go stale."""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "check-site-name: ok"
SCANNED = re.compile(r"\.(py|js|mjs|html|ts|sql|ps1|sh|spec|service)$")
TOKEN = re.compile(r"[A-Za-z0-9_-]*[Ss][Ii][Tt][Ee][A-Za-z0-9_-]*")
QUOTED = re.compile(r"""['"]Sites?['"]|/sites\b""")
# Words that merely contain the letters; each was reviewed.
WORDS = ("site-to-site", "prerequisite", "opposite", "offsite", "onsite",
         "composite", "website", "requisite", "parasite")

PENDING = frozenset({
    # Filled in Step 3 from the first run's output.
})


def _bad(token: str) -> bool:
    t = token.lower()
    for w in WORDS:
        t = t.replace(w, "")
    return "site" in t and t not in ("site", "sites")


def offending(text: str):
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        if MARK in line:
            continue
        bad = [t for t in TOKEN.findall(line) if _bad(t)] + QUOTED.findall(line)
        if bad:
            hits.append((n, bad))
    return hits


def _tracked():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout.splitlines()
    return [p for p in out if not p.startswith("docs/")]


class TestNoSiteIdentifier(unittest.TestCase):
    def _offenders(self):
        found = {}
        for rel in _tracked():
            if rel == "tests/test_no_site_identifier.py":
                continue
            if _bad(Path(rel).name):
                found[rel] = [(0, ["<file name>"])]
                continue
            if not SCANNED.search(rel):
                continue
            hits = offending((ROOT / rel).read_text(encoding="utf-8", errors="replace"))
            if hits:
                found[rel] = hits
        return found

    def test_no_new_offenders(self):
        new = {p: h[:3] for p, h in self._offenders().items() if p not in PENDING}
        self.assertEqual(new, {}, "rename to probe, or mark the line with " + MARK)

    def test_pending_only_shrinks(self):
        stale = sorted(PENDING - set(self._offenders()))
        self.assertEqual(stale, [], "remove these from PENDING: they are clean")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to see the full offender list**

Run: `uv run pytest tests/test_no_site_identifier.py -q`
Expected: `test_no_new_offenders` FAILS listing ~150 files; `test_pending_only_shrinks` passes (PENDING empty).

- [ ] **Step 3: Review false positives, then fill PENDING**

Print every offending token:

```bash
uv run python -c "
import tests.test_no_site_identifier as t
for p,h in sorted(t.TestNoSiteIdentifier()._offenders().items()):
    print(p, sorted({x for _,b in h for x in b})[:8])"
```

For each token that is an ordinary English/Italian word and not an identifier (e.g. `visited`, `exquisite`), add the word to `WORDS`, nothing else. Then paste every remaining offending path into `PENDING`, sorted, one per line.

- [ ] **Step 4: Run it to verify it passes**

Run: `uv run pytest tests/test_no_site_identifier.py -q`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add tests/test_no_site_identifier.py
git commit -m "test: scanner for site identifiers, with a shrinking pending list"
```

---

### Task 2: One-shot data migration (not wired yet)

**Model:** sonnet

**Files:**
- Create: `core/probe_migration.py`
- Modify: `security/user_manager.py` (add `rename_allowed_tab`)
- Test: `tests/test_probe_migration.py`

**Interfaces:**
- Produces: `core.probe_migration.migrate(data_dir: str) -> list[str]` — human-readable steps performed, `[]` when nothing to do. `security.user_manager.rename_allowed_tab(old: str, new: str) -> list[str]` — usernames changed.

Each step is independently idempotent (keyed on the old name being present), so an install that never had `sites.json` still gets its CSV header renamed, and a crash mid-way finishes on the next start.

- [ ] **Step 1: Write the failing tests**

First read `security/user_manager.py` for the real allowed-tabs setter name (`grep -n "allowed_tabs" security/user_manager.py`) and use it where the test says `set_allowed_tabs`.

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""One-shot rename of persisted 'site' names to 'probe'."""
import csv
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from core import probe_migration
from security import user_manager

PW = "PasswordSicura1!"
HEADER_OLD = "IP,Vendor,Group,Hostname,Site\n"  # check-site-name: ok


class TestProbeMigration(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="probe_mig_")
        p = patch.object(user_manager, "USERS_JSON", os.path.join(self.d, "users.json"))
        p.start()
        self.addCleanup(p.stop)

    def _write(self, name, text):
        with open(os.path.join(self.d, name), "w", encoding="utf-8", newline="") as f:
            f.write(text)

    def _hosts_header(self):
        with open(os.path.join(self.d, "network_hosts.csv"), encoding="utf-8") as f:
            return next(csv.reader(f))

    def test_registry_file_renamed_and_backed_up(self):
        self._write("sites.json", json.dumps({"central": {"id": "central"}}))  # check-site-name: ok
        self.assertTrue(probe_migration.migrate(self.d))
        self.assertTrue(os.path.exists(os.path.join(self.d, "probes.json")))
        self.assertFalse(os.path.exists(os.path.join(self.d, "sites.json")))  # check-site-name: ok
        self.assertTrue(os.path.exists(os.path.join(self.d, "sites.json.pre-probe")))  # check-site-name: ok

    def test_csv_header_renamed_without_registry_file(self):
        self._write("network_hosts.csv", HEADER_OLD + "192.0.2.1,cisco,acme,sw-01,central\n")
        probe_migration.migrate(self.d)
        self.assertEqual(self._hosts_header()[-1], "Probe")
        with open(os.path.join(self.d, "network_hosts.csv"), encoding="utf-8") as f:
            self.assertEqual(list(csv.DictReader(f))[0]["Probe"], "central")

    def test_mac_history_column_renamed(self):
        db = os.path.join(self.d, "mac_history.db")
        with sqlite3.connect(db) as c:
            c.execute("CREATE TABLE mac_sightings (mac TEXT, site TEXT DEFAULT 'central')")  # check-site-name: ok
            c.execute("INSERT INTO mac_sightings VALUES ('AA:BB:CC:DD:EE:FF', 'central')")
        probe_migration.migrate(self.d)
        with sqlite3.connect(db) as c:
            cols = [r[1] for r in c.execute("PRAGMA table_info(mac_sightings)")]
            self.assertIn("probe", cols)
            self.assertEqual(c.execute("SELECT probe FROM mac_sightings").fetchone()[0], "central")

    def test_jobs_table_dropped(self):
        db = os.path.join(self.d, "agent_jobs.db")
        with sqlite3.connect(db) as c:
            c.execute("CREATE TABLE command_jobs (id TEXT, site_id TEXT)")  # check-site-name: ok
        probe_migration.migrate(self.d)
        with sqlite3.connect(db) as c:
            self.assertIsNone(c.execute(
                "SELECT name FROM sqlite_master WHERE name='command_jobs'").fetchone())

    def test_user_tab_restriction_follows_the_rename(self):
        user_manager.create_user("op", PW, role="operator")
        user_manager.set_allowed_tabs("op", ["tab-devices", "tab-sites"])  # check-site-name: ok
        probe_migration.migrate(self.d)
        self.assertEqual(user_manager.get_allowed_tabs("op"), ["tab-devices", "tab-probes"])

    def test_second_run_is_a_noop(self):
        self._write("sites.json", "{}")  # check-site-name: ok
        self._write("network_hosts.csv", HEADER_OLD)
        probe_migration.migrate(self.d)
        self.assertEqual(probe_migration.migrate(self.d), [])
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_probe_migration.py -q`
Expected: FAIL with `ImportError: cannot import name 'probe_migration'`.

- [ ] **Step 3: Implement `rename_allowed_tab` in `security/user_manager.py`**

Add next to `migrate_admins_to_super_admin`:

```python
def rename_allowed_tab(old: str, new: str) -> list:
    """Rename a tab id inside every user's allowed-tab list (one-shot
    migrations). Returns the usernames changed."""
    changed = []
    with _users_lock:
        users = get_users()
        for name, d in users.items():
            tabs = d.get("allowed_tabs") or []
            if old in tabs:
                d["allowed_tabs"] = [new if t == old else t for t in tabs]
                changed.append(name)
        if changed:
            _save_users(users)
    return sorted(changed)
```

- [ ] **Step 4: Implement `core/probe_migration.py`**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""One-shot rename of persisted 'site' names to 'probe'.

Each step is keyed on the old name still being present, so it is idempotent
on its own: an install that never wrote the registry file still gets its CSV
header renamed, and a crash half-way finishes on the next start."""
import csv
import io
import os
import shutil
import sqlite3

OLD = "site"  # check-site-name: ok


def _backup(path: str) -> None:
    bak = path + ".pre-probe"
    if not os.path.exists(bak):
        shutil.copy2(path, bak)


def _registry(d: str) -> list:
    old, new = os.path.join(d, OLD + "s.json"), os.path.join(d, "probes.json")
    if not os.path.exists(old) or os.path.exists(new):
        return []
    _backup(old)
    os.replace(old, new)
    return ["registro sonde: " + OLD + "s.json -> probes.json"]


def _hosts_header(d: str) -> list:
    path = os.path.join(d, "network_hosts.csv")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as f:
        text = f.read()
    rows = list(csv.reader(io.StringIO(text)))
    if not rows or OLD.capitalize() not in rows[0]:
        return []
    _backup(path)
    rows[0] = ["Probe" if h == OLD.capitalize() else h for h in rows[0]]
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows(rows)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(buf.getvalue())
    os.replace(tmp, path)
    return ["network_hosts.csv: colonna " + OLD.capitalize() + " -> Probe"]


def _columns(db: str, table: str) -> list:
    with sqlite3.connect(db) as c:
        return [r[1] for r in c.execute(f"PRAGMA table_info({table})")]


def _mac_history(d: str) -> list:
    db = os.path.join(d, "mac_history.db")
    if not os.path.exists(db) or OLD not in _columns(db, "mac_sightings"):
        return []
    with sqlite3.connect(db) as c:
        c.execute(f"ALTER TABLE mac_sightings RENAME COLUMN {OLD} TO probe")
    return ["mac_history: colonna " + OLD + " -> probe"]


def _jobs(d: str) -> list:
    db = os.path.join(d, "agent_jobs.db")
    if not os.path.exists(db) or OLD + "_id" not in _columns(db, "command_jobs"):
        return []
    # Queued jobs are transient and the test probes are reinstalled.
    with sqlite3.connect(db) as c:
        c.execute("DROP TABLE command_jobs")
    return ["agent_jobs: tabella command_jobs ricreata"]


def _user_tabs() -> list:
    from security import user_manager
    users = user_manager.rename_allowed_tab("tab-" + OLD + "s", "tab-probes")
    return [f"scheda Sonde negli accessi di {', '.join(users)}"] if users else []


def migrate(data_dir: str) -> list:
    """Run every pending step; returns what was done ([] = nothing)."""
    steps = []
    for step in (_registry, _hosts_header, _mac_history, _jobs):
        steps += step(data_dir)
    return steps + _user_tabs()
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/test_probe_migration.py -q`
Expected: 6 passed.

- [ ] **Step 6: Gate and commit**

```bash
uv run pyrefly check
uv run pytest tests -n 4 -q
git add core/probe_migration.py security/user_manager.py tests/test_probe_migration.py
git commit -m "feat(migration): one-shot rename of persisted site names to probe"
```

---

### Task 3: Backend internals — module, data, SQLite, device column

**Model:** sonnet

**Files:**
- Rename: `services/site_manager.py` → `services/probe_manager.py` (`git mv`)
- Modify: every Python importer/caller. Find them with
  `grep -rlnE "site_manager|SITES_JSON|DEFAULT_SITE_ID|is_agent_site|get_site\(|list_sites|'Site'|\"Site\"|\[.site.\]" --include=*.py . | grep -v .venv`.
  Expected set includes `services/inventory_manager.py`, `core/core_engine.py`, `core/net_ssh.py`, `core/device_credentials.py`, `core/backup_store.py`, `core/data_config.py`, `collectors/mac_history.py`, `collectors/mac_collector.py`, `collectors/arp_collector.py`, `services/client_diagnosis.py`, `services/route_table.py`, `services/ping_monitor.py`, `services/triage_scheduler.py`, `services/device_history.py`, `services/switch_provisioner.py`, `observability/ingesters/linux_poller.py`, `observability/ingesters/windows_poller.py`, `observability/endpoints.py`, `ai/ai_assistant.py`, `ai/mcp_server.py`, `ai/config_analyzer.py`, `routers/*.py` (bodies only — **URL paths, headers and tab ids stay** until Tasks 4–5), `app_server.py`.
- Modify: `services/audit_checklist.py`, `routers/audit_checklist.py`, `observability/storage/schema.sql`, `core/db.py`, `scripts/check_no_private_data.py`, `.gitignore`
- Modify: tests that import or patch these names (same grep under `tests/`)
- Test: `tests/test_probe_migration.py` (wiring), `tests/test_csv_import_probe_alias.py` (new)

**Interfaces:**
- Consumes: `core.probe_migration.migrate(data_dir)` (Task 2).
- Produces: `services.probe_manager` with `PROBES_JSON`, `DEFAULT_PROBE_ID = "central"`, `VALID_MODES`, `list_probes()`, `get_probe(probe_id)`, `create_probe(name, mode, subnets=None, **kwargs) -> (dict, str|None)`, `update_probe(probe_id, ...)`, `delete_probe(probe_id)`, `set_probe_flow_status(probe_id, active)`, `is_agent_probe(probe_id)`, `has_direct_path(probe_id)`, `authenticate(token) -> probe_id|None`, `touch_last_seen(probe_id)`, `enqueue_job(probe_id, device_ip, command, ...)`, `claim_pending_jobs(probe_id, limit)`, `complete_job(job_id, probe_id, status, result)`. Device dicts carry `"Probe"`. `inventory_manager.get_device_by_ip(...)` returns `{'ip','hostname','tenant','probe'}`.

- [ ] **Step 1: Write the failing tests**

`tests/test_csv_import_probe_alias.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""An export made before the rename (column 'Site') reimports onto Probe."""
import unittest

from services import inventory_manager


class TestProbeAlias(unittest.TestCase):
    def test_old_and_new_headers_map_to_probe(self):
        for header in ("Site", "site", "Probe", "sonda"):  # check-site-name: ok
            with self.subTest(header=header):
                self.assertEqual(inventory_manager._canonical_header(header), "Probe")

    def test_sede_is_not_a_probe(self):
        # Reserved for the Location column of sub-project 1.
        self.assertIsNone(inventory_manager._canonical_header("sede"))
```

Append to `tests/test_probe_migration.py`:

```python
class TestWiring(unittest.TestCase):
    def test_lifespan_runs_the_migration_first(self):
        import inspect
        import app_server
        src = inspect.getsource(app_server.lifespan)
        self.assertLess(src.index("probe_migration.migrate"), src.index("db.start_writer"))
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_csv_import_probe_alias.py tests/test_probe_migration.py -q`
Expected: FAIL (`'Site'` maps to `'Site'`; `sede` maps to `'Site'`; migration not in lifespan).

- [ ] **Step 3: Rename the module and its internals**

```bash
git mv services/site_manager.py services/probe_manager.py
```

Apply the identifier rename table to `services/probe_manager.py`, SQL included: `site_id` → `probe_id`, `ix_jobs_site` → `ix_jobs_probe`. Then update every importer from the grep in **Files**. Local variables named `site`/`sites` that hold registry entries become `probe`/`probes`. Comments containing a renamed identifier are updated; other Italian prose stays.

- [ ] **Step 4: Device column and CSV aliases in `services/inventory_manager.py`**

- `_fieldnames`: `'Site'` → `'Probe'`.
- `_CSV_ALIASES`: remove `"site": "Site", "sede": "Site"`; add

```python
    # 'site' is the column's name before the rename: an old export must
    # reimport onto the same probes. 'sede' is reserved for Location.
    "probe": "Probe", "sonda": "Probe", "site": "Probe",  # check-site-name: ok
```

  and rewrite the comment above it: Group = tenant (RBAC boundary); Probe = how the device is reached (`central`, an agent probe, a bastion probe).
- `get_device_by_ip`: key `'site'` → `'probe'`, value `d.get('Probe') or 'central'`; update every reader of that key (`grep -rn "\[.site.\]\|get(.site.)" --include=*.py .`).
- `add_or_update_device(..., site=None, ...)` → `probe=None`; update callers.

- [ ] **Step 5: SQLite columns**

- `collectors/mac_history.py`: the `ALTER TABLE mac_sightings ADD COLUMN site …` and any `CREATE TABLE` column → `probe`; every query using it.
- `observability/storage/schema.sql`: `audit_engagements.site_id` → `location_id`. In `core/db.py` `apply_schema`, before the version bump:

```python
        # v15: an engagement's place is a location, not a probe.
        ae_cols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(audit_engagements)").fetchall()}
        if "site_id" in ae_cols:  # check-site-name: ok
            conn.execute("ALTER TABLE audit_engagements "
                         "RENAME COLUMN site_id TO location_id")  # check-site-name: ok
```

  and set `SCHEMA_VERSION = 15` with its comment. Rename `site_id` → `location_id` in `services/audit_checklist.py` and `routers/audit_checklist.py` (request model field, insert, select).

- [ ] **Step 6: Data-dir lists and gitignore**

- `core/data_config.py`: `"sites.json"` → `"probes.json"` in `_STATE_FILES` and `_SENSITIVE_FILES`.
- `scripts/check_no_private_data.py`: `sites\.json` → `probes\.json` in the state-file pattern.
- `.gitignore`: `sites.json` → `probes.json`.

- [ ] **Step 7: Wire the migration in `app_server.lifespan`**

Read `core/data_config.get_path` first to get the data directory the same way the app does. At the very top of `lifespan`:

```python
    # Before anything reads probes.json, the CSV or the SQLite files: the
    # persisted names were 'site' until 0.52 (spec 2026-10-09 site-to-probe).
    from core import probe_migration
    from security.security_manager import log_audit
    data_dir = os.path.dirname(data_config.get_path("users.json"))
    for step in probe_migration.migrate(data_dir):
        log_audit(f"Migrazione sonde: {step}.")
```

- [ ] **Step 8: Update tests, rename test files**

```bash
git mv tests/test_sites.py tests/test_probes.py
git mv tests/test_jump_site.py tests/test_bastion_probe.py
git mv tests/test_remote_site.py tests/test_agent_probe.py
git mv tests/test_site_editing.py tests/test_probe_editing.py
git mv tests/test_site_verified.py tests/test_probe_verified.py
git mv tests/test_device_site_gui.py tests/test_device_probe_gui.py
```

In all tests apply the identifier table for Python names and data (`'Site'` → `'Probe'`, `site_manager` → `probe_manager`, `patch("…site_manager…")`), and `tests/conftest.py`'s import list. **Do not** change URL paths, headers or `tab-sites` in tests yet (Tasks 4–5).

- [ ] **Step 9: Run tests**

Run: `uv run pytest tests -n 4 -q`
Expected: all green, including the two new tests.

- [ ] **Step 10: Shrink PENDING, gate, commit**

Remove from `PENDING` every file `test_pending_only_shrinks` names. Run pyrefly, full suite, `check_no_private_data`.

```bash
git add -A services core collectors observability ai routers app_server.py scripts .gitignore tests
git commit -m "refactor(probes): rename site internals, data files and SQLite columns to probe"
```

---

### Task 4: Wire protocol — agent program, headers, CLI, config

**Model:** sonnet

**Files:**
- Rename: `services/site_agent.py` → `services/probe_agent.py`
- Modify: `routers/agent.py`, `routers/route_classes.py` (comment naming the header), `scripts/vm_agent_test_helper.py`, and every file that ships or names the agent program (`grep -rn "site_agent" --include=*.py --include=*.spec --include=*.ps1 --include=*.sh .`)
- Test: `tests/test_agent_protocol_headers.py` (new), `tests/test_agent_probe.py` (renamed in Task 3)

**Interfaces:**
- Consumes: `probe_manager.authenticate`, `get_probe`, `touch_last_seen`, `create_probe` (Task 3).
- Produces: agent requests carry `X-Probe-Id`, `X-Probe-Token`; agent config `{"central_url", "probe_id", "token", ...}`; CLI `--probe-id`; FastAPI dependency `routers.agent.get_agent_probe`.

- [ ] **Step 1: Write the failing test**

Read the heartbeat handler in `routers/agent.py` first and send a valid body, so auth is the only failure cause.

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Agents authenticate with X-Probe-*; the old headers are refused with a
message that says what to do (reinstall), not a bare 401."""
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from services import probe_manager


class TestAgentHeaders(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp(prefix="probe_hdr_")
        p = patch.object(probe_manager, "PROBES_JSON", os.path.join(d, "probes.json"))
        p.start()
        self.addCleanup(p.stop)
        self.probe, self.token = probe_manager.create_probe("Lab", "agent")
        self.c = TestClient(app_server.app, raise_server_exceptions=False)

    def test_new_headers_accepted(self):
        r = self.c.post("/api/agent/heartbeat", json={},
                        headers={"X-Probe-Id": self.probe["id"], "X-Probe-Token": self.token})
        self.assertNotEqual(r.status_code, 401, r.text)

    def test_old_headers_refused_with_reinstall_hint(self):
        r = self.c.post("/api/agent/heartbeat", json={},
                        headers={"X-Site-Id": self.probe["id"],  # check-site-name: ok
                                 "X-Site-Token": self.token})  # check-site-name: ok
        self.assertEqual(r.status_code, 401)
        self.assertIn("reinstall", r.json()["detail"].lower())
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_agent_protocol_headers.py -q`
Expected: FAIL (new headers → 401; old headers accepted).

- [ ] **Step 3: Implement**

- `git mv services/site_agent.py services/probe_agent.py`; apply the table: headers, `--probe-id`, config key `probe_id`, the usage docstring, required keys `("central_url", "probe_id", "token")`.
- `routers/agent.py`:

```python
def get_agent_probe(request: Request):
    """Authenticate a probe agent by X-Probe-Token (+ optional X-Probe-Id).
    Header lookup is case-insensitive in Starlette."""
    token = request.headers.get("X-Probe-Token")
    claimed_id = request.headers.get("X-Probe-Id")
    probe_id = probe_manager.authenticate(token)
    if not probe_id or (claimed_id and claimed_id != probe_id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token di sonda non valido. Un agente installato prima "
                                   "della 0.52 va reinstallato (reinstall the probe agent).")
    probe_manager.touch_last_seen(probe_id)
    return probe_manager.get_probe(probe_id)
```

  Rename every `Depends(get_agent_site)` and `_devices_for_site`.
- Every place that ships or names the agent file (grep in **Files**).

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests -n 4 -q`
Expected: all green.

- [ ] **Step 5: Shrink PENDING, gate, commit**

```bash
git add -A services routers scripts tests
git commit -m "refactor(probes)!: agent protocol uses X-Probe-* headers and probe_id

Agents installed before this commit must be reinstalled."
```

---

### Task 5: HTTP API and frontend

**Model:** sonnet

**Files:**
- Rename: `routers/sites.py` → `routers/probes.py`; `static/js/site-agent.js` → `static/js/probe-agent.js`; `tests/test_site_wizard_api.py` → `test_probe_wizard_api.py`; `tests/test_site_wizard_ui.py` → `test_probe_wizard_ui.py`; `tests/js/test_site_enrollment.mjs` → `test_probe_enrollment.mjs`
- Modify: `app_server.py` (router include), every `require_tab(... "tab-sites" ...)` in `routers/*.py`, `routers/inventory.py` (`/api/reassign-device-probe`), `templates/dashboard.html` (nav button, panel id, script tag, element ids), `static/js/core.js` (`LAZY_TAB_SCRIPTS`, `switchTab`, command-palette entry), `static/js/settings.js`, `static/js/devices.js`, `static/js/provisioning.js`, `static/js/topology.js`, `static/js/manual-config.js`, `static/js/diagnosi.js`, `static/js/home.js`, `static/js/ui-wizard.js`, `static/js/i18n.js` (keys **and** values meaning probe, both languages), `types/globals.d.ts`, role/tab maps that list `tab-sites` (`grep -rn "tab-sites" --include=*.py --include=*.js .`)
- Test: existing route/lazy-tab/i18n/a11y tests, `tests/test_probes.py`

**Interfaces:**
- Consumes: `probe_manager` (Task 3).
- Produces: routes `GET/POST /api/probes`, `POST /api/probes/update|delete|test-bastion|test-bastion/draft|regenerate-token`, `/api/probes/{probe_id}/command|command-jobs|agent/update|agent/restart|agent/logs|agent/config|agent/inventory/get|agent/inventory/save|agent/flow-control`, `/api/reassign-device-probe`; tab id `tab-probes`; JS `loadProbes()`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_probes.py`:

```python
class TestApiPaths(unittest.TestCase):
    def test_no_route_says_sites(self):
        import app_server
        paths = list(app_server.app.openapi()["paths"])
        self.assertEqual([p for p in paths if "/sites" in p], [])  # check-site-name: ok
        self.assertIn("/api/probes", paths)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_probes.py -q -k ApiPaths`
Expected: FAIL listing the `/api/sites…` paths.

- [ ] **Step 3: Backend paths**

`git mv routers/sites.py routers/probes.py`; rename paths, path params (`{probe_id}`), handler names (`list_probes_ep`, `create_probe_ep`, …) and `require_tab("tab-probes", …)` everywhere. Update the `app_server.py` include and any route-map fixture under `tests/` that lists paths.

- [ ] **Step 4: Frontend**

- `git mv static/js/site-agent.js static/js/probe-agent.js`; script tag in `dashboard.html`.
- Tab: `data-tab="tab-probes"`, `aria-controls`, panel `id="tab-probes"`; `LAZY_TAB_SCRIPTS['tab-probes']`; `switchTab` branch → `loadProbes()`; command-palette entry.
- Every `fetch`/`apiFetch` URL `/api/sites…` → `/api/probes…`; `/api/reassign-device-site` → `/api/reassign-device-probe`.
- Element ids and JS identifiers with `site`/`Site` → `probe`/`Probe`; `window.X` exposures and `types/globals.d.ts` entries renamed together.
- `i18n.js`: rename keys containing `Site`/`site` (e.g. `tabSites` → `tabProbes`, `coreSites` → `coreProbes`) in **both** dictionaries and every `tr('…')` / `data-i18n="…"` use. Values meaning the probe registry: IT «Sonde», «Sonda agente», «Sonda bastion», «Diretto (server centrale)»; EN "Probes", "Agent probe", "Bastion probe", "Direct (central server)". Values where "site"/«sede» means a customer location stay (sub-project 1).

- [ ] **Step 5: Rename UI tests and update them**

`git mv` the three test files listed in **Files**; update ids, URLs and tab ids inside them and in `tests/test_lazy_tab_scripts.py`, `tests/test_i18n_keys.py`, `tests/test_a11y_dashboard.py`, `tests/test_ui_modal.py`, `tests/test_admin_tenant_scope.py` (`MUST_BE_GLOBAL` paths), `tests/test_old_header_*` if any.

- [ ] **Step 6: TestClient smoke per touched router**

Add to `tests/test_probes.py` one logged-in request per router whose body changed in Tasks 3–5 (`probes`, `agent`, `inventory`, `scan`, `triage`, `commands`, `audit_checklist`, `manual_config`, `provisioner`, `ai`, `endpoint_inventory`, `settings`, `auth`, `cloud_backup`). Any of 200/400/401/403/422 proves the handler body ran (AGENTS.md: OpenAPI parity hides missing imports). Reuse the `_Isolated` / `_as(name)` login pattern from `tests/test_group_identity.py`.

- [ ] **Step 7: Run checks**

```bash
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
uv run pytest tests -n 4 -q
node --test tests/js
```

Expected: all clean / green.

- [ ] **Step 8: Shrink PENDING, gate, commit**

```bash
git add -A routers app_server.py static templates types security tests
git commit -m "refactor(probes): /api/probes, tab-probes and probe ids in the UI"
```

---

### Task 6: Living documentation

**Model:** haiku

**Files:**
- Rename: `docs/remote-sites.md` → `docs/probes.md`
- Modify: `README.md`, `docs/README.md`, `docs/architecture.md`, `docs/collectors.md`, `docs/operations.md`, `docs/provisioning-tutorial.md`, `docs/roadmap.md`, `docs/ubuntu-agent-install.md`, `docs/linux-server-management-plan.md`, `docs/adr/0008-agent-rest-relay.md`, `docs/adr/README.md`
- **Do not touch:** `docs/superpowers/plans/*`, `docs/superpowers/specs/*` (history), `docs/fortios-notes/*`.

- [ ] **Step 1: Rename and update**

`git mv docs/remote-sites.md docs/probes.md`. In every listed file apply the identifier rename table to code names, paths, headers, CLI flags and config keys (`--probe-id`, `"probe_id"`, `X-Probe-Token`, `/api/probes`, `probes.json`, `probe_agent.py`). Prose: "site agent" → "probe agent", "jump site" → "bastion probe", "Sites tab" → "Probes tab". Keep "site-to-site VPN" (networking term). Fix every link to `remote-sites.md`.

- [ ] **Step 2: Add the upgrade note**

At the top of `docs/probes.md`, after the title:

```markdown
> **Upgrading from 0.51 or earlier:** probes used to be called "sites". The
> agent protocol changed (`X-Probe-Id` / `X-Probe-Token`, config key
> `probe_id`, flag `--probe-id`): reinstall every probe agent after upgrading
> central. Data files are renamed automatically on first start.
```

- [ ] **Step 3: Verify links**

Run: `grep -rn "remote-sites" README.md docs --include=*.md | grep -v "docs/superpowers/"`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add -A README.md docs
git commit -m "docs(probes): rename site to probe in living docs, upgrade note"
```

---

### Task 7: Close the ratchet, full gate, screenshots

**Model:** the session's own model (no subagent).

**Files:**
- Modify: `tests/test_no_site_identifier.py`
- Regenerate: `docs/images/*` (README screenshots)

- [ ] **Step 1: Empty PENDING**

Delete `PENDING` and `test_pending_only_shrinks`; in `test_no_new_offenders`:

```python
        new = {p: h[:3] for p, h in self._offenders().items()}
```

Update the module docstring (no pending list any more).

Run: `uv run pytest tests/test_no_site_identifier.py -q`
Expected: PASS. Any remaining hit: rename it, or — only for the CSV alias, the old-header test, the migration's old names, the scanner patterns — mark the line `check-site-name: ok`.

- [ ] **Step 2: Full gate**

```bash
uv run pyrefly check
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
uv run pytest tests -n 4
uv run python scripts/check_no_private_data.py
graphify update .
```

Expected: 0 errors, all green, no private data.

- [ ] **Step 3: Upgrade check on a copy of the real data dir**

Copy the current data directory to a scratch folder, start the app with `SENTINELNET_DATA_DIR` pointing at it, open «Sonde» and the Devices table: every device keeps its probe, the audit log shows the «Migrazione sonde» steps, a second start logs nothing. Delete the scratch copy afterwards; nothing from it enters a tracked file.

- [ ] **Step 4: Screenshots**

Run: `uv run python scripts/dev/capture_screenshots.py` (the tab label changed visibly).

- [ ] **Step 5: Commit**

```bash
git add tests/test_no_site_identifier.py docs/images
git commit -m "test(probes): no site identifier left anywhere; screenshots"
```

- [ ] **Step 6: Rebuild the exe**

Run: `uv run pyinstaller SentinelNet.spec`
Expected: build completes (`dist/` is gitignored).
