# app_server.py Destructuring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce `app_server.py` from 3460 lines to a ~200-line application shell by extracting every remaining route handler into focused `routers/*.py` modules, with byte-identical HTTP behaviour.

**Architecture:** Continues phase 2 of the previous refactor (`routers/deps.py`, `routers/fortigate.py`, `routers/wlc.py`, `routers/observability.py` already exist — follow their pattern exactly). Each domain gets one `APIRouter` module; Pydantic schemas live in the router that uses them; shared settings/host helpers move to a new flat `app_settings.py` module to remove the `routers/observability.py → app_server` import cycle. `app_server.py` keeps only: imports, `lifespan`, `app = FastAPI(...)`, CORS + security-headers middleware, `include_router` calls, `GET /`, `main()`, and a small block of test-compat re-exports. It stays the PyInstaller entry point (`SentinelNet.spec` line 4).

**Tech Stack:** Python 3.14, FastAPI, Pydantic v2, uvicorn, unittest (run as scripts), uv, PyInstaller.

**Branch:** all work happens on `worktree-destructure` (worktree at `.claude/worktrees/destructure`), branched off `master` at `bb00b00`. `master` stays untouched as the backup app. Do **not** commit any of this to `master`.

`worktree-ui-revamp` is a *separate, finished, unmerged* branch that touches only frontend files. This refactor must stay off it: the two are independently mergeable only if neither depends on the other. They do not conflict — the UI branch changes `templates/dashboard.html`, `test_ui_revamp.py`, and docs; this branch changes Python only.

**`SentinelNet.spec` is gitignored and untracked** (`.gitignore:36: *.spec`). It exists only in the main repo working directory (`c:\Users\vidhi\dev_ved\SentinelNet`), **not in this worktree**. The PyInstaller rebuild therefore cannot run from here — see Task 21 Step 5.

**Execution:** implement via Claude API with Opus (`claude-opus-4-8`), one fresh subagent per task, review between tasks.

---

## Global Constraints

- **Zero behaviour change.** Paths, HTTP methods, query/path/body parameters, response shapes, status codes, and OpenAPI component schema names must be identical before and after. The only permitted OpenAPI diff is `tags` (routers add them).
- **Flat layout (Decision #1 of the previous refactor).** Modules at repo root, sub-packages `routers/` and `observability/` only. No `sentinelnet.` import prefix.
- **Verbatim moves.** Handler bodies are copied unchanged. The only edits allowed while moving: `@app.` → `@router.`, and adding the imports the new module needs. If you find a bug while moving, **leave it** and note it in the task report — fixing it in the same commit destroys the parity signal.
- **Scope is a SET.** `user_group_scope` returns `set | None`. Never reduce it to a scalar group (CONTRIBUTING.md §4).
- **Comments and docstrings stay Italian.** This codebase is documented in Italian; match it.
- **`app_server.app` must keep working.** 17 test call sites do `app_server.app`. Never rename or relocate that symbol.
- **No new dependencies.** Nothing gets added to `pyproject.toml`.
- **No CI.** Never add GitHub Actions. Verification is local commands only.
- **Test command form:** `uv run python test_<name>.py` (tests are unittest-as-scripts, each sets `SENTINELNET_DATA_DIR` to a temp dir at import time).
- **Router module header:** every new router starts with `# -*- coding: utf-8 -*-` and a docstring naming the source (`Estratto da app_server.py (fase 6.6)`).

---

## File Structure

**New shared module:**

| File | Responsibility |
|---|---|
| `app_settings.py` | `_app_settings_lock`, `_app_adv_setting`, `get_app_settings`, `save_app_settings`, `effective_port`, `list_local_ips`, `resolve_bind_host`, `PORT`. Imported by `app_server.py` and by routers. Breaks the `routers/observability.py → app_server` cycle. |

**New routers** (all under `routers/`, all following the `wlc.py` pattern):

| File | Endpoints | Source lines in current `app_server.py` |
|---|---|---|
| `auth.py` | `/api/auth/*`, `/api/users*` | 821–1018 |
| `inventory.py` | `/api/local-devices`, `/api/export/devices`, `/api/add-device`, `/api/delete-device`, `/api/rename-device`, `/api/import-csv`, `/api/promote-device`, `/api/reassign-device` | 306–318, 366–372, 390–392, 403–406, 650–660, 1020–1162, 1345–1387, 1831–1859 |
| `catalog.py` | `/api/groups*`, `/api/vendors*`, `/api/models*`, `/api/device-categories*`, `/api/device-classification` | 319–330, 420–453, 1164–1343, 1389–1407 |
| `settings.py` | `/api/settings/network`, `/api/settings/cli-blacklist`, `/api/settings/app` | 454–459, 1409–1515 |
| `topology.py` | `/api/topology`, `/api/network-map`, `/api/portchannels`, `/api/topology/reset`, `/api/map/export/vsdx` | 1517–1606 |
| `triage.py` | `/api/run-triage`, `/api/triage/{ip}`, `/api/triage-status`, `/api/ping-check`, `/api/ping/{ip}` | 407–412, 726–766, 1608–1679, 1861–1941 |
| `commands.py` | `/api/send-command`, `/api/bulk-command`, `/api/bulk-command/{job_id}`, `/api/ws-token`, `/api/ws-terminal/{ip}` | 393–402, 662–724, 1681–1829, 1943–2110 |
| `backup.py` | `/api/download-backup/{ip_or_filename}`, `/api/search` | 2112–2211 |
| `mac.py` | `/api/mac/*` | 373–389, 2213–2559 |
| `arp.py` | `/api/arp/*` | 2561–2622 |
| `analyzer.py` | `/api/config-analyzer*` | 2624–2658 |
| `ai.py` | `/api/ai/*` + AI context helpers | 460–502, 2660–3015 |
| `provisioner.py` | `/api/provisioner/*` | 503–606, 3017–3172 |
| `mcp.py` | `/api/mcp/*` | 607–609, 3174–3207 |
| `scan.py` | `/api/scan-subnet*` | 413–419, 663–664, 768–813, 3209–3264 |
| `sites.py` | `/api/sites/*`, `/api/command-jobs/{job_id}` | 610–629, 3266–3345 |
| `agent.py` | `/api/agent/*` | 630–649, 3347–3416 |

**Modified:**
- `app_server.py` — shrinks to ~200 lines (shell + `main()` + re-exports).
- `routers/deps.py` — gains `filter_map_to_scope`.
- `routers/observability.py:221` — stops importing from `app_server`, imports from `app_settings`.
- `test_router_parity.py` — gains a full-snapshot parity class; `MIGRATED_PREFIXES` grows each task.
- `test_transports.py` — patch targets move from `app_server` to `routers.inventory`.

**Line numbers drift as you go.** They are accurate against commit `8bab241` / `bb00b00`. After the first extraction, locate code by symbol name (`grep -n "def promote_device" app_server.py`), not by the number in this table.

---

### Task 1: Full-parity safety net

The existing `tests_data/openapi_golden.json` is a 120-route snapshot from *before* the first refactor and only deep-compares `MIGRATED_PREFIXES`. Endpoints added since (`/api/observability/*`, `/api/arp/*`, `/api/settings/app`) are unguarded. This task captures a fresh full snapshot of the app **as it is today** and adds a test that every path, method, parameter, and schema still matches it. That test is the safety net for Tasks 2–21 — it must pass at the end of every single task.

**Files:**
- Create: `tests_data/openapi_pre_destructure.json` (generated, committed)
- Create: `scripts/snapshot_openapi.py`
- Modify: `test_router_parity.py`

**Interfaces:**
- Produces: `tests_data/openapi_pre_destructure.json` — the frozen contract every later task validates against. `test_router_parity.TestFullParity` — the gate command every later task runs.

- [ ] **Step 1: Write the snapshot generator**

Create `scripts/snapshot_openapi.py`:

```python
# -*- coding: utf-8 -*-
"""Cattura lo schema OpenAPI corrente in tests_data/openapi_pre_destructure.json.

Snapshot di riferimento per il destructuring di app_server.py (fase 6.6):
va rigenerato SOLO quando si aggiungono endpoint nuovi in modo deliberato,
mai per far passare un test di parity fallito.

Uso: uv run python scripts/snapshot_openapi.py
"""

import json
import os
import sys
import tempfile

os.environ.setdefault("SENTINELNET_DATA_DIR",
                      tempfile.mkdtemp(prefix="sentinelnet_snapshot_"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app_server  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "tests_data", "openapi_pre_destructure.json")


def main():
    spec = app_server.app.openapi()
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(spec, fh, indent=2, sort_keys=True, ensure_ascii=False)
    print(f"Snapshot scritto: {OUT} ({len(spec['paths'])} percorsi)")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Generate the snapshot**

Run: `uv run python scripts/snapshot_openapi.py`
Expected: `Snapshot scritto: ...openapi_pre_destructure.json (N percorsi)` where N > 120. Record N — it must never change again.

- [ ] **Step 3: Add the full-parity test**

Append to `test_router_parity.py`, after the existing `TestRouterParity` class and before `if __name__ == "__main__":`:

```python
PRE_DESTRUCTURE = os.path.join(os.path.dirname(__file__), "tests_data",
                               "openapi_pre_destructure.json")


class TestFullParity(unittest.TestCase):
    """Gate del destructuring (fase 6.6): OGNI percorso, metodo, parametro e
    schema deve restare identico allo snapshot catturato prima dell'estrazione.
    Unica differenza ammessa: i ``tags`` aggiunti dai router."""

    @classmethod
    def setUpClass(cls):
        with open(PRE_DESTRUCTURE, encoding="utf-8") as f:
            cls.snap = json.load(f)
        cls.current = app_server.app.openapi()

    def test_path_set_identical(self):
        self.assertEqual(sorted(self.snap["paths"]), sorted(self.current["paths"]),
                         "l'insieme dei percorsi è cambiato")

    def test_every_operation_identical(self):
        for path, ops in self.snap["paths"].items():
            cur_ops = self.current["paths"][path]
            self.assertEqual(set(ops), set(cur_ops), f"metodi diversi su {path}")
            for method, op in ops.items():
                self.assertEqual(
                    json.dumps(_normalize(op), sort_keys=True),
                    json.dumps(_normalize(cur_ops[method]), sort_keys=True),
                    f"contratto cambiato: {method.upper()} {path}",
                )

    def test_every_schema_identical(self):
        snap_schemas = self.snap.get("components", {}).get("schemas", {})
        cur_schemas = self.current.get("components", {}).get("schemas", {})
        self.assertEqual(sorted(snap_schemas), sorted(cur_schemas),
                         "l'insieme degli schemi componenti è cambiato")
        for name, schema in snap_schemas.items():
            self.assertEqual(
                json.dumps(schema, sort_keys=True),
                json.dumps(cur_schemas[name], sort_keys=True),
                f"schema {name} cambiato",
            )
```

- [ ] **Step 4: Run it — must pass against the unmodified app**

Run: `uv run python test_router_parity.py -v`
Expected: PASS, all tests (the pre-existing golden tests plus the 3 new `TestFullParity` ones). If `TestFullParity` fails here, the snapshot generator and the test disagree about normalization — fix that now, before any code moves.

- [ ] **Step 5: Prove the net catches a real regression**

Temporarily comment out the `@app.get("/api/mcp/tool-config")` decorator line in `app_server.py`, then:

Run: `uv run python test_router_parity.py TestFullParity.test_path_set_identical -v`
Expected: FAIL with "l'insieme dei percorsi è cambiato".

Restore the decorator. Re-run: `uv run python test_router_parity.py -v` → PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/snapshot_openapi.py tests_data/openapi_pre_destructure.json test_router_parity.py
git commit -m "test: full OpenAPI parity snapshot as destructuring gate"
```

---

### Task 2: Extract `app_settings.py`

Settings/host helpers are needed by `app_server.main()`, by the future `routers/settings.py`, and already by `routers/observability.py` (which today does a function-local `from app_server import get_app_settings, save_app_settings` at line 221 purely to dodge the import cycle). Moving them to a flat module removes the cycle and unblocks every later task.

**Files:**
- Create: `app_settings.py`
- Modify: `app_server.py` (remove lines 49, 55–71, 241–303; add re-export)
- Modify: `routers/observability.py:221`
- Test: `test_router_parity.py` (no change — it is the gate)

**Interfaces:**
- Produces:
  - `app_settings.PORT: int = 8765`
  - `app_settings._app_adv_setting(key, default=None)`
  - `app_settings.get_app_settings() -> dict`
  - `app_settings.save_app_settings(settings: dict) -> None`
  - `app_settings.effective_port() -> int`
  - `app_settings.list_local_ips() -> list`
  - `app_settings.resolve_bind_host() -> str`

- [ ] **Step 1: Create `app_settings.py`**

Create the file with this header, then move the bodies of `_app_adv_setting` (lines 55–65), `effective_port` (67–71), `_app_settings_lock` + `get_app_settings` + `save_app_settings` (241–266), `list_local_ips` (268–290), `resolve_bind_host` (292–303) **verbatim** from `app_server.py`, in that order:

```python
# -*- coding: utf-8 -*-
"""Impostazioni applicative e risoluzione host/porta.

Spostate qui da app_server.py (fase 6.6) per essere usate dai router modulari
e da main() senza import circolari: routers/observability.py importava
get_app_settings/save_app_settings da app_server dentro la funzione proprio
per evitare il ciclo. app_server reimporta questi nomi, quindi i punti di
patch dei test restano invariati.

Il file app_settings.json è tollerante a mancanza/corruzione: in entrambi i
casi si legge {}.
"""

import json
import os
import socket
import threading

import data_config

PORT = 8765
```

- [ ] **Step 2: Rewire `app_server.py`**

Delete line 49 (`PORT = 8765`, keeping `BASE_URL` at line 50), lines 55–71 (`_app_adv_setting` and `effective_port`), and lines 241–303. In their place, near the other imports:

```python
from app_settings import (  # noqa: F401
    PORT, _app_adv_setting, get_app_settings, save_app_settings,
    effective_port, list_local_ips, resolve_bind_host,
)
```

**Do not touch lines 72–76.** `from contextlib import asynccontextmanager` and `import db` sit between `effective_port` and `lifespan`, in the middle of the range you are deleting from. `lifespan` needs both. Delete 55–71 only.

`socket` and `threading` may now be unused in `app_server.py` — check with `grep -n "socket\.\|threading\." app_server.py` and drop the import only if there are zero hits. (`threading` is still used by `open_browser`'s thread and by the job locks, so it almost certainly stays.)

- [ ] **Step 3: Rewire `routers/observability.py`**

At line 221, replace:

```python
    from app_server import get_app_settings, save_app_settings
```

with a module-level import at the top of the file (alongside the other imports):

```python
from app_settings import get_app_settings, save_app_settings
```

and delete the function-local import line. The cycle it was avoiding no longer exists.

- [ ] **Step 4: Run the gate plus the settings-touching tests**

```bash
uv run python test_router_parity.py -v
uv run python test_observability_ui.py -v
uv run python test_app_server_ai_profiles.py -v
uv run python test_tls_config.py -v
```
Expected: all PASS. `test_app_server_ai_profiles.py` calls `app_server.save_app_settings(...)` directly — the re-export keeps that working.

- [ ] **Step 5: Commit**

```bash
git add app_settings.py app_server.py routers/observability.py
git commit -m "refactor: extract app_settings.py, break observability->app_server cycle"
```

---

### Task 3: Move `filter_map_to_scope` into `routers/deps.py`

`filter_map_to_scope` is scope-filtering logic used by two future routers (`catalog.py` at line 1247, `topology.py` at 1521 and 1527). `routers/deps.py` already owns scoping (`user_group_scope`, `assert_group_allowed`, `assert_device_allowed`), so it belongs there — otherwise both routers would import it from the monolith and re-create the cycle Task 2 just removed.

**Files:**
- Modify: `routers/deps.py` (append)
- Modify: `app_server.py` (delete lines 225–239, extend the existing `from routers.deps import (...)` block at 220–224)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `routers.deps.filter_map_to_scope(data: dict, scope: set | None) -> dict`

- [ ] **Step 1: Append to `routers/deps.py`**

Move the function verbatim from `app_server.py:225-239` to the end of `routers/deps.py`:

```python
def filter_map_to_scope(data, scope):
    """Riduce nodi e link della mappa alle sole sedi consentite."""
    if scope is None:
        return data
    allowed_nodes = {n["id"] for n in data.get("nodes", []) if n.get("group") in scope}
    nodes = [n for n in data.get("nodes", []) if n["id"] in allowed_nodes]
    links = [l for l in data.get("links", [])
             if l["source"] in allowed_nodes and l["target"] in allowed_nodes]
    return {"nodes": nodes, "links": links}
```

- [ ] **Step 2: Rewire `app_server.py`**

Delete lines 225–239 and add `filter_map_to_scope` to the existing re-export block:

```python
from routers.deps import (  # noqa: F401
    SESSION_COOKIE, CSRF_HEADER, get_current_user, require_role,
    require_admin, require_operator, user_group_scope,
    assert_group_allowed, assert_device_allowed, filter_map_to_scope,
)
```

- [ ] **Step 3: Run the gate**

```bash
uv run python test_router_parity.py -v
uv run python test_rbac_scope.py -v
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add routers/deps.py app_server.py
git commit -m "refactor: move filter_map_to_scope into routers/deps.py"
```

---

## Extraction tasks (4–20): the common recipe

Tasks 4 through 20 are the same five moves against different line ranges. **Read this recipe once; each task below only states what differs.** Do not skip a step because the router "looks trivial" — the parity gate is what makes this refactor safe, and it only helps if you run it.

**The recipe, for a router named `<name>` owning path prefix `<prefix>`:**

1. **Create `routers/<name>.py`** with this header, adapting the docstring:

   ```python
   # -*- coding: utf-8 -*-
   """Router <dominio>. Estratto da app_server.py (fase 6.6): percorsi, metodi,
   parametri e risposte identici al monolite."""

   from fastapi import APIRouter, Depends, HTTPException
   from pydantic import BaseModel, Field

   from routers.deps import get_current_user, require_admin, require_operator

   router = APIRouter(tags=["<Tag>"])
   ```

   Trim that import list to what the module actually uses — an unused `HTTPException` is noise, and `Field` is only needed if a moved schema uses it.

2. **Move the code verbatim.** Cut the Pydantic schemas, module-level state, private helpers, and handlers listed in the task from `app_server.py` into the new module, preserving their relative order and their Italian docstrings. Change `@app.` to `@router.` and nothing else. Add whatever module imports the moved code references (`inventory_manager`, `core_engine`, `log_audit`, …) — copy them from `app_server.py`'s import block; do not invent new ones.

3. **Register the router** in `app_server.py`, in the existing block after `app = FastAPI(...)`:

   ```python
   from routers import <name> as _<name>_router
   app.include_router(_<name>_router.router)
   ```

   Keep the order of `include_router` calls stable — OpenAPI path ordering follows it, and `TestFullParity.test_path_set_identical` sorts, but `test_every_operation_identical` does not care about order. Stable order still makes diffs readable.

4. **Extend `MIGRATED_PREFIXES`** in `test_router_parity.py` with `<prefix>` (only for prefixes that exist in the old golden snapshot — for prefixes added after the golden, `TestFullParity` already covers them and adding them to `MIGRATED_PREFIXES` is a no-op, not an error).

5. **Verify, then commit.** Always:

   ```bash
   uv run python test_router_parity.py -v
   uv run python test_rbac_scope.py -v
   ```

   plus the domain tests named in the task. Then:

   ```bash
   git add routers/<name>.py app_server.py test_router_parity.py
   git commit -m "refactor: extract routers/<name>.py from app_server"
   ```

**If the parity gate fails:** you changed behaviour. Do not edit the snapshot. Diff the failing operation against `tests_data/openapi_pre_destructure.json` — the usual causes are a dropped `Depends`, a default value lost off a query parameter, or a schema class left behind in `app_server.py` so FastAPI generated it under a different module path.

---

### Task 4: `routers/auth.py`

**Files:**
- Create: `routers/auth.py`
- Modify: `app_server.py` (remove lines 331–365, 821–1018)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.get_current_user`, `routers.deps.require_admin`, `routers.deps.SESSION_COOKIE`.
- Produces: `routers.auth.router`; schemas `UserSchema`, `ChangePasswordSchema`, `UserCreateSchema`, `UserDeleteSchema`, `UserRoleSchema`, `UserGroupsSchema`, `UserDisableSchema`, `UserTabsSchema`; the alias `LoginRequest = UserSchema`; helper `_set_session_cookie(request, response, token)`.

Endpoints: `GET /api/auth/status`, `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/change-password`, `POST /api/auth/logout`, `GET /api/auth/me`, `GET /api/users`, `POST /api/users`, `POST /api/users/delete`, `POST /api/users/role`, `POST /api/users/disable`, `POST /api/users/groups`, `POST /api/users/tabs`.

`<prefix>` for `MIGRATED_PREFIXES`: `"/api/auth"`, `"/api/users"`. Tag: `"Auth"`.

Extra imports the moved code needs: `user_manager`, `from datetime import timedelta`, `from fastapi import Request, Response, status`, and from `security_manager`: `create_access_token`, `log_audit`, `is_locked_out`, `record_failed_attempt`, `reset_failed_attempts`, `ACCESS_TOKEN_EXPIRE_MINUTES`.

Watch: **`LoginRequest` is not a class — it is the alias `LoginRequest = UserSchema` at line 335.** `login()` annotates its body with it, so the OpenAPI body schema for `POST /api/auth/login` is named `UserSchema`, not `LoginRequest`. Move the alias line verbatim, directly after the `UserSchema` definition. Replacing it with a real `class LoginRequest(BaseModel)` renames the component schema and fails parity.

Watch: `_set_session_cookie` (843–854) reads TLS state to decide the `secure` flag. Move it with the router and verify `test_auth_cookie.py` still passes — it is the only test covering the cookie flags.

Domain tests: `uv run python test_auth_cookie.py -v`

---

### Task 5: `routers/inventory.py`

**Files:**
- Create: `routers/inventory.py`
- Modify: `app_server.py` (remove lines 306–318, 366–372, 390–392, 403–406, 650–660, 1020–1162, 1345–1387, 1831–1859)
- Modify: `test_router_parity.py`, `test_transports.py`

**Interfaces:**
- Consumes: `routers.deps.get_current_user`, `require_operator`, `assert_group_allowed`.
- Produces: `routers.inventory.router`; schemas `DeviceSchema`, `DeviceDelete`, `DeviceRenameSchema`, `CSVImportRequest`, `DeviceReassignSchema`, `PromoteDeviceSchema`; handler `add_device(device, current_user)` (called directly by `test_transports.py`).

Endpoints: `GET /api/local-devices`, `GET /api/export/devices`, `POST /api/add-device`, `POST /api/delete-device`, `POST /api/rename-device`, `POST /api/import-csv`, `POST /api/promote-device`, `POST /api/reassign-device`.

`<prefix>`: `"/api/local-devices"`, `"/api/export"`, `"/api/add-device"`, `"/api/delete-device"`, `"/api/rename-device"`, `"/api/import-csv"`, `"/api/promote-device"`, `"/api/reassign-device"`. Tag: `"Inventory"`.

Extra imports: `inventory_manager`, `mac_history`, `core_engine`, `from security_manager import log_audit`. Confirm each against the moved bodies before adding.

Watch: `csv` and `io` are **function-local** imports in the current code (`import csv, io` inside `export_devices_csv` at line 1039; `import csv as csv_parser` inside `import_csv` at line 1114). Move those lines along with their function bodies. Do not hoist them to module level — that is a gratuitous change, and `csv_parser` is an alias the body depends on.

- [ ] **Extra step (before committing): fix `test_transports.py` patch targets**

This is the one test that genuinely breaks, and re-exports cannot save it. At lines 146–147 it does `app_server.log_audit = lambda msg: ...` and then calls `app_server.add_device(...)` at 159/168/177. After the move, `add_device` resolves `log_audit` in `routers.inventory`'s globals, so patching `app_server.log_audit` silently stops working and the audit assertions fail.

Change the import at line 20 from `import app_server` to:

```python
from routers import inventory as inventory_router  # noqa: E402
```

then rewrite the four call sites:

```python
        self._log = inventory_router.log_audit
        inventory_router.log_audit = lambda msg: self.audits.append(msg)
```
```python
        inventory_router.log_audit = self._log
```
```python
        dev = inventory_router.DeviceSchema(
```
```python
        inventory_router.add_device(dev, current_user=ADMIN)
```

Run `uv run python test_transports.py -v` **before** the move to see it pass, and after the move to see it pass again. If it passes before your edit but fails after, you changed a target that did not need changing.

Domain tests: `uv run python test_transports.py -v`

---

### Task 6: `routers/catalog.py`

**Files:**
- Create: `routers/catalog.py`
- Modify: `app_server.py` (remove lines 319–330, 420–453, 1164–1343, 1389–1407)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.get_current_user`, `require_operator`, `user_group_scope`, `filter_map_to_scope` (Task 3).
- Produces: `routers.catalog.router`; schemas `GroupSchema`, `GroupDeleteSchema`, `GroupRenameSchema`, `VendorSchema`, `VendorDeleteSchema`, `CategoryCreateSchema`, `CategoryDeleteSchema`, `SubcategoryDeleteSchema`, `DeviceCategorySchema`, `ModelSchema`.

Endpoints: `GET/POST /api/groups`, `POST /api/groups/rename`, `POST /api/groups/delete`, `GET/POST /api/vendors`, `POST /api/vendors/delete`, `GET /api/device-classification`, `POST /api/device-categories`, `POST /api/device-categories/delete`, `POST /api/device-categories/delete-subcategory`, `POST /api/device-categories/assign`, `GET/POST /api/models`, `POST /api/models/delete`.

`<prefix>`: `"/api/groups"`, `"/api/vendors"`, `"/api/models"`, `"/api/device-categories"`, `"/api/device-classification"`. Tag: `"Catalog"`.

Watch: `device_classification` (1242–1293) is the `filter_map_to_scope` consumer at line 1247 — import it from `routers.deps`, not from `app_server`.

Domain tests: `uv run python test_rbac_scope.py -v` (already in the standard gate; no additional file).

---

### Task 7: `routers/settings.py`

**Files:**
- Create: `routers/settings.py`
- Modify: `app_server.py` (remove lines 454–459, 1409–1515)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.require_admin`; `app_settings.get_app_settings`, `save_app_settings`, `effective_port`, `list_local_ips` (Task 2).
- Produces: `routers.settings.router`; schemas `NetworkSettingsSchema`, `CliBlacklistSchema`.

Endpoints: `GET/POST /api/settings/network`, `GET/POST /api/settings/cli-blacklist`, `GET/POST /api/settings/app`.

`<prefix>`: `"/api/settings"`. Tag: `"Settings"`.

Watch: `/api/settings/app` is one of `test_router_parity.ALLOWED_NEW_PREFIXES` — it postdates the golden snapshot. `TestFullParity` from Task 1 covers it. Leave `ALLOWED_NEW_PREFIXES` alone.

Watch: `set_app_advanced_settings` (1480–1515) takes a bare `payload: dict`. Bare-dict bodies generate a distinctive OpenAPI body schema — if parity fails on this endpoint, you changed the annotation.

Domain tests: `uv run python test_tls_config.py -v`

---

### Task 8: `routers/topology.py`

**Files:**
- Create: `routers/topology.py`
- Modify: `app_server.py` (remove lines 1517–1606, including the `VisioNodeSchema`/`VisioEdgeSchema`/`VisioExportSchema` classes at 1529–1556)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.get_current_user`, `require_operator`, `user_group_scope`, `filter_map_to_scope` (Task 3).
- Produces: `routers.topology.router`; schemas `VisioNodeSchema`, `VisioEdgeSchema`, `VisioExportSchema`.

Endpoints: `GET /api/topology`, `GET /api/network-map`, `POST /api/map/export/vsdx`, `GET /api/portchannels`, `POST /api/topology/reset`.

`<prefix>`: `"/api/topology"`, `"/api/network-map"`, `"/api/portchannels"`, `"/api/map/export"`. Tag: `"Topology"`.

Extra imports: `core_engine`, `visio_export`, `from security_manager import log_audit`.

---

### Task 9: `routers/triage.py`

**Files:**
- Create: `routers/triage.py`
- Modify: `app_server.py` (remove lines 407–412, 726–766, 1608–1679, 1861–1941)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.get_current_user`, `require_operator`, `user_group_scope`, `assert_device_allowed`.
- Produces: `routers.triage.router`; schemas `TriageRunRequest`, `PingCheckRequest`; background worker `run_triage_background(allowed_groups=None)`.

Endpoints: `POST /api/run-triage`, `POST /api/triage/{ip}`, `GET /api/triage-status`, `POST /api/ping-check`, `GET /api/ping/{ip}`.

`<prefix>`: `"/api/run-triage"`, `"/api/triage"`, `"/api/triage-status"`, `"/api/ping-check"`, `"/api/ping"`. Tag: `"Triage"`.

Extra imports: `core_engine`, `inventory_manager`, `from concurrent.futures import ThreadPoolExecutor`, `from security_manager import log_audit`, `from fastapi import BackgroundTasks`.

Watch: `run_triage` (1609) takes `payload: TriageRunRequest = TriageRunRequest()` — a mutable-ish default instance evaluated at import time. Move it exactly as written; "improving" it to `Depends()` or `= None` changes the OpenAPI body schema and fails parity.

Watch: `run_triage_background` (726–766) is dispatched via `BackgroundTasks`. Confirm whether it reads any module-global triage state that stays behind in `app_server.py` (`grep -n "triage" app_server.py` after the move) — if so, that state moves too.

---

### Task 10: `routers/commands.py`

The largest and highest-risk extraction: it owns the WebSocket terminal (168 lines), the bulk-command job registry, and the CLI safety blacklist.

**Files:**
- Create: `routers/commands.py`
- Modify: `app_server.py` (remove lines 393–402, 662–724, 1681–1829, 1943–2110, plus `_ws_tokens` at line 160)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.get_current_user`, `require_operator`, `assert_device_allowed`; `app_settings.get_app_settings` (for the CLI blacklist).
- Produces: `routers.commands.router`; schemas `CommandRequest`, `BulkCommandRequest`; state `_ws_tokens: dict[str, tuple[str, float]]`, `_bulk_jobs: dict[str, dict]`, `_bulk_jobs_lock`; helpers `is_command_safe(command) -> bool`, `command_allowed(command, current_user) -> bool`, `is_bulk_command_allowed(command) -> bool`, `_bypass_note(current_user) -> str`, `_run_bulk_job(job_id, req)`; constant `BULK_DESTRUCTIVE_BLACKLIST`.

Endpoints: `POST /api/send-command`, `POST /api/bulk-command`, `GET /api/bulk-command/{job_id}`, `POST /api/ws-token`, `WEBSOCKET /api/ws-terminal/{ip}`.

`<prefix>`: `"/api/send-command"`, `"/api/bulk-command"`, `"/api/ws-token"`, `"/api/ws-terminal"`. Tag: `"Commands"`.

Extra imports: `asyncio`, `re`, `threading`, `time`, `uuid`, `paramiko`, `inventory_manager`, `core_engine`, `crypto_vault`, `from concurrent.futures import ThreadPoolExecutor`, `from fastapi import WebSocket, WebSocketDisconnect, BackgroundTasks`, `from security_manager import log_audit`.

Watch: **`_ws_tokens` must move as one unit with both its writer (`get_ws_token`, 1825) and its reader (`ws_terminal`, 1944).** If `_ws_tokens` stays in `app_server.py` while `ws_terminal` moves, the router gets a *separate* dict, every terminal handshake fails with an invalid OTP, and **no test catches it** — the WebSocket route contributes nothing to the OpenAPI schema, so the parity gate is blind here. This is the single most dangerous step in the plan.

Watch: `@app.websocket(...)` becomes `@router.websocket(...)`, not `@router.get(...)`.

- [ ] **Extra step (before committing): drive the terminal by hand**

The parity gate cannot see this route. After the move, actually exercise it:

```bash
uv run python app_server.py
```

Log in through the browser at the printed URL, open the terminal tab against any inventory device, and confirm the shell attaches and echoes a command. Then stop the server. If you have no reachable device, at minimum confirm that `POST /api/ws-token` returns an OTP and that connecting to `/api/ws-terminal/<ip>` with it does **not** close with an auth error — a 4401-style immediate close means `_ws_tokens` got split.

Report what you observed. Do not claim this task is done on the strength of the parity test alone.

---

### Task 11: `routers/backup.py`

**Files:**
- Create: `routers/backup.py`
- Modify: `app_server.py` (remove lines 2112–2211)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.get_current_user`, `require_operator`, `assert_device_allowed`.
- Produces: `routers.backup.router`.

Endpoints: `GET /api/download-backup/{ip_or_filename}`, `GET /api/search`.

`<prefix>`: `"/api/download-backup"`, `"/api/search"`. Tag: `"Backup"`.

Extra imports: `os`, `requests`, `data_config`, `from fastapi import Request`, `from fastapi.responses import FileResponse`, `from security_manager import log_audit`. `BASE_URL` (the ENISA endpoint constant, `app_server.py:50`) is used only by `proxy_enisa_search` — move the constant into this router.

Watch: `download_backup` (2113–2171) does path traversal defence on `ip_or_filename`. Move that validation verbatim; it is a security control, not incidental code.

---

### Task 12: `routers/mac.py`

**Files:**
- Create: `routers/mac.py`
- Modify: `app_server.py` (remove lines 373–389, 2213–2559)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.get_current_user`, `require_operator`, `require_admin`, `user_group_scope`, `assert_device_allowed`.
- Produces: `routers.mac.router`; schemas `MacScanSchema`, `MacRetentionSchema`, `MacOverrideSchema`, `MacOverrideDeleteSchema`; helpers `_mac_uplink_ports(ip) -> dict`, `_mac_topology_uplinks()`, `_reclassify_sightings(rows, uplink_map=None, known_switches=None)`, `_mac_collect_one(device, transport=None) -> dict`, `_mac_group(rows)`.

Endpoints: `POST /api/mac/scan`, `GET /api/mac/search`, `GET /api/mac/locate`, `GET /api/mac/switch/{ip}`, `GET /api/mac/stats`, `POST /api/mac/settings`, `GET/POST /api/mac/overrides`, `POST /api/mac/overrides/delete`.

`<prefix>`: `"/api/mac"`. Tag: `"MAC"`.

Extra imports: `inventory_manager`, `mac_history`, `mac_collector`, `core_engine`, `from concurrent.futures import ThreadPoolExecutor`, `from security_manager import log_audit`.

Watch: `MacScanSchema` is used by **both** `mac_scan` (2366) and `arp_scan` (2562, Task 13). It stays defined here; Task 13 imports it. Defining it twice would produce `MacScanSchema` and `MacScanSchema-Input`-style OpenAPI collisions and fail parity.

---

### Task 13: `routers/arp.py`

**Files:**
- Create: `routers/arp.py`
- Modify: `app_server.py` (remove lines 2561–2622)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.mac.MacScanSchema` (Task 12); `routers.deps.get_current_user`, `require_operator`, `user_group_scope`.
- Produces: `routers.arp.router`.

Endpoints: `POST /api/arp/scan`, `GET /api/arp/search`, `GET /api/arp/client-map`, `GET /api/arp/stats`.

`<prefix>`: `"/api/arp"`. Tag: `"ARP"`. These postdate the golden snapshot — `TestFullParity` is what guards them.

Extra imports: `arp_collector`, `inventory_manager`, `from typing import Optional`, `from routers.mac import MacScanSchema`, `from security_manager import log_audit`.

---

### Task 14: `routers/analyzer.py`

**Files:**
- Create: `routers/analyzer.py`
- Modify: `app_server.py` (remove lines 2624–2658)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.get_current_user`, `user_group_scope`, `assert_device_allowed`.
- Produces: `routers.analyzer.router`.

Endpoints: `GET /api/config-analyzer`, `GET /api/config-analyzer/{ip}`.

`<prefix>`: `"/api/config-analyzer"`. Tag: `"Analyzer"`. Extra imports: `config_analyzer`, `inventory_manager`.

Domain tests: `uv run python test_config_analyzer_multivendor.py -v`

---

### Task 15: `routers/ai.py`

**Files:**
- Create: `routers/ai.py`
- Modify: `app_server.py` (remove lines 460–502, 2660–3015; add re-exports)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.get_current_user`, `require_admin`, `user_group_scope`; `app_settings.get_app_settings`, `save_app_settings`; `routers.fortigate._fgt_device`.
- Produces: `routers.ai.router`; schemas `AiProfileSchema`, `AiProfileUpdateSchema`, `AiChatMessage`, `FlowKeySchema`, `AiChatSchema`; helpers `_mask_ai_profile(p) -> dict`, `_get_ai_profiles_raw()`, `_find_ai_profile(profiles, profile_id)`, `_get_active_ai_profile()`, `_device_inventory_summary(current_user) -> str`, `_device_running_config_context(ip, current_user) -> str`, `_fortigate_live_context(ip, current_user) -> str`, `_tenant_context_block(tenant, current_user) -> str`, `_assert_unredacted_allowed(allow_unredacted, provider, base_url)`.

Endpoints: `GET/POST /api/ai/profiles`, `PUT /api/ai/profiles/{profile_id}`, `DELETE /api/ai/profiles/{profile_id}`, `POST /api/ai/profiles/{profile_id}/activate`, `GET /api/ai/models`, `POST /api/ai/chat`.

`<prefix>`: `"/api/ai"`. Tag: `"AI"`.

Extra imports: `ai_assistant`, `crypto_vault`, `redaction`, `inventory_manager`, `core_engine`, `fortigate_service`, `from typing import Optional, List`, `from security_manager import log_audit`.

Watch: `_fortigate_live_context` (2749) already imports `_fgt_device` from `routers.fortigate` — that import survives the move unchanged.

Watch: `_assert_unredacted_allowed` (2803) is the guard behind `test_ssh_port_and_unredacted.py`. Move verbatim.

- [ ] **Extra step: keep `test_app_server_ai_profiles.py` green via re-exports**

That test calls `app_server._get_ai_profiles_raw()`, `app_server._mask_ai_profile(...)`, `app_server._find_ai_profile(...)`, `app_server._get_active_ai_profile()`, and `app_server.crypto_vault.encrypt_password(...)` **directly** — it never monkeypatches them. Direct calls resolve fine through a re-export, so add to `app_server.py`:

```python
from routers.ai import (  # noqa: F401  (compat: test_app_server_ai_profiles)
    _get_ai_profiles_raw, _find_ai_profile, _get_active_ai_profile,
    _mask_ai_profile,
)
```

and keep `import crypto_vault` in `app_server.py` (`test_observability_ui.py` does `patch.object(app_server.crypto_vault, "decrypt_password", ...)`, which patches the shared module object and works regardless of where the router imported it from).

Do **not** rewrite this test to import from `routers.ai`. The re-export is the cheaper, lower-risk option here, and unlike `test_transports.py` there is no monkeypatch to break.

Domain tests:
```bash
uv run python test_app_server_ai_profiles.py -v
uv run python test_ai_assistant.py -v
uv run python test_ssh_port_and_unredacted.py -v
uv run python test_redaction.py -v
```

---

### Task 16: `routers/provisioner.py`

**Files:**
- Create: `routers/provisioner.py`
- Modify: `app_server.py` (remove lines 503–606, 3017–3172)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.require_operator`.
- Produces: `routers.provisioner.router`; schemas `SwitchProvisionSchema`, `SwitchProvisionSSHSchema`, `SwitchProvisionSerialSchema`, `FortiGateProvisionSchema`, `FortiGateProvisionSSHSchema`, `FortiGateProvisionSerialSchema`; helper `_provision_cfg(payload_dict, materialized, current_user, vendor) -> dict`.

Endpoints: `POST /api/provisioner/generate`, `POST /api/provisioner/download`, `POST /api/provisioner/push-ssh`, `POST /api/provisioner/push-serial`, `GET /api/provisioner/serial-ports`, `POST /api/provisioner/fgt/generate`, `POST /api/provisioner/fgt/download`, `POST /api/provisioner/fgt/push-ssh`, `POST /api/provisioner/fgt/push-serial`.

`<prefix>`: `"/api/provisioner"`. Tag: `"Provisioner"`.

Extra imports: `switch_provisioner`, `fortigate_provisioner`, `provisioning_secrets`, `from fastapi.responses import Response` (check what `provisioner_download` returns at 3040 and 3111), `from security_manager import log_audit`.

Watch: the six schemas form two inheritance chains (`SwitchProvisionSSHSchema(SwitchProvisionSchema)`, `FortiGateProvisionSerialSchema(FortiGateProvisionSchema)`, …). Move all six together and keep the definition order — a base class defined after its subclass is a `NameError` at import.

Domain tests:
```bash
uv run python test_switch_provisioner.py -v
uv run python test_provisioning_secrets.py -v
```

---

### Task 17: `routers/mcp.py`

**Files:**
- Create: `routers/mcp.py`
- Modify: `app_server.py` (remove lines 607–609, 3174–3207)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.get_current_user`, `require_admin`; `app_settings.get_app_settings`, `save_app_settings`.
- Produces: `routers.mcp.router`; schema `McpSettingsSchema`; helper `_mcp_disabled_tools() -> list`.

Endpoints: `GET/POST /api/mcp/settings`, `GET /api/mcp/tool-config`.

`<prefix>`: `"/api/mcp"`. Tag: `"MCP"`. Extra imports: `mcp_server`.

Watch: `app_server.main()` does `import mcp_server` lazily inside the `--mcp` branch (line 3429). That stays in `app_server.py` and is unrelated to this router's top-level `import mcp_server`.

---

### Task 18: `routers/scan.py`

**Files:**
- Create: `routers/scan.py`
- Modify: `app_server.py` (remove lines 413–419, 663–664, 768–813, 3209–3264)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.get_current_user`, `require_operator`, `assert_group_allowed`.
- Produces: `routers.scan.router`; schema `SubnetScanRequest`; state `_scan_jobs: dict[str, dict]`, `_scan_jobs_lock`; worker `_run_scan_job(job_id, req)`.

Endpoints: `POST /api/scan-subnet`, `GET /api/scan-subnet/{job_id}`.

`<prefix>`: `"/api/scan-subnet"`. Tag: `"Scan"`.

Extra imports: `threading`, `uuid`, `from network_scanner import parse_network, scan_subnet`, `from fastapi import BackgroundTasks`, `from security_manager import log_audit`.

Watch: same split hazard as Task 10 — `_scan_jobs` + `_scan_jobs_lock` + `_run_scan_job` + both endpoints move as one unit, or job polling returns 404 for every job. Unlike the WebSocket, this one is at least reachable: after the move, `POST /api/scan-subnet` and then `GET /api/scan-subnet/{job_id}` with the returned id, and confirm you get a status object rather than a 404.

---

### Task 19: `routers/sites.py`

**Files:**
- Create: `routers/sites.py`
- Modify: `app_server.py` (remove lines 610–629, 3266–3345)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: `routers.deps.require_admin`, `require_operator`.
- Produces: `routers.sites.router`; schemas `SiteSchema`, `SiteUpdateSchema`, `SiteIdSchema`, `SiteCommandSchema`.

Endpoints: `GET/POST /api/sites`, `POST /api/sites/update`, `POST /api/sites/delete`, `POST /api/sites/regenerate-token`, `POST /api/sites/{site_id}/command`, `GET /api/command-jobs/{job_id}`, `GET /api/sites/{site_id}/command-jobs`.

`<prefix>`: `"/api/sites"`, `"/api/command-jobs"`. Tag: `"Sites"`.

Extra imports: `site_manager`, `from security_manager import log_audit`.

Watch: route order matters within this router. `POST /api/sites/update`, `/delete`, `/regenerate-token` are declared **before** `POST /api/sites/{site_id}/command`; keep that order or the `{site_id}` path parameter will start swallowing the literal segments.

Domain tests: `uv run python test_sites.py -v`

---

### Task 20: `routers/agent.py`

**Files:**
- Create: `routers/agent.py`
- Modify: `app_server.py` (remove lines 630–649, 3347–3416)
- Modify: `test_router_parity.py`

**Interfaces:**
- Consumes: nothing from `routers.deps` — agents authenticate with a site token, not a user session.
- Produces: `routers.agent.router`; schemas `AgentDeviceSchema`, `AgentInventorySchema`, `AgentMacCollection`, `AgentMacSchema`, `AgentJobResultSchema`; dependency `get_agent_site(request)`.

Endpoints: `POST /api/agent/heartbeat`, `POST /api/agent/inventory`, `POST /api/agent/mac`, `GET /api/agent/jobs`, `POST /api/agent/jobs/{job_id}/result`.

`<prefix>`: `"/api/agent"`. Tag: `"Agent"`.

Extra imports: `site_manager`, `inventory_manager`, `mac_history`, `from fastapi import Request`.

Watch: `get_agent_site` (3347–3357) is this router's own auth dependency. It moves here, **not** into `routers/deps.py` — nothing else uses it, and deps.py is for user-session auth.

Domain tests: `uv run python test_remote_site.py -v`

---

### Task 21: Thin `app_server.py` + full verification + rebuild

**Files:**
- Modify: `app_server.py` (final cleanup)
- Create: `docs/REFACTOR-DESTRUCTURE.md`

**Interfaces:**
- Consumes: every `routers.*.router` from Tasks 4–20.
- Produces: `app_server.app` (unchanged symbol), `app_server.main()`.

- [ ] **Step 1: Prune dead imports**

`app_server.py` should now import only what its remaining code uses. For each name in the import block, check it is still referenced:

```bash
uv run python -c "import ast,sys; src=open('app_server.py',encoding='utf-8').read(); print(len(src.splitlines()),'righe')"
```

Then, for each suspect: `grep -n "paramiko\.\|requests\.\|csv\.\|uuid\.\|re\.\|asyncio\." app_server.py`. Drop imports with zero hits — **except** anything inside the `# noqa: F401` compat blocks, which exist precisely because nothing in this file uses them.

Expected survivors: `os`, `sys`, `asyncio` (lifespan), `threading` + `time` + `webbrowser` (open_browser), `uvicorn`, `data_config`, `db`, `from contextlib import asynccontextmanager` (lifespan), `crypto_vault` (compat — kept for `test_observability_ui.py`), plus the FastAPI/CORS/`FileResponse` names.

- [ ] **Step 2: Verify the final shape**

`app_server.py` must now contain, and nothing else:
1. imports (`BASE_URL` should be **gone** — it moved to `routers/backup.py` in Task 11; delete it if it is still here)
2. `lifespan` (observability startup/shutdown)
3. `app = FastAPI(title="SentinelNet API", version="0.2.0-beta.1", lifespan=lifespan)`
4. the `include_router` block — all 21 routers (4 pre-existing: `deps` is not a router, so `fortigate`, `wlc`, `observability`, plus the 17 from Tasks 4–20)
5. CORS middleware + `_CSP` + `security_headers_middleware`
6. `get_resource_path` + `GET /` (`read_index`) — the app shell; a single `FileResponse` for `templates/dashboard.html`
7. the compat re-export blocks (`routers.deps`, `app_settings`, `routers.ai`)
8. `open_browser` + `main()`

Run: `uv run python -c "import app_server; print(len(app_server.app.routes), 'route')"`
Expected: the same route count as the snapshot from Task 1, and the file is ≤ 250 lines.

- [ ] **Step 3: Run the entire test suite**

```bash
uv run python test_router_parity.py -v
uv run python test_rbac_scope.py -v
uv run python test_auth_cookie.py -v
uv run python test_transports.py -v
uv run python test_sites.py -v
uv run python test_remote_site.py -v
uv run python test_db.py -v
uv run python test_ai_assistant.py -v
uv run python test_app_server_ai_profiles.py -v
uv run python test_arp_collector.py -v
uv run python test_config_analyzer_multivendor.py -v
uv run python test_fortigate_service.py -v
uv run python test_observability_api.py -v
uv run python test_observability_ingest.py -v
uv run python test_observability_ui.py -v
uv run python test_provisioning_secrets.py -v
uv run python test_redaction.py -v
uv run python test_ssh_port_and_unredacted.py -v
uv run python test_switch_provisioner.py -v
uv run python test_tls_config.py -v
uv run python test_wlc_service.py -v
```
Expected: every file OK. Paste the actual tail of each run into the task report — "tests pass" without output is not evidence.

- [ ] **Step 4: Drive the real app**

```bash
uv run python app_server.py
```

Log in; then click through every tab that got its own router: inventory, map/topology, triage, terminal (WebSocket — Task 10's blind spot), MAC, Client Map, config analyzer, AI chat, provisioner, sites, settings. Confirm no 404/500 in the server log. Stop the server.

This is the only check that covers `GET /`, static templates, and the WebSocket. Report what you actually clicked.

- [ ] **Step 5: Hand the rebuild back to the driver — do NOT run it here**

`SentinelNet.spec` is gitignored, untracked, and **absent from this worktree**. It lives only in the main repo working directory. Building from here is impossible, and building from the repo root before the merge would produce an exe from unmerged code.

So: **stop, and report that the branch is ready for merge + rebuild.** The rebuild is a post-merge step run by the driver from the repo root:

```bash
# from c:\Users\vidhi\dev_ved\SentinelNet, AFTER merging worktree-destructure
uv run pyinstaller SentinelNet.spec
```

Note for whoever runs it: PyInstaller follows the `from routers import ...` statements in `app_server.py` statically, so `hiddenimports` should stay empty. If the frozen app dies with `ModuleNotFoundError: routers.<name>`, add that module to `hiddenimports` in `SentinelNet.spec` (in the repo root — the file is gitignored, so the edit is not committed) and rebuild. Then launch `dist/SentinelNet/SentinelNet.exe` and confirm the dashboard loads: a working `uv run` does **not** imply a working exe, because `get_resource_path` branches on `sys._MEIPASS`, which only exists when frozen.

- [ ] **Step 6: Write the refactor record**

Create `docs/REFACTOR-DESTRUCTURE.md` following the shape of the old `docs/REFACTOR.md` (recover it with `git show bb00b00^:docs/REFACTOR.md` for reference): the layout decision, the migration table (endpoint → router), the final line count of `app_server.py`, the test patch-point changes (`test_transports.py`), and anything you had to leave alone.

- [ ] **Step 7: Commit**

```bash
git add app_server.py docs/REFACTOR-DESTRUCTURE.md
git commit -m "refactor: app_server.py reduced to application shell"
```

---

## Notes for the implementer

- **`master` is the backup.** Everything here lands on `worktree-destructure`. Do not merge to `master` until the manual click-through in Task 21 Step 4 has actually been done; the exe rebuild happens after the merge, from the repo root.
- **The parity gate is not optional and not sufficient.** It cannot see the WebSocket (Task 10), the `GET /` template response, or any behaviour that does not show up in an OpenAPI schema. Tasks 10, 18, and 21 have explicit manual checks for exactly that reason.
- **Line numbers in this plan are from commit `8bab241`** and drift the moment Task 2 lands. After that, find code by symbol name.
- **Resist improving things.** Every dead-looking parameter, odd default, and duplicated block in the moved code is out of scope. Note it in the task report; do not fix it in an extraction commit.
