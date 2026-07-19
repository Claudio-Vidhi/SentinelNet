# Reorg + Multi-FortiGate Targets + Live Flows Graph — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize root modules into domain packages, add named multi-FortiGate connection management to the FortiGate LIVE tab, and add a flow graph + dashboard tables to Live Flows — all on the **Dev** branch.

**Architecture:** Python/FastAPI backend (routers/ + root modules → new packages), vanilla-JS dark dashboard (templates/dashboard.html + static/js/*), SQLite (db.py) for observability, encrypted JSON (crypto_vault) for FortiGate tokens. No new dependencies, no CDN.

**Tech Stack:** Python 3.x (uv), FastAPI, SQLite, vanilla JS/canvas, PyInstaller.

## Global Constraints

- Branch: **Dev** only. Never touch master. Never push unless asked.
- No new pip dependencies. No external JS/CSS (strict no-CDN).
- UI escaping convention: `escapeHtml(jsStr(x))` for anything interpolated into HTML.
- Codebase comments/docstrings are in Italian — match that style.
- Tests are unittest modules run as scripts; after reorg they live in `tests/` and run via `python -m tests.<name>` from repo root (each keeps `if __name__ == "__main__": unittest.main()`).
- Never delete `.patch`/`.diff` files.
- No CI — verification is local only.
- Final step of the whole plan: `graphify update .` and `pyinstaller SentinelNet.spec`.

**Deviation from spec §2 (approved rationale):** `fortigate_service` already stores per-IP encrypted tokens with port/verify_tls in `data/fortigate_tokens.json`. We extend that store with `name` + an active-target pointer instead of creating a `fortigate_targets` DB table. Less code, no migration.

---

### Task 1: Repository reorganization into domain packages

**Files:**
- Create: `core/__init__.py`, `services/__init__.py`, `collectors/__init__.py`, `security/__init__.py`, `ai/__init__.py`, `tests/__init__.py` (all empty)
- Move (git mv), root → package:
  - `core/`: core_engine.py, db.py, data_config.py, app_settings.py
  - `services/`: fortigate_service.py, fortigate_provisioner.py, switch_provisioner.py, wlc_service.py, site_manager.py, site_agent.py, inventory_manager.py, visio_export.py
  - `collectors/`: mac_collector.py, arp_collector.py, mac_history.py, network_scanner.py
  - `security/`: crypto_vault.py, secure_key_store.py, security_manager.py, user_manager.py, identity_manager.py, redaction.py, provisioning_secrets.py
  - `ai/`: ai_assistant.py, mcp_server.py, mcp_client.py, config_analyzer.py
  - `tests/`: every root `test_*.py`
  - `docs/dev/`: claude_plan.md, report.md, semgrep.md, DESIGN-sentry.md, INTEGRATIONS-IDEAS.md, Semgrep_Code_Combined_Findings_2026_07_19.csv (if tracked)
  - `patches/`: destructure.diff, ui-revamp.diff
  - `scripts/dev/`: ask_claude.py, fix_ui_tests.py, fix_ui_tests2.py
- Modify: every importer (~74 files: root modules themselves, `routers/*.py`, `observability/**/*.py`, `fw_analyzers/*.py`, `app_server.py`, moved tests), `SentinelNet.spec`, `Dockerfile` (check COPY lines), any dynamic import strings (grep `importlib`, `__import__`, quoted module names).

**Interfaces:**
- Produces: modules importable as `from core import db`, `from services import fortigate_service`, `from security import crypto_vault`, `from collectors import mac_collector`, `from ai import mcp_server`. Root keeps `main.py`, `app_server.py`.

**Steps:**

- [ ] **Step 1: Baseline** — run full suite from repo root, record pass/fail counts:
  `Get-ChildItem test_*.py | ForEach-Object { python $_.Name }` (or loop with failure capture). Expected: all green (record any pre-existing failures — do not fix them, just note).
- [ ] **Step 2: git mv** all files per mapping above; create `__init__.py` files. Commit `chore: move modules into domain packages (no import fixes yet)`.
- [ ] **Step 3: Rewrite imports** mechanically across the repo. Mapping (regex over `*.py`):
  - `^import X$` → `from <pkg> import X` ; `^import X as Y` → `from <pkg> import X as Y`
  - `^from X import ...` → `from <pkg>.X import ...`
  for each moved module name X. Include intra-package imports (e.g. fortigate_service imports crypto_vault → `from security.crypto_vault import ...`). Use a Python script in scratchpad, not hand-edits, then review `git diff` for false positives (e.g. `import db` vs local variable, `from db import` inside strings/docs — skip .md except runnable snippets).
- [ ] **Step 4: Update SentinelNet.spec** — Analysis stays `['app_server.py']`; add `hiddenimports=['core', 'services', 'collectors', 'security', 'ai']` only if runtime import errors appear in the built exe (PyInstaller follows static imports; likely nothing needed). Check `datas` untouched.
- [ ] **Step 5: Fix tests** — moved tests import app modules with new paths; run `python -m tests.test_db` etc. from root. Add nothing to sys.path (repo root on path when run from root).
- [ ] **Step 6: Verify** — boot app (`python main.py` or `uvicorn app_server:app` — check main.py, 95 bytes) until routes register, Ctrl-C. Run full suite: `Get-ChildItem tests/test_*.py | ForEach-Object { python -m tests.$($_.BaseName) }`. Expected: same results as Step 1 baseline.
- [ ] **Step 7: Commit** `refactor: rewrite imports for domain packages; move tests, docs, patches, dev scripts`.

---

### Task 2: Multi-FortiGate connection manager (FortiGate LIVE tab)

Depends on Task 1 (new import paths: `services.fortigate_service`, `routers.fortigate`).

**Files:**
- Modify: `services/fortigate_service.py`, `routers/fortigate.py`, `static/js/fortigate-preview.js`, `templates/dashboard.html`, `static/js/i18n.js`
- Test: `tests/test_fortigate_targets.py` (new), extend `tests/test_fortigate_service.py`

**Interfaces:**
- Produces (fortigate_service):
  - `list_targets() -> list[dict]` — `[{ip, name, port, verify_tls, active: bool}]`, never tokens.
  - `set_target_name(ip: str, name: str) -> None`
  - `set_active_target(ip: str) -> None` / `get_active_target() -> str | None` (persisted in same JSON under key `"_active"`; entries keyed by ip as today)
  - `test_connection(ip: str) -> dict` — calls `/api/v2/monitor/system/status`, returns `{ok: bool, version?: str, error?: str}`
  - existing `set_api_token(ip, token, port, verify_tls)` gains optional `name: str = ""` param.
- Produces (routers/fortigate.py):
  - `GET /api/fortigate/targets` (require_admin) → list_targets()
  - `POST /api/fortigate/targets/active` body `{ip}` (require_admin)
  - `POST /api/fortigate/targets/{ip}/test` (require_admin) → test_connection
  - existing `POST /api/fortigate/token` accepts optional `name` (empty token still deletes entry)
- JSON store shape after change: `{"_active": "1.2.3.4", "1.2.3.4": {"token": <enc>, "port": 443, "verify_tls": false, "name": "HQ-FGT"}}` — loader must skip `_active` when iterating entries (backward compatible: old files have no `_active`/`name`).

**Steps:**

- [ ] **Step 1: Failing tests** in `tests/test_fortigate_targets.py` (unittest, temp token file via existing test pattern in test_fortigate_service.py): test set_api_token with name → list_targets returns name and no token; test set/get active target persists; test `_active` key not listed as target; test empty-token delete removes entry and clears active if it pointed there.
- [ ] **Step 2: Run** `python -m tests.test_fortigate_targets` → FAIL (missing functions).
- [ ] **Step 3: Implement** in services/fortigate_service.py per interfaces above; `test_connection` reuses existing REST call helper with short timeout (5 s), catches exceptions → `{ok: False, error: str(e)}`.
- [ ] **Step 4: Run tests** → PASS. Also `python -m tests.test_fortigate_service` still PASS.
- [ ] **Step 5: Router endpoints** per interfaces; audit-log actions like existing token endpoint does. Extend `FgtTokenSchema` with `name: str = ""`.
- [ ] **Step 6: UI** — in FortiGate LIVE tab (dashboard.html + fortigate-preview.js):
  - Header: `<select id="fgtTargetSelect">` listing targets as `name (ip)`, changing it sets active via POST and reloads live objects; current live-object fetches use selected ip.
  - "Gestisci FortiGate" button opens modal: table of targets (name, ip, port, TLS badge, active radio, Test button with ok/fail badge, Delete), plus add/edit form (name, ip, port, verify_tls checkbox, token field write-only placeholder "•••• invariato" when editing). All rendering escaped with `escapeHtml(jsStr(x))`.
  - i18n: add keys to i18n.js for both languages following existing structure.
- [ ] **Step 7: Button restyle** — audit FortiGate LIVE tab controls in dashboard.html/fortigate-preview.js; replace any ad-hoc inline-styled buttons with the standard button classes used elsewhere in the dashboard (grep existing `class="btn` patterns and match). No new CSS framework; small additions to existing stylesheet only if a needed variant is missing.
- [ ] **Step 8: Verify** — run tests + `python -m tests.test_ui_revamp` and router smoke tests; boot app and eyeball tab if feasible.
- [ ] **Step 9: Commit** `feat: named multi-FortiGate targets — selector, manager modal, test-connection; restyle LIVE tab buttons`.

---

### Task 3: Live Flows — flow graph, KPI strip, tenant cards, tables

Depends on Task 1 (paths `routers/observability.py`, `observability/`). Independent of Task 2 — parallelizable.

**Files:**
- Modify: `routers/observability.py`, `observability/summary.py` (or new `observability/flowgraph.py` if summary.py doesn't fit), `static/js/observability.js`, `templates/dashboard.html`, `static/js/i18n.js`, stylesheet used by dashboard
- Test: `tests/test_observability_flowgraph.py` (new)

**Interfaces:**
- Produces: `GET /api/observability/flowgraph?window=5m` (get_current_user, tenant-scoped via existing `_tenant_filter`) returning:
  ```json
  {
    "nodes": [{"id": "10.24.1.12", "bytes": 123, "vlan": 100}],
    "edges": [{"src": "10.24.1.12", "dst": "10.0.0.5", "rate_bps": 21e8, "vlan": 100, "proto": "tcp"}],
    "kpi": {"throughput_bps": 84e8, "top_path": {"src": "...", "dst": "...", "pct": 24}, "talkers": 24, "spikes": 3},
    "tenant": {"name": "test_g", "vlans": [100], "flows_shown": 12,
               "top_talker": {"src": "...", "dst": "...", "rate_bps": 21e8}},
    "protocols": [{"proto": "tcp", "port": 443, "rate_bps": 1e9}]
  }
  ```
  Built from the same store queries `obs_top_talkers`/`obs_syslog` use (read those first; reuse their SQL/aggregation helpers, add grouping by proto/port and vlan). `spikes` = count of open anomalies in window (reuse anomalies query).

**Steps:**

- [ ] **Step 1: Failing tests** in `tests/test_observability_flowgraph.py`, modeled on `tests/test_observability_api.py` (same fixtures/ingest helpers): ingest sample flows → assert response shape above, tenant filtering (non-admin sees only own VLANs), window parsing rejects garbage (400), nodes/edges consistent (every edge endpoint in nodes).
- [ ] **Step 2: Run** → FAIL (404).
- [ ] **Step 3: Implement** aggregation + endpoint. Cap nodes/edges at top 50 by rate.
- [ ] **Step 4: Run tests** → PASS; `python -m tests.test_observability_api` still PASS.
- [ ] **Step 5: UI — cards/tables** in Live Flows section (dashboard.html + observability.js), styled like existing dark cards:
  - KPI strip (4 cards): Throughput / Top path / Talkers / Spikes.
  - Tenant summary cards (stacked): current tenant + VLAN, visible VLANs count, top talker, flows shown.
  - "Top talkers" table: Source / Target / VLAN / Rate.
  - "Protocol breakdown" table: Protocol / Port / Rate.
  - Rate formatting helper (bps → Gbps/Mbps) — reuse if one exists in observability.js, else add one.
  - Polling: refresh with the existing Live Flows refresh cycle (find current setInterval/refresh function and hook in — one fetch of /flowgraph feeds graph + all cards/tables).
- [ ] **Step 6: UI — canvas force-directed graph**: `<canvas id="flowGraphCanvas">` above tables. Vanilla implementation (~150 lines): nodes with spring-embedder iteration (repulsion + edge attraction, ~100 ticks then settle), node radius ∝ sqrt(bytes), edge width ∝ rate (clamped 1–8 px), edge color by VLAN (hash → hue), labels = ip. Hover tooltip (host, total rate); click node → filter the two tables to flows touching it (click background clears). requestAnimationFrame only while animating.
- [ ] **Step 7: i18n keys** for all new labels, both languages.
- [ ] **Step 8: Verify** — new + existing observability tests PASS (`test_observability_api`, `test_observability_ui`, `test_observability_ingest`); boot app, hit `/api/observability/flowgraph` manually.
- [ ] **Step 9: Commit** `feat: Live Flows flow graph, KPI strip, tenant cards, talkers+protocol tables`.

---

### Task 4: Final verification & build

- [ ] **Step 1:** Full test suite from repo root; expected: baseline-green.
- [ ] **Step 2:** `graphify update .`
- [ ] **Step 3:** `pyinstaller SentinelNet.spec` — expected: `dist/SentinelNet.exe` built without errors; launch exe briefly to confirm boot.
- [ ] **Step 4:** Commit any spec/build fixes: `chore: build fixes after reorg`.
