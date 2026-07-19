# Design: Repo reorg, multi-FortiGate connections, Live Flows graph + tables

Date: 2026-07-19. Branch: Dev (all work lands on Dev; master untouched until user tests and requests push).

## 1. Repository reorganization (Dev branch)

New domain packages, each with `__init__.py`:

- `core/` — core_engine.py, db.py, data_config.py, app_settings.py
- `services/` — fortigate_service.py, fortigate_provisioner.py, switch_provisioner.py, wlc_service.py, site_manager.py, site_agent.py, inventory_manager.py, visio_export.py
- `collectors/` — mac_collector.py, arp_collector.py, mac_history.py, network_scanner.py
- `security/` — crypto_vault.py, secure_key_store.py, security_manager.py, user_manager.py, identity_manager.py, redaction.py, provisioning_secrets.py
- `ai/` — ai_assistant.py, mcp_server.py, mcp_client.py, config_analyzer.py

Dev-only root files:

- `tests/` — all test_*.py (they run as unittest scripts; keep runnable: adjust sys.path or run from repo root with `python -m tests.test_x`)
- `docs/dev/` — claude_plan.md, report.md, semgrep.md, DESIGN-sentry.md, INTEGRATIONS-IDEAS.md, Semgrep CSV
- `patches/` — destructure.diff, ui-revamp.diff (never delete patch files)
- `scripts/dev/` — ask_claude.py, fix_ui_tests.py, fix_ui_tests2.py

Root keeps: main.py, app_server.py, Dockerfile, docker-compose.yml, pyproject.toml, requirements.txt, uv.lock, SentinelNet.spec, README, LICENSE, CONTRIBUTING, .gitignore, .dockerignore, .python-version, CLAUDE.md, c_api_key.txt (untracked).

Use `git mv`. Update every import site (root modules, routers/, observability/, fw_analyzers/, tests, mcp files), SentinelNet.spec hiddenimports/pathex, Dockerfile COPY lines if module-specific, and any dynamic import strings. Verification: full test suite passes, app boots, `pyinstaller SentinelNet.spec` succeeds.

## 2. Multi-FortiGate API connections (FortiGate LIVE tab)

- New DB table `fortigate_targets`: id, name (unique), host, port (default 443), verify_tls (bool), token_encrypted (crypto_vault), created_at. One row flagged `is_active` (single active target).
- Backend (routers/fortigate.py + fortigate_service.py): CRUD endpoints `GET/POST/PUT/DELETE /api/fortigate/targets`, `POST /api/fortigate/targets/{id}/activate`, `POST /api/fortigate/targets/{id}/test` (probe /api/v2/monitor/system/status). Tokens never returned to UI (write-only, masked display). RBAC same as existing token management. Existing single-token flow migrates: on startup, if legacy token exists and table empty, create a "default" target from it.
- All live firewall-object calls resolve the active target.
- UI (fortigate-preview.js + dashboard.html): target selector dropdown in tab header + "Manage targets" modal (list, add/edit/delete, test-connection with status badge, activate). Escaping via escapeHtml(jsStr(x)).
- Button restyle: audit FortiGate LIVE tab buttons; align to existing design language (same classes/tokens used elsewhere in dashboard) — no new CSS framework.

## 3. Live Flows: flow graph + dashboard tables

Data source: existing observability flow/syslog ingest (routers/observability.py, observability/). New aggregation endpoint(s) returning: per-host totals, per-pair rates, per-VLAN scope, per-protocol/port breakdown, spike events, window = last 5 min.

UI additions in Live Flows (Top Talkers) section, vanilla JS in observability.js, no external libs:

- **Force-directed flow graph** (canvas): nodes = hosts (size ∝ total traffic), edges = flows (width ∝ rate, color by VLAN), simple spring simulation, click node → filters tables below, tooltip with host/rate.
- **KPI strip**: Throughput (last 5 min), Top path (% of flow), Talkers (active hosts), Spikes (new events).
- **Tenant summary cards**: current tenant, visible VLANs, top talker, flows shown — respects tenant/RBAC scope.
- **Top talkers table**: Source / Target / VLAN / Rate.
- **Protocol breakdown table**: protocol (TCP/UDP/ICMP) + top ports with rates.

Styling matches existing dark dashboard cards. i18n strings added to i18n.js.

## 4. Execution

Order: Task 1 (reorg) first — everything else builds on new layout. Then Task 2 (multi-FGT) and Task 3 (flow graph/tables) in parallel subagents. Each task: tests written/updated, suite green. Final: `graphify update .`, rebuild exe with `pyinstaller SentinelNet.spec`.

Out of scope: master merge/push (user tests first, then requests), CI (none by policy), new dependencies.
