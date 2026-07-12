# SentinelNet — Master Implementation Plan (Final)

> Principal-engineer master plan consolidating the *State Report* (commit `6fcb9039`), the *Complete Observability & Refactoring Implementation Guide* (v1.0), and the *Gap Analysis & Roadmap*. This document supersedes the original guide. Where the guide and this plan conflict, **this plan wins**.
>
> **Scope note:** This is a planning artifact. It contains **no implementation code**. Interface sketches (signatures, schema DDL, semantic SQL sketches, config shapes) appear only to remove ambiguity for downstream executors and are non-normative in syntax, normative in semantics.

---

## 1. Executive Summary & Objectives

### 1.1 What we are building

SentinelNet today is a self-hosted, multivendor network management platform: configuration backup, firmware/CVE triage against ENISA EUVD, topology mapping, SSH terminal, FortiGate/WLC integrations, multi-site polling, and an AI assistant + MCP server. Storage is flat JSON/CSV, the API is a single monolithic `app_server.py` (~51 heterogeneous endpoints, cohesion 0.04), and there is **no traffic-flow observability at all**.

This program delivers two intertwined outcomes:

1. **Day-2 flow observability (net-new capability):** ingest IPFIX/NetFlow, sFlow, and syslog from network devices; aggregate into a transactional store; correlate flows × syslog × MAC history into actionable events; expose scoped query APIs, MCP tools, and a "Live Flows" UI tab.
2. **Structural refactoring (pays down existing debt):** split `app_server.py` into domain routers with dependency-injected auth, introduce a real async-safe SQLite layer, adopt a FastAPI `lifespan` manager, and resolve the flat-vs-package import question.

Both outcomes are gated behind a **security-first Phase 0** that closes the report's own open findings (H-1 TLS, L-1 JWT storage, I-1 AI leakage, I-2 provisioner secrets) *before* any new attack surface (cleartext UDP ingest) is introduced.

Because SentinelNet is an **EU-market product ingesting IP-level traffic metadata (personal data under GDPR)**, this plan also treats retention limits, per-tenant purge, log minimization, and processor documentation as first-class deliverables — not afterthoughts (items 3.7, 6.7).

### 1.2 Why the sequencing matters

The original guide, if merged verbatim, would:
- Add three **unauthenticated cleartext UDP listeners** bound to `0.0.0.0` while TLS is still absent (aggravates H-1).
- **Block the Uvicorn event loop** with synchronous `sqlite3` calls and unbounded per-packet task spawning (stalls terminal, API, everything).
- **Bypass the multi-group RBAC model** (`user.group` scalar vs. `user_group_scope` set) — silent data leakage/hiding.
- Ship a `flow_aggregates` table that never aggregates, a `correlated_events` table nothing populates, and hard-coded `tenant="default"` at ingest.
- Reintroduce `sessionStorage` JWT (directly regressing L-1).

This plan corrects all nine defects as **mandatory design decisions** (Section 4) and phases the work so each artifact (PyInstaller exe **and** Docker image) stays buildable and the test suite stays green at every step.

### 1.3 Primary objectives (measurable)

- **O1 — Security baseline:** H-1 mitigated (native TLS option + hardening guide), L-1 closed (cookie auth), I-1 mitigated (redaction with leak-assertion tests), I-2 closed (no cleartext secrets in generated day-0 configs).
- **O2 — Cohesion:** `app_server.py` endpoint count reduced measurably (target: ≤10 routes remaining after Phase 6; FortiGate + WLC out by Phase 2); router paths/responses contract-verified.
- **O3 — Transactional store:** `observability.db` created via versioned migration under `SENTINELNET_DATA_DIR`; **zero synchronous DB calls in async handlers**; aggregation is a true minute rollup (UPSERT); code refuses to start against a newer schema version than it supports.
- **O4 — Ingestion safety:** sustained 5k pps ingest with **p99 event-loop added latency < 5 ms** (terminal WS + API responsive); unknown exporters dropped/quarantined with audit; per-flow tenant attribution correct; pipeline health self-observable (metrics: received/parsed/dropped/queue depth/commit latency).
- **O5 — Correlation:** `correlated_events` actually populated from flow × syslog × MAC-history joins, enriched with switch port, deduplicated.
- **O6 — Multi-site parity:** remote-site (Mode B) flows arrive via the authenticated agent channel — **no raw UDP over VPN**.
- **O7 — Dual-artifact integrity:** every phase ships buildable exe + Docker; listeners default **off** on desktop/exe.
- **O8 — Data protection:** retention enforced technically; per-tenant purge available; `docs/PRIVACY.md` shipped before observability GA.

---

## 2. Guiding Principles & Global Constraints

These constraints are **binding on every work item and every executor** unless a work item explicitly overrides one with owner sign-off.

### 2.1 Language policy (Italian codebase)
- **User-facing strings, log messages, audit entries, UI labels, error text → Italian.**
- **Identifiers (functions, classes, variables, DB columns, config keys, env vars, file names) → English**, matching existing style (e.g. `run_backup_and_triage`, `user_group_scope`, `get_full_config`).
- Docstrings/comments: English preferred for new code; do not rewrite existing Italian comments.
- Codified in `CONTRIBUTING.md` (item 1.5); enforced as a code-review gate.

### 2.2 Dual-artifact gate (exe + Docker)
- Every PR **must** produce a working **PyInstaller exe** *and* a working **Docker image**. CI runs both builds plus an exe launch smoke test.
- Bundled resources (e.g. `schema.sql`) must resolve through the existing `get_path`/resource-path mechanism in **both** artifacts.
- **Desktop/exe default = UDP listeners OFF.** Docker default = listeners off unless explicitly enabled via env, bound to loopback unless explicitly opened.

### 2.3 Security-first ordering
- **No new plaintext ingress channel may ship before Phase 0 delivers TLS option + cookie auth.** Phase 3 (UDP ingest) is hard-blocked on Phase 0 acceptance.
- Every new endpoint, MCP tool, and ingest path must respect: audit log, rate-limit/lockout, CLI blacklist (where applicable), and **multi-group tenant scope**.

### 2.4 Async-DB rule (non-negotiable)
- After Phase 1, **no code path in an async endpoint or async protocol handler may call a synchronous SQLite connection directly.**
- All DB writes on the hot path go through the **bounded async queue → dedicated writer worker → batched commit** pipeline.
- All DB reads in async handlers go through the async DB layer (executor-offloaded) — never a raw `sqlite3` call in the event loop.
- A CI lint/grep gate flags `sqlite3.connect(`, `.commit()`, and `get_observability_connection(` usage inside `async def` bodies.

### 2.5 Scope-correctness rule
- Tenant scoping **always** uses the multi-group model: `user_group_scope(user)` → set of allowed groups; queries filter `WHERE tenant IN (:scoped_groups)`; device access uses `assert_group_allowed`/`assert_device_allowed`.
- **The scalar `user.group` pattern from the original guide is forbidden.** A standing grep test asserts no `user.group` scalar reference exists in `routers/` or `observability/`.
- **Empty scope returns empty results** — never an unfiltered query.

### 2.6 Single-process assumption (pending Decision #12)
- The async-SQLite single-writer design assumes **one Uvicorn worker**. Until Decision #12 says otherwise, the app **fails closed at startup** (Italian error) if `--workers > 1` is configured with observability enabled.

### 2.7 Failure-mode posture
- Ingest pipeline degrades by **dropping with metrics**, never by blocking the event loop or crashing the app.
- Disk-full / DB-error on the writer: stop accepting new ingest payloads (drop + metric + Italian error log at WARN, rate-limited), keep the management app alive.
- The writer worker is supervised: on unexpected death it is restarted (bounded restarts, then listeners are shut down and an audit event is emitted).

### 2.8 Executor tiering
- **Standard agent:** well-specified, low-ambiguity, low-blast-radius items.
- **Frontier model (Fable 5):** reserved for genuinely hard/high-risk items — IPFIX template decoding, sFlow sampling correctness, async ingestion pipeline (loop-safety), correlation engine, RBAC-sensitive scope work, auth-DI extraction, tenant attribution, and the multi-site relay. Justification given per item; assignments summarized in Section 8.

---

## 3. Phase-by-Phase Plan

Effort key: **S** ≤ 2 days · **M** 3–8 days · **L** 2–4 weeks.

---

### PHASE 0 — Security Quick Wins

**Rationale:** Close the report's open findings before adding UDP attack surface. All of Phase 0 is independent of observability and can proceed in parallel with Phase 1 packaging.

---

#### 0.1 — Native TLS option + hardened reverse-proxy guide
- **Files:** `app_server.py`, `data_config.py`, `docs/HARDENING.md`, `docker-compose.yml`
- **Agent brief:** Add optional native ASGI TLS. Read `SENTINELNET_SSL_CERTFILE` and `SENTINELNET_SSL_KEYFILE` env vars via `data_config.py`; when both are present and readable, pass them to the Uvicorn run configuration (certfile/keyfile). When absent, behavior is unchanged (HTTP). Do **not** auto-generate certs silently; if exactly one of the pair is set, or a file is unreadable/malformed, **fail closed at startup** with an Italian error message stating which variable is wrong. Relative cert paths resolve against `SENTINELNET_DATA_DIR` (must work identically in exe and Docker). Author `docs/HARDENING.md` describing: (a) native TLS usage and cert-renewal responsibility (operator-owned); (b) the recommended reverse-proxy pattern (nginx/Caddy) with TLS termination, security headers (HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`), and WebSocket upgrade passthrough for the terminal; (c) an explicit statement that the management panel must never be exposed to untrusted networks over HTTP. Add commented proxy stanza to `docker-compose.yml`.
- **Definition of Done:**
  - Both env vars set → HTTPS serves the dashboard (browser-verified in test via TLS TestClient/self-signed fixture).
  - Neither set → HTTP unchanged; existing tests green.
  - Exactly one set, or unreadable file → process exits non-zero with Italian error.
  - `docs/HARDENING.md` exists and is linked from README.
- **Dependencies:** none. **Effort:** M. **Risk:** cert lifecycle on desktop/exe. **Mitigation:** native TLS is optional; primary recommendation remains reverse proxy; renewal responsibility documented.
- **Executor:** Standard agent.

---

#### 0.2 — Move JWT to `HttpOnly`/`Secure`/`SameSite` cookie; retire `sessionStorage`
- **Files:** `security_manager.py`, `templates/dashboard.html`, `app_server.py` (auth extraction points, WS handshake)
- **Agent brief:** Replace `sessionStorage`-based JWT with a cookie: `HttpOnly` always; `Secure` when TLS is active (conditional on TLS/env flag so local HTTP dev still works); `SameSite=Strict` unless Decision #2 selects otherwise. On successful login, set the cookie server-side; on logout, clear it and invalidate the session. Update all frontend `fetch`/XHR calls to `credentials:'include'` and **remove every `sessionStorage.getItem/setItem('jwt_token')`** usage. WebSocket terminal: browsers cannot set custom headers on WS upgrade, so authenticate the WS from the cookie carried on the upgrade request (validate in the WS accept path before opening the terminal channel); preserve the existing OTP/one-shot token flow if it layers on top. CSRF: implement the mechanism chosen in Decision #2 (default if no decision by start date: `SameSite=Strict` **plus** a custom-header check, e.g. `X-Requested-With`, on all state-changing methods); document it in `docs/HARDENING.md`. **Dual-accept:** `Authorization: Bearer` must remain valid for programmatic API clients (accept cookie OR Bearer); only browser Bearer usage is deprecated.
- **Definition of Done:**
  - Grep test: zero occurrences of `sessionStorage` for tokens in `templates/dashboard.html`.
  - Login sets `HttpOnly` cookie; authenticated API + WS terminal both work over the cookie (integration test).
  - Bearer path still works for programmatic clients (test asserts both accepted).
  - CSRF mechanism documented and enforced on POST/PUT/DELETE (test: state-changing request without CSRF proof → rejected).
  - Logout invalidates the session; expired cookie → 401 with Italian message.
  - Existing auth/audit/lockout tests green.
- **Dependencies:** 0.1 (`Secure` flag needs the TLS story). **Effort:** M. **Risk:** WS + CSRF handling; breaking external clients. **Mitigation:** dual-accept transition; explicit CSRF design note; WS auth integration test.
- **Executor:** **Frontier (Fable 5)** — session-security-sensitive; WS auth + CSRF + backward compat is subtle and high-blast-radius.

---

#### 0.3 — AI-context secret redaction
- **Files:** `ai_assistant.py`, new `redaction.py`
- **Agent brief:** Create `redaction.py` exposing a pure, idempotent function `redact(payload)` accepting `str` or nested `dict`/`list` and returning the same shape with secrets masked (`***REDACTED***`, keys preserved) — applied before **any** data leaves the process to **any** LLM provider (in-app assistant and MCP alike). Minimum pattern library: Cisco `enable secret`/`enable password`, `username … password/secret`, SNMP `community`, RADIUS/TACACS keys, PSKs, FortiOS `set psksecret`/`set passwd`/`set password`/`set private-key`, WLC keys, generic `api[-_]?key`/`token`/`bearer` values, PEM private-key blocks (multiline), and Fernet blobs. Route **all** existing AI context builders (`build_tenant_context`, `_device_running_config_context`, `_fortigate_live_context`) through the masking pass — a single choke-point function that all LLM-bound paths must call (design so Phase 4/5 flow contexts reuse it). Avoid over-redaction: interface names, VLAN IDs, hostnames, IPs must survive (IPs are handled separately under GDPR policy, not redaction — see 6.7).
- **Definition of Done:**
  - Golden-fixture test: multivendor config containing 10+ known secret patterns → **zero** secret substrings in output.
  - Negative test: VLANs, hostnames, IPs, interface names survive.
  - Unit test with spy/monkeypatch proving every AI context path calls `redact`.
  - `redact(redact(x)) == redact(x)` (idempotency test).
- **Dependencies:** none. **Effort:** M. **Risk:** over/under-redaction; false confidence. **Mitigation:** per-vendor fixtures; leak-assertion test is the gate; documented known limits in module docstring.
- **Executor:** Standard agent (fixture set provided in the brief).

---

#### 0.4 — Provisioner secret handling (no cleartext in generated day-0)
- **Files:** `switch_provisioner.py`, `fortigate_provisioner.py`, `crypto_vault.py`
- **Agent brief:** Eliminate cleartext secrets in generated day-0 configurations. Default mode: generated configs contain placeholder tokens (`{{VAULT:enable_secret}}` or vendor-appropriate equivalent) instead of literal secrets. Provide a "materialize" step that resolves placeholders from `crypto_vault.py` **only at push time** (SSH/serial), in-memory, never persisting the materialized config to disk and never logging the resolved values (verify logging paths). Fully-materialized file generation remains possible **only** via explicit flag + on-screen Italian warning + audit entry. Existing saved templates must keep working (placeholder mode is additive).
- **Definition of Done:**
  - Default generation output contains **no** cleartext secret (automated scan of generated text against the vault's known secrets).
  - Push path materializes and applies successfully (integration test with mocked transport); serial push materializes just-in-time.
  - Materialized-file generation emits an audit entry; secret never appears in any log (test).
- **Dependencies:** none. **Effort:** S/M. **Risk:** backward compat of generated configs. **Mitigation:** additive placeholder mode; legacy full-materialize behind explicit flag.
- **Executor:** Standard agent.

**Phase 0 exit gate:** H-1 mitigated + documented; L-1 closed; I-1 leak-test green; I-2 no-cleartext test green; exe + Docker build; full existing suite green.

---

### PHASE 1 — Packaging & Storage Foundation

**Rationale:** Resolve the flat-vs-package import mismatch and stand up an async-safe transactional store, while JSON/CSV keep working untouched.

---

#### 1.1 — Decide & apply package layout; fix PyInstaller spec + entrypoint
- **Files:** `pyproject.toml`, `*.spec`, module imports, `app_server.py` entrypoint
- **Agent brief:** Execute the layout decision (Open Decision #1; **recommended default and assumed baseline: keep flat layout**). Under flat layout: create `pyproject.toml` declaring project metadata, dependencies (mirroring `requirements.txt`, managed via **uv**), and console entrypoint; make new subpackages (`observability/`, `observability/ingesters/`, `observability/storage/`, `routers/`) importable without a `sentinelnet.` prefix; update `*.spec` `datas`/`hiddenimports` so new packages and `schema.sql` bundle correctly. **Rewrite every guide import of the form `from sentinelnet.X import Y` to flat form.** Verify `get_path`/resource resolution in all three run modes (source, exe, Docker), including Netmiko/driver hidden imports.
- **Definition of Done:**
  - App runs identically from source, exe, and Docker (CI smoke tests all three).
  - Import-consistency check: no broken or `sentinelnet.`-prefixed imports anywhere.
  - `observability/` and `routers/` import cleanly in all run modes.
  - Layout decision documented in `docs/REFACTOR.md`.
- **Dependencies:** none (enables 1.2 and 2.2). **Effort:** M. **Risk:** PyInstaller path regressions. **Mitigation:** CI exe launch smoke test; flat layout minimizes churn.
- **Executor:** Standard agent (escalate to frontier only if Decision #1 selects the package migration).

---

#### 1.2 — Async-safe SQLite layer (WAL, single writer, executor/queue)
- **Files:** `data_config.py`, new `db.py`
- **Agent brief:** Implement the async-safe DB access layer: (a) a single WAL-mode connection owned exclusively by the writer worker; (b) an async read helper offloading queries to a threadpool executor; (c) a **bounded** queue for write payloads consumed by the dedicated writer task/thread; (d) supervised writer lifecycle (start/stop/drain; restart-on-crash with bounded attempts per §2.7). Pragmas: `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout` set. Expose a synchronous `get_observability_connection()` **for migrations and tests only**, documented as forbidden on async hot paths (enforced by the CI grep gate, §2.4). Enforce the single-process guard (§2.6). Interface sketch (semantics binding, syntax not):
    ```
    # db.py — interface sketch
    async def read(query: str, params: Mapping) -> list[Row]      # executor-offloaded
    def enqueue_write(payload: WritePayload) -> bool              # non-blocking; False = dropped (queue full) + metric
    async def start_writer() -> None                              # started by lifespan
    async def stop_writer() -> None                               # graceful drain on shutdown
    def get_observability_connection() -> Connection              # migrations/tests ONLY
    ```
- **Definition of Done:**
  - Load test: N concurrent async producers enqueue at rate without blocking the loop (**p99 added loop latency < 5 ms**, measured with a loop-latency probe).
  - No raw `sqlite3` in the event loop for reads (executor-offloaded, verified by grep gate).
  - Writer drains queue on shutdown; kill/restart leaves DB recoverable via WAL (test).
  - Disk-full / write-error path: payloads dropped with metric, app stays alive (fault-injection test).
  - Startup with `--workers > 1` + obs enabled → fail closed, Italian error.
- **Dependencies:** 1.1. **Effort:** M. **Risk:** concurrency bugs; WAL on network volumes. **Mitigation:** single-writer design; load test in CI; volume-placement guidance in `docs/HARDENING.md` (local volume recommended, network volume documented as unsupported for WAL).
- **Executor:** **Frontier (Fable 5)** — event-loop safety and concurrency correctness are the core value; a subtle bug here stalls the whole app.

---

#### 1.3 — Observability schema + idempotent versioned migration
- **Files:** `observability/storage/schema.sql`, `db.py`
- **Agent brief:** Author `schema.sql` defining the three tables plus a quarantine table for unknown exporters (see 3.5), with correct types, indexes, the aggregation UNIQUE key, and a `schema_version` table. Implement **versioned, forward-only, idempotent** migrations (run-once, safe to re-run). **Version guard:** if the DB's `schema_version` is *newer* than the code supports, refuse to start observability (Italian error, management app stays up) — this is the downgrade-safety contract for the rollout plan (§6.3). Bundle `schema.sql` for exe + Docker. Schema sketch:
    ```sql
    -- schema.sql — interface sketch (semantics binding)
    CREATE TABLE IF NOT EXISTS flow_aggregates (
      window_start   INTEGER NOT NULL,          -- unix ts truncated to 60s
      tenant         TEXT NOT NULL,
      src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,
      protocol INTEGER, dst_port INTEGER,
      total_bytes INTEGER NOT NULL DEFAULT 0,
      total_packets INTEGER NOT NULL DEFAULT 0,
      flow_count INTEGER NOT NULL DEFAULT 0,
      exporter_ip TEXT,
      UNIQUE(window_start, tenant, src_ip, dst_ip, protocol, dst_port)
    );
    CREATE INDEX ... idx_flow_window_tenant ON flow_aggregates(window_start, tenant);

    CREATE TABLE IF NOT EXISTS syslog_events (
      id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, tenant TEXT NOT NULL,
      device_ip TEXT, severity INTEGER, action TEXT, message TEXT, exporter_ip TEXT
    );
    CREATE INDEX ... idx_syslog_ts_tenant ON syslog_events(ts, tenant);

    CREATE TABLE IF NOT EXISTS correlated_events (
      id INTEGER PRIMARY KEY, created_ts INTEGER NOT NULL, tenant TEXT NOT NULL,
      kind TEXT, src_ip TEXT, dst_ip TEXT, switch_port TEXT,
      severity INTEGER, status TEXT DEFAULT 'new',       -- new|ack|resolved
      dedup_key TEXT UNIQUE,                              -- prevents duplicate emission (4.2)
      evidence_json TEXT
    );
    CREATE INDEX ... idx_corr_tenant_status ON correlated_events(tenant, status);

    CREATE TABLE IF NOT EXISTS quarantined_exporters (
      exporter_ip TEXT PRIMARY KEY, first_seen INTEGER, last_seen INTEGER, packet_count INTEGER
    );
    CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
    ```
- **Definition of Done:** `observability.db` created under `SENTINELNET_DATA_DIR` on first run; re-run is a no-op (idempotency test); newer-schema-than-code → observability refuses to start, app survives (test); `schema.sql` present and resolvable in exe + Docker artifacts.
- **Dependencies:** 1.2. **Effort:** S. **Risk:** schema drift. **Mitigation:** versioned migrations + drift test + version guard.
- **Executor:** Standard agent.

---

#### 1.4 — Fix aggregation semantics (true minute rollup via UPSERT)
- **Files:** `observability/storage/*`, `db.py`
- **Agent brief:** Implement the flow write payload as an **UPSERT** keyed on the UNIQUE tuple, truncating the timestamp to the 60-second bucket (`window_start = ts - (ts % 60)`) and summing counters via `ON CONFLICT … DO UPDATE` (semantic sketch: `total_bytes += excluded.total_bytes`, `total_packets += excluded.total_packets`, `flow_count += 1`). **Time source (binding):** use exporter-reported flow-end time when parseable **and** within ±300 s of receipt time; otherwise fall back to receipt time and increment a `clock_skew_fallback` metric. Batched commits (3.2) must preserve UPSERT semantics.
- **Definition of Done:** test: two flows in the same minute bucket + same 5-tuple → **one** row, counters summed; adjacent buckets → two rows; skewed exporter timestamp (> ±300 s) → receipt time used + metric incremented; no UNIQUE-constraint violations under load.
- **Dependencies:** 1.3. **Effort:** S. **Risk:** bucketing correctness. **Mitigation:** dedicated bucketing unit tests incl. skew cases.
- **Executor:** Standard agent.

---

#### 1.5 — Language/style policy + contributor rules doc
- **Files:** `CONTRIBUTING.md`
- **Agent brief:** Document as contributor guidelines, with concrete do/don't examples: the language policy (§2.1), dual-artifact gate (§2.2), async-DB rule (§2.4), scope-correctness rule (§2.5), single-process assumption (§2.6), and the standing security grep gates (Section 5). Reference from README.
- **Definition of Done:** `CONTRIBUTING.md` exists, referenced from README, covers all listed rules with examples.
- **Dependencies:** none. **Effort:** S. **Risk:** none. **Executor:** Standard agent.

**Phase 1 exit gate:** exe + Docker build; `observability.db` migrated idempotently with version guard; async writers don't block loop (load test, p99 < 5 ms); aggregation UPSERT + time-source rules verified.

---

### PHASE 2 — `app_server.py` Refactor into Routers

**Rationale:** Highest-alignment debt paydown. Prove the DI-auth + router pattern on FortiGate + WLC first, with contract parity tests.

---

#### 2.1 — Auth as FastAPI dependencies (multi-group scoped `User`)
- **Files:** `security_manager.py`, `user_manager.py`, new `routers/deps.py`
- **Agent brief:** Convert the current middleware/inline auth into reusable FastAPI dependencies: `get_current_user()` (validates cookie **or** Bearer per 0.2, returns a `User` carrying **multi-group scope**: `groups: set[str]`, `role`), `require_operator()`, `require_admin()`. These must preserve **all** existing cross-cutting behavior: audit logging (one entry per authenticated request, same fields as today), rate-limit, lockout (`is_locked_out`), and CLI blacklist enforcement where relevant. Expose `scoped_groups(user) -> set[str]` plus `assert_group_allowed`/`assert_device_allowed` helpers for router use. **Do not introduce a scalar `user.group`.** Write behavior-parity tests for audit/rate-limit/lockout/blacklist *before* switching any route over. Interface sketch:
    ```
    # routers/deps.py — interface sketch
    async def get_current_user(request) -> User          # cookie or Bearer; 401 on neither
    async def require_operator(user = Depends(get_current_user)) -> User
    async def require_admin(user = Depends(get_current_user)) -> User
    def scoped_groups(user: User) -> set[str]
    ```
- **Definition of Done:** dependencies enforce role + scope; audit/rate-limit/lockout/blacklist parity tests pass; multi-group user resolves to a set (test); viewer denied operator routes; anonymous/expired token → 401.
- **Dependencies:** 0.2. **Effort:** M. **Risk:** losing middleware behaviors. **Mitigation:** parity tests authored first.
- **Executor:** **Frontier (Fable 5)** — RBAC-sensitive; regressions leak or lock out.

---

#### 2.2 — Extract `routers/fortigate.py`
- **Files:** `routers/fortigate.py`, `app_server.py`
- **Agent brief:** Move all FortiGate endpoints (`fgt_arp`, `fgt_device_inventory`, `fgt_full_config`, `fgt_diagnose_client`, `fgt_dhcp`, `fgt_interfaces`, and any others enumerated from the live `app_server.py` — enumerate first, list in `docs/REFACTOR.md`) into an `APIRouter`, wiring auth via 2.1 dependencies and scope via `assert_device_allowed`. **Route paths, methods, params, status codes, and response shapes must be identical** (verified by 2.6). Business logic stays in `fortigate_service.py`; routers are thin. Preserve streaming/large-config response behavior.
- **Definition of Done:** parity test (2.6) green for all FortiGate routes; auth/scope enforced; routes removed from `app_server.py`; migration table row added per route.
- **Dependencies:** 2.1, 1.1. **Effort:** M. **Risk:** behavior drift. **Mitigation:** OpenAPI snapshot diff + per-route parity checklist.
- **Executor:** Standard agent (mechanical once 2.1 exists).

---

#### 2.3 — Extract `routers/wlc.py`
- **Files:** `routers/wlc.py`, `app_server.py`
- **Agent brief:** Same pattern as 2.2 for WLC endpoints (`wlc_ap_summary`, `wlc_client_detail`, `wlc_client_summary`, `wlc_interfaces`, `wlc_diagnose_client`; enumerate from live code). Logic stays in `wlc_service.py`.
- **Definition of Done:** parity test green for WLC routes; auth/scope enforced; routes removed from monolith.
- **Dependencies:** 2.1. **Effort:** M. **Risk:** drift. **Mitigation:** OpenAPI snapshot diff.
- **Executor:** Standard agent.

---

#### 2.4 — Replace `on_event` with `lifespan` context manager
- **Files:** `app_server.py`
- **Agent brief:** First **verify** the actual startup mechanism in current code (the guide assumes `@app.on_event`; the state report doesn't confirm — inspect and record the finding in `docs/REFACTOR.md`). Introduce a single `lifespan` async context manager with **explicit ordered startup**: (1) run migrations, (2) start DB writer, (3) start periodic jobs and — from Phase 3 — UDP listeners; shutdown in reverse order with graceful writer drain. Any exception during startup fails closed (non-zero exit, Italian error). Routers are included at app construction. Verify `TestClient` compatibility (lifespan runs in tests).
- **Definition of Done:** app starts/stops cleanly via `lifespan`; no `on_event` remains; startup ordering asserted in a smoke test; TestClient works; writer starts/stops with app.
- **Dependencies:** 2.2, 2.3, 1.2. **Effort:** S. **Risk:** startup ordering. **Mitigation:** explicit ordered steps; smoke test.
- **Executor:** Standard agent.

---

#### 2.5 — Correct scope dependency in routers (multi-group)
- **Files:** `routers/*`, `tests/test_rbac_scope.py`
- **Agent brief:** Audit every extracted route: device/group access must use `assert_group_allowed`/`assert_device_allowed`/`scoped_groups` — **never** scalar `user.group`. Add explicit scope checks where the monolith relied on middleware. Author the **reusable multi-group RBAC test harness** (`tests/test_rbac_scope.py`): fixtures for single-group, multi-group, and empty-scope users; parametrizable against any router. This harness is reused by 4.1, 5.5, 6.3, 6.6.
- **Definition of Done:** multi-group user sees all in-scope groups, denied out-of-scope devices; single-group user unaffected; empty-scope user gets empty/denied, never unfiltered; standing grep test asserting no scalar `user.group` in `routers/`.
- **Dependencies:** 2.1. **Effort:** S/M. **Risk:** RBAC leak. **Mitigation:** dedicated harness; standing grep gate.
- **Executor:** **Frontier (Fable 5)** — RBAC-sensitive; this is the exact defect the guide introduces, and the harness built here guards all later phases.

---

#### 2.6 — Migration table + OpenAPI parity snapshot test
- **Files:** `docs/REFACTOR.md`, `tests/test_router_parity.py`
- **Agent brief:** Capture the pre-refactor OpenAPI schema (`/openapi.json`) as a golden snapshot **before** 2.2/2.3 merge; write a test asserting the post-refactor schema matches for all migrated routes (paths, methods, params, response models, status codes). Document the endpoint→router migration table in `docs/REFACTOR.md`. Design the harness to be reusable per-domain for 6.6.
- **Definition of Done:** parity test green; `/docs` renders; migration table complete for FortiGate + WLC; harness reusable.
- **Dependencies:** 2.2, 2.3, 2.4 (snapshot taken before 2.2/2.3 land). **Effort:** S. **Risk:** none. **Executor:** Standard agent.

**Phase 2 exit gate:** FortiGate + WLC served from routers with contract parity; auth/audit/rate-limit/blacklist enforced; multi-group scope correct with harness in place; `app_server.py` endpoint count measurably lower; `lifespan` in place; both artifacts build.

---

### PHASE 3 — Flow/Event Ingestion (Hard, New Capability)

**Rationale:** Ingest IPFIX/sFlow/syslog **safely** — loop-safe, tenant-attributed, backpressured, self-observable. Hard-blocked on Phase 0 (TLS/cookie) and Phase 1 (async DB).

---

#### 3.1 — Async UDP server factory + bounded ingest queue
- **Files:** `observability/ingesters/udp_server.py`
- **Agent brief:** Implement an asyncio UDP protocol factory. `datagram_received` must be **non-blocking and cheap**: capture `(data, addr, recv_ts)` and `put_nowait` onto the **bounded ingest queue**; on queue-full, drop and increment the `dropped_queue_full` metric. **Never** spawn a task per packet; **never** touch the DB or parse deeply in the handler. Parsing happens in consumer tasks fed from the queue. Provide a factory binding a given parser (IPFIX/sFlow/syslog) to a given port. Malformed/oversized datagrams must never crash the protocol (catch, count `parse_errors`, continue). Graceful stop on shutdown (transport close, consumer drain). Interface sketch:
    ```
    # udp_server.py — interface sketch
    async def start_udp_listener(host, port, parser: Parser, queue: IngestQueue) -> ListenerHandle
    # datagram_received: queue.put_nowait(RawDatagram(data, addr, recv_ts)) or drop + metric
    ```
- **Definition of Done:** listener binds and receives; malformed packet doesn't crash (fuzz-ish test with garbage payloads); queue-full drops with metric; no per-packet task; **p99 loop latency < 5 ms under 5k pps burst** (load test); clean shutdown.
- **Dependencies:** 1.2. **Effort:** M. **Risk:** loop starvation / memory growth. **Mitigation:** bounded queue + drop-metric; load-test gate.
- **Executor:** **Frontier (Fable 5)** — event-loop safety is the whole point; the guide's version stalls the loop.

---

#### 3.2 — Dedicated writer worker with batched commits
- **Files:** `observability/ingesters/writer.py`
- **Agent brief:** Consume decoded, tenant-attributed records and perform **batched** DB writes via the single WAL writer (1.2): accumulate up to N records **or** T milliseconds (both configurable; defaults N=500, T=250 ms), then commit once — UPSERT (1.4) for flows, plain inserts for syslog. Runs off the event loop's critical path. Crash-safety: shutdown flushes current batch; commit failure → retry-with-backoff (bounded), then drop batch + metric + rate-limited Italian WARN. Record `commit_latency` and `batch_size` metrics per commit (for 3.8). Accept and document bounded loss on hard crash (≤ one batch window).
- **Definition of Done:** batching verified (one commit per batch, not per record); UPSERT semantics preserved within a batch; shutdown flushes; sustained-load test shows bounded memory; commit-failure fault injection follows the retry→drop path without killing the worker.
- **Dependencies:** 3.1, 1.4. **Effort:** M. **Risk:** batch loss on crash. **Mitigation:** small batch window; documented at-most-one-batch loss; WAL recovery.
- **Executor:** **Frontier (Fable 5)** — correctness under load + crash-safety.

---

#### 3.3 — Real IPFIX/NetFlow decoder (template handling)
- **Files:** `observability/ingesters/ipfix.py`
- **Agent brief:** Replace any mock with a real IPFIX (RFC 7011) + NetFlow v9 decoder with **template management**: cache templates per `(exporter, observation domain, template id)` with bounded cache size and expiry; buffer data records arriving before their template (bounded buffer, drop + `data_before_template_dropped` metric on overflow); decode common IEs (src/dst address v4/v6, ports, protocol, octet/packet deltas, flow start/end). NetFlow v5 as a fixed-format fast path. Unknown IEs skipped gracefully; endianness and variable-length fields handled per RFC. Emit normalized records `(src_ip, dst_ip, protocol, dst_port, bytes, packets, flow_start, flow_end, exporter_ip)` to the attribution stage (3.5) then writer (3.2). Fixtures: synthetic captures for FortiGate + at least one additional vendor per Decision #6 (create with a scapy-style generator if real captures unavailable; fixture generator lives in `tests/`).
- **Definition of Done:** IPFIX + NetFlow v9 + v5 golden fixtures decode to expected normalized records; data-before-template buffered then resolved on template arrival (test); template re-announce replaces cleanly; unknown IEs, truncated packets, and garbage don't crash; caches bounded (test asserts eviction).
- **Dependencies:** 3.1. **Effort:** L. **Risk:** template state + vendor quirks. **Mitigation:** fixture-driven incremental IE support; bounded caches; fuzz inputs.
- **Executor:** **Frontier (Fable 5)** — genuinely hard protocol/state work.

---

#### 3.4 — sFlow + syslog parsers (severity/action normalization)
- **Files:** `observability/ingesters/sflow.py`, `observability/ingesters/syslog.py`
- **Agent brief:** Two sub-deliverables:
  - **sFlow v5 decoder:** flow samples → normalized flow records; **bytes/packets must be scaled by the sampling rate** carried in the sample header (binding; document the estimation semantics in the module docstring). Counter samples: parked unless Decision #5 says otherwise (parse header, skip body, count `counter_samples_skipped`).
  - **Syslog parser:** normalize RFC 3164 and RFC 5424 into `(ts, device_ip, severity, action, message)`: PRI parsing, timezone handling (normalize to UTC epoch), multi-line tolerance. Vendor normalization for FortiGate (key=value body: extract `action`, `level`, UTM/threat fields) and Palo Alto (CSV THREAT/TRAFFIC formats: extract action, severity). Unknown formats stored with `action=NULL`, raw message preserved (truncated to a configured max length — log minimization, see 6.7).
- **Definition of Done:** sFlow fixture decodes with sampling-rate scaling applied (golden test asserting scaled values); syslog fixtures (FortiGate + Palo Alto + generic 3164/5424) normalize action/severity/UTC timestamps correctly; garbage input doesn't crash either parser.
- **Dependencies:** 3.1. **Effort:** M. **Risk:** format variance. **Mitigation:** per-vendor fixtures; small stable normalized schema.
- **Executor:** **Frontier (Fable 5)** for the sFlow decoder (sampling-scaling correctness); the **syslog parser may be delegated to a standard agent** under frontier review — fixtures and normalized schema are fully specified.

---

#### 3.5 — Exporter-IP → device → tenant mapping at ingest
- **Files:** `observability/ingesters/*`, `inventory_manager.py`
- **Agent brief:** **Kill the hard-coded `tenant="default"`.** At ingest (post-parse, pre-write), resolve `exporter_ip` (datagram source) → device → group/tenant via a new `get_device_by_ip(ip) -> DeviceRef | None` in `inventory_manager.py` — cached, invalidated on inventory change (hook the existing inventory write path). Unknown exporters: **drop the records**, upsert `quarantined_exporters` (first/last seen, packet count), emit **one rate-limited audit entry per exporter per hour** (not per packet), increment `dropped_unknown_exporter`. Multiple devices sharing an IP: attribute to none, audit anomaly. NAT'd exporters: documented limitation in `docs/HARDENING.md` (remote sites use the 6.3 relay instead). **No record may ever be written with tenant `default`** — enforce with a standing test scanning the DB after ingest fixtures run.
    ```
    # inventory_manager.py — interface sketch
    def get_device_by_ip(ip: str) -> Optional[DeviceRef]   # (hostname, tenant/group); cached
    ```
- **Definition of Done:** flow/syslog from known exporter lands with correct tenant; unknown exporter → dropped + quarantined + audited (rate-limited); no `default` tenant in DB (scan test); cache invalidation on inventory change (test); IP-collision audited.
- **Dependencies:** 3.2. **Effort:** M. **Risk:** misattribution/leakage. **Mitigation:** fail-closed on unknown; audit; cache-invalidation test.
- **Executor:** **Frontier (Fable 5)** — tenant attribution is the security boundary for all downstream RBAC.

---

#### 3.6 — Listener config: high-port defaults, loopback bind, env-gated
- **Files:** `app_server.py` (lifespan), `data_config.py`
- **Agent brief:** Add listener configuration: defaults **IPFIX 4739 / sFlow 6343 / syslog 5514** (never 514 in-process); default bind **`127.0.0.1`**; `0.0.0.0` only via explicit env opt-in; master enable flag plus per-listener enable. **Desktop/exe default = all listeners OFF; Docker default = OFF unless `SENTINELNET_OBS_ENABLE=1`.** Listeners are started/stopped inside `lifespan` only when enabled; disabled listeners must not open sockets. Bind failure (port in use, permission) → Italian ERROR log, that listener skipped, app stays up, `listener_bind_failed` metric set. Startup logs (Italian) state which listeners are active, on which bind/port. Env shape:
    ```
    SENTINELNET_OBS_ENABLE=0|1
    SENTINELNET_OBS_BIND=127.0.0.1|0.0.0.0
    SENTINELNET_OBS_IPFIX_PORT=4739   SENTINELNET_OBS_IPFIX_ENABLE=0|1
    SENTINELNET_OBS_SFLOW_PORT=6343   SENTINELNET_OBS_SFLOW_ENABLE=0|1
    SENTINELNET_OBS_SYSLOG_PORT=5514  SENTINELNET_OBS_SYSLOG_ENABLE=0|1
    ```
- **Definition of Done:** default exe run opens **no** UDP sockets (asserted via socket enumeration in test); env-enabled binds high ports on loopback; `0.0.0.0` requires explicit opt-in; bind failure degrades gracefully; startup logs correct.
- **Dependencies:** 2.4, 3.1. **Effort:** S. **Risk:** attack surface / privileged port. **Mitigation:** high ports + loopback + env gate; 514 only via Docker mapping (6.1).
- **Executor:** Standard agent.

---

#### 3.7 — Retention/pruning job (+ optional coarser rollup)
- **Files:** `observability/rollup.py`
- **Agent brief:** Async periodic task (started in `lifespan`) enforcing retention: prune rows **strictly older** than `now - retention` per table, with **per-table windows** (defaults pending Decision #4: `flow_aggregates` 30d, `syslog_events` 7d, `correlated_events` 90d — resolved events only; `new`/`ack` events are never auto-pruned). Retention enforcement is a **GDPR technical measure** (see 6.7) — it must be reliable, logged (Italian, summary counts), and covered by tests. Large deletes batched (bounded rows per transaction, executed via the writer path) to avoid long locks; job overlap prevented (skip if previous run active). Optional hourly rollup from minute buckets: parked unless Decision #4 requests it. Env: `SENTINELNET_OBS_RETENTION_FLOWS_DAYS`, `_SYSLOG_DAYS`, `_EVENTS_DAYS`.
- **Definition of Done:** rows older than window pruned; rows inside window untouched (strict `<` boundary test); unresolved correlated events survive pruning; job never overlaps itself; large prune batched (test with seeded large table); prune summary logged.
- **Dependencies:** 3.2, 1.4, 2.4. **Effort:** M. **Risk:** retention wiping live data. **Mitigation:** strict boundary tests; batched deletes; per-table config.
- **Executor:** Standard agent.

---

#### 3.8 — Pipeline self-observability: metrics + health endpoint
- **Files:** `observability/metrics.py`, `routers/observability.py` (health route), `app_server.py`
- **Agent brief:** The ingest pipeline must be observable itself. Implement an in-process metrics registry (simple counters/gauges; Prometheus export deferred to Decision #14) covering at minimum: `datagrams_received` (per listener), `parse_errors`, `dropped_queue_full`, `dropped_unknown_exporter`, `clock_skew_fallback`, `queue_depth` (gauge), `batch_size` / `commit_latency_ms` (last/rolling), `template_cache_size`, `writer_restarts`, `listener_bind_failed`, `db_size_bytes`, `last_prune_ts`. Expose via `GET /api/observability/health` — **admin-only**, returns listener status + metrics snapshot + DB size + schema version. Rate-limited Italian WARN when drop counters grow (avoid log flooding). This endpoint is the primary operational diagnostic for the whole capability.
- **Definition of Done:** health endpoint returns all metrics, admin-gated (viewer/operator denied — RBAC test); drop counters visibly increment in queue-full and unknown-exporter test scenarios; DB size and schema version reported; no per-packet logging.
- **Dependencies:** 3.1, 3.2, 3.5, 2.1. **Effort:** S/M. **Risk:** none significant. **Executor:** Standard agent.

**Phase 3 exit gate:** synthetic IPFIX/sFlow/syslog → correct rows + correct tenant; **5k pps sustained with p99 loop latency < 5 ms** (terminal WS + API responsive throughout); unknown exporter dropped/quarantined + audited; retention prunes correctly; health endpoint live; exe default = listeners off.

---

### PHASE 4 — Observability API + Correlation Engine

**Rationale:** Serve scoped queries and actually populate `correlated_events`.

---

#### 4.1 — `routers/observability.py`: `/top` + `/anomalies` (multi-tenant scoped)
- **Files:** `routers/observability.py`
- **Agent brief:** Implement read-only endpoints: `GET /api/observability/top?window=15m&limit=50&metric=bytes|packets` (top talkers over a window) and `GET /api/observability/anomalies?status=new&window=24h` (from `correlated_events`). **All queries filter `WHERE tenant IN (:scoped_groups)`** via the 2.1/2.5 dependency; empty scope → empty result (never unfiltered). Fully parameterized (no string interpolation — the dynamic `IN` list is built from bound placeholders). Enforce max window and max limit; paginate anomalies. Reads via the async DB layer (1.2). Validate the endpoints against the 2.5 RBAC harness.
- **Definition of Done:** multi-group RBAC harness green (in-scope only; out-of-scope never returned; empty scope → empty); injection test (hostile params rejected/bound); large-window request capped; reads don't block loop; latency **< 500 ms** on a 1M-row seeded DB.
- **Dependencies:** 2.5, 3.7. **Effort:** M. **Risk:** SQL perf; scope regression. **Mitigation:** indexes (4.3); pagination; RBAC harness reuse.
- **Executor:** **Frontier (Fable 5)** — this is the exact query surface where the guide's scope defect (D2) lives; the harness reduces risk but the query construction (dynamic `IN` binding) must be done correctly once, then reused everywhere.

---

#### 4.2 — Correlation/stitching engine → `correlated_events`
- **Files:** `observability/correlator.py`
- **Agent brief:** Implement the engine the guide left orphaned. As an async periodic task (in `lifespan`), per tenant and bounded time window: match syslog security events (FortiGate/Palo Alto `deny`/`blocked`/threat actions) × flow aggregates (same src/dst/port within a configurable delta, default ±120 s — Decision #9) × MAC history (`src_ip` → MAC → switch/port via `mac_history`/`mac_locate`, reusing `_mac_topology_uplinks` to skip uplinks). Emit `correlated_events` with `kind`, `severity`, `switch_port` (nullable), `evidence_json` (provenance: contributing syslog id(s), flow tuple, MAC lookup), and a deterministic `dedup_key` (hash of tenant + kind + evidence identity) so re-runs never duplicate (UNIQUE constraint from 1.3). Require corroborating flow evidence before emitting (precision over recall, per Decision #9 default). Never correlate across tenants. Writes go through the writer path; reads via async layer. Bounded windows + indexed joins for cost control.
- **Definition of Done:** scripted fixture ("malware-blocked syslog + matching flow + known MAC") → **one** correlated event with enriched switch port + full evidence; re-run emits nothing new (dedup test); missing MAC → event with `switch_port=null`; syslog-without-flow → no event (precision test); no cross-tenant correlation (RBAC-style fixture); runtime bounded on seeded large tables.
- **Dependencies:** 3.4, 3.5, 2.4. **Effort:** L. **Risk:** false positives; join cost. **Mitigation:** conservative windows; corroboration requirement; dedup key; indexes; fixture-driven precision tests.
- **Executor:** **Frontier (Fable 5)** — genuinely hard join/correlation logic with correctness + performance stakes.

---

#### 4.3 — Query performance pass
- **Files:** `observability/storage/*`, `routers/observability.py`
- **Agent brief:** Validate indexes against real plans (`EXPLAIN QUERY PLAN`) for `/top`, `/anomalies`, and the correlator's joins on a seeded 1M-row dataset; eliminate full-table scans (leverage `idx_flow_window_tenant`); add covering indexes if needed; record plans and thresholds in `docs/REFACTOR.md`.
- **Definition of Done:** no full-table scan in any hot query (plan assertions in test); `/top` < 500 ms and correlator cycle within its period on the seeded dataset.
- **Dependencies:** 4.1, 4.2. **Effort:** S. **Risk:** none. **Executor:** Standard agent.

---

#### 4.4 — MCP tools + AI redaction hook
- **Files:** `mcp_server.py`, `ai_assistant.py`
- **Agent brief:** Expose `get_top_talkers` and `get_anomalies` as **read-only** MCP tools reusing the 4.1 query logic (do not duplicate SQL), honoring viewer/operator roles and multi-group scope. All LLM-bound output (in-app assistant and MCP) passes the 0.3 `redact` choke point; flow data is **summarized** (top-N, aggregates), never raw dumps. Register both tools in the existing MCP admin allow-list mechanism (admin-selectable, default off pending Decision #7). Respect Decision #7 if it mandates local-provider-only for flow data.
- **Definition of Done:** MCP tools return scoped data per role (RBAC harness); redaction applied on the tool output path (leak-assertion test); tools appear in and honor the allow-list; raw-dump path impossible (output size bounded).
- **Dependencies:** 4.1, 0.3. **Effort:** M. **Risk:** over-exposure to LLM (I-1). **Mitigation:** redaction gate + summarization + allow-list default off.
- **Executor:** **Frontier (Fable 5)** — scope + LLM-exposure sensitivity.

**Phase 4 exit gate:** `/top` + `/anomalies` in-scope only (harness green); correlated events generated, enriched, deduplicated from fixtures; query plans index-backed; MCP tools role-gated + redacted.

---

### PHASE 5 — Frontend "Live Flows" Tab

**Rationale:** Wire the UI into the existing Vis.js + tab system using Phase-0 cookie auth. **Never `sessionStorage`.**

---

#### 5.1 — "Live Flows" tab HTML + table/bars (Italian strings)
- **Files:** `templates/dashboard.html`
- **Agent brief:** Add a "Flussi Live" tab consistent with the existing tab system and styling; render a top-talkers table (src, dst, protocol/port, bytes, packets) with simple bar visualization, window/metric selectors, and Italian labels/tooltips/empty-states ("Nessun flusso nel periodo selezionato", etc.). Respect the existing `get_allowed_tabs` mechanism — the tab must be gated like the others.
- **Definition of Done:** tab appears (gated by allowed-tabs), renders, Italian strings, consistent styling, no console errors.
- **Dependencies:** 4.1. **Effort:** S. **Executor:** Standard agent.

---

#### 5.2 — JS `loadTopTalkers`/auto-refresh using cookie auth
- **Files:** `templates/dashboard.html`
- **Agent brief:** Fetch `/api/observability/top` with `credentials:'include'` — **no `Authorization: Bearer`, no `sessionStorage`, ever.** Auto-refresh interval (default 30 s) **pauses on `document.visibilitychange`** (hidden → pause, visible → immediate refresh + resume) and also pauses when another tab is active. Guard against overlapping fetches (in-flight flag). 401 → redirect to login. Errors → Italian toast, no console spam.
- **Definition of Done:** flows load via cookie; refresh pauses when hidden/inactive; no overlapping fetches; **grep test confirms no `sessionStorage`/Bearer in the flows code path**; 401 redirects.
- **Dependencies:** 0.2, 5.1. **Effort:** S. **Risk:** regressing L-1. **Mitigation:** standing no-sessionStorage grep gate + review checklist.
- **Executor:** Standard agent.

---

#### 5.3 — `highlightInTopology()` against real Vis.js model
- **Files:** `templates/dashboard.html`
- **Agent brief:** Clicking an IP in the flows table switches to the topology tab and focuses/highlights the corresponding node in the existing Vis.js `window.network`. Map IP → node using the existing node model (inspect actual node id/label conventions first; record the mapping strategy in a code comment). No matching node → graceful no-op + Italian toast ("Nodo non presente nella topologia"). Multiple matches → focus first, toast noting ambiguity.
- **Definition of Done:** known IP focuses correct node; unknown IP → graceful message; no exceptions; works after topology re-render.
- **Dependencies:** 5.1. **Effort:** S. **Risk:** node id/label mapping. **Mitigation:** reuse existing node model; fallback no-op.
- **Executor:** Standard agent.

---

#### 5.4 — `analyzeFlow()` → AI tab through redaction
- **Files:** `templates/dashboard.html`, `ai_assistant.py`
- **Agent brief:** "Analizza" button sends the flow context to the AI assistant via a **server-side** path that applies 0.3 redaction and summarization — the browser never assembles raw context for the LLM. Large contexts summarized server-side. UI displays a persistent Italian note that data is sent to the configured AI provider (with provider name), and the button is disabled entirely if Decision #7 mandates local-only and no local provider is configured.
- **Definition of Done:** button triggers analysis on redacted, summarized context; leak-assertion test on the outbound payload; Italian provider note visible; Decision #7 gating honored.
- **Dependencies:** 0.3, 4.4. **Effort:** S. **Risk:** third-party LLM leakage. **Mitigation:** server-side redaction choke point; summarization; provider disclosure.
- **Executor:** Standard agent.

---

#### 5.5 — Anomalies panel bound to `/anomalies` with ack/resolve
- **Files:** `templates/dashboard.html`, `routers/observability.py`
- **Agent brief:** Panel listing correlated anomalies with **ack/resolve** actions transitioning `correlated_events.status` via a scoped, **audited**, CSRF-protected POST endpoint (`POST /api/observability/anomalies/{id}/status`). Allowed transitions only (`new→ack`, `new→resolved`, `ack→resolved`); invalid transition → 409 with Italian message. Operator role required; out-of-scope event → 404 (not 403 — don't confirm existence). Optimistic-concurrency: reject stale transitions gracefully. Italian UI strings.
- **Definition of Done:** panel lists in-scope anomalies; transitions persist + audit entries emitted; operator-gated; out-of-scope denied via harness; invalid transition rejected; CSRF enforced.
- **Dependencies:** 4.1, 4.2, 0.2. **Effort:** M. **Risk:** state transitions. **Mitigation:** explicit transition validation + audit + harness.
- **Executor:** Standard agent.

**Phase 5 exit gate:** tab loads scoped flows via cookie; refresh pauses when hidden; IP click focuses node; AI uses redacted server-side context; anomalies ack/resolve work + audited; **no token in `sessionStorage`** (grep-audited).

---

### PHASE 6 — Deployment, Multi-site, Data Protection & Test Hardening

---

#### 6.1 — Docker UDP ports + documented risk
- **Files:** `docker-compose.yml`, `docs/HARDENING.md`
- **Agent brief:** Add (commented-by-default) UDP mappings for `4739/udp`, `6343/udp`, `5514/udp`; document the optional privileged `514:5514/udp` mapping (per Decision #11 support level). Listeners remain env-gated (3.6). Extend `docs/HARDENING.md`: UDP spoofing residual risk (D8), firewall guidance (source-restrict to exporter subnets), and the recommendation to prefer the site-agent relay (6.3) where possible.
- **Definition of Done:** compose mappings present (commented, with Italian-commented instructions); hardening doc covers risk, 514 mapping, and firewall guidance.
- **Dependencies:** 3.6. **Effort:** S. **Risk:** attack surface. **Mitigation:** opt-in + docs + loopback default.
- **Executor:** Standard agent.

---

#### 6.2 — PyInstaller bundle: packages + `schema.sql`, listeners off
- **Files:** `*.spec`, `data_config.py`
- **Agent brief:** Ensure `observability/`, `routers/`, and `schema.sql` bundle correctly; verify resource resolution at runtime in the exe (migration must run from bundled `schema.sql`); confirm desktop default = listeners OFF and no UDP sockets open.
- **Definition of Done:** CI exe smoke test: launches, migrates DB from bundled schema, serves UI, zero UDP sockets by default.
- **Dependencies:** 1.1, 1.3, 3.6. **Effort:** M. **Risk:** missing bundled resource. **Mitigation:** CI exe smoke test exercising the DB path.
- **Executor:** Standard agent.

---

#### 6.3 — Site-agent flow relay (Mode B)
- **Files:** `site_agent.py`, `site_manager.py`, `observability/ingesters/*`
- **Agent brief:** Remote (Mode B) sites must **not** send raw UDP over the VPN. The site agent runs local UDP listeners (reusing 3.1/3.3/3.4 components), normalizes and tenant-attributes records **at the agent** (exporter→device mapping from the site's inventory slice; fallback: central attribution by `site_id`→tenant), then forwards **batched normalized records** over the existing authenticated agent channel (`X-Site-Id`/`X-Site-Token`) to a new central endpoint `POST /api/agent/push_flows` (analogous to `agent_push_mac`/`agent_push_inventory`). Central endpoint: validates agent auth, validates the site is authorized for the claimed tenant(s) (**an agent may never inject records for another site's tenants** — enforce and test), applies batch-level dedup (batch sequence id per agent; replayed batch ids rejected + audited), then feeds the standard writer path. Unauthenticated/invalid push → 401 + audit. Agent-side: bounded local buffer with drop-oldest on backpressure + metric; batch size/interval configurable.
- **Definition of Done:** remote-site fixture flows arrive centrally via authenticated push with correct tenant; **no raw UDP over VPN**; unauthenticated push rejected + audited; cross-tenant injection attempt rejected + audited (test); replayed batch rejected; agent buffer bounded under central outage (test).
- **Dependencies:** 3.5, 3.3, 3.4. **Effort:** L. **Risk:** multi-site auth boundary + tenant attribution. **Mitigation:** reuse existing agent auth; sequence-id dedup; explicit tenant-authorization check; audit.
- **Executor:** **Frontier (Fable 5)** — spans auth boundary + tenant attribution + ingestion; security-sensitive.

---

#### 6.4 — Multi-site hardening (queue observability, retries, token rotation)
- **Files:** `site_manager.py`, `site_agent.py`
- **Agent brief:** Address the open multi-site debt: expose job-queue observability (pending/claimed/completed counts, stuck-job detection with reclaim) via an admin endpoint; retry-with-backoff (capped) for failed jobs; **agent token rotation** (issue/rotate/revoke `X-Site-Token`) with an **overlap window** during which both old and new tokens validate, so in-flight jobs and pushes are not dropped; revoked tokens rejected + audited.
- **Definition of Done:** queue metrics exposed (admin-gated); failed jobs retried with capped backoff; rotation works without breaking an active agent (test simulating in-flight job across rotation); revoked token rejected + audited; stuck job reclaimed.
- **Dependencies:** 6.3. **Effort:** M. **Risk:** in-flight disruption. **Mitigation:** overlap window; backoff caps.
- **Executor:** Standard agent, with **frontier review on the token-rotation design** (security-sensitive).

---

#### 6.5 — Test coverage: ingesters, routers, obs API, correlator, RBAC, load/soak
- **Files:** `tests/test_observability_*`, `tests/test_router_parity.py`, `tests/test_rbac_scope.py`
- **Agent brief:** Consolidate coverage for all new modules: parser golden fixtures (IPFIX/NetFlow/sFlow/syslog), router parity, obs API scoping (harness applied to every observability route), correlator precision/dedup, tenant attribution, agent relay auth, and the standing security tests (Section 5). Load/soak: sustained 5k pps generator + **24h soak** asserting no loop stalls (latency probe), bounded memory, bounded DB growth (retention active) — run in a **nightly/scheduled lane**, not the per-PR CI lane.
- **Definition of Done:** every new module has tests; RBAC harness applied across all observability surfaces; soak result documented (memory/latency/DB-size graphs or summaries in the run artifact); fast CI lane stays fast.
- **Dependencies:** all prior. **Effort:** M. **Risk:** flaky load tests. **Mitigation:** deterministic fixtures; soak separated from fast CI.
- **Executor:** Standard agent (correlator/RBAC/relay test authoring pairs with the frontier implementers).

---

#### 6.6 — Complete remaining router extraction (mac, ai, sites, backup)
- **Files:** `routers/mac.py`, `routers/ai.py`, `routers/sites.py`, `routers/backup.py`, `app_server.py`
- **Agent brief:** Apply the proven Phase-2 pattern to remaining domains — **one domain per PR**, each with the 2.6 parity harness and the 2.5 scope audit. End state: `app_server.py` reduced to app assembly + `lifespan` + any residual glue (target ≤10 routes).
- **Definition of Done:** each domain's routes served from its router with parity test green; monolith reduced to assembly; scope correct throughout (harness per domain).
- **Dependencies:** 2.1–2.6. **Effort:** M. **Risk:** incremental parity. **Mitigation:** reuse parity harness per domain.
- **Executor:** Standard agent; **frontier for `routers/sites.py`** (agent auth boundary) and frontier review for `routers/ai.py` (LLM exposure).

---

#### 6.7 — Data-protection (GDPR) compliance pack
- **Files:** `docs/PRIVACY.md`, `routers/observability.py` (purge endpoint), `observability/rollup.py`, logging paths
- **Agent brief:** SentinelNet ingests IP-level traffic metadata and syslog messages — **personal data under GDPR** in EU deployments. Deliver: (a) `docs/PRIVACY.md` (Italian) documenting what is collected (flow tuples, syslog, MAC history correlation), purposes, retention defaults and how to configure them, the operator's controller responsibilities, and the AI-provider processor implication (data leaves premises when a third-party LLM is configured — cross-reference Decision #7); (b) **per-tenant purge**: admin-only, audited action deleting all observability data for a given tenant (`flow_aggregates`, `syslog_events`, `correlated_events`), executed batched via the writer path; (c) **log minimization audit**: verify no code path logs full flow/syslog payloads (rate-limited summaries only; raw message truncation from 3.4 confirmed); (d) statement that retention (3.7) is the standing technical measure. No DPIA is authored here (operator responsibility), but `PRIVACY.md` gives operators the inputs they need for one.
- **Definition of Done:** `docs/PRIVACY.md` shipped (Italian) and linked from README + release notes; per-tenant purge works, is admin-gated, audited, and leaves other tenants intact (test); log-minimization grep/audit clean; retention cross-referenced.
- **Dependencies:** 3.7, 4.1. **Effort:** M. **Risk:** legal-adjacent scope creep. **Mitigation:** scoped to technical measures + documentation; legal review is Owner's (Decision #13).
- **Executor:** Standard agent.

**Phase 6 exit gate:** Docker exposes UDP with documented risk; exe listeners off by default with bundled schema; remote-site flows via authenticated agent (cross-tenant injection impossible); token rotation clean; full coverage incl. multi-group RBAC; 24h soak clean; monolith reduced to assembly; GDPR pack shipped.

---

## 4. Design Corrections to the Original Guide (Mandatory Decisions)

Each of the nine defects from the gap analysis is resolved here as a binding decision. Executors implement the **Resolution**, never the guide's original.

| # | Defect (guide) | Mandatory resolution | Enforced by |
|---|---|---|---|
| **D1** | Blocking `sqlite3`/`commit()` in async handlers; unbounded `create_task` per packet | **Bounded ingest queue → dedicated supervised writer worker → batched commits.** `datagram_received` only enqueues; no DB call or task-spawn per packet. WAL, single writer, single process (§2.6). | §2.4; items 1.2, 3.1, 3.2; CI grep gate; loop-latency load test (p99 < 5 ms @ 5k pps) |
| **D2** | RBAC scalar `user.group` (`WHERE tenant = user.group`) | **Multi-group scope everywhere:** `scoped_groups(user)` set; `WHERE tenant IN (:scoped_groups)` with bound placeholders; empty scope → empty result; `assert_group_allowed`/`assert_device_allowed`. Scalar `user.group` **forbidden** (standing grep test). | §2.5; items 2.1, 2.5, 4.1; RBAC harness reused in 4.4, 5.5, 6.3, 6.6 |
| **D3** | `flow_aggregates` never aggregates (plain INSERT vs UNIQUE) | **Write-time UPSERT** on `UNIQUE(window_start, tenant, 5-tuple)`; timestamp truncated to 60 s; counters summed; binding time-source rule (exporter flow-end within ±300 s of receipt, else receipt time). | Item 1.4; bucketing + skew tests |
| **D4** | Hard-coded `tenant="default"` at ingest | **Exporter-IP → device → tenant resolution** via cached `get_device_by_ip`; unknown exporters dropped + quarantined (`quarantined_exporters`) + rate-limited audit. **No record ever written with tenant `default`.** | Item 3.5; "no default tenant" DB-scan test; item 3.8 drop metrics |
| **D5** | Syslog on privileged port 514 | **Default high port 5514, loopback bind, env-gated, off on exe.** Privileged 514 only via optional Docker port mapping; never bound in-process. Bind failure degrades gracefully. | Items 3.6, 6.1 |
| **D6** | `sentinelnet.` package imports vs flat codebase | **Keep flat layout (recommended baseline); rewrite all guide imports to flat.** (If Decision #1 selects the package migration, execute fully under 1.1.) | Item 1.1; import-consistency check; CI smoke tests in all three run modes |
| **D7** | English code in Italian codebase | **Italian user-facing strings/logs/audit; English identifiers.** Codified in `CONTRIBUTING.md`; review gate. | §2.1; item 1.5 |
| **D8** | Unauthenticated, spoofable UDP ingest | **Loopback default + explicit `0.0.0.0` opt-in; exporter allow-list via inventory (unknown dropped/quarantined); remote sites use authenticated agent relay (no raw UDP over VPN); drop metrics visible in health endpoint.** TLS/cookie land first (Phase 0). Residual spoofing risk documented in `docs/HARDENING.md` with firewall guidance. | Items 3.5, 3.6, 3.8, 6.1, 6.3; Phase-0 hard gate |
| **D9** | `correlated_events` orphaned (nothing populates it) | **Correlation engine** (`observability/correlator.py`): periodic, per-tenant, bounded-window stitching of flow × syslog × MAC-history → enriched, **deduplicated** (`dedup_key` UNIQUE) `correlated_events`; precision-first (corroborating flow required). | Item 4.2; precision + dedup fixture tests |

**Additional binding decisions:**
- **JWT storage (L-1):** cookie-based (`HttpOnly`/`Secure`/`SameSite`); the guide's `sessionStorage.getItem('jwt_token')` is **prohibited** (item 0.2; standing grep gate; guarded again in 5.2). Bearer remains for programmatic clients (dual-accept).
- **TLS ordering (H-1):** no new cleartext ingress before Phase 0; native TLS optional + reverse-proxy guide mandatory (item 0.1).
- **AI exposure (I-1):** all LLM-bound context (config + flows + MCP tool output) passes the single `redact` choke point, with server-side summarization for flows (items 0.3, 4.4, 5.4); provider disclosure in UI.
- **Provisioner secrets (I-2):** placeholder-by-default, push-time in-memory materialization, audited exceptions (item 0.4).
- **GDPR:** retention (3.7) + per-tenant purge + `PRIVACY.md` + log minimization are release-blocking for observability GA (item 6.7).

---

## 5. Testing & Verification Strategy per Phase

**Global harness:** `pytest` (extend existing suite); FastAPI `TestClient` (lifespan-aware); fixture-driven parsers with a synthetic packet generator in `tests/`; loop-latency probe utility; load/soak harness in a **nightly lane** separate from fast per-PR CI.

**Every PR gate:** existing suite green + PyInstaller exe build + launch smoke + Docker build + the standing grep gates below.

**Standing security/correctness gates (run on every PR from the phase they land):**
1. No secret substring in LLM-bound output (redaction leak-assertion) — from Phase 0.
2. No token in `sessionStorage` / no browser Bearer in new code — from Phase 0.
3. No sync DB call (`sqlite3.connect`/`.commit()`/`get_observability_connection(`) inside `async def` bodies — from Phase 1.
4. No scalar `user.group` in `routers/` or `observability/` — from Phase 2.
5. No record with tenant `default` after ingest fixtures — from Phase 3.
6. No full flow/syslog payload logging (log-minimization grep) — from Phase 3.

| Phase | Key verifications |
|---|---|
| **0** | TLS on/off/half-config behavior (fail closed); cookie auth incl. WS terminal; Bearer still works; CSRF enforced on state-changing methods; redaction leak-assertion + idempotency; provisioner no-cleartext scan + no-log test; audit/lockout parity. |
| **1** | exe+Docker+source all run post-packaging; migration idempotent; **newer-schema refusal** (downgrade safety); async-writer load test (p99 loop latency < 5 ms); disk-full fault injection (drop, survive); UPSERT bucketing + clock-skew fallback; multi-worker fail-closed guard. |
| **2** | OpenAPI parity snapshot (FortiGate + WLC); auth/audit/rate-limit/blacklist behavior parity; multi-group RBAC harness (in-scope / out-of-scope / empty-scope); `lifespan` startup ordering + TestClient; endpoint-count reduction metric recorded. |
| **3** | Golden fixtures: IPFIX/NetFlow v9/v5 (templates, data-before-template, re-announce), sFlow (sampling-rate scaling asserted), syslog (FortiGate/Palo Alto/generic, UTC normalization) → expected normalized rows; garbage/fuzz inputs don't crash; tenant attribution correct + cache invalidation; unknown exporter dropped/quarantined + rate-limited audit; **5k pps sustained, p99 < 5 ms, WS/API responsive**; retention strict-boundary + unresolved-events survival; health endpoint metrics move under fault scenarios; zero UDP sockets in default exe. |
| **4** | `/top` + `/anomalies` scoped via harness; dynamic `IN` binding injection-safe; `EXPLAIN QUERY PLAN` index-backed on 1M rows, `/top` < 500 ms; correlation precision (blocked+flow+MAC → 1 enriched event), dedup on re-run, no cross-tenant, syslog-without-flow → nothing; MCP tools role-gated + redacted + allow-listed + size-bounded. |
| **5** | Tab renders (Italian, allowed-tabs gated); flows via cookie; no sessionStorage/Bearer (grep); refresh pauses when hidden, no overlapping fetches; topology highlight known/unknown IP; `analyzeFlow` server-side redacted payload; anomaly transitions validated + audited + CSRF'd + out-of-scope → 404. |
| **6** | Docker UDP mappings documented; exe bundled-schema smoke; relay: authenticated push, unauth rejected+audited, **cross-tenant injection rejected**, replay rejected, agent buffer bounded; token rotation with overlap; per-tenant purge isolation test; **24h soak**: no loop stall, bounded memory, bounded DB size (retention active); coverage report across all new modules. |

---

## 6. Rollout / Release Plan

### 6.1 Versioning
- **SemVer**, phase-aligned minor releases:
  - `v1.1.0` — Phase 0 (security baseline).
  - `v1.2.0` — Phase 1 (packaging + storage foundation).
  - `v1.3.0` — Phase 2 (router refactor; no user-visible feature change).
  - `v1.4.0` — Phase 3 (ingestion; listeners off by default — feature-flagged).
  - `v1.5.0` — Phase 4 (obs API + correlation; still flagged).
  - `v1.6.0` — Phase 5 (Live Flows UI; still flagged).
  - `v1.7.0` — Phase 6 (multi-site relay, hardening, GDPR pack, coverage) — **observability GA**.
- Observability remains **feature-flagged off by default** through `v1.6.x`. GA at `v1.7.0` requires: soak-test pass, multi-site relay shipped, and the GDPR pack (6.7) — all three are release blockers.

### 6.2 Migration of existing installs (upgrade path)
- **State migration:** JSON/CSV stores (`network_hosts.csv`, `users.json`, `groups.json`, `detected_versions.json`) remain authoritative and untouched through this program; **`observability.db` is purely additive**, created on first `v1.2.0+` start via idempotent migration under `SENTINELNET_DATA_DIR`.
- **Auth migration (`v1.1.0`):** on upgrade, existing browser sessions are invalidated; users re-login and receive the cookie. Release notes flag this (Italian). API clients using Bearer are unaffected (dual-accept; deprecation timeline per Decision #3).
- **Schema upgrades:** forward-only versioned migrations run automatically at startup. **Downgrade safety:** older code encountering a newer `schema_version` disables observability with a clear Italian error and keeps the management app running (1.3 version guard).
- **Docker:** `docker compose pull && up -d`; volume `./data:/app/data` preserved; UDP mappings appear (commented) in `v1.4.0+` compose; listeners stay off until `SENTINELNET_OBS_ENABLE=1`.
- **exe:** in-place replacement; DB migration on launch; listeners off by default — zero behavior change for desktop users until opted in.
- **Multi-site agents (`v1.7.0`):** roll central first, then agents (central endpoint tolerates old agents that simply don't push flows); token rotation uses the overlap window so in-flight jobs survive.

### 6.3 Rollback
- **Every phase is independently rollback-able.**
- **Additive DB:** rolling back to a pre-observability version ignores `observability.db`; no schema coupling to core JSON/CSV. Release notes document a "backup `observability.db` before upgrade" recommendation.
- **Router refactor (Phase 2 / 6.6):** routers are per-domain, independently revertible PRs; OpenAPI parity guarantees a clean revert.
- **Auth cookie (Phase 0):** revert re-enables the old path; Bearer never broke, so API clients are unaffected; browser users re-login.
- **Ingestion (Phase 3+):** primary rollback is the **kill switch** (`SENTINELNET_OBS_ENABLE=0`) — no downgrade needed; code rollback is secondary. Health endpoint (3.8) is the diagnostic for deciding.
- **Corruption safeguard:** WAL + graceful writer drain; documented recovery: "delete `observability.db` to reset observability" (core data unaffected); per-tenant purge (6.7) for surgical resets.

---

## 7. Open Decisions Requiring the Human Owner

Defaults in **bold** apply if no decision is recorded before the blocking item starts.

1. **Package layout** (blocks 1.1): **keep flat** (rewrite guide imports; minimal churn) vs. migrate to `sentinelnet/` package.
2. **CSRF mechanism** (blocks 0.2): **`SameSite=Strict` + custom-header check** vs. double-submit token. Affects cross-origin usage and reverse-proxy setup.
3. **Bearer deprecation timeline** (0.2): duration of dual-accept before browser-Bearer removal. **Default: dual-accept through `v1.7.x`.**
4. **Retention windows** (3.7, 6.7): **flows 30d / raw syslog 7d / correlated events 90d (resolved only)**. GDPR + forensics + storage trade-off. Also: enable hourly rollup? **Default: no.**
5. **sFlow counter samples** (3.4): ingest now or **park** (parse-skip + metric).
6. **Vendor fixture priority** (3.3/3.4): **FortiGate + Palo Alto first**; order for Cisco, Juniper, Aruba next.
7. **AI/LLM exposure policy (I-1)** (0.3, 4.4, 5.4, 6.7): is redaction+summarization sufficient for third-party providers, or is flow/config data **local-provider-only** (Ollama)? **Default: redaction sufficient, provider disclosed in UI, MCP obs tools default-off in allow-list.**
8. **UDP `0.0.0.0` exposure policy (D8)** (3.6): allow opt-in direct UDP at central, or **mandate the agent relay even for central-site devices**? **Default: opt-in allowed with documented firewall guidance.**
9. **Correlation sensitivity** (4.2): time-delta window (**default ±120 s**) and FP/FN posture (**default precision-first: corroborating flow required**). Drives anomaly-panel volume.
10. **Native TLS support level** (0.1): first-class supported path vs. **documentation-first, reverse proxy strongly recommended**. Affects cert-lifecycle support burden.
11. **Privileged syslog 514** (6.1): officially support the Docker `514:5514/udp` mapping, or **document-only**.
12. **DB concurrency model** (1.2, §2.6): confirm **single Uvicorn worker** (enforced fail-closed), or require `--workers > 1` support (would force a redesign of the single in-process writer — significant scope change; decide before Phase 3).
13. **GDPR ownership** (6.7): confirm the split — **SentinelNet ships technical measures + `PRIVACY.md`; DPIA and controller obligations are the operator's**; owner arranges legal review of `PRIVACY.md`.
14. **Metrics exposure format** (3.8): internal JSON health endpoint only (**default**) vs. Prometheus `/metrics` endpoint (adds scrape-auth considerations).

---

## 8. Appendix — Dependency Matrix & Executor Tiers

| Item | Title | Depends on |
|---|---|---|
| 0.1 | TLS native + proxy guide | — |
| 0.2 | JWT → cookie (+CSRF, WS) | 0.1 |
| 0.3 | AI redaction | — |
| 0.4 | Provisioner secrets | — |
| 1.1 | Package layout + PyInstaller | — |
| 1.2 | Async SQLite layer | 1.1 |
| 1.3 | Obs schema + versioned migration + version guard | 1.2 |
| 1.4 | Aggregation UPSERT + time-source rule | 1.3 |
| 1.5 | Contributor rules doc | — |
| 2.1 | Auth as DI (multi-group) | 0.2 |
| 2.2 | routers/fortigate | 2.1, 1.1 |
| 2.3 | routers/wlc | 2.1 |
| 2.4 | lifespan manager | 2.2, 2.3, 1.2 |
| 2.5 | Multi-group scope fix + RBAC harness | 2.1 |
| 2.6 | OpenAPI parity test (snapshot pre-2.2) | 2.2, 2.3, 2.4 |
| 3.1 | UDP factory + bounded queue | 1.2 |
| 3.2 | Batched writer worker | 3.1, 1.4 |
| 3.3 | IPFIX/NetFlow decoder | 3.1 |
| 3.4 | sFlow + syslog parsers | 3.1 |
| 3.5 | Exporter → tenant mapping + quarantine | 3.2 |
| 3.6 | Listener config + ports | 2.4, 3.1 |
| 3.7 | Retention/pruning job | 3.2, 1.4, 2.4 |
| 3.8 | Pipeline metrics + health endpoint | 3.1, 3.2, 3.5, 2.1 |
| 4.1 | /top + /anomalies scoped | 2.5, 3.7 |
| 4.2 | Correlation engine | 3.4, 3.5, 2.4 |
| 4.3 | Query perf pass | 4.1, 4.2 |
| 4.4 | MCP tools + redaction | 4.1, 0.3 |
| 5.1 | Live Flows tab HTML | 4.1 |
| 5.2 | JS cookie auth + visibility pause | 0.2, 5.1 |
| 5.3 | Topology highlight | 5.1 |
| 5.4 | analyzeFlow → AI (server-side redaction) | 0.3, 4.4 |
| 5.5 | Anomalies panel + ack/resolve | 4.1, 4.2, 0.2 |
| 6.1 | Docker UDP ports + risk docs | 3.6 |
| 6.2 | PyInstaller bundle verification | 1.1, 1.3, 3.6 |
| 6.3 | Site-agent flow relay | 3.5, 3.3, 3.4 |
| 6.4 | Multi-site hardening + token rotation | 6.3 |
| 6.5 | Test coverage + load/soak | all prior |
| 6.6 | Remaining routers | 2.1–2.6 |
| 6.7 | GDPR compliance pack | 3.7, 4.1 |

### Executor-tier summary

| Tier | Items |
|---|---|
| **Frontier (Fable 5)** | 0.2, 1.2, 2.1, 2.5, 3.1, 3.2, 3.3, 3.4 (sFlow portion), 3.5, 4.1, 4.2, 4.4, 6.3 |
| **Standard agent** | 0.1, 0.3, 0.4, 1.1, 1.3, 1.4, 1.5, 2.2, 2.3, 2.4, 2.6, 3.4 (syslog portion, under frontier review), 3.6, 3.7, 3.8, 4.3, 5.1, 5.2, 5.3, 5.4, 5.5, 6.1, 6.2, 6.4 (frontier review on rotation), 6.5, 6.6 (frontier for `routers/sites.py`), 6.7 |

**Frontier justification (summary):** all reserved items are either **event-loop-safety-critical** (1.2, 3.1, 3.2), **hard protocol/state or correlation logic** (3.3, 3.4-sFlow, 4.2), or **security-boundary-sensitive** (0.2 session/CSRF/WS; 2.1/2.5/4.1 multi-group RBAC and the query surface where the guide's scope defect lives; 3.5 tenant attribution; 4.4 LLM exposure; 6.3 authenticated multi-site relay with cross-tenant injection risk). Everything else is well-specified, harness-guarded, and low-blast-radius for a standard agent operating under the cross-cutting rules of Section 2 and the standing gates of Section 5.

---

*End of Master Implementation Plan (Final). Verify freshness against commit `6fcb9039` before execution — in particular the actual startup mechanism (2.4), the live endpoint inventory (2.2/2.3), and the Vis.js node model (5.3). Re-run `graphify update .` after each phase merges.*