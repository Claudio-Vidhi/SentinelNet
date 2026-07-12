# SentinelNet — Master Implementation Plan (Final Draft)

> Principal-engineer master plan consolidating the *State Report* (commit `6fcb9039`), the *Complete Observability & Refactoring Implementation Guide* (v1.0), and the *Gap Analysis & Roadmap*. This document supersedes the original guide. Where the guide and this plan conflict, **this plan wins**.
>
> **Scope note:** This is a planning artifact. It contains **no implementation code**. Interface sketches (signatures, schema DDL, config shapes) appear only to remove ambiguity for downstream executors.

---

## 1. Executive Summary & Objectives

### 1.1 What we are building

SentinelNet today is a self-hosted, multivendor network management platform: configuration backup, firmware/CVE triage against ENISA EUVD, topology mapping, SSH terminal, FortiGate/WLC integrations, multi-site polling, and an AI assistant + MCP server. Storage is flat JSON/CSV, the API is a single monolithic `app_server.py` (~51 heterogeneous endpoints, cohesion 0.04), and there is **no traffic-flow observability at all**.

This program delivers two intertwined outcomes:

1. **Day-2 flow observability (net-new capability):** ingest IPFIX/NetFlow, sFlow, and syslog from network devices; aggregate into a transactional store; correlate flows × syslog × MAC history into actionable events; expose scoped query APIs, MCP tools, and a "Live Flows" UI tab.
2. **Structural refactoring (pays down existing debt):** split `app_server.py` into domain routers with dependency-injected auth, introduce a real async-safe SQLite layer, adopt a FastAPI `lifespan` manager, and resolve the flat-vs-package import question.

Both outcomes are gated behind a **security-first Phase 0** that closes the report's own open findings (H-1 TLS, L-1 JWT storage, I-1 AI leakage, I-2 provisioner secrets) *before* any new attack surface (cleartext UDP ingest) is introduced.

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
- **O2 — Cohesion:** `app_server.py` endpoint count reduced measurably; FortiGate, WLC, observability served from dedicated routers with contract-verified path/response parity.
- **O3 — Transactional store:** `observability.db` created via versioned migration under `SENTINELNET_DATA_DIR`; **zero synchronous DB calls in async handlers**; aggregation is a true minute rollup (UPSERT).
- **O4 — Ingestion safety:** sustained 5k pps ingest with **no measurable event-loop latency impact**; unknown exporters dropped/quarantined with audit; per-flow tenant attribution correct.
- **O5 — Correlation:** `correlated_events` actually populated from flow × syslog × MAC-history joins, enriched with switch port.
- **O6 — Multi-site parity:** remote-site (Mode B) flows arrive via the authenticated agent channel — **no raw UDP over VPN**.
- **O7 — Dual-artifact integrity:** every phase ships buildable exe + Docker; listeners default **off** on desktop/exe.

---

## 2. Guiding Principles & Global Constraints

These constraints are **binding on every work item and every executor** unless a work item explicitly overrides one with owner sign-off.

### 2.1 Language policy (Italian codebase)
- **User-facing strings, log messages, audit entries, UI labels, error text → Italian.**
- **Identifiers (functions, classes, variables, DB columns, config keys, env vars, file names) → English**, matching existing style (e.g. `run_backup_and_triage`, `user_group_scope`, `get_full_config`).
- Docstrings/comments: English preferred for new code; do not rewrite existing Italian comments.
- This policy is codified in `CONTRIBUTING.md` (item 1.5) and is a code-review gate.

### 2.2 Dual-artifact gate (exe + Docker)
- Every PR **must** produce a working **PyInstaller exe** *and* a working **Docker image**. CI runs both builds.
- Bundled resources (e.g. `schema.sql`) must resolve through the existing `get_path`/resource-path mechanism in **both** artifacts.
- **Desktop/exe default = UDP listeners OFF.** Docker default = listeners opt-in via env, bound to loopback unless explicitly opened.

### 2.3 Security-first ordering
- **No new plaintext ingress channel may ship before Phase 0 delivers TLS option + cookie auth.** Phase 3 (UDP ingest) is hard-blocked on Phase 0 acceptance.
- Every new endpoint, MCP tool, and ingest path must respect: audit log, rate-limit/lockout, CLI blacklist (where applicable), and **multi-group tenant scope**.

### 2.4 Async-DB rule (non-negotiable)
- After Phase 1, **no code path in an async endpoint or async protocol handler may call a synchronous SQLite connection directly.**
- All DB writes on the hot path go through the **bounded async queue → dedicated writer worker → batched commit** pipeline.
- All DB reads in async handlers go through the async DB layer (executor-offloaded) — never a raw `sqlite3` call in the event loop.
- A CI lint/grep gate flags `sqlite3.connect(` / `.commit()` / `get_observability_connection(` usage inside `async def` bodies.

### 2.5 Scope-correctness rule
- Tenant scoping **always** uses the multi-group model: `user_group_scope(user)` → set of allowed groups; queries filter `WHERE tenant IN (:scoped_groups)`; device access uses `assert_group_allowed`/`assert_device_allowed`.
- **The scalar `user.group` pattern from the original guide is forbidden.**

### 2.6 Executor tiering
- **Standard agent:** well-specified, low-ambiguity, low-blast-radius items.
- **Frontier model (Fable 5):** reserved for genuinely hard/high-risk items — IPFIX template decoding, async ingestion pipeline (loop-safety), correlation engine, RBAC-sensitive scope work, and the auth-DI extraction. Justification given per item.

---

## 3. Phase-by-Phase Plan

Effort key: **S** ≤ 2 days · **M** 3–8 days · **L** 2–4 weeks.

---

### PHASE 0 — Security Quick Wins

**Rationale:** Close the report's open findings before adding UDP attack surface. All of Phase 0 is independent of observability and can proceed in parallel with Phase 1 packaging.

---

#### 0.1 — Native TLS option + hardened reverse-proxy guide
- **Files:** `app_server.py`, `data_config.py`, `docs/HARDENING.md`, `docker-compose.yml`
- **Agent brief:** Add optional native ASGI TLS. Read `SENTINELNET_SSL_CERTFILE` and `SENTINELNET_SSL_KEYFILE` env vars via `data_config.py`; when both present and readable, pass them to the Uvicorn run configuration (certfile/keyfile). When absent, behavior is unchanged (HTTP). Do **not** auto-generate certs silently; if only one of the pair is set, fail closed at startup with an Italian error message. Author `docs/HARDENING.md` describing (a) native TLS usage, (b) the recommended reverse-proxy pattern (nginx/Caddy) with TLS termination, security headers (HSTS, X-Content-Type-Options, Referrer-Policy), and (c) explicit statement that the management panel must never be exposed to untrusted networks in HTTP.
  - **Inputs:** existing Uvicorn startup call; env-var resolution conventions in `data_config.py`.
  - **Outputs:** TLS-capable startup; hardening doc; docker-compose comments showing where a proxy sits.
  - **Edge cases:** unreadable/expired cert file → fail closed with clear message; PyInstaller path resolution for cert files given as relative paths (resolve against `SENTINELNET_DATA_DIR`).
- **Definition of Done:**
  - Starting with both env vars set serves HTTPS; browser reaches dashboard over TLS.
  - Starting with neither serves HTTP unchanged (existing tests green).
  - Starting with exactly one → process exits non-zero with Italian error.
  - `docs/HARDENING.md` exists and is linked from README.
- **Dependencies:** none. **Effort:** M. **Risk:** Cert lifecycle on desktop/exe. **Mitigation:** native TLS is *optional*; primary recommendation remains reverse proxy; document cert renewal responsibility.
- **Executor:** Standard agent.

---

#### 0.2 — Move JWT to `HttpOnly`/`Secure`/`SameSite` cookie; retire `sessionStorage`
- **Files:** `security_manager.py`, `templates/dashboard.html`, `app_server.py` (auth extraction points, WS handshake)
- **Agent brief:** Replace `sessionStorage`-based JWT with an `HttpOnly`, `Secure` (when TLS active), `SameSite=Strict` (or `Lax` if a documented reason requires cross-site) cookie. On successful login, set the cookie server-side; on logout, clear it. Update all frontend `fetch`/XHR calls to use `credentials:'include'` and **remove all `sessionStorage.getItem/setItem('jwt_token')`** usage. Update the WebSocket terminal handshake: since browsers cannot set custom headers on WS, authenticate the WS using the cookie sent automatically on the upgrade request (validate cookie in the WS accept path). Add CSRF protection for state-changing requests (double-submit token or `SameSite=Strict` + custom header check) — document the chosen mechanism.
  - **Inputs:** current JWT issuance in `security_manager.py`; current WS OTP token flow; dashboard fetch calls.
  - **Outputs:** cookie-based auth end-to-end incl. WS terminal; no token in JS-accessible storage.
  - **Edge cases:** external API clients using `Authorization: Bearer` — **must remain supported** (accept both cookie and Bearer during a transition window; document deprecation of Bearer-from-browser only). WS reconnection. Logout invalidation. `Secure` flag must be conditional so local HTTP dev still works (gated on TLS active / env flag).
- **Definition of Done:**
  - No occurrence of `sessionStorage` for tokens anywhere in `templates/dashboard.html` (grep-verified in test).
  - Login sets `HttpOnly` cookie; authenticated API + WS terminal both work over the cookie.
  - Bearer-token API path still works for programmatic clients (test asserts both).
  - CSRF mechanism documented and enforced on POST/PUT/DELETE.
  - Existing auth/audit/lockout tests green.
- **Dependencies:** 0.1 (Secure flag needs TLS story). **Effort:** M. **Risk:** WS + CSRF handling; breaking external clients. **Mitigation:** dual-accept (cookie + Bearer) transition; explicit CSRF design doc.
- **Executor:** **Frontier (Fable 5)** — RBAC/session-security-sensitive; WS auth + CSRF + backward compat is subtle and high-blast-radius.

---

#### 0.3 — AI-context secret redaction
- **Files:** `ai_assistant.py`, new `redaction.py`
- **Agent brief:** Create `redaction.py` exposing a pure function that masks secrets in text/structured payloads before they leave the process to any LLM provider. Redact at minimum: password/secret/key lines in configs (Cisco `enable secret`, `username … password`, SNMP communities, PSKs, `set passwd`, FortiOS `set psksecret`/`set passwd`, WLC keys), API tokens, private keys (PEM blocks), and credential-bearing fields. Route **all** existing AI context builders (`build_tenant_context`, `_device_running_config_context`, `_fortigate_live_context`) through this masking pass. Redaction must be idempotent and must preserve enough structure for the model to reason (replace value with `***REDACTED***`, keep keys).
  - **Inputs:** current context-builder outputs; representative multivendor config fixtures.
  - **Outputs:** `redact(text|dict) -> same shape, masked`; wired into all LLM-bound context.
  - **Edge cases:** avoid over-redaction of non-secret tokens (interface names, VLAN IDs); handle multiline PEM; handle already-encrypted Fernet blobs (should never appear, but mask if seen); ensure no secret survives via JSON nesting.
- **Definition of Done:**
  - Golden-fixture test: a config containing 10+ known secret patterns → assert **zero** secret substrings present in redacted output.
  - Negative test: non-secret tokens (VLAN, hostname, IP) survive.
  - All AI context paths demonstrably call `redact` (unit test with a spy/monkeypatch).
- **Dependencies:** none. **Effort:** M. **Risk:** over/under-redaction; false confidence. **Mitigation:** pattern library with fixtures per vendor; leak-assertion test is the gate; document known limits.
- **Executor:** Standard agent (with a strong fixture set provided).

---

#### 0.4 — Provisioner secret handling (no cleartext in generated day-0)
- **Files:** `switch_provisioner.py`, `fortigate_provisioner.py`, `crypto_vault.py`
- **Agent brief:** Eliminate cleartext secrets in generated day-0 configurations. Introduce placeholder/vault-reference mode: generated configs contain tokens like `{{VAULT:enable_secret}}` (or vendor-appropriate placeholder) rather than literal secrets by default. Provide a controlled "materialize" step that resolves placeholders from `crypto_vault.py` only at push time (SSH/serial), never persisting the materialized config to disk. Preserve the option to generate a fully materialized config **only** with explicit, audited operator action and an on-screen warning.
  - **Inputs:** current `build_config()` in both provisioners; `crypto_vault.py` API.
  - **Outputs:** placeholder-by-default generation; push-time materialization; audit entry when materialized config is produced.
  - **Edge cases:** serial push (no re-fetch possible) must materialize in-memory just-in-time; ensure materialized secret is not logged; backward compat for existing saved templates.
- **Definition of Done:**
  - Default generation output contains **no** cleartext secret (test scans generated text).
  - Push path materializes and successfully applies (integration test with mocked transport).
  - Producing a materialized config emits an audit log entry.
- **Dependencies:** none. **Effort:** S/M. **Risk:** backward compat of generated configs. **Mitigation:** placeholder mode is additive; keep legacy full-materialize behind explicit flag.
- **Executor:** Standard agent.

**Phase 0 exit gate:** H-1 mitigated + documented; L-1 closed; I-1 leak-test green; I-2 no-cleartext test green; exe + Docker both build; full existing suite green.

---

### PHASE 1 — Packaging & Storage Foundation

**Rationale:** Resolve the flat-vs-package import mismatch and stand up an async-safe transactional store, while JSON/CSV keep working.

---

#### 1.1 — Decide & apply package layout; fix PyInstaller spec + entrypoint
- **Files:** `pyproject.toml`, `*.spec`, all module headers (imports), `app_server.py` entrypoint
- **Agent brief:** Execute the layout decision (see Open Decision #1; **recommended default: keep flat layout and rewrite all guide imports to flat** to minimize blast radius). If flat is confirmed: create `pyproject.toml` declaring the project, dependencies (mirroring `requirements.txt`), and console entrypoint; ensure new subpackages (`observability/`, `routers/`) are discoverable without a `sentinelnet.` prefix; update `*.spec` `datas`/`hiddenimports` so new modules and `schema.sql` bundle correctly. **All guide imports of the form `from sentinelnet.X import Y` must be rewritten to the flat form.** Verify `get_path`/resource resolution still works in exe.
  - **Inputs:** existing flat modules; existing `.spec`; existing `requirements.txt`.
  - **Outputs:** `pyproject.toml`; corrected `.spec`; consistent import style project-wide; documented layout decision.
  - **Edge cases:** PyInstaller hidden imports for dynamically imported drivers; resource path differences between exe and source run; `SENTINELNET_DATA_DIR` interaction.
- **Definition of Done:**
  - App runs identically from source, exe, and Docker.
  - `graphify`-style import check shows no broken/`sentinelnet.`-prefixed imports.
  - New `observability/` and `routers/` packages import cleanly in all three run modes.
- **Dependencies:** none (but enables 1.2 and 2.2). **Effort:** M. **Risk:** PyInstaller path regressions. **Mitigation:** smoke-test exe launch in CI; keep flat layout to avoid mass churn.
- **Executor:** Standard agent (frontier only if package migration chosen in Decision #1).

---

#### 1.2 — Async-safe SQLite layer (WAL, single writer, executor/queue)
- **Files:** `data_config.py`, new `db.py`
- **Agent brief:** Implement the async-safe DB access layer. Provide: (a) a single WAL-mode connection dedicated to the writer worker; (b) an async read helper that offloads queries to a threadpool executor and returns rows; (c) a **bounded `asyncio.Queue`** for write payloads consumed by a dedicated writer task/thread. Expose a synchronous `get_observability_connection()` for **migrations/tests only**, clearly documented as forbidden on async hot paths (enforced by CI grep in async bodies). Ensure WAL is enabled with sane pragmas (`journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout`).
  - **Inputs:** `SENTINELNET_DATA_DIR` resolution; async-DB rule (2.4).
  - **Outputs:** `db.py` with clearly separated read path (executor) and write path (queue→writer); documented API sketch:
    ```
    # db.py — interface sketch (NOT implementation)
    async def read(query: str, params: Mapping) -> list[Row]
    def enqueue_write(payload: WritePayload) -> None          # non-blocking, bounded; drops+metrics on full
    async def start_writer() -> None                          # started by lifespan
    async def stop_writer() -> None                           # graceful drain on shutdown
    def get_observability_connection() -> Connection          # migrations/tests ONLY
    ```
  - **Edge cases:** WAL on network/Docker volumes (document risk; recommend local volume); queue-full backpressure (drop with counter, never block loop); graceful drain on shutdown; multiple processes (single-process assumption documented).
- **Definition of Done:**
  - Load test: N concurrent async writers enqueue without blocking the event loop (measured loop-latency stays flat).
  - Reads never run raw `sqlite3` in the event loop (executor-offloaded).
  - Writer drains queue on shutdown; no partial-DB corruption after kill/restart (WAL recovery).
- **Dependencies:** 1.1. **Effort:** M. **Risk:** concurrency bugs; WAL on network volumes. **Mitigation:** single-writer design; load test in CI; document volume placement.
- **Executor:** **Frontier (Fable 5)** — event-loop safety and concurrency correctness are the core value; a subtle bug here stalls the whole app.

---

#### 1.3 — Observability schema + idempotent versioned migration
- **Files:** `observability/storage/schema.sql`, `db.py`
- **Agent brief:** Author `schema.sql` defining the three tables with correct types, indexes, and the aggregation UNIQUE key. Implement a **versioned, idempotent migration** (a `schema_version` table; migrations run once, safe to re-run). Bundle `schema.sql` for exe + Docker. Schema sketch:
    ```sql
    -- schema.sql — interface sketch
    CREATE TABLE IF NOT EXISTS flow_aggregates (
      window_start   INTEGER NOT NULL,     -- unix ts truncated to 60s
      tenant         TEXT NOT NULL,
      src_ip         TEXT NOT NULL,
      dst_ip         TEXT NOT NULL,
      protocol       INTEGER,
      dst_port       INTEGER,
      total_bytes    INTEGER NOT NULL DEFAULT 0,
      total_packets  INTEGER NOT NULL DEFAULT 0,
      flow_count     INTEGER NOT NULL DEFAULT 0,
      exporter_ip    TEXT,
      UNIQUE(window_start, tenant, src_ip, dst_ip, protocol, dst_port)
    );
    CREATE INDEX IF NOT EXISTS idx_flow_window_tenant ON flow_aggregates(window_start, tenant);
    CREATE TABLE IF NOT EXISTS syslog_events (
      id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, tenant TEXT NOT NULL,
      device_ip TEXT, severity INTEGER, action TEXT, message TEXT, exporter_ip TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_syslog_ts_tenant ON syslog_events(ts, tenant);
    CREATE TABLE IF NOT EXISTS correlated_events (
      id INTEGER PRIMARY KEY, created_ts INTEGER NOT NULL, tenant TEXT NOT NULL,
      kind TEXT, src_ip TEXT, dst_ip TEXT, switch_port TEXT,
      severity INTEGER, status TEXT DEFAULT 'new',  -- new|ack|resolved
      evidence_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_corr_tenant_status ON correlated_events(tenant, status);
    CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
    ```
  - **Edge cases:** re-running migration must be a no-op; schema drift detection; forward-only versioning.
- **Definition of Done:** `observability.db` created under `SENTINELNET_DATA_DIR` on first run; re-run is a no-op; `schema.sql` present in exe + Docker artifacts; migration test asserts idempotency.
- **Dependencies:** 1.2. **Effort:** S. **Risk:** schema drift. **Mitigation:** versioned migrations + drift test.
- **Executor:** Standard agent.

---

#### 1.4 — Fix aggregation semantics (true minute rollup via UPSERT)
- **Files:** `observability/storage/*`, `db.py`
- **Agent brief:** Implement the write payload for flows as an **UPSERT** keyed on the UNIQUE tuple, truncating timestamp to the 60-second bucket (`window_start = ts - (ts % 60)`), and summing counters:
    ```sql
    INSERT INTO flow_aggregates (window_start, tenant, src_ip, dst_ip, protocol, dst_port,
                                 total_bytes, total_packets, flow_count, exporter_ip)
    VALUES (:window_start, :tenant, :src_ip, :dst_ip, :protocol, :dst_port,
            :bytes, :packets, 1, :exporter_ip)
    ON CONFLICT(window_start, tenant, src_ip, dst_ip, protocol, dst_port)
    DO UPDATE SET total_bytes = total_bytes + excluded.total_bytes,
                  total_packets = total_packets + excluded.total_packets,
                  flow_count = flow_count + 1;
    ```
  - **Edge cases:** clock skew across exporters (use receipt time or exporter time — document choice; recommend exporter-reported flow end time truncated, fallback to receipt time); batch commits must preserve UPSERT semantics.
- **Definition of Done:** test: two flows in the same minute bucket + same 5-tuple → **one row**, counters summed; two flows in adjacent buckets → two rows. No UNIQUE-constraint violations under load.
- **Dependencies:** 1.3. **Effort:** S. **Risk:** correct bucketing. **Mitigation:** dedicated bucketing unit test; document time-source choice.
- **Executor:** Standard agent.

---

#### 1.5 — Language/style policy doc
- **Files:** `CONTRIBUTING.md`
- **Agent brief:** Document the language policy (Section 2.1), the dual-artifact gate, the async-DB rule, and the scope-correctness rule as contributor guidelines with concrete do/don't examples.
- **Definition of Done:** `CONTRIBUTING.md` exists, referenced from README, covers all four cross-cutting rules with examples.
- **Dependencies:** none. **Effort:** S. **Risk:** none. **Executor:** Standard agent.

**Phase 1 exit gate:** exe + Docker build; `observability.db` migrated idempotently; async writers don't block loop (load test); aggregation UPSERT verified.

---

### PHASE 2 — `app_server.py` Refactor into Routers

**Rationale:** Highest-alignment debt paydown. Prove the DI-auth + router pattern on FortiGate + WLC first, with contract parity tests.

---

#### 2.1 — Auth as FastAPI dependencies (multi-group scoped `User`)
- **Files:** `security_manager.py`, `user_manager.py`, new `routers/deps.py`
- **Agent brief:** Convert the current middleware/inline auth into reusable FastAPI dependencies: `get_current_user()` (validates cookie/Bearer, returns a `User` carrying **multi-group scope**), `require_operator()`, `require_admin()`. These must preserve **all** existing cross-cutting behavior: audit logging, rate-limit, lockout (`is_locked_out`), and CLI blacklist enforcement where relevant. Expose `user_group_scope(user) -> set[str]` and helpers `assert_group_allowed`, `assert_device_allowed` for use inside routers. **Do not** introduce a scalar `user.group`.
  - **Inputs:** current auth middleware; `user_group_scope`, `get_allowed_tabs`, existing lockout/rate-limit.
  - **Outputs:** dependency callables; `User` type with `groups: set[str]`, `role`; documented sketch:
    ```
    # routers/deps.py — interface sketch
    async def get_current_user(request) -> User
    async def require_operator(user: User = Depends(get_current_user)) -> User
    async def require_admin(user: User = Depends(get_current_user)) -> User
    def scoped_groups(user: User) -> set[str]
    ```
  - **Edge cases:** anonymous/expired token; lockout must still trigger; audit entry per request must not regress; both cookie and Bearer accepted (per 0.2).
- **Definition of Done:** dependencies enforce role + scope; audit/rate-limit/lockout tests pass unchanged; a multi-group user resolves to a set (test); a viewer is denied operator routes.
- **Dependencies:** 0.2. **Effort:** M. **Risk:** losing middleware behaviors. **Mitigation:** behavior-parity tests for audit/rate-limit/lockout/blacklist before/after.
- **Executor:** **Frontier (Fable 5)** — RBAC-sensitive; regressions leak or lock out; must faithfully preserve security middleware.

---

#### 2.2 — Extract `routers/fortigate.py`
- **Files:** `routers/fortigate.py`, `app_server.py`
- **Agent brief:** Move all FortiGate endpoints (`fgt_arp`, `fgt_device_inventory`, `fgt_full_config`, `fgt_diagnose_client`, `fgt_dhcp`, `fgt_interfaces`, etc.) from `app_server.py` into `routers/fortigate.py` as an `APIRouter`, wiring auth via the Phase 2.1 dependencies and scope checks via `assert_device_allowed`. **Route paths and response shapes must be byte-for-byte identical.** Business logic stays in `fortigate_service.py`; the router is thin.
  - **Edge cases:** path prefixes (`/api/…`), query/body params, error codes, streaming/large-config responses.
- **Definition of Done:** contract test (2.6) shows identical paths + response schemas for all FortiGate routes; auth/scope enforced; `app_server.py` no longer defines these routes.
- **Dependencies:** 2.1, 1.1. **Effort:** M. **Risk:** behavior drift. **Mitigation:** OpenAPI snapshot diff (2.6).
- **Executor:** Standard agent (pattern is mechanical once 2.1 exists).

---

#### 2.3 — Extract `routers/wlc.py`
- **Files:** `routers/wlc.py`, `app_server.py`
- **Agent brief:** Same pattern as 2.2 for WLC endpoints (`wlc_ap_summary`, `wlc_client_detail`, `wlc_client_summary`, `wlc_interfaces`, `wlc_diagnose_client`). Logic stays in `wlc_service.py`.
- **Definition of Done:** contract-parity test green for WLC routes; auth/scope enforced; routes removed from `app_server.py`.
- **Dependencies:** 2.1. **Effort:** M. **Risk:** drift. **Mitigation:** OpenAPI snapshot diff.
- **Executor:** Standard agent.

---

#### 2.4 — Replace `on_event` with `lifespan` context manager
- **Files:** `app_server.py`
- **Agent brief:** First **verify** whether current code uses `@app.on_event("startup"/"shutdown")` (guide assumes so; confirm). Introduce a single `@asynccontextmanager lifespan(app)` that: performs DB migration, starts the DB writer worker (from 1.2), `include_router`s all routers, and (later, Phase 3) starts UDP listeners. On shutdown, gracefully drains the writer and stops listeners. Migrate any existing startup logic into `lifespan`.
    ```
    # app_server.py — interface sketch
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await run_migrations()
        await start_writer()
        # include_router(...) done at app construction; listeners started in Phase 3
        yield
        await stop_writer()
    ```
  - **Edge cases:** TestClient compatibility; startup ordering (DB before writer before listeners); exception during startup must fail closed.
- **Definition of Done:** app starts/stops cleanly via `lifespan`; no `on_event` remains; TestClient works; writer starts/stops with app.
- **Dependencies:** 2.2, 2.3, 1.2. **Effort:** S. **Risk:** startup ordering. **Mitigation:** explicit ordered steps; startup smoke test.
- **Executor:** Standard agent.

---

#### 2.5 — Correct scope dependency in routers (multi-group)
- **Files:** `routers/*`
- **Agent brief:** Audit every extracted route to ensure device/group access uses `assert_group_allowed`/`assert_device_allowed`/`user_group_scope` — **never** a scalar `user.group`. Add explicit scope checks where the monolith relied on middleware.
- **Definition of Done:** RBAC test with a multi-group user: sees all in-scope groups, denied out-of-scope devices; single-group user unaffected; test asserting no scalar `user.group` reference in routers.
- **Dependencies:** 2.1. **Effort:** S. **Risk:** RBAC leak. **Mitigation:** dedicated multi-group RBAC test suite.
- **Executor:** **Frontier (Fable 5)** — RBAC-sensitive; the exact defect the guide introduces.

---

#### 2.6 — Migration table + OpenAPI parity snapshot test
- **Files:** `docs/REFACTOR.md`, `tests/test_router_parity.py`
- **Agent brief:** Capture the pre-refactor OpenAPI schema as a golden snapshot; write a test asserting the post-refactor `/openapi.json` matches for all migrated routes (paths, methods, params, response models). Document the endpoint→router migration table in `docs/REFACTOR.md`.
- **Definition of Done:** parity test green; `/docs` renders; migration table complete for FortiGate + WLC.
- **Dependencies:** 2.2–2.4. **Effort:** S. **Risk:** none. **Executor:** Standard agent.

**Phase 2 exit gate:** FortiGate + WLC served from routers with contract parity; auth/audit/rate-limit/blacklist enforced; multi-group scope correct; `app_server.py` endpoint count measurably lower; `lifespan` in place; both artifacts build.

---

### PHASE 3 — Flow/Event Ingestion (Hard, New Capability)

**Rationale:** Ingest IPFIX/sFlow/syslog **safely** — loop-safe, tenant-attributed, backpressured. Hard-blocked on Phase 0 (TLS/cookie) and Phase 1 (async DB).

---

#### 3.1 — Async UDP server factory + bounded ingest queue
- **Files:** `observability/ingesters/udp_server.py`
- **Agent brief:** Implement an asyncio UDP protocol factory. `datagram_received` must be **non-blocking and cheap**: parse the minimum needed to route, then push a raw-datagram payload onto the **bounded ingest queue** from `db.py`/a shared queue. **Never** spawn an unbounded `create_task` per packet; **never** call DB in the handler. On queue-full, drop the packet and increment a dropped-packets metric (exposed for later). Provide a factory that binds a given parser (IPFIX/sFlow/syslog) to a given port.
    ```
    # udp_server.py — interface sketch
    async def start_udp_listener(host: str, port: int, parser: Parser, queue: IngestQueue) -> Transport
    # datagram_received(data, addr): queue.put_nowait(RawDatagram(data, addr, recv_ts)) or drop+metric
    ```
  - **Edge cases:** oversized datagrams; malformed packets (must not crash the protocol); queue growth under burst; graceful stop on shutdown.
- **Definition of Done:** listener binds and receives; malformed packet does not crash; queue-full drops with metric; no `create_task`-per-packet; loop latency flat under burst (load test).
- **Dependencies:** 1.2. **Effort:** M. **Risk:** loop starvation / memory growth. **Mitigation:** bounded queue + drop-metric; load test gate.
- **Executor:** **Frontier (Fable 5)** — event-loop safety is the whole point; the guide's version stalls the loop.

---

#### 3.2 — Dedicated writer worker with batched commits
- **Files:** `observability/ingesters/writer.py`
- **Agent brief:** Consume decoded records from the parse pipeline and perform **batched** DB writes via the single WAL writer (from 1.2): accumulate up to N records or T milliseconds, then commit once (using the UPSERT from 1.4 for flows, plain inserts for syslog). Runs in the writer worker context, **off** the event loop's critical path. Handle crash-safety: on shutdown, flush the current batch.
  - **Edge cases:** partial batch on crash (accept bounded loss; document); commit failure → retry-with-backoff then drop+metric; batch size tuning.
- **Definition of Done:** batching verified (one commit per batch, not per record); UPSERT semantics preserved in batch; shutdown flushes; sustained-load test shows bounded memory.
- **Dependencies:** 3.1, 1.4. **Effort:** M. **Risk:** batch loss on crash. **Mitigation:** small batch window; document at-most-bounded-loss guarantee; WAL recovery.
- **Executor:** **Frontier (Fable 5)** — correctness under load + crash-safety.

---

#### 3.3 — Real IPFIX/NetFlow decoder (template handling)
- **Files:** `observability/ingesters/ipfix.py`
- **Agent brief:** Replace any mock with a real IPFIX (RFC 7011) + NetFlow v9 decoder supporting **template management**: cache templates per (exporter, domain, template-id); buffer data records that arrive before their template; decode common IEs (src/dst addr, ports, protocol, octet/packet deltas, flow start/end). Emit normalized flow records to the writer pipeline. Handle NetFlow v5 as a fixed-format fast path if present in fixtures.
  - **Inputs:** captured IPFIX/NetFlow fixtures (obtain/create synthetic pcaps for FortiGate + at least one other vendor).
  - **Outputs:** normalized flow records `(src_ip, dst_ip, protocol, dst_port, bytes, packets, start, end, exporter_ip)`.
  - **Edge cases:** template expiry/re-announce; option templates; variable-length fields; endianness; unknown IEs (skip gracefully); data-before-template buffering with bounded memory.
- **Definition of Done:** synthetic IPFIX + NetFlow v9 fixtures decode to expected normalized records (golden test); data-before-template is buffered then resolved; unknown IEs don't crash.
- **Dependencies:** 3.1. **Effort:** L. **Risk:** template state + vendor quirks. **Mitigation:** fixture-driven, incremental IE support; bounded template/buffer caches.
- **Executor:** **Frontier (Fable 5)** — genuinely hard protocol/state work.

---

#### 3.4 — sFlow + syslog parsers (severity/action normalization)
- **Files:** `observability/ingesters/sflow.py`, `observability/ingesters/syslog.py`
- **Agent brief:** Implement an sFlow v5 sample decoder (flow samples → normalized flow records; counter samples optional/parked) and a syslog parser normalizing RFC 3164/5424 into `(ts, device_ip, severity, action, message)`. Normalize FortiGate and Palo Alto syslog specifics: extract `action` (e.g. `deny`/`accept`/`blocked`), severity mapping, threat/UTM fields where present.
  - **Edge cases:** sFlow sampling-rate scaling (bytes must be multiplied by sampling rate — document); syslog format variance, multi-line messages, priority (PRI) parsing; timezone handling.
- **Definition of Done:** sFlow fixture decodes with sampling-rate applied; syslog fixtures (FortiGate + Palo Alto) normalize action/severity correctly (golden test).
- **Dependencies:** 3.1. **Effort:** M. **Risk:** format variance. **Mitigation:** fixtures per vendor; normalize to a small stable schema.
- **Executor:** **Frontier (Fable 5)** for sFlow sampling correctness; syslog portion could be standard, but keep unified under frontier given normalization subtlety.

---

#### 3.5 — Exporter-IP → device → tenant mapping at ingest
- **Files:** `observability/ingesters/*`, `inventory_manager.py`
- **Agent brief:** **Kill the hard-coded `tenant="default"`.** At ingest, resolve `exporter_ip` (packet source) → device (via inventory) → group/tenant. Add/extend `inventory_manager.py` with `get_device_by_ip(ip) -> Device | None` (cached, refreshed on inventory change). Unknown exporters are **dropped or quarantined** (parked table or metric) with an **audit entry** — never silently attributed to `default`.
    ```
    # inventory_manager.py — interface sketch
    def get_device_by_ip(ip: str) -> Optional[DeviceRef]   # returns (hostname, group/tenant)
    ```
  - **Edge cases:** NAT'd exporters (document limitation); exporter IP not in inventory; inventory reload invalidating cache; multiple devices sharing an IP (shouldn't happen — audit if it does).
- **Definition of Done:** flow/syslog from a known exporter lands with correct tenant; unknown exporter → dropped/quarantined + audit entry (test); no record ever written with tenant `default` (test scans DB).
- **Dependencies:** 3.2. **Effort:** M. **Risk:** misattribution/leakage. **Mitigation:** fail-closed on unknown; audit; cache-invalidation test.
- **Executor:** **Frontier (Fable 5)** — tenant-attribution is the security boundary for all downstream RBAC.

---

#### 3.6 — Listener config: high-port defaults, loopback bind, env-gated
- **Files:** `app_server.py` (lifespan), `data_config.py`
- **Agent brief:** Add config for listeners: default ports **IPFIX 4739 / sFlow 6343 / syslog 5514** (high port, **not** 514); default bind **`127.0.0.1`**; opt-in `0.0.0.0` via env; a master env flag to enable/disable each listener entirely. **Desktop/exe default = all listeners OFF.** Docker default = off unless enabled. Start listeners inside `lifespan` (3.x, 2.4) only when enabled.
    ```
    # env shape
    SENTINELNET_OBS_ENABLE=0|1
    SENTINELNET_OBS_BIND=127.0.0.1|0.0.0.0
    SENTINELNET_OBS_IPFIX_PORT=4739
    SENTINELNET_OBS_SFLOW_PORT=6343
    SENTINELNET_OBS_SYSLOG_PORT=5514
    ```
  - **Edge cases:** privileged 514 only via Docker port mapping (never bind 514 in-process); disabled listeners must not open sockets; exe must not attempt to bind by default.
- **Definition of Done:** default exe run opens **no** UDP sockets; enabling via env binds high ports on loopback; `0.0.0.0` requires explicit opt-in; startup logs (Italian) state which listeners are active.
- **Dependencies:** 2.4, 3.1. **Effort:** S. **Risk:** privileged-port/attack-surface. **Mitigation:** high ports + loopback default + env gate; 514 only via Docker mapping.
- **Executor:** Standard agent.

---

#### 3.7 — Minute rollup + retention/pruning job
- **Files:** `observability/rollup.py`
- **Agent brief:** Async periodic task (started in `lifespan`) that verifies rollup integrity and prunes data beyond the retention window (configurable, default e.g. 30 days for flows, shorter for raw syslog). Since 1.4 does write-time UPSERT rollup, this job primarily handles **retention/pruning** and optional coarser rollups (hourly from minute). Must never delete data inside the active window.
    ```
    SENTINELNET_OBS_RETENTION_DAYS=30
    ```
  - **Edge cases:** retention wiping live data (guard: prune strictly older than `now - retention`); large deletes (batch to avoid long locks); job overlap prevention.
- **Definition of Done:** retention test: rows older than window pruned, rows inside window untouched; job runs periodically without overlapping itself; large prune batched.
- **Dependencies:** 3.2, 1.4. **Effort:** M. **Risk:** retention wiping live data. **Mitigation:** strict `<` boundary test; batched deletes.
- **Executor:** Standard agent.

**Phase 3 exit gate:** synthetic IPFIX/sFlow/syslog → correct rows + correct tenant; 5k pps sustained with flat loop latency (terminal WS + API responsive); unknown exporter dropped/quarantined + audited; retention prunes correctly; exe default = listeners off.

---

### PHASE 4 — Observability API + Correlation Engine

**Rationale:** Serve scoped queries and actually populate `correlated_events`.

---

#### 4.1 — `routers/observability.py` `/top` + `/anomalies` (multi-tenant scoped)
- **Files:** `routers/observability.py`
- **Agent brief:** Implement read-only endpoints: `/api/observability/top` (top talkers by bytes/packets over a time window) and `/api/observability/anomalies` (from `correlated_events`). **All queries filter `WHERE tenant IN (:scoped_groups)`** using the 2.1/2.5 scope dependency, fully parameterized (no string interpolation). Reads go through the async DB layer (executor).
    ```
    GET /api/observability/top?window=15m&limit=50&metric=bytes
    GET /api/observability/anomalies?status=new&window=24h
    ```
  - **Edge cases:** empty scope (return empty, not all); large windows (enforce max + pagination); SQL injection (parameterized only); no data yet (empty arrays).
- **Definition of Done:** multi-group RBAC test: user sees only in-scope tenants; out-of-scope data never returned; parameterized queries (injection test); reads don't block loop.
- **Dependencies:** 2.5, 3.7. **Effort:** M. **Risk:** SQL perf. **Mitigation:** indexes (4.3); pagination; `EXPLAIN QUERY PLAN` review.
- **Executor:** **Frontier (Fable 5)** — RBAC-sensitive query surface; the exact scope defect must not recur.

---

#### 4.2 — Correlation/stitching engine → `correlated_events`
- **Files:** `observability/correlator.py`
- **Agent brief:** Implement the engine that populates `correlated_events` (the guide leaves it orphaned). Correlate, per tenant and time window: syslog security events (e.g. FortiGate/Palo Alto `blocked`/threat) × matching flow aggregates (same src/dst/port near the event time) × MAC history (resolve `src_ip` → MAC → switch/port via `mac_history`). Emit enriched `correlated_events` rows with `switch_port`, `kind`, `severity`, and `evidence_json`. Runs as an async periodic task (in `lifespan`), scoped and batched.
  - **Inputs:** `syslog_events`, `flow_aggregates`, `mac_history` (`mac_locate`, `_mac_topology_uplinks`).
  - **Outputs:** populated `correlated_events` with provenance in `evidence_json`.
  - **Edge cases:** false positives (require corroborating flow within a time delta); join cost (bounded windows, indexed); missing MAC mapping (still emit event, `switch_port=null`); dedup (don't emit duplicate correlated events for the same underlying evidence).
- **Definition of Done:** scripted fixture ("malware-blocked syslog + matching flow + known MAC") → **one** correlated event with enriched switch port + evidence; no duplicate emission on re-run; per-tenant scoping preserved (no cross-tenant correlation).
- **Dependencies:** 3.4, 3.5. **Effort:** L. **Risk:** false positives; join cost. **Mitigation:** conservative correlation windows; indexes; dedup key; fixture-driven precision tests.
- **Executor:** **Frontier (Fable 5)** — genuinely hard join/correlation logic with correctness + performance stakes.

---

#### 4.3 — Query performance pass
- **Files:** `observability/storage/*`, `routers/observability.py`
- **Agent brief:** Validate/adjust indexes against real query plans (`EXPLAIN QUERY PLAN`) for `/top` and `/anomalies`; rewrite the top-talkers query to avoid full scans (leverage `idx_flow_window_tenant`); add covering indexes if needed.
- **Definition of Done:** `EXPLAIN QUERY PLAN` shows index use (no full-table scan) for both endpoints on a populated DB; latency within target (document threshold) on a seeded large dataset.
- **Dependencies:** 4.1. **Effort:** S. **Risk:** none. **Executor:** Standard agent.

---

#### 4.4 — MCP tools + AI redaction hook
- **Files:** `mcp_server.py`, `ai_assistant.py`
- **Agent brief:** Expose `get_top_talkers` and `get_anomalies` as **read-only** MCP tools honoring viewer/operator roles and the multi-group scope (reuse 4.1 logic). All data passed to any LLM (in-app assistant or MCP) routes through the 0.3 redaction pass. Add these to the MCP tool allow-list mechanism (admin-selectable).
  - **Edge cases:** viewer role gets read-only; operator no additional write here; over-exposure (I-1) — flows summarized/redacted, not raw dumps.
- **Definition of Done:** MCP tools return scoped data per role; redaction applied (leak-assertion test on tool output path); tools appear in MCP admin allow-list.
- **Dependencies:** 4.1, 0.3. **Effort:** M. **Risk:** over-exposure to LLM. **Mitigation:** redaction gate + summarization; role checks.
- **Executor:** **Frontier (Fable 5)** — scope + LLM-exposure sensitivity.

**Phase 4 exit gate:** `/top` and `/anomalies` return in-scope only (multi-group RBAC test); correlated events generated + enriched from fixtures; MCP tools honor roles + redaction.

---

### PHASE 5 — Frontend "Live Flows" Tab

**Rationale:** Wire the UI into existing Vis.js + tab system using Phase-0 cookie auth. **Never `sessionStorage`.**

---

#### 5.1 — "Live Flows" tab HTML + table/bars (Italian strings)
- **Files:** `templates/dashboard.html`
- **Agent brief:** Add a "Live Flows" tab consistent with existing tab styling; render a top-talkers table + simple bar visualization. All labels/tooltips/empty-states in **Italian**.
- **Definition of Done:** tab appears and renders; Italian strings; consistent with existing UI; no console errors.
- **Dependencies:** 4.1. **Effort:** S. **Executor:** Standard agent.

---

#### 5.2 — JS `loadTopTalkers`/auto-refresh using cookie auth
- **Files:** `templates/dashboard.html`
- **Agent brief:** Fetch `/api/observability/top` using `credentials:'include'` (cookie auth) — **no `Authorization: Bearer`, no `sessionStorage`.** Auto-refresh on an interval that **pauses when the tab is hidden** (`document.visibilitychange`).
  - **Edge cases:** 401 handling (redirect to login); refresh pause/resume; avoid overlapping fetches.
- **Definition of Done:** flows load via cookie; refresh pauses when tab hidden; **grep test confirms no `sessionStorage`/Bearer** in the flows code path.
- **Dependencies:** 0.2, 5.1. **Effort:** S. **Risk:** regressing L-1. **Mitigation:** explicit no-sessionStorage test + code-review gate.
- **Executor:** Standard agent (with L-1 guard test).

---

#### 5.3 — `highlightInTopology()` against real Vis.js model
- **Files:** `templates/dashboard.html`
- **Agent brief:** Clicking an IP in the flows table focuses/highlights the corresponding node in the existing Vis.js `window.network` topology. Map flow IP → topology node id/label using the existing node model.
  - **Edge cases:** IP with no topology node (graceful no-op + Italian toast); label vs id mismatch; multiple nodes.
- **Definition of Done:** clicking a known IP focuses the correct node; unknown IP → graceful message; no exceptions.
- **Dependencies:** 5.1. **Effort:** S. **Risk:** node id/label mapping. **Mitigation:** reuse existing map's node model; fallback no-op.
- **Executor:** Standard agent.

---

#### 5.4 — `analyzeFlow()` → AI tab through redaction
- **Files:** `templates/dashboard.html`, `ai_assistant.py`
- **Agent brief:** "Analizza" button on a flow sends a **redacted** (0.3) flow context to the AI tab/assistant. Must route through the redaction pass server-side; never send raw flow dumps.
  - **Edge cases:** large flow context (summarize); third-party LLM (I-1) — ensure redaction + user-visible note that data goes to configured provider.
- **Definition of Done:** button triggers AI analysis on redacted context; leak-assertion test on the payload; UI note (Italian) about provider.
- **Dependencies:** 0.3, 4.4. **Effort:** S. **Risk:** third-party LLM leakage. **Mitigation:** server-side redaction gate; summarize.
- **Executor:** Standard agent.

---

#### 5.5 — Anomalies panel bound to `/anomalies` with ack/resolve
- **Files:** `templates/dashboard.html`, `routers/observability.py`
- **Agent brief:** Panel listing correlated anomalies with **ack/resolve** actions that transition `correlated_events.status` (`new`→`ack`→`resolved`) via a scoped, audited POST endpoint. Actions require operator role.
  - **Edge cases:** concurrent status updates; out-of-scope event (deny); invalid transition.
- **Definition of Done:** panel lists in-scope anomalies; ack/resolve transitions persist + audited; operator-gated; out-of-scope denied (test).
- **Dependencies:** 4.1. **Effort:** M. **Risk:** state transitions. **Mitigation:** explicit allowed-transition validation + audit.
- **Executor:** Standard agent.

**Phase 5 exit gate:** tab loads scoped flows via cookie; refresh pauses when hidden; IP click focuses node; AI uses redacted context; anomalies ack/resolve work; **no token in sessionStorage** (audited).

---

### PHASE 6 — Deployment, Multi-site & Test Hardening

---

#### 6.1 — Docker UDP ports + documented risk
- **Files:** `docker-compose.yml`, `docs/HARDENING.md`
- **Agent brief:** Expose UDP `4739/6343` and `5514`; document optional privileged `514:5514` mapping. Keep listeners opt-in via env (3.6). Document attack surface + firewall guidance in `docs/HARDENING.md`.
- **Definition of Done:** compose exposes UDP with env-gated listeners; hardening doc covers risk + 514 mapping.
- **Dependencies:** 3.6. **Effort:** S. **Risk:** attack surface. **Mitigation:** opt-in + docs + loopback default.
- **Executor:** Standard agent.

---

#### 6.2 — PyInstaller bundle: package + `schema.sql`, listeners off
- **Files:** `*.spec`, `data_config.py`
- **Agent brief:** Ensure `observability/`, `routers/`, and `schema.sql` bundle correctly; verify resource resolution at runtime in the exe; confirm desktop default = listeners OFF.
- **Definition of Done:** exe launches, migrates DB, serves UI, listeners off by default; `schema.sql` resolves in bundled mode (smoke test).
- **Dependencies:** 1.1, 3.6. **Effort:** M. **Risk:** missing bundled resource. **Mitigation:** CI exe smoke test that touches the DB path.
- **Executor:** Standard agent.

---

#### 6.3 — Site-agent flow relay (Mode B)
- **Files:** `site_agent.py`, `site_manager.py`, `observability/ingesters/*`
- **Agent brief:** For remote (Mode B) sites, remote collectors must **not** require exposing central UDP over the VPN. Instead, the site agent ingests flows/syslog **locally** at the remote site and forwards them over the **authenticated agent channel** (`X-Site-Token`/`X-Site-Id`, existing agent HTTP polling/post pattern) to a central ingest endpoint. Reuse exporter→device→tenant mapping (3.5) at the agent (or attribute centrally by site). Add `agent_push_flows` analogous to `agent_push_mac`/`agent_push_inventory`.
    ```
    POST /api/agent/push_flows   (X-Site-Id, X-Site-Token)  -> batched normalized flow/syslog records
    ```
  - **Edge cases:** agent auth failure (reject + audit); replay/dedup; batch size; site→tenant attribution; ordering with central UDP ingest.
- **Definition of Done:** remote-site flows arrive centrally via authenticated agent channel; **no raw UDP over VPN required**; unauthenticated push rejected + audited; records correctly tenant-attributed.
- **Dependencies:** 3.5. **Effort:** L. **Risk:** multi-site auth/queue hardening. **Mitigation:** reuse existing agent auth; batched authenticated push; dedup.
- **Executor:** **Frontier (Fable 5)** — spans auth boundary + tenant attribution + ingestion; security-sensitive.

---

#### 6.4 — Multi-site hardening (queue observability, retries, token rotation)
- **Files:** `site_manager.py`, `site_agent.py`
- **Agent brief:** Address the open multi-site debt: expose job-queue observability (pending/claimed/completed counts, stuck-job detection), add retry-with-backoff for failed jobs, and implement **agent token rotation** (issue/rotate/revoke `X-Site-Token`).
  - **Edge cases:** token rotation without dropping in-flight jobs; retry storms (backoff cap); stuck-job reclaim.
- **Definition of Done:** queue metrics exposed; failed jobs retried with backoff; token rotation works without breaking active agents (test); revoked token rejected.
- **Dependencies:** 6.3. **Effort:** M. **Risk:** in-flight disruption. **Mitigation:** overlap window for rotation; backoff caps.
- **Executor:** Standard agent (frontier optional if token-rotation security review warrants).

---

#### 6.5 — Test coverage: ingesters, routers, obs API, correlator, RBAC, load/soak
- **Files:** `tests/test_observability_*`, `tests/test_router_parity.py`, `tests/test_rbac_scope.py`
- **Agent brief:** Add coverage for all new modules: ingester parsers (fixtures), router parity, obs API scoping, correlator precision, **multi-group RBAC**, and a **24h soak / sustained-load** test asserting no loop stalls and bounded memory.
- **Definition of Done:** coverage added for every new module; multi-group RBAC tests green; soak test runs 24h without loop stalls or unbounded memory (documented result).
- **Dependencies:** all. **Effort:** M. **Risk:** flaky load tests. **Mitigation:** deterministic fixtures; separate soak from unit CI.
- **Executor:** Standard agent (correlator/RBAC test authoring may pair with the frontier implementers).

---

#### 6.6 — Complete remaining router extraction (mac, ai, sites, backup)
- **Files:** `routers/mac.py`, `routers/ai.py`, `routers/sites.py`, `routers/backup.py`, `app_server.py`
- **Agent brief:** Apply the proven Phase-2 pattern to the remaining endpoint domains, each with contract-parity tests and correct multi-group scope. Incremental — one domain per PR.
- **Definition of Done:** each domain's routes served from its router with parity test green; `app_server.py` reduced to app assembly + lifespan; scope correct throughout.
- **Dependencies:** 2.*. **Effort:** M. **Risk:** incremental parity. **Mitigation:** reuse 2.6 parity harness per domain.
- **Executor:** Standard agent (frontier for any RBAC-heavy domain, e.g. sites/agent).

**Phase 6 exit gate:** Docker exposes UDP with documented risk; exe listeners off by default; remote-site flows via authenticated agent; full coverage incl. multi-group RBAC; 24h soak clean; monolith reduced to assembly.

---

## 4. Design Corrections to the Original Guide (Mandatory Decisions)

Each of the nine defects from the gap analysis is resolved here as a binding decision. Executors must implement the **Resolution**, not the guide's original.

| # | Defect (guide) | Mandatory resolution | Enforced by |
|---|---|---|---|
| **D1** | Blocking `sqlite3`/`commit()` in async handlers; unbounded `create_task` per packet | **Bounded async ingest queue → dedicated writer worker → batched commits.** `datagram_received` only enqueues; no DB or task-spawn per packet. WAL, single writer. | Async-DB rule (2.4); items 1.2, 3.1, 3.2; CI grep gate; load test |
| **D2** | RBAC scalar `user.group` (`WHERE tenant = user.group`) | **Multi-group scope everywhere**: `user_group_scope(user)` → set; `WHERE tenant IN (:scoped_groups)`; `assert_group_allowed`/`assert_device_allowed`. Scalar `user.group` **forbidden**. | Scope-correctness rule (2.5); items 2.1, 2.5, 4.1; multi-group RBAC tests |
| **D3** | `flow_aggregates` never aggregates (plain INSERT vs UNIQUE) | **Write-time UPSERT** on `UNIQUE(window_start, tenant, 5-tuple)`, timestamp truncated to 60s, counters summed via `ON CONFLICT DO UPDATE`. | Item 1.4; bucketing test |
| **D4** | Hard-coded `tenant="default"` at ingest | **Exporter-IP → device → tenant resolution** via `get_device_by_ip`. Unknown exporters dropped/quarantined + audited. No record ever written with `default`. | Item 3.5; "no default tenant" DB-scan test |
| **D5** | Syslog on privileged port 514 | **Default high port 5514, loopback bind, env-gated, off on exe.** Privileged 514 only via optional Docker port mapping; never bound in-process. | Item 3.6, 6.1 |
| **D6** | `sentinelnet.` package imports vs flat codebase | **Keep flat layout (recommended); rewrite all guide imports to flat.** (If package chosen — Decision #1 — do full migration under 1.1.) | Item 1.1; import-consistency check |
| **D7** | English code in Italian codebase | **Italian user-facing strings/logs; English identifiers.** Codified in `CONTRIBUTING.md`. | Language policy (2.1); item 1.5; review gate |
| **D8** | Unauthenticated, spoofable UDP ingest | **Loopback default + explicit opt-in for `0.0.0.0`; exporter allow-list via inventory (unknown dropped); remote sites use authenticated agent relay (no raw UDP over VPN).** TLS/cookie land first (Phase 0). Document residual UDP-spoofing risk in `docs/HARDENING.md`. | Items 3.5, 3.6, 6.1, 6.3; Phase-0 gate |
| **D9** | `correlated_events` orphaned (nothing populates it) | **Correlation engine** (`observability/correlator.py`) stitches flow × syslog × MAC-history → enriched `correlated_events`; periodic, scoped, dedup'd. | Item 4.2; correlation precision fixture test |

**Additional binding decisions:**
- **JWT storage (L-1):** cookie-based (`HttpOnly`/`Secure`/`SameSite`); the guide's `sessionStorage.getItem('jwt_token')` is **prohibited** (item 0.2, guarded in 5.2).
- **TLS ordering (H-1):** no new cleartext ingress before Phase 0; native TLS optional + reverse-proxy guide mandatory (item 0.1).
- **AI exposure (I-1):** all LLM-bound context (config + flows) passes redaction (items 0.3, 4.4, 5.4).

---

## 5. Testing & Verification Strategy per Phase

**Global harness:** `pytest` (extend existing suite); FastAPI `TestClient`; fixture-driven parsers; a load/soak harness (async packet generator) run outside the fast CI lane. **Every PR gate:** existing suite green + exe build + Docker build + language/async-DB/no-sessionStorage grep gates.

| Phase | Key verifications |
|---|---|
| **0** | TLS on/off/half-config behavior; cookie auth incl. WS terminal; Bearer still works for API clients; CSRF enforced; **redaction leak-assertion** (0 secrets in AI-bound output); provisioner **no-cleartext** scan; audit/lockout unchanged. |
| **1** | exe+Docker run post-packaging; `observability.db` migration idempotent; **async-writer load test** (loop latency flat); **UPSERT bucketing** (2 flows same bucket → 1 summed row). |
| **2** | **OpenAPI parity snapshot** (FortiGate+WLC); auth/audit/rate-limit/blacklist behavior parity; **multi-group RBAC** (sees in-scope, denied out-of-scope); `lifespan` startup/shutdown + TestClient; endpoint-count reduction metric. |
| **3** | Golden fixtures: IPFIX (+NetFlow v9/v5), sFlow (sampling-rate applied), syslog (FortiGate/Palo Alto) → expected normalized rows; **tenant attribution correct**; **unknown exporter dropped + audited**; **5k pps soak** with responsive WS/API; retention prunes strictly outside window. |
| **4** | `/top` + `/anomalies` **multi-group scoped**; parameterized/injection-safe; `EXPLAIN QUERY PLAN` index use; **correlation precision** (scripted malware-blocked+flow+MAC → 1 enriched event, no dupes); MCP tools role-gated + redacted. |
| **5** | Tab renders (Italian); flows via cookie; **no sessionStorage/Bearer** (grep test); refresh pauses when hidden; topology highlight on known IP; `analyzeFlow` payload redacted; anomaly ack/resolve transitions + audit + scope-deny. |
| **6** | Docker UDP exposure; exe listeners-off default + `schema.sql` resolves; **remote-site flows via authenticated agent** (unauth rejected+audited); token rotation without disruption; **24h soak** (no loop stall, bounded memory); coverage across all new modules. |

**Standing security tests (run every phase):** no secret in LLM-bound output; no `default` tenant in DB; no scalar `user.group`; no sync DB in async body; no `sessionStorage` token.

---

## 6. Rollout / Release Plan

### 6.1 Versioning
- **SemVer**, phase-aligned minor releases:
  - `v1.1.0` — Phase 0 (security baseline).
  - `v1.2.0` — Phase 1 (packaging + storage).
  - `v1.3.0` — Phase 2 (router refactor; no user-visible feature change).
  - `v1.4.0` — Phase 3 (ingestion; listeners off by default → behind feature flag).
  - `v1.5.0` — Phase 4 (obs API + correlation).
  - `v1.6.0` — Phase 5 (Live Flows UI).
  - `v1.7.0` — Phase 6 (multi-site relay, hardening, coverage).
- Observability is **feature-flagged off by default** through `v1.6.x`; general availability announced with `v1.7.0` once multi-site + soak-tested.

### 6.2 Migration of existing installs
- **State migration:** JSON/CSV stores (`network_hosts.csv`, `users.json`, `groups.json`, `detected_versions.json`) remain authoritative and untouched through this program; **`observability.db` is additive**, created on first `v1.2.0+` start via idempotent migration under `SENTINELNET_DATA_DIR`.
- **Auth migration (v1.1.0):** on upgrade, existing sessions using `sessionStorage` are invalidated; users re-login and receive the cookie. Release note flags this; API clients using Bearer are unaffected (dual-accept).
- **Docker:** `docker compose pull && up -d`; volume `./data:/app/data` preserved; UDP ports added in `v1.4.0+` compose but listeners stay off until `SENTINELNET_OBS_ENABLE=1`.
- **exe:** in-place replacement; DB migration on launch; listeners off by default (no behavior change for desktop users).
- **Multi-site agents (v1.7.0):** roll central first, then agents; token rotation performed with an overlap window so in-flight jobs are not dropped.

### 6.3 Rollback
- **Every phase must be independently rollback-able.**
- **Additive DB:** rolling back to a pre-observability version simply ignores `observability.db` (no schema coupling to core JSON/CSV). Keep a pre-migration copy note in release docs.
- **Router refactor (Phase 2):** OpenAPI parity guarantees a clean revert; if a route regresses, revert the specific router PR (routers are per-domain, independently revertible).
- **Auth cookie (Phase 0):** rollback re-enables the old path; because Bearer remained supported, API clients are unaffected; browser users re-login.
- **Ingestion (Phase 3+):** disable via `SENTINELNET_OBS_ENABLE=0` without downgrading — kill switch is the primary rollback for listeners; code rollback is secondary.
- **DB corruption safeguard:** WAL + graceful writer drain; document a "delete `observability.db` to reset observability" recovery step (core data unaffected).

---

## 7. Open Decisions Requiring the Human Owner

1. **Package layout:** Keep **flat** (recommended — rewrite guide imports, minimal churn) or migrate to a `sentinelnet/` package (cleaner, but PyInstaller-spec and import-wide churn)? Blocks 1.1.
2. **CSRF mechanism (0.2):** `SameSite=Strict` alone, double-submit token, or custom-header check? Affects any legitimate cross-origin usage and the reverse-proxy setup.
3. **Bearer-token deprecation timeline (0.2):** how long to keep dual-accept (cookie + Bearer) for programmatic clients before deprecating browser Bearer? Affects external integrations.
4. **Retention windows (3.7):** default retention for `flow_aggregates` vs raw `syslog_events` vs `correlated_events` (proposed 30d / 7d / 90d)? Storage-size and forensics trade-off.
5. **sFlow counter samples:** ingest now or park for later? Affects 3.4 scope.
6. **Vendor coverage priority for IPFIX/syslog fixtures (3.3/3.4):** confirm FortiGate + Palo Alto first; which additional vendors (Cisco, Juniper, Aruba) and in what order?
7. **AI/LLM exposure policy (I-1):** is redaction sufficient, or should flow/config data to *third-party* providers be **blocked entirely** unless the provider is local (Ollama)? Affects 0.3, 4.4, 5.4.
8. **UDP `0.0.0.0` exposure policy (D8):** allow opt-in direct UDP exposure at central at all, or **mandate** the site-agent relay path even for the central site's local devices?
9. **Correlation sensitivity (4.2):** acceptable false-positive vs false-negative posture and the correlation time-delta window (affects alert volume in the anomalies panel).
10. **Native TLS support level (0.1):** is native ASGI TLS a first-class supported path, or documentation-only "reverse proxy strongly recommended"? Affects cert-lifecycle support burden.
11. **Privileged syslog 514 (D5):** support the optional Docker `514:5514` mapping officially, or document-only/unsupported?
12. **DB concurrency model:** confirm the **single-process** assumption for WAL single-writer (no multi-worker Uvicorn for the app process), or do we need to support `--workers > 1` (which would break the single in-process writer design)?

---

## 8. Appendix — Dependency Matrix

| Item | Title | Depends on |
|---|---|---|
| 0.1 | TLS native + proxy guide | — |
| 0.2 | JWT → cookie | 0.1 |
| 0.3 | AI redaction | — |
| 0.4 | Provisioner secrets | — |
| 1.1 | Package layout + PyInstaller | — |
| 1.2 | Async SQLite layer | 1.1 |
| 1.3 | Obs schema + migration | 1.2 |
| 1.4 | Aggregation UPSERT fix | 1.3 |
| 1.5 | Language/style policy | — |
| 2.1 | Auth as DI (multi-group) | 0.2 |
| 2.2 | routers/fortigate | 2.1, 1.1 |
| 2.3 | routers/wlc | 2.1 |
| 2.4 | lifespan manager | 2.2, 2.3, 1.2 |
| 2.5 | Multi-group scope fix | 2.1 |
| 2.6 | OpenAPI parity test | 2.2, 2.3, 2.4 |
| 3.1 | UDP factory + queue | 1.2 |
| 3.2 | Batched writer | 3.1, 1.4 |
| 3.3 | IPFIX/NetFlow decoder | 3.1 |
| 3.4 | sFlow + syslog parsers | 3.1 |
| 3.5 | Exporter → tenant mapping | 3.2 |
| 3.6 | Listener config + ports | 2.4, 3.1 |
| 3.7 | Rollup + retention | 3.2, 1.4 |
| 4.1 | /top + /anomalies scoped | 2.5, 3.7 |
| 4.2 | Correlation engine | 3.4, 3.5 |
| 4.3 | Query perf | 4.1 |
| 4.4 | MCP tools + redaction | 4.1, 0.3 |
| 5.1 | Live Flows tab HTML | 4.1 |
| 5.2 | JS cookie auth | 0.2, 5.1 |
| 5.3 | Topology highlight | 5.1 |
| 5.4 | analyzeFlow → AI | 0.3, 4.4 |
| 5.5 | Anomalies panel | 4.1 |
| 6.1 | Docker UDP ports | 3.6 |
| 6.2 | PyInstaller bundle | 1.1, 3.6 |
| 6.3 | Site-agent flow relay | 3.5 |
| 6.4 | Multi-site hardening | 6.3 |
| 6.5 | Test coverage + soak | all prior |
| 6.6 | Remaining routers | 2.* |

### Executor-tier summary

| Tier | Items |
|---|---|
| **Frontier (Fable 5)** | 0.2, 1.2, 2.1, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5, 4.1, 4.2, 4.4, 6.3 |
| **Standard agent** | 0.1, 0.3, 0.4, 1.1, 1.3, 1.4, 1.5, 2.2, 2.3, 2.4, 2.6, 3.6, 3.7, 4.3, 5.1, 5.2, 5.3, 5.4, 5.5, 6.1, 6.2, 6.4, 6.5, 6.6 |

**Frontier justification (summary):** all reserved items are either **event-loop-safety-critical** (1.2, 3.1, 3.2), **hard protocol/state or correlation logic** (3.3, 3.4, 4.2), or **security-boundary-sensitive** (0.2 session/CSRF/WS, 2.1/2.5/4.1 multi-group RBAC, 3.5 tenant attribution, 4.4 LLM exposure, 6.3 authenticated multi-site relay). Everything else is well-specified and low-blast-radius for a standard agent operating under the cross-cutting rules.

---

*End of Master Implementation Plan (Final Draft). Verify freshness against commit `6fcb9039` before execution; re-run `graphify update .` after each phase merges.*