# Contributing to SentinelNet

Binding rules for every change, human or AI-authored. Architectural context is in
[docs/architecture.md](docs/architecture.md); layout, tests and build in
[docs/development.md](docs/development.md).

## 1. Language

- **User-facing strings, logs, error messages, comments and docstrings: Italian.**
- **Identifiers (functions, variables, modules, endpoints): English.**
- **Documentation under `docs/`: English.**

```python
# ✅ correct
def resolve_tls_config():
    raise TlsConfigError("Configurazione TLS incompleta: ...")

# ❌ wrong
def risolvi_config_tls():
    raise TlsConfigError("Incomplete TLS configuration: ...")
```

## 2. Dual artifact (exe + Docker)

Every change must leave **both** artifacts buildable:

```sh
uv run pyinstaller SentinelNet.spec   # Windows exe
docker compose build                  # Docker image
```

New data files (e.g. `schema.sql`) must be added to `datas` in
`SentinelNet.spec` and verified in all three modes (source, exe, Docker).
Bundled paths resolve via `sys._MEIPASS`.

## 3. Async-DB rule (non-negotiable)

- **Never use `sqlite3` directly on async paths** (FastAPI endpoints, UDP
  handlers).
- Reads: `await db.read(sql, params)` (off-loaded to a thread).
- Writes: `db.enqueue_write(...)` / `db.enqueue_flow(...)` (bounded queue,
  dedicated writer, batch commit).
- `db.get_observability_connection()` is permitted ONLY in migrations and tests.

```python
# ✅ correct (async endpoint)
rows = await db.read("SELECT ... WHERE tenant IN (...)", scoped)

# ❌ wrong: blocks the event loop (WS terminal, API, everything)
conn = db.get_observability_connection()
rows = conn.execute("SELECT ...").fetchall()
```

Rationale: [docs/adr/0004-single-process-sqlite-writer.md](docs/adr/0004-single-process-sqlite-writer.md).

## 4. Multi-group scope rule

A user can belong to **multiple** groups (`user_group_scope`). Never use a scalar
`user.group` in queries or authorization checks:

```python
# ✅ correct
placeholders = ",".join("?" * len(groups))
await db.read(f"SELECT ... WHERE tenant IN ({placeholders})", tuple(groups))

# ❌ wrong: hides or exposes data for multi-group users
await db.read("SELECT ... WHERE tenant = ?", (user.group,))
```

For devices: `assert_group_allowed` / `assert_device_allowed`.

## 5. Single-process assumption

The SQLite writer is single-process. Do not start the app with `--workers > 1`
while observability is enabled; horizontal scaling is not supported for the
observability module.

## 6. Permanent security gates

| Gate | What it protects | Command | Expected |
|---|---|---|---|
| L-1 | Session JWT must not be readable by JavaScript — cookie only | `grep -c "sessionStorage" templates/dashboard.html` | No token usage |
| — | No `sqlite3` on async paths | `grep -n "get_observability_connection" app_server.py routers/ observability/ingesters/` | Migrations and tests only |
| I-2 | Provisioner day-0 config must not emit cleartext secrets | `tests/test_provisioning_secrets.py` | Green |
| I-1 | LLM context passes the redaction choke-point | `tests/test_redaction.py` | Green |
| H-1 | TLS config is fail-closed, no silent HTTP fallback | `tests/test_tls_config.py` | Green |

Each gate carries its own meaning above; the audit documents that assigned these
identifiers are kept outside the public tree (see the next section).

### Security findings stay out of the public tree

**This repository is public.** A document that names an unfixed vulnerability at
`file:line` is an exploitation roadmap for source anyone can already read.

Audit and scan results live in `data/security/`, which is gitignored. A finding
may be written up publicly only once it is fixed and the fix is covered by a
gate above.

### Do not launder gitignored data into tracked files

`data/` is gitignored — `backup-config/`, `detected_versions.json`,
`network_hosts.csv`, `mac_history.db` — because it holds real customer network
state. **Conclusions derived from it are as sensitive as the files themselves**
and must not be written into tracked files, including documentation.

Device models, software versions, hostnames, serial numbers, management IPs and
topology roles are all customer intelligence. Software versions in particular
are CVE-relevant: recording that a given model runs a given release publishes an
attack surface.

Using a real backup to *verify* a parser is correct and encouraged. Writing what
that backup revealed about a customer's network into `docs/` is not.

Reference material under `docs/reference/` describes **vendor products**, never a
deployment. Examples and IP addresses there must come from vendor
documentation, not from `data/`.

## 7. Tests

`unittest`, under `tests/`, run from the repository root:

```sh
uv run python -m unittest discover -s tests -v   # everything
uv run python -m unittest tests.test_db -v       # one file
```

Every new module ships its own `test_<module>.py`. Tests use a temporary
`SENTINELNET_DATA_DIR`, never real state.

## 8. Documentation

A change that invalidates a line in `docs/` is not finished until that line is
corrected. A decision that changes an invariant gets an
[ADR](docs/adr/README.md).
