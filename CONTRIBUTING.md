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

| Gate | Command | Expected |
|---|---|---|
| Token in sessionStorage (L-1) | `grep -c "sessionStorage" templates/dashboard.html` | No token usage |
| sqlite3 on async paths | `grep -n "get_observability_connection" app_server.py routers/ observability/ingesters/` | Migrations and tests only |
| Cleartext secrets in the provisioner (I-2) | `tests/test_provisioning_secrets.py` | Green |
| LLM redaction (I-1) | `tests/test_redaction.py` | Green |
| TLS fail-closed (H-1) | `tests/test_tls_config.py` | Green |

Finding identifiers refer to [docs/security-audit.md](docs/security-audit.md).

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
