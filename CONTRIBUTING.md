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
- `db.get_observability_connection()` is a blocking connection: never in the
  body of an `async def`. Migrations, tests, worker threads and a helper
  handed to `asyncio.to_thread` may use it — that is how short transactional
  read-modify-writes (incident transitions, notification cursors) are done.
  `tests/test_no_sync_db_on_event_loop.py` enforces it.

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

An IP with no inventory row is **out of scope, not unscoped**. A route that
serves a stored artifact addressed by IP — a backup, its parsed analysis — must
deny it, because the artifact is read off disk by IP and outlives the device row
it belonged to. `assert_device_allowed` returns `None` for an unknown device and
raises nothing, so the caller owns that decision:

```python
# ✅ correct: unknown IP is refused
if scope is not None and (device is None
                          or device.get('Group', 'Generale') not in scope):
    raise HTTPException(status_code=403, detail="...")

# ❌ wrong: an IP absent from inventory skips the check entirely
if device is not None and scope is not None:
    ...
```

## 5. Single-process assumption

The SQLite writer is single-process. Do not start the app with `--workers > 1`
while observability is enabled; horizontal scaling is not supported for the
observability module.

## 6. Permanent security gates

| Gate | What it protects | Command | Expected |
|---|---|---|---|
| L-1 | Session JWT must not be readable by JavaScript — cookie only | `grep -c "sessionStorage" templates/dashboard.html` | No token usage |
| — | No blocking `sqlite3` on the event loop | `uv run pytest tests/test_no_sync_db_on_event_loop.py` | Green |
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

`unittest.TestCase` classes under `tests/`, run with pytest from the repository
root:

```sh
uv run pytest tests -n 4                         # everything
uv run pytest tests/test_db.py                   # one file
```

Do not use `unittest discover`: it collects only `TestCase` methods, so any
module-level `def test_*()` silently never runs. See
[docs/development.md](docs/development.md) §3.

Every new module ships its own `test_<module>.py`. Tests use a temporary
`SENTINELNET_DATA_DIR`, never real state.

## 8. Documentation

A change that invalidates a line in `docs/` is not finished until that line is
corrected. A decision that changes an invariant gets an
[ADR](docs/adr/README.md).

## 9. Licensing and provenance of contributions

SentinelNet is licensed **AGPL-3.0-only** from version 0.39.0 on. Versions up to
0.38.0 were Apache-2.0 and stay that way: that grant cannot be revoked.

Every source file carries a two-line header. New files must ship it, editors
must not strip it:

```python
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
```

This is not decoration. AGPL-3.0 §5(a) and the §7(b)/§7(c) additional terms in
`NOTICE` oblige anyone redistributing or modifying the code to keep those
notices. A file with no notice in it gives a downstream redistributor nothing to
preserve — which is exactly how attribution disappears.

`NOTICE` carries the §7 additional terms (trademark, attribution) and the
commercial-licence contact. Keep it short: it is a legal instrument, not a
credits roll.

### The network clause

AGPL §13 is the point of this licence: whoever **modifies** SentinelNet and lets
anyone use it over a network must offer those users the complete corresponding
source of their modified version. A change that would make that offer harder to
honour — bundling an opaque blob, moving logic behind a service the user cannot
rebuild — needs an [ADR](docs/adr/README.md) before it lands.

### Sign-off

Every commit is signed off, certifying the
[Developer Certificate of Origin](https://developercertificate.org/) 1.1 — that
you wrote the change, or have the right to submit it under this licence:

```sh
git commit -s -m "..."
```

### Contributor licence

By submitting a contribution you grant Claudio Vidhi a perpetual, worldwide,
irrevocable, royalty-free licence to use, reproduce, modify, distribute and
sublicense it, **including the right to release it under a different licence**,
present or future. You keep the copyright on what you wrote; this grant is what
makes the dual licence possible — commercial licences are sold on the whole
work, which is only lawful if one party can license all of it.

### Dependencies

A new dependency must be under a licence that can be combined into an AGPL-3.0
work (MIT, BSD, Apache-2.0, LGPL, GPL-3.0, AGPL-3.0). **Apache-2.0 is one-way**:
it flows into AGPL-3.0, never back out. GPL-2.0-only is incompatible and cannot
be added. Record every new component in `THIRD_PARTY_LICENSES.md`, with its
licence text under `LICENSES/` when that licence requires a copy to travel with
the binary.

### Name and logo

"SentinelNet" is an unregistered trademark, reserved under AGPL §7(e) in
`NOTICE`. A fork may use the code, not the name.
