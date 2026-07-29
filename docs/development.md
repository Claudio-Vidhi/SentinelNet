# Development

The binding rules — language, dual artifact, async-DB, multi-group scope,
security gates — are in [CONTRIBUTING.md](../CONTRIBUTING.md). This document
does not repeat them; it covers layout, tests and build.

---

## 1. Setup

```sh
uv venv
uv pip install -r requirements.txt
uv run app_server.py
```

`pyproject.toml` declares `requires-python = ">=3.14"`; the root README still
says 3.11+. The compiled artifacts in the tree are CPython 3.14 — treat
`pyproject.toml` as authoritative and don't assume 3.11 works.

---

## 2. Layout

Flat by design. No `src/`, no package nesting beyond one level.

| Folder | Rule of thumb |
|---|---|
| `core/` | Infrastructure everyone depends on: DB writer, path/config resolution, SSH engine |
| `observability/` | The event → evidence → incident pipeline; `ingesters/` holds the decoders |
| `collectors/` | Data collected over SSH/NETCONF/RESTCONF (ARP, MAC, scan) |
| `routers/` | One FastAPI router per area. HTTP concerns only: validation, RBAC, shaping |
| `services/` | Business logic reused by routers, MCP and agents |
| `security/` | Everything that authenticates, authorizes, encrypts or redacts |
| `ai/` | LLM assistant, config analyzer, MCP server and client |
| `drivers/` | One per vendor, subclassing `BaseDriver` |
| `static/js/` | One file per tab, no business logic |
| `tests/` | One `test_<module>.py` per module |

Where does new code go? If a router needs more than validation + a call + a
response shape, the excess belongs in `services/` or `observability/`. The
reason [app_server.py](../app_server.py) is 200-odd lines is that this line was
held.

**Naming convention:** Italian for user-facing strings, logs, errors, comments
and docstrings; English for identifiers. See
[CONTRIBUTING.md](../CONTRIBUTING.md) §1. New documentation in `docs/` is
written in English.

---

## 3. Tests

`unittest`. Each test sets a temporary `SENTINELNET_DATA_DIR` **before**
importing project modules — that ordering is load-bearing, since
`data_config.DATA_DIR` is resolved at import time.

```sh
uv run python -m unittest discover -s tests -v     # everything
uv run python -m unittest tests.test_db -v         # one file
```

Run from the repository root, and use the module path form.
`uv run python tests/test_db.py` fails with `ModuleNotFoundError: core`,
because that puts `tests/` on `sys.path` instead of the root. (The instruction
in [CONTRIBUTING.md](../CONTRIBUTING.md) §7 predates the move into `tests/`.)

Every new module ships its own `test_<module>.py`. Tests never touch real state.

Three tests are structural rather than functional, and a failure means something
different from a normal one:

| Test | What it protects |
|---|---|
| `test_router_parity.py` | The OpenAPI schema must match the golden snapshot in `tests_data/`. A failure means an endpoint changed shape. Regenerate the snapshot (`uv run python scripts/snapshot_openapi.py`) **only** for deliberate additions, never to make the test pass |
| `test_router_smoke.py` | Every router is importable and mountable |
| `test_observability_ui.py` | Tab markup and wiring — catches JS/HTML drift the Python tests can't see |

The permanent security gates (`test_provisioning_secrets.py`,
`test_redaction.py`, `test_tls_config.py`, plus the grep checks) are listed in
[CONTRIBUTING.md](../CONTRIBUTING.md) §6. They are not optional.

---

## 4. Type checking

```sh
pyrefly check
```

Configured in `pyproject.toml`, which excludes `.venv/`, `build/`, `dist/` and
`tests/`.

---

## 5. Build

```powershell
pwsh scripts/build.ps1          # pyinstaller + smoke test
docker compose build
```

Both artifacts must stay buildable on every change
([CONTRIBUTING.md](../CONTRIBUTING.md) §2). Details on the smoke test and on
`SentinelNet.spec` `datas`: [operations.md](operations.md) §6.

There is no CI. It was removed deliberately — the build is local and stays
local.

---

## 6. Pre-commit checklist

1. `pyrefly check` clean on the modified files.
2. Full test suite green.
3. New data files added to `SentinelNet.spec`, verified in source / exe / Docker.
4. Documentation touched by the change updated (see the maintenance rule in
   [README.md](README.md)); a decision that changes an invariant gets an
   [ADR](adr/).
5. `graphify update .` to keep the knowledge graph current.

---

## 7. Knowledge graph

`graphify-out/` holds an AST-derived graph of the codebase. For "where is X"
and "what touches Y" questions it's faster than grepping:

```sh
graphify query "<question>"
graphify path "<A>" "<B>"
graphify explain "<concept>"
graphify update .        # after changing code
```

It answers *how* the code is wired. It does not answer *why* — that's what
`docs/` is for.
