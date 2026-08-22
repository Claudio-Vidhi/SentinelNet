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
| `test_i18n_parity.py` | Every i18n key exists in both `it` and `en` language dictionaries in `static/js/i18n.js` |

The permanent security gates (`test_provisioning_secrets.py`,
`test_redaction.py`, `test_tls_config.py`, plus the grep checks) are listed in
[CONTRIBUTING.md](../CONTRIBUTING.md) §6. They are not optional.

---

## 4. Type checking

```sh
pyrefly check                              # Python
uv run python scripts/check_frontend.py    # static/js
```

`pyrefly` is configured in `pyproject.toml`, which excludes `.venv/`, `build/`,
`dist/` and `tests/`.

The frontend check runs TypeScript in `checkJs` mode over `static/js` — types
only, no bundler, no build artifact, no change to how the files are served. One
`npm install` in the project root is needed first; `node_modules/` is
gitignored.

It exists because 23k lines of JS previously had no static analysis at all, and
the resulting bugs were all the same shape: a name that must match something in
another file, checked by nobody. `window.globalDevices` read a property that
never existed (`globalDevices` is a `let` in `core.js`, so it lives in the
global lexical scope, not on `window`), and the `|| []` fallback turned that
into an empty device list instead of a crash.

`scripts/check_frontend.py` filters roughly 900 structural DOM complaints that
unannotated JS cannot avoid — `getElementById()` returns `HTMLElement`, so every
`.value` is flagged; `e.target` is `EventTarget`, so every `.closest()` is.
Everything else fails the check. Never widen that filter to cover
`Window & typeof globalThis`: that is precisely the case worth seeing.

`types/globals.d.ts` records the cross-module contract — every `window.X = ...`
a module exposes for another to call. Add an entry only together with the
assignment it describes; an undeclared `window` property is meant to be an
error.

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
2. `uv run python scripts/check_frontend.py` clean, if the change touched
   `static/js` or `templates/`.
3. Full test suite green.
4. New data files added to `SentinelNet.spec`, verified in source / exe / Docker.
5. Documentation touched by the change updated (see the maintenance rule in
   [README.md](README.md)); a decision that changes an invariant gets an
   [ADR](adr/).
6. `graphify update .` to keep the knowledge graph current.

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
