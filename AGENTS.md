## Communication Style
- Respond like caveman.
- Drop articles (a, an, the).
- Drop filler words.
- No preamble.
- No postamble.
- Execute first, explain only if asked.

## Coding Style
- Keep all technical accuracy.
- Don't add features, refactor, or introduce abstractions beyond what task requires.
- Bug fix doesn't need surrounding cleanup.
- One-shot operation usually doesn't need helper.
- Don't design for hypothetical future requirements: do simplest thing that works well.
- Avoid premature abstraction and half-finished implementations.
- Don't add error handling, fallbacks, or validation for scenarios that cannot happen. Trust internal code and framework guarantees.
- Only validate at system boundaries (user input, external APIs).
- Don't use feature flags or backwards-compatibility shims when you can just change code.
- Code comments must be in english. Most of existing tree commented in Italian: leave alone, but write every new or rewritten comment in English, including in files whose other comments are Italian. Mixed files expected during migration — do not "fix" surrounding Italian comments as drive-by.

## Software Versioning (SemVer)
- Single source of truth is `core/version.py` (`__version__ = "X.Y.Z"`).
- `pyproject.toml` version must always match `core/version.py`.
- Bump version based on modification scope:
  - **PATCH** (`0.2.0` -> `0.2.1`): bug fixes, security patches, minor UI refinements.
  - **MINOR** (`0.2.0` -> `0.3.0`): new features, new modules/tabs, vendor engines, significant architectural updates.
  - **MAJOR** (`0.2.0` -> `1.0.0`): breaking API/schema changes, incompatible DB changes.
- When updating version, update both `core/version.py` and `pyproject.toml`.

## Protect real data (repo is PUBLIC on GitHub)

- `data/` is gitignored because it holds real customer network state. **Facts derived from it are as sensitive as files.** Never write device models, software versions, hostnames, serial numbers, management IPs or topology roles into tracked files — code, docs, comments, commit messages.
- Using real backups to verify parser: correct. Writing what they revealed about customer network into repo: not.
- **Always use example data instead.** `192.0.2.x` / `198.51.100.x` (RFC 5737), `switch-01`, `<hostname>`, `AA:BB:CC:DD:EE:FF`, vendor-doc examples. Never real value, even "just as illustration".
- Security findings that name unfixed issues at `file:line` stay out of public tree — see `.gitignore`.

## Before each commit

Applies to every branch. Full checklist: `docs/development.md` §6 — canonical list, do not restate here.

Non-negotiable, verify by running them and reading output:

```sh
uv run pyrefly check                          # 0 errors
uv run python scripts/check_frontend.py       # if static/js or templates/ changed
uv run pytest tests -n 4                      # all green
graphify update .                             # after code changes
```

Never claim check passed without having run it.

## Frontend (`static/js` + `templates/dashboard.html`)

Classic scripts, one shared global scope, no bundler. Each rule below comes from bug that shipped:

- `core.js` globals (`globalDevices`, `globalGroups`, …) declared `let`, so they are NOT `window` properties. Reading them as `window.X` always yields `undefined`, and usual `|| []` fallback hides it.
- Exposing something cross-module means `window.X = ...` **and** entry in `types/globals.d.ts`. Undeclared `window` property failing check is intended behaviour, not noise to silence.
- Delegated listener must bind to id that exists in `dashboard.html`. `getElementById('missing')?.addEventListener` raises nothing and leaves button silently dead.
- No inline handlers: template has zero `onclick=`/`onsubmit=`. Use id or `data-action` plus delegated listener.
- Modules lazy-loaded per tab via `LAZY_TAB_SCRIPTS` in `core.js`. Module that binds controls living in **another** tab needs entry for that tab too, or that tab dead when opened cold: bindings never run, `switchTab` loader call throws `ReferenceError`, and user sees empty panel whose buttons do nothing — silently. `tests/test_lazy_tab_scripts.py` checks both halves for every lazy module; do not narrow scope to silence it.

## FastAPI Refactoring & Destructuring
- **OpenAPI Parity is Insufficient**: When extracting or refactoring FastAPI routers, do not rely solely on OpenAPI schema parity (`app.openapi()`). Introspection does not execute handler bodies and will mask `NameError` or `ImportError` bugs.
- **Mandatory Smoke Tests**: Always add smoke test suite using `TestClient` that actually hits at least one route per router. Goal: verify handler executes without 500 server error (missing imports). 401/403/422 responses acceptable as they prove code ran.
- **WebSocket Coverage**: OpenAPI parity cannot cover WebSockets. Always write manual or automated check that actually connects to WebSocket endpoint to verify reader/writer paths.
- **Clean Commits**: Never leave intermediate scratch files (like orphaned route backups) in repository. Delete before verifying.

## Verification & Code Quality
- **Mandatory Import & Syntax Verification**: After editing any file in ANY programming language (Python, JS, HTML/CSS, Go, Bash, etc.), immediately run compilation, syntax, or test suite checks to catch missing imports (`NameError`, `ImportError`, `ReferenceError`) and broken formatting before reporting completion.

## graphify

Knowledge graph at graphify-out/ with god nodes, community structure, cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. Return scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep graph current (AST-only, no API cost).
