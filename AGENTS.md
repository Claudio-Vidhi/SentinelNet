# Agent Rules

Canonical for this repo. `CLAUDE.md` and `.agents/AGENTS.md` point here.

## Communication Style
- Respond like caveman: drop articles and filler, no preamble, no postamble.
- Execute first, explain only if asked.

## Coding Style
- Keep all technical accuracy.
- Don't add features, refactor, or introduce abstractions beyond what task requires.
- Bug fix doesn't need surrounding cleanup. One-shot operation usually doesn't need helper.
- Don't design for hypothetical future requirements: do simplest thing that works well.
- Avoid premature abstraction and half-finished implementations.
- Don't add error handling, fallbacks, or validation for scenarios that cannot happen. Trust internal code and framework guarantees.
- Only validate at system boundaries (user input, external APIs).
- Don't use feature flags or backwards-compatibility shims when you can just change code.
- New and rewritten comments in English. Most of existing tree is commented in
  Italian: leave it alone. Mixed files are expected during migration — do not
  "fix" surrounding Italian comments as a drive-by.

## Software Versioning (SemVer)
- Single source of truth is `core/version.py` (`__version__ = "X.Y.Z"`); `pyproject.toml` must match it. Update both.
- **PATCH**: bug fixes, security patches, minor UI refinements.
- **MINOR**: new features, new modules/tabs, vendor engines, significant architectural updates.
- **MAJOR**: breaking API/schema changes, incompatible DB changes.

## Protect real data (repo is PUBLIC on GitHub)

- `data/` is gitignored because it holds real customer network state. **Facts
  derived from it are as sensitive as the files.** Never write device models,
  software versions, hostnames, serial numbers, management IPs or topology roles
  into tracked files — code, docs, comments, commit messages.
- Using real backups to verify a parser: correct. Writing what they revealed
  about a customer network into the repo: not.
- **Always use example data instead.** `192.0.2.x` / `198.51.100.x` (RFC 5737),
  `switch-01`, `<hostname>`, `AA:BB:CC:DD:EE:FF`, vendor-doc examples. Never a
  real value, even "just as an illustration".
- Security findings that name unfixed issues at `file:line` stay out of the
  public tree — see `.gitignore`.

## Before each commit

Applies to every branch. Full checklist: `docs/development.md` §6 — that is the
canonical list, do not restate it here.

Non-negotiable, verify by running them and reading the output:

```sh
uv run pyrefly check                          # 0 errors
uv run python scripts/check_frontend.py       # if static/js or templates/ changed
uv run pytest tests -n 4                      # all green
graphify update .                             # after code changes
```

Never claim a check passed without having run it.

## Verification

After editing a file in any language, run the compile/syntax/test check for it
before reporting completion — that is what catches `NameError`, `ImportError`,
`ReferenceError` and broken formatting.

Refactoring FastAPI routers: OpenAPI parity (`app.openapi()`) is not enough,
introspection never executes handler bodies and hides missing imports. Add
`TestClient` smoke tests hitting at least one route per router (401/403/422 are
fine, they prove the handler ran), and an actual connect for each WebSocket
endpoint. Delete intermediate scratch files before verifying.

## Frontend (`static/js` + `templates/dashboard.html`)

Classic scripts, one shared global scope, no bundler. Each rule below comes from
a bug that shipped:

- `core.js` globals (`globalDevices`, `globalGroups`, …) are declared `let`, so
  they are NOT `window` properties. Reading them as `window.X` always yields
  `undefined`, and the usual `|| []` fallback hides it.
- Exposing something cross-module means `window.X = ...` **and** an entry in
  `types/globals.d.ts`. An undeclared `window` property failing the check is the
  intended behaviour, not noise to silence.
- A delegated listener must bind to an id that exists in `dashboard.html`.
  `getElementById('missing')?.addEventListener` raises nothing and leaves the
  button silently dead.
- No inline handlers: the template has zero `onclick=`/`onsubmit=`. Use an id or
  `data-action` plus a delegated listener.
- Modules are lazy-loaded per tab via `LAZY_TAB_SCRIPTS` in `core.js`. A module
  that binds controls living in **another** tab needs an entry for that tab too,
  or that tab is dead when opened cold: the bindings never run, `switchTab`'s
  loader call throws `ReferenceError`, and the user sees an empty panel whose
  buttons do nothing — silently. `tests/test_lazy_tab_scripts.py` checks both
  halves for every lazy module; do not narrow its scope to silence it.

## graphify

`graphify-out/` holds an AST-derived knowledge graph of the codebase.

- For codebase questions run `graphify query "<question>"` first (graph.json
  exists). `graphify path "<A>" "<B>"` for relationships, `graphify explain
  "<concept>"` for focused concepts. These return a scoped subgraph, usually
  much smaller than GRAPH_REPORT.md or raw grep output.
- `graphify-out/wiki/index.md`, when present, beats raw source browsing for
  broad navigation.
- Read `graphify-out/GRAPH_REPORT.md` only for broad architecture review, or
  when query/path/explain do not surface enough.
- After modifying code, `graphify update .` (AST-only, no API cost).
