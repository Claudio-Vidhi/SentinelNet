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

## Branches

Only two branches matter: `Dev` and `master`. They carry the **same app
features and the same fixes** — a change landing on one belongs on the other.

- A new branch merges into `Dev` first. `Dev` → `master` after that, never
  straight to `master`.
- `master` is the public branch: it holds the product with dev-only files
  stripped (`tests/`, `tests_data/`, `AGENTS.md`, `.claude/`, `.agents/`,
  `scripts/dev/`, the dev-only `docs/` and helper scripts). That strip is the
  *only* thing that may differ — never app code, never `.gitignore`.
- So `master` carries no test suite. Verify on `Dev`, where the gate runs,
  then port. Never `git merge --ff-only master` from `Dev`: master's history
  contains those deletions, and fast-forwarding would wipe `Dev`'s tests.

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
- **New state file under `data/` → `.gitignore` entry in the same change, before
  the user runs the tool.** `data/` is ignored file by file, not wholesale: a
  new `data/*.json` (or `.db`, `.db-shm`, `.db-wal`, and any sibling the code
  writes) is tracked by default. As soon as the feature runs once against a real
  network that file fills with customer state, and the next `git add` leaks it.
  Add the ignore rule while writing the code that creates the file, never after
  testing, and verify with `git status --porcelain data/` printing nothing.

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
- User-facing strings go through `tr('key')` (i18n.js), never an inline
  `currentLang === 'en' ? ... : ...`. The dictionary holds both languages;
  `scripts/check_i18n_coverage.py --strict` and `tests/test_i18n_keys.py`
  fail on a ternary, an Italian-only alert, or a key missing from `en`.
  The function is `tr` and not `t` because `t` is already the name of a
  dozen local variables in this one shared scope.
- Modals open with `openModal(id[, onClose])` and close with
  `closeModal(id)` (`ui-modal.js`): the manager adds `role="dialog"`,
  `aria-modal`, the focus trap, Esc and the backdrop click. Toggling
  `style.display` by hand skips all of it and fails
  `tests/test_ui_modal.py`.
- A new form control needs an accessible name — a `<label for>` or
  `aria-label` + `data-i18n-aria-label`. `scripts/check_a11y.py --strict`
  is at zero and `tests/test_a11y_dashboard.py` keeps it there.
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
