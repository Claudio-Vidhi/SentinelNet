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

Only two branches matter: `Dev` and `master`, and **they have the same
content**. No strip, no dev-only exclusions: what is committed on `Dev` is
what the world sees.

- Work lands on `Dev` first. Publishing is one command, always a
  fast-forward:

  ```sh
  git push origin Dev:master
  ```

- `master` is not a merge and never has been. It is now simply the commit
  `Dev` points at. Nothing is ever merged from `master` back into `Dev`:
  there is nothing there that is not already here.
- **This means the privacy boundary is `git add`, not the branch.** The old
  strip hid `tests/`, `AGENTS.md`, the plans and the CI templates from the
  public branch as a side effect; that accident is gone. Before committing a
  file, the question is not "is this dev-only?" but "would I publish this?".
  See **Protect real data** below and run
  `uv run python scripts/check_no_private_data.py`.
- The strip existed because `master` was meant for someone who had never seen
  SentinelNet. That audience is still served by `README.md` being the first
  thing they read — not by hiding the test suite from them. A contributor who
  can run the gate is worth more than a tidy file listing.
- If the two branches ever diverge (someone committed straight to `master`),
  the fix is to bring that commit onto `Dev` and publish again, never to
  merge `master` into `Dev`.


## Software Versioning (SemVer)
- Single source of truth is `core/version.py` (`__version__ = "X.Y.Z"`); `pyproject.toml` must match it. Update both.
- **PATCH**: bug fixes, security patches, minor UI refinements.
- **MINOR**: new features, new modules/tabs, vendor engines, significant architectural updates.
- **MAJOR**: breaking API/schema changes, incompatible DB changes.

## Protect real data (repo is PUBLIC on GitHub)

**Every tracked file is published.** `Dev` and `master` carry the same tree, so
there is no branch left that quietly keeps something private. The boundary is
`git add`.

- `data/` and `agent-data/` are gitignored **as directories**, not file by
  file: a new state file the code writes there is ignored the moment it
  appears, without anyone remembering to add a rule. Keep it that way — a
  per-file list is one forgotten line away from a leak.
- **Facts derived from customer data are as sensitive as the files.** Never
  write device models, software versions, hostnames, serial numbers,
  management IPs or topology roles into tracked files — code, docs, comments,
  commit messages.
- Using real backups to verify a parser: correct. Writing what they revealed
  about a customer network into the repo: not.
- **Always use example data instead.** `192.0.2.x` / `198.51.100.x` /
  `203.0.113.x` (RFC 5737), private ranges, `switch-01`, `<hostname>`,
  `AA:BB:CC:DD:EE:FF`, vendor-doc examples. Never a real value, even "just as
  an illustration". A real OUI with a real host part counts as a real value.
- Security findings that name unfixed issues at `file:line` stay under
  `data/security/`, which is ignored with the rest of `data/`.
- **The check is not a matter of memory.** `scripts/check_no_private_data.py`
  scans every tracked file for public IPs, tracked state files and pasted
  secrets, and `tests/test_no_private_data.py` runs it inside the suite. A
  line that legitimately must contain a public address (a vendor manual's
  example) is marked with the comment `check-private-data: ok`, which is
  reviewable — silently widening the scanner's allow-list is not.
- A state file that must live outside `data/` needs its `.gitignore` entry in
  the same change that creates it, before the tool runs against a real
  network. Verify with `git status --porcelain` printing nothing for it.


## Before each commit

Applies to every branch. Full checklist: `docs/development.md` §6 — that is the
canonical list, do not restate it here.

Non-negotiable, verify by running them and reading the output:

```sh
uv run pyrefly check                          # 0 errors
uv run python scripts/check_frontend.py       # if static/js or templates/ changed
uv run pytest tests -n 4                      # all green
uv run python scripts/check_no_private_data.py  # nessun dato di cliente
graphify update .                             # after code changes
```

Never claim a check passed without having run it.

## Verification

The README screenshots live in `docs/images/` and are regenerated with
`uv run python scripts/dev/capture_screenshots.py`. Rerun it when the UI
changes visibly: no test catches a stale screenshot.


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
