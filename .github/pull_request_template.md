## What this changes

<!-- One paragraph: the behaviour before, the behaviour after, and why. -->

## Why

<!-- The problem this solves. Link the issue if there is one. -->

## Checklist

Rules in full: [CONTRIBUTING.md](../CONTRIBUTING.md).

- [ ] Targets `Dev`, not `master` — `master` is the public branch and carries no test suite.
- [ ] Tests added or updated on `Dev`, and `uv run pytest tests -n 4` is green.
- [ ] Language convention respected: Italian for user-facing strings, logs, errors and comments; English for identifiers; English for `docs/`.
- [ ] New user-facing strings go through the `it`/`en` dictionaries in `static/js/i18n.js` — no inline `currentLang === 'en' ? …` ternaries.
- [ ] No `sqlite3` used directly on an async path (`await db.read(...)` / `db.enqueue_write(...)` instead).
- [ ] Authorization uses the multi-group scope (`user_group_scope`), never a scalar `user.group`.
- [ ] Both artifacts still build: `uv run pyinstaller SentinelNet.spec` and `docker compose build`. New data files added to `datas` in `SentinelNet.spec`.
- [ ] `core/version.py` and `pyproject.toml` bumped together, if this is a release.
- [ ] No credentials, tokens, customer hostnames or IPs in the diff — including in tests and fixtures.
