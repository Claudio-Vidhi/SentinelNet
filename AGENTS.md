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
uv run python -m unittest discover -s tests   # all green
graphify update .                             # after code changes
```

Never claim a check passed without having run it.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
