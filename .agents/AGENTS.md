# Agent Rules

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
- Code comments only in english

## Software Versioning (SemVer)
- Single source of truth is `core/version.py` (`__version__ = "X.Y.Z"`).
- `pyproject.toml` version must always match `core/version.py`.
- Bump version based on modification scope:
  - **PATCH** (`0.2.0` -> `0.2.1`): bug fixes, security patches, minor UI refinements.
  - **MINOR** (`0.2.0` -> `0.3.0`): new features, new modules/tabs, vendor engines, significant architectural updates.
  - **MAJOR** (`0.2.0` -> `1.0.0`): breaking API/schema changes, incompatible DB changes.
- When updating version, update both `core/version.py` and `pyproject.toml`.

## FastAPI Refactoring & Destructuring
- **OpenAPI Parity is Insufficient**: When extracting or refactoring FastAPI routers, do not rely solely on OpenAPI schema parity (`app.openapi()`). Introspection does not execute handler bodies and will mask `NameError` or `ImportError` bugs.
- **Mandatory Smoke Tests**: Always add a smoke test suite using `TestClient` that actually hits at least one route per router. The goal is to verify the handler executes without a 500 server error (missing imports). 401/403/422 responses are acceptable as they prove the code ran.
- **WebSocket Coverage**: OpenAPI parity cannot cover WebSockets. Always write a manual or automated check that actually connects to the WebSocket endpoint to verify reader/writer paths.
- **Clean Commits**: Never leave intermediate scratch files (like orphaned route backups) in the repository. Delete them before verifying.

## Verification & Code Quality
- **Mandatory Import & Syntax Verification**: After editing any file in ANY programming language (Python, JS, HTML/CSS, Go, Bash, etc.), immediately run compilation, syntax, or test suite checks to catch missing imports (`NameError`, `ImportError`, `ReferenceError`) and broken formatting before reporting completion.
