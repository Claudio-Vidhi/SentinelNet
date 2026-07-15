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

## FastAPI Refactoring & Destructuring
- **OpenAPI Parity is Insufficient**: When extracting or refactoring FastAPI routers, do not rely solely on OpenAPI schema parity (`app.openapi()`). Introspection does not execute handler bodies and will mask `NameError` or `ImportError` bugs.
- **Mandatory Smoke Tests**: Always add a smoke test suite using `TestClient` that actually hits at least one route per router. The goal is to verify the handler executes without a 500 server error (missing imports). 401/403/422 responses are acceptable as they prove the code ran.
- **WebSocket Coverage**: OpenAPI parity cannot cover WebSockets. Always write a manual or automated check that actually connects to the WebSocket endpoint to verify reader/writer paths.
- **Clean Commits**: Never leave intermediate scratch files (like orphaned route backups) in the repository. Delete them before verifying.
