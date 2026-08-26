# -*- coding: utf-8 -*-
"""Single-use password reset tokens.

The store is a process-local dict, like the login lockout counters in
security_manager: tokens live 15 minutes and the server is a single uvicorn
process, so a restart invalidating a pending link is an acceptable cost for
keeping recovery state off disk entirely. Nothing here survives a restart, and
nothing here needs to.

Only the SHA-256 of the token is kept, so a memory dump does not yield a usable
link.
"""
import hashlib
import secrets
import time

# ponytail: single process. A multi-worker deployment needs a shared store
# (Redis, or the SQLite writer queue) — the dict would then only cover one
# worker and every other one would reject the token.
_tokens: dict[str, tuple[str, float]] = {}

TTL_SECONDS = 15 * 60


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _purge(now: float) -> None:
    for key in [k for k, (_u, exp) in _tokens.items() if exp <= now]:
        del _tokens[key]


def issue(username: str) -> str:
    """Creates a token for the user and returns it. The caller mails it and
    must not log it: it is a bearer credential until used or expired."""
    now = time.time()
    _purge(now)
    token = secrets.token_urlsafe(32)
    _tokens[_digest(token)] = (username, now + TTL_SECONDS)
    return token


def consume(token: str):
    """Returns the username and burns the token, or None when the token is
    unknown, already used or expired. Single use is enforced here rather than
    by the caller, so no code path can redeem one twice."""
    now = time.time()
    _purge(now)
    entry = _tokens.pop(_digest(token), None)
    if entry is None:
        return None
    username, expires_at = entry
    return username if expires_at > now else None


def clear() -> None:
    """Drops every pending token. Used by the tests."""
    _tokens.clear()
