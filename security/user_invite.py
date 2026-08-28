# -*- coding: utf-8 -*-
"""Single-use user invitation tokens.

Same shape and same trade-off as password_reset: process-local, hashed, single
use. The payload is what the administrator decided at invite time — address and
role — so redeeming an invitation cannot widen the role it was issued for.

Kept separate from password_reset rather than sharing a store: the two have
different lifetimes (24 hours against 15 minutes) and a redeemed invite creates
an account while a redeemed reset only changes one. Merging them would mean a
token-type flag on every read, to save twenty lines.
"""
import hashlib
import secrets
import time

# ponytail: single process, like password_reset. A multi-worker deployment
# needs a shared store or every worker but one rejects the invitation.
_invites: dict[str, tuple[tuple[str, str], float]] = {}

TTL_SECONDS = 24 * 60 * 60


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _purge(now: float) -> None:
    for key in [k for k, (_p, exp) in _invites.items() if exp <= now]:
        del _invites[key]


def issue(email: str, role: str) -> str:
    """Creates an invitation for an address and role, returning the token."""
    now = time.time()
    _purge(now)
    token = secrets.token_urlsafe(32)
    _invites[_digest(token)] = ((email, role), now + TTL_SECONDS)
    return token


def consume(token: str):
    """Returns (email, role) and burns the invitation, or None when the token
    is unknown, already redeemed or expired."""
    now = time.time()
    _purge(now)
    entry = _invites.pop(_digest(token), None)
    if entry is None:
        return None
    payload, expires_at = entry
    return payload if expires_at > now else None


def clear() -> None:
    """Drops every pending invitation. Used by the tests."""
    _invites.clear()
