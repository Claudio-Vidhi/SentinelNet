# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Single-use tokens proving a user controls a new recovery address.

Same shape as password_reset and user_invite: process-local, hashed, single
use. The recovery address decides where reset links go, so a user changing it
must prove the new mailbox is theirs; otherwise a stolen session could point
recovery at an attacker's address and keep the account after a password change.
"""
import hashlib
import secrets
import time

# ponytail: single process, like password_reset.
_tokens: dict[str, tuple[tuple[str, str], float]] = {}

TTL_SECONDS = 60 * 60


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _purge(now: float) -> None:
    for key in [k for k, (_p, exp) in _tokens.items() if exp <= now]:
        del _tokens[key]


def issue(username: str, email: str) -> str:
    now = time.time()
    _purge(now)
    token = secrets.token_urlsafe(32)
    _tokens[_digest(token)] = ((username, email), now + TTL_SECONDS)
    return token


def consume(token: str):
    """Returns (username, email) and burns the token, or None when unknown,
    already used or expired."""
    now = time.time()
    _purge(now)
    entry = _tokens.pop(_digest(token), None)
    if entry is None:
        return None
    payload, expires_at = entry
    return payload if expires_at > now else None


def clear() -> None:
    """Drops every pending token. Used by the tests."""
    _tokens.clear()
