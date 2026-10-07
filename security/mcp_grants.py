# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Browser sign-in for the MCP bridge: no password in the client's config.

The flow is OAuth's loopback redirect with PKCE (RFC 8252 + RFC 7636), cut to
what one server and one bridge need:

1. The bridge listens on 127.0.0.1, makes a PKCE verifier and opens the
   dashboard with ``?mcp_authorize=1&port=&state=&challenge=``.
2. The operator signs in as usual (password or SSO) and approves.
   ``create_code`` binds a one-time code to that user and challenge; the page
   sends the browser to the bridge's loopback port with it.
3. The bridge trades code + verifier for a grant token (``redeem_code``) and
   keeps it in the OS keychain.
4. Each bridge start trades the grant for a normal short-lived JWT
   (``user_for_grant``), so every route keeps its usual checks.

Only the SHA-256 of a grant token is stored. A grant dies when revoked, when
its user is deleted, disabled or pending, and on "sign out everywhere"
(it remembers the session epoch it was issued under).
"""
import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Optional

from core import data_config
from security import user_manager

CODE_TTL_SECONDS = 120
TOKEN_PREFIX = "snmcp_"

_lock = threading.RLock()
# One-time codes live in memory: they last two minutes, and a restart in
# between only means approving again.
_codes: "dict[str, dict]" = {}


def _path() -> str:
    return data_config.get_path("mcp_grants.json")


def _load() -> dict:
    try:
        with open(_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save(grants: dict) -> None:
    data_config.atomic_write(_path(), grants, restrict=True)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def challenge_for(verifier: str) -> str:
    """PKCE S256: base64url(sha256(verifier)) without padding."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def create_code(username: str, challenge: str, label: str, read_only: bool) -> str:
    """``label`` names the client on the grant list; ``read_only`` makes every
    session of the grant a viewer session whatever the user's role."""
    code = secrets.token_urlsafe(32)
    now = time.time()
    with _lock:
        for k in [k for k, v in _codes.items() if v["exp"] <= now]:
            _codes.pop(k, None)
        _codes[code] = {"user": username, "challenge": challenge, "label": label[:80],
                        "read_only": read_only, "exp": now + CODE_TTL_SECONDS}
    return code


def redeem_code(code: str, verifier: str) -> Optional[dict]:
    """Single use: the code is gone whatever the outcome. Returns
    ``{"token", "user"}`` or None."""
    with _lock:
        entry = _codes.pop(code, None)
    if not entry or entry["exp"] <= time.time():
        return None
    if not hmac.compare_digest(challenge_for(verifier), entry["challenge"]):
        return None
    username = entry["user"]
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    with _lock:
        grants = _load()
        grants[secrets.token_hex(8)] = {
            "user": username,
            "hash": _hash(token),
            "label": entry["label"],
            "read_only": entry["read_only"],
            "sep": user_manager.session_epoch(username),
            "created": int(time.time()),
            "last_used": None,
        }
        _save(grants)
    return {"token": token, "user": username}


def user_for_grant(token: str) -> Optional[dict]:
    """``{"user", "read_only"}`` the grant token speaks for, or None if it
    no longer does."""
    if not token.startswith(TOKEN_PREFIX):
        return None
    h = _hash(token)
    with _lock:
        grants = _load()
        gid = next((k for k, g in grants.items()
                    if hmac.compare_digest(g.get("hash", ""), h)), None)
        if gid is None:
            return None
        g = grants[gid]
        user = g["user"]
        if (user_manager.get_role(user) is None or user_manager.is_disabled(user)
                or user_manager.is_pending(user)
                or int(g.get("sep", 0)) != user_manager.session_epoch(user)):
            return None
        g["last_used"] = int(time.time())
        _save(grants)
    return {"user": user, "read_only": bool(g.get("read_only"))}


def list_grants(user: Optional[str] = None) -> list:
    """Every grant, or only ``user``'s."""
    with _lock:
        grants = _load()
    if user is not None:
        grants = {k: g for k, g in grants.items() if g.get("user") == user}
    return [{"id": k, "user": g.get("user"), "label": g.get("label", ""),
             "read_only": bool(g.get("read_only")),
             "created": g.get("created"), "last_used": g.get("last_used")}
            for k, g in sorted(grants.items(), key=lambda kv: kv[1].get("created") or 0)]


def revoke(grant_id: str, user: Optional[str] = None) -> Optional[str]:
    """Deletes the grant (only if it is ``user``'s, when given); returns its
    user, or None if there was none."""
    with _lock:
        grants = _load()
        g = grants.get(grant_id)
        if g is None or (user is not None and g.get("user") != user):
            return None
        grants.pop(grant_id)
        _save(grants)
    return g.get("user")
