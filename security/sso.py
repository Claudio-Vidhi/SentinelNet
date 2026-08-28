# -*- coding: utf-8 -*-
"""OpenID Connect single sign-on (authorization code + PKCE).

The point of this module is the verification in `verify_id_token`. An id_token
is a bearer assertion about who the caller is, and its claims decide whether
they become an administrator here: decoding the payload without checking the
signature would let anyone who can reach the callback mint their own identity.
So the token is verified against the provider's published keys, with issuer,
audience, expiry and the per-login nonce all asserted, and only asymmetric
algorithms accepted — `none` and the HMAC family are refused outright.

Login state (nonce and PKCE verifier) lives in a process-local dict, like the
other short-lived secrets in this package.
"""
import base64
import hashlib
import secrets
import time
from urllib.parse import urlencode

import jwt
import requests

from core.app_settings import get_app_settings, save_app_settings

# Firme asimmetriche soltanto: mai "none", mai HMAC.
ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"]
STATE_TTL_SECONDS = 10 * 60
CLOCK_SKEW_SECONDS = 60
_HTTP_TIMEOUT = 15

# ponytail: single process, like password_reset and user_invite.
_states: dict[str, tuple[str, str, float]] = {}

# Il documento di discovery cambia raramente: una cache breve evita una
# richiesta all'IdP per ogni singolo passo del login.
_discovery_cache: dict[str, tuple[dict, float]] = {}
_DISCOVERY_TTL = 10 * 60


class SSOError(RuntimeError):
    """Configuration or protocol failure, safe to show to the user."""


def get_config() -> dict:
    """Stored SSO configuration with defaults applied."""
    cfg = get_app_settings().get("sso") or {}
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "provider_name": cfg.get("provider_name") or "Single Sign-On",
        "client_id": (cfg.get("client_id") or "").strip(),
        "client_secret_enc": cfg.get("client_secret_enc") or "",
        "issuer_url": (cfg.get("issuer_url") or "").strip().rstrip("/"),
        "default_role": cfg.get("default_role") or "viewer",
        "admin_group": (cfg.get("admin_group") or "").strip(),
        "operator_group": (cfg.get("operator_group") or "").strip(),
        # Chi non ha ancora un account NON ne ottiene uno per il solo fatto di
        # esistere nell'IdP: su una directory aziendale sarebbe l'intera
        # rubrica, non gli operatori di rete.
        "auto_provision": bool(cfg.get("auto_provision", False)),
        # I gruppi dell'IdP non sovrascrivono un ruolo deciso qui, salvo che
        # l'amministratore lo chieda: altrimenti un declassamento locale
        # tornerebbe indietro al login successivo.
        "sync_roles": bool(cfg.get("sync_roles", False)),
    }


def save_config(cfg: dict) -> None:
    save_app_settings({"sso": cfg})


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def discover(issuer_url: str) -> dict:
    """Fetches (and briefly caches) the provider's OpenID configuration."""
    if not issuer_url:
        raise SSOError("URL dell'issuer non configurato.")
    cached = _discovery_cache.get(issuer_url)
    if cached and cached[1] > time.time():
        return cached[0]
    url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    try:
        resp = requests.get(url, timeout=_HTTP_TIMEOUT)
        resp.raise_for_status()
        doc = resp.json()
    except (requests.RequestException, ValueError) as e:
        raise SSOError(f"Discovery OIDC fallita: {e}") from e
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if not doc.get(field):
            raise SSOError(f"Discovery OIDC incompleta: manca '{field}'.")
    _discovery_cache[issuer_url] = (doc, time.time() + _DISCOVERY_TTL)
    return doc


def start_login(cfg: dict, redirect_uri: str) -> str:
    """Returns the authorization URL to redirect the browser to.

    Generates state, nonce and a PKCE verifier and keeps them server-side: the
    callback is trusted only if it returns a state we issued, and the code can
    be exchanged only by whoever holds the matching verifier.
    """
    doc = discover(cfg["issuer_url"])
    now = time.time()
    for key in [k for k, (_n, _v, exp) in _states.items() if exp <= now]:
        del _states[key]

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    _states[_digest(state)] = (nonce, verifier, now + STATE_TTL_SECONDS)

    params = {
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    sep = "&" if "?" in doc["authorization_endpoint"] else "?"
    return doc["authorization_endpoint"] + sep + urlencode(params)


def consume_state(state: str):
    """Returns (nonce, code_verifier) once for a state we issued, else None."""
    now = time.time()
    entry = _states.pop(_digest(state), None)
    if entry is None:
        return None
    nonce, verifier, expires_at = entry
    return (nonce, verifier) if expires_at > now else None


def exchange_code(cfg: dict, code: str, verifier: str, redirect_uri: str,
                  client_secret: str) -> dict:
    """Trades the authorization code for tokens over the back channel."""
    doc = discover(cfg["issuer_url"])
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": cfg["client_id"],
        "code_verifier": verifier,
    }
    if client_secret:
        data["client_secret"] = client_secret
    try:
        resp = requests.post(doc["token_endpoint"], data=data, timeout=_HTTP_TIMEOUT)
    except requests.RequestException as e:
        raise SSOError(f"Richiesta del token fallita: {e}") from e
    if resp.status_code != 200:
        raise SSOError(f"Scambio del codice rifiutato dall'IdP (HTTP {resp.status_code}).")
    try:
        tokens = resp.json()
    except ValueError as e:
        raise SSOError("Risposta del token endpoint non valida.") from e
    if not tokens.get("id_token"):
        raise SSOError("L'IdP non ha restituito un id_token.")
    return tokens


def verify_id_token(cfg: dict, id_token: str, nonce: str) -> dict:
    """Verifies signature, issuer, audience, expiry and nonce, and returns the
    claims. Every failure raises: there is no partially trusted token."""
    doc = discover(cfg["issuer_url"])
    try:
        signing_key = jwt.PyJWKClient(doc["jwks_uri"]).get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=ALLOWED_ALGORITHMS,
            audience=cfg["client_id"],
            issuer=doc["issuer"],
            leeway=CLOCK_SKEW_SECONDS,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as e:
        raise SSOError(f"id_token non valido: {e}") from e
    except Exception as e:  # rete irraggiungibile o JWKS malformato
        raise SSOError(f"Verifica dell'id_token non riuscita: {e}") from e

    # Il nonce lega il token alla richiesta di login appena partita: senza il
    # confronto, un id_token catturato altrove sarebbe riutilizzabile.
    if claims.get("nonce") != nonce:
        raise SSOError("Nonce non corrispondente: possibile replay del login.")
    return claims


def resolve_username(claims: dict) -> str:
    """Stable local identity for the authenticated subject."""
    for key in ("preferred_username", "email", "sub"):
        value = (claims.get(key) or "").strip()
        if value:
            return value
    raise SSOError("L'IdP non ha fornito un identificativo utente utilizzabile.")


def resolve_role(cfg: dict, claims: dict) -> str:
    """Maps the token's groups to a local role, admin winning over operator."""
    groups = []
    for key in ("groups", "roles"):
        value = claims.get(key)
        if isinstance(value, str):
            groups.append(value)
        elif isinstance(value, (list, tuple)):
            groups.extend(str(g) for g in value)
    lowered = {g.strip().lower() for g in groups if g}

    if cfg["admin_group"] and cfg["admin_group"].lower() in lowered:
        return "admin"
    if cfg["operator_group"] and cfg["operator_group"].lower() in lowered:
        return "operator"
    return cfg["default_role"]


def clear() -> None:
    """Drops pending login states and the discovery cache. Used by the tests."""
    _states.clear()
    _discovery_cache.clear()
