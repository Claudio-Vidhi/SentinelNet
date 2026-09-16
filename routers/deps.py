# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Dipendenze FastAPI condivise: autenticazione (cookie HttpOnly O Bearer,
con prova anti-CSRF sul cookie) e scoping multi-gruppo per sede.

Spostate qui da app_server.py (fase 2.1 del piano) per essere riusate dai
router modulari senza import circolari. I router importano direttamente da
questo modulo (il vecchio reimport in app_server, senza consumatori, e'
stato rimosso).

REGOLA (CONTRIBUTING.md §4): lo scope utente è un SET di gruppi
(``user_group_scope`` → set | None). Mai ridurlo a un singolo gruppo scalare.
"""

from typing import Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from services import inventory_manager
from security import user_manager
from security.security_manager import verify_access_token

security_scheme = HTTPBearer(auto_error=False)

SESSION_COOKIE = "net_session"
# Metodi che modificano stato: su autenticazione via cookie richiedono la
# prova anti-CSRF (header custom X-Requested-With, non impostabile cross-site
# da un form; vedi docs/hardening.md).
_CSRF_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_HEADER = "x-requested-with"


def get_current_user(request: Request,
                     credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme)):
    # Doppia accettazione (L-1): Bearer per client programmatici (MCP, agent,
    # script) e cookie HttpOnly per il browser.
    token = credentials.credentials if credentials else request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Token missing or invalid."
        )
    if not credentials and request.method in _CSRF_METHODS:
        # Autenticazione via cookie su richiesta che modifica stato: esigi la
        # prova anti-CSRF. Il Bearer esplicito non è forgiabile cross-site.
        if not request.headers.get(CSRF_HEADER):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Request rejected: missing anti-CSRF header."
            )
    payload = verify_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token."
        )
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject.")
    # L'utente deve esistere ancora (gestisce account eliminati con token valido)
    role = user_manager.get_role(sub)
    if role is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is no longer valid.")
    # Lockout immediato degli account disabilitati anche con token ancora valido
    if user_manager.is_disabled(sub):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled.")
    if user_manager.is_pending(sub):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account awaiting approval.")
    # "Sign out everywhere" bumps the epoch: every token issued before it dies.
    if int(payload.get("sep", 0)) != user_manager.session_epoch(sub):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session ended.")
    # Allinea sempre il ruolo allo stato corrente su disco.
    payload["role"] = role
    return payload


def require_role(*allowed):
    """Dipendenza FastAPI: consente l'accesso solo ai ruoli indicati."""
    def _dep(current_user = Depends(get_current_user)):
        if current_user.get("role") not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient privileges for this operation."
            )
        return current_user
    return _dep


def require_tab(*tab_ids: str):
    """Server-side counterpart of the 'visible tabs' setting: a route owned
    by a tab answers only users who hold that tab."""
    wanted = frozenset(tab_ids)

    def _dep(current_user=Depends(get_current_user)):
        tabs = user_manager.effective_tabs(current_user.get("sub"))
        if tabs is not None and not (tabs & wanted):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Funzionalita' non abilitata per questo utente.")
        return current_user
    _dep.tabs = wanted  # type: ignore[attr-defined]
    return _dep


require_super_admin = require_role("super_admin")
require_admin = require_role("super_admin", "admin")              # solo amministratori
require_operator = require_role("super_admin", "admin", "operator")  # scritture/operazioni di rete

# --- SCOPING PER SEDE/GRUPPO ---
# Un utente operator/viewer può essere limitato dall'admin a un sottoinsieme di
# sedi (gruppi). L'admin non ha restrizioni. Lista vuota = tutte le sedi.


def user_group_scope(current_user):
    """Set dei gruppi consentiti, oppure None se l'utente vede/gestisce tutto."""
    # Only super_admin is exempt: an admin limited to tenants is scoped too.
    if current_user.get("role") == "super_admin":
        return None
    groups = user_manager.get_user_groups(current_user.get("sub"))
    return set(groups) if groups else None


def is_unscoped_admin(current_user) -> bool:
    """super_admin, or an admin with no tenant restriction."""
    role = current_user.get("role")
    return role == "super_admin" or (
        role == "admin" and not user_manager.get_user_groups(current_user.get("sub")))


def require_unscoped_admin(current_user=Depends(require_admin)):
    """Global admin routes (settings, sites, tenants, ...): their effect crosses
    tenants, so a tenant-scoped admin must not reach them."""
    if not is_unscoped_admin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Operazione riservata ad amministratori senza limiti di tenant.")
    return current_user


def devices_in_scope(current_user) -> list:
    """L'inventario che il chiamante puo' vedere. Nessuna sessione aperta."""
    devices = inventory_manager.get_all_devices()
    scope = user_group_scope(current_user)
    if scope is None:
        return devices
    return [d for d in devices if (d.get("Group") or "Generale") in scope]


def assert_group_allowed(current_user, group):
    scope = user_group_scope(current_user)
    if scope is not None and group not in scope:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Group '{group}' is not allowed for your profile."
        )


def assert_device_allowed(current_user, ip, tenant=None):
    """Resolve an IP to a device the caller may see.

    Identity is (tenant, IP): two customers may each own 192.0.2.10. A scoped
    user has exactly one candidate, because an IP is unique inside a tenant, so
    their existing IP-keyed URLs stay unambiguous. Only an unscoped admin can
    see more than one, and only then is `tenant` needed.
    """
    all_matches = [d for d in inventory_manager.get_all_devices() if d.get("IP") == ip]
    if not all_matches:
        return None

    scope = user_group_scope(current_user)
    if scope is not None:
        scope_matches = [d for d in all_matches if (d.get("Group") or "Generale") in scope]
        if not scope_matches:
            # Device exists in inventory but outside user's scope -> 403
            assert_group_allowed(current_user, all_matches[0].get("Group", "Generale"))
        if tenant:
            scope_matches = [d for d in scope_matches if (d.get("Group") or "Generale") == tenant]
        if len(scope_matches) > 1:
            tenants = ", ".join(sorted(m.get("Group", "Generale") for m in scope_matches))
            raise HTTPException(
                status_code=409,
                detail=f"{ip} esiste in piu' tenant ({tenants}). Specificare il tenant."
            )
        if not scope_matches:
            return None
        device = scope_matches[0]
        assert_group_allowed(current_user, device.get("Group", "Generale"))
        return device

    # Unscoped user (admin)
    if tenant:
        matches = [d for d in all_matches if (d.get("Group") or "Generale") == tenant]
        if not matches:
            return None
        return matches[0]

    if len(all_matches) > 1:
        tenants = ", ".join(sorted(m.get("Group", "Generale") for m in all_matches))
        raise HTTPException(
            status_code=409,
            detail=f"{ip} esiste in piu' tenant ({tenants}). Specificare il tenant."
        )
    return all_matches[0]


def user_visible_to(current_user, target_username: str) -> bool:
    """Whether a scoped actor may see/manage this target account.

    An unscoped actor (super_admin, or an admin with no group restriction)
    sees everyone. A scoped actor sees only itself and accounts whose groups
    are non-empty and entirely inside its own scope: an unrestricted target
    (empty groups) is invisible to it, same as a target in another tenant.
    """
    scope = user_group_scope(current_user)
    if scope is None:
        return True
    if target_username == current_user.get("sub"):
        return True
    target_groups = set(user_manager.get_user_groups(target_username))
    return bool(target_groups) and target_groups <= scope


def assert_can_manage(current_user, target_username: str, new_role=None,
                      allow_self: bool = False) -> None:
    """The single gate for acting on another account (FortiGate model: only a
    super_admin touches admin-level accounts). allow_self keeps self-service
    routes (own email, own deletion) open to every role; it never lets anyone
    raise their own role, because new_role is still checked."""
    target_role = user_manager.get_role(target_username)
    if target_role is None or not user_visible_to(current_user, target_username):
        # A target outside the actor's scope answers exactly like a missing
        # one, so existence outside the tenant is never leaked.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utente non trovato.")
    actor_role = current_user.get("role")
    is_self = target_username == current_user.get("sub")
    if not (is_self and allow_self) and not user_manager.can_manage(actor_role, target_role):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Insufficient privileges for this operation.")
    if new_role is not None:
        assert_can_assign(current_user, new_role)


def assert_can_assign(current_user, new_role: str) -> None:
    """For routes that create an account or change a role."""
    if not user_manager.can_assign(current_user.get("role"), new_role):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Insufficient privileges for this operation.")


def assert_groups_within_scope(current_user, groups: list) -> None:
    """For routes assigning tenant groups to a target account: a scoped actor
    may grant only groups inside its own scope, and never the unrestricted
    grant (empty list), which would hand the target every tenant."""
    scope = user_group_scope(current_user)
    if scope is None:
        return
    if not groups or not set(groups) <= scope:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Insufficient privileges for this operation.")


def assert_tabs_within_grant(current_user, tabs: list) -> None:
    """For routes assigning dashboard tabs to a target account: a tab-restricted
    actor may grant only tabs it holds itself, and never the unrestricted grant
    (empty list). Applies to any tab-restricted actor, not only scoped admins."""
    actor_tabs = user_manager.effective_tabs(current_user.get("sub"))
    if actor_tabs is None:
        return
    normalized = {user_manager.TAB_ALIASES.get(t, t) for t in tabs if t != "tab-home"}
    if not normalized or not normalized <= actor_tabs:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Insufficient privileges for this operation.")


def filter_map_to_scope(data, scope):
    """Riduce nodi e link della mappa alle sole sedi consentite."""
    if scope is None:
        return data
    allowed_nodes = {n["id"] for n in data.get("nodes", []) if n.get("group") in scope}
    nodes = [n for n in data.get("nodes", []) if n["id"] in allowed_nodes]
    links = [l for l in data.get("links", [])
             if l["source"] in allowed_nodes and l["target"] in allowed_nodes]
    return {"nodes": nodes, "links": links}
