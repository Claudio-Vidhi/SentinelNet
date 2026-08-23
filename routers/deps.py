# -*- coding: utf-8 -*-
"""Dipendenze FastAPI condivise: autenticazione (cookie HttpOnly O Bearer,
con prova anti-CSRF sul cookie) e scoping multi-gruppo per sede.

Spostate qui da app_server.py (fase 2.1 del piano) per essere riusate dai
router modulari senza import circolari. app_server reimporta questi nomi,
quindi il comportamento e i punti di patch dei test restano invariati.

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


require_admin = require_role("admin")              # solo amministratori
require_operator = require_role("admin", "operator")  # scritture/operazioni di rete

# --- SCOPING PER SEDE/GRUPPO ---
# Un utente operator/viewer può essere limitato dall'admin a un sottoinsieme di
# sedi (gruppi). L'admin non ha restrizioni. Lista vuota = tutte le sedi.


def user_group_scope(current_user):
    """Set dei gruppi consentiti, oppure None se l'utente vede/gestisce tutto."""
    if current_user.get("role") == "admin":
        return None
    groups = user_manager.get_user_groups(current_user.get("sub"))
    return set(groups) if groups else None


def assert_group_allowed(current_user, group):
    scope = user_group_scope(current_user)
    if scope is not None and group not in scope:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Site '{group}' is not allowed for your profile."
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


def filter_map_to_scope(data, scope):
    """Riduce nodi e link della mappa alle sole sedi consentite."""
    if scope is None:
        return data
    allowed_nodes = {n["id"] for n in data.get("nodes", []) if n.get("group") in scope}
    nodes = [n for n in data.get("nodes", []) if n["id"] in allowed_nodes]
    links = [l for l in data.get("links", [])
             if l["source"] in allowed_nodes and l["target"] in allowed_nodes]
    return {"nodes": nodes, "links": links}
