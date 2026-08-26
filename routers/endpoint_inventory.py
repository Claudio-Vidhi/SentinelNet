# -*- coding: utf-8 -*-
"""Router inventario endpoint: elenco dei client scoperti, e occupazione porte.

Sottile per scelta, come gli altri: qui stanno routing e scoping per tenant;
le due query stanno in ``collectors/mac_history.py``, che possiede il DB.

Il modulo si chiama ``endpoint_inventory`` e non ``endpoints`` perche' quel
nome e' gia' di ``observability/endpoints.py`` (classificatore di indirizzi):
due moduli omonimi con scopi diversi si confondono alla prima lettura.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status

from collectors import mac_history
from routers.deps import assert_device_allowed, get_current_user, user_group_scope

router = APIRouter(tags=["Endpoint Inventory"])


def _scope(current_user, tenant: Optional[str]):
    """Scope effettivo. ``tenant`` RESTRINGE, non allarga: un tenant fuori dal
    profilo e' 403, non un silenzioso "vabbe', glielo mostro" — risponderebbe
    su una sede che l'utente non puo' vedere."""
    scope = user_group_scope(current_user)
    if not tenant or tenant == "all":
        return scope
    if scope is not None and tenant not in scope:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Tenant '{tenant}' non consentito.")
    return [tenant]


@router.get("/api/endpoints/list")
def endpoints_list(tenant: Optional[str] = None, site: Optional[str] = None,
                   switch: Optional[str] = None, vlan: Optional[str] = None,
                   q: Optional[str] = None, stale_days: int = 7,
                   limit: int = 2000,
                   frm: Optional[str] = None, to: Optional[str] = None,
                   current_user = Depends(get_current_user)):
    """Gli endpoint scoperti, uno per (MAC, tenant).

    Sola lettura sul dato gia' raccolto: non interroga nessun apparato, quindi
    basta ``get_current_user`` e non ``require_operator``.
    """
    return mac_history.endpoint_inventory(
        tenants=_scope(current_user, tenant), site=site or None,
        switch_ip=switch or None, vlan=vlan or None, q=(q or "").strip() or None,
        stale_days=max(1, min(3650, stale_days)), limit=limit,
        frm=frm or None, to=to or None)


@router.get("/api/endpoints/ports")
def endpoints_ports(switch: str, current_user = Depends(get_current_user)):
    """Stato delle porte di uno switch: occupata, uplink, libera.

    Le righe di ``mac_sightings`` sono scopate per tenant, ma lo switch stesso
    no (``switch_if_macs`` non ha colonna tenant): senza questo controllo un
    utente della sede A poteva chiedere l'IP di uno switch della sede B e
    riceverne comunque l'elenco interfacce, la freschezza della scansione e i
    vicini di uplink — e una porta occupata da un MAC non suo tornava "free",
    cioe' il referto mentiva oltre a trapelare.
    """
    if not switch or not switch.strip():
        raise HTTPException(status_code=400, detail="Parametro switch obbligatorio")
    switch = switch.strip()
    device = assert_device_allowed(current_user, switch)
    if device is None:
        raise HTTPException(status_code=404,
                            detail=f"Apparato {switch} non in inventario.")
    return mac_history.port_occupancy(switch, tenants=user_group_scope(current_user))
