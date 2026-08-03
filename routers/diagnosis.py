# -*- coding: utf-8 -*-
"""Router diagnosi client: un referto solo per L2 e L3.

Sottile per scelta, come gli altri: qui stanno routing, auth e scoping per
sede; la composizione delle sezioni sta in ``services/client_diagnosis.py``.
"""

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from routers.deps import (get_current_user, require_admin, user_group_scope,
                          assert_device_allowed)
from security.security_manager import log_audit
from services import client_diagnosis

router = APIRouter(tags=["Diagnosis"])


class ClientDiagnosisSchema(BaseModel):
    client: str                    # IP o MAC del client da diagnosticare
    dest: Optional[str] = None     # destinazione (IP/FQDN) per il policy lookup
    dest_port: int = 443
    protocol: str = "TCP"
    # Soglia di freschezza in secondi: oltre, gateway e switch di accesso
    # vengono riscansionati prima di rispondere. None = impostazione salvata.
    max_age_s: Optional[int] = None
    # Tenant scelto quando lo stesso indirizzo risulta in più sedi. RESTRINGE
    # lo scoping dell'utente, non lo allarga: un tenant fuori dal suo profilo
    # è 403, non "vabbè, glielo mostro".
    tenant: Optional[str] = None


class PortBounceSchema(BaseModel):
    client_mac: str                # il client di cui si sta staccando la porta
    switch_ip: str                 # apparato su cui agire
    interface: str                 # porta, come l'ha risolta la diagnosi


@router.post("/api/diagnose/client")
async def diagnose_client(payload: ClientDiagnosisSchema,
                          current_user = Depends(get_current_user)):
    """Referto L2+L3 su un client: dove è attaccato, come sta la sua porta, che
    strada fa il traffico, quale policy lo governa e quanti blocchi ha subito.

    Sola lettura: interroga apparati e storico, non tocca nulla. Per questo
    basta ``get_current_user`` e non ``require_operator``.
    """
    tenants = user_group_scope(current_user)
    scope = sorted(tenants) if tenants is not None else None
    if payload.tenant:
        # Stessa regola di /api/mac/search: la scelta restringe, e un tenant
        # fuori profilo si rifiuta invece di ignorarlo in silenzio — ignorarlo
        # risponderebbe su una sede che l'utente non può vedere.
        if scope is not None and payload.tenant not in scope:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"Tenant '{payload.tenant}' non consentito.")
        scope = [payload.tenant]
    # Il servizio blocca su SSH e REST verso gli apparati: fuori dal loop, come
    # ogni altra chiamata agli apparati in questo progetto.
    result = await asyncio.to_thread(
        client_diagnosis.diagnose, payload.client, payload.dest,
        payload.dest_port, payload.protocol, scope, payload.max_age_s)
    log_audit(f"Diagnosi client '{payload.client}'"
              + (f" verso '{payload.dest}'" if payload.dest else "")
              + f" richiesta da {current_user.get('sub')}.")
    return result


@router.post("/api/diagnose/port-bounce")
async def port_bounce(payload: PortBounceSchema,
                      current_user = Depends(require_admin)):
    """Spegne e riaccende la porta di accesso di un client.

    L'unica scrittura di questa tab, e l'unica di tutta la diagnosi. I due
    controlli sotto non sono formalità: la porta arriva da una MAC table
    scansionata a mano, e se il dato è vecchio la porta di oggi appartiene a
    qualcun altro. Staccare l'utente sbagliato è un guasto causato dallo
    strumento che doveva ripararne uno.

    ``require_admin``: il comando entra in modalità di configurazione. Chi può
    farlo è la stessa categoria che può scavalcare la blacklist dei comandi.
    """
    from services import port_action

    device = assert_device_allowed(current_user, payload.switch_ip)
    if device is None:
        raise HTTPException(status_code=404,
                            detail=f"Apparato {payload.switch_ip} non in inventario.")

    # La posizione deve dire ADESSO quello che dice il chiamante: stesso
    # apparato, stessa porta, e binding dentro la soglia di freschezza.
    scope = user_group_scope(current_user)
    pos = await asyncio.to_thread(client_diagnosis.verify_port,
                                  payload.client_mac, payload.switch_ip,
                                  payload.interface, scope)
    if not pos["ok"]:
        log_audit(f"Port bounce RIFIUTATO su '{payload.switch_ip}' porta "
                  f"'{payload.interface}' per il client '{payload.client_mac}' "
                  f"(utente '{current_user.get('sub')}'): {pos['reason']}.")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=pos["reason"])

    log_audit(f"Port bounce AVVIATO da '{current_user.get('sub')}' su "
              f"'{payload.switch_ip}' porta '{payload.interface}' "
              f"(client '{payload.client_mac}').")
    try:
        res = await asyncio.to_thread(port_action.bounce, device, payload.interface)
    except port_action.PortActionError as e:
        log_audit(f"Port bounce NON ESEGUITO su '{payload.switch_ip}' porta "
                  f"'{payload.interface}': {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log_audit(f"Port bounce FALLITO su '{payload.switch_ip}' porta "
                  f"'{payload.interface}': {e}")
        raise HTTPException(status_code=502, detail=str(e))

    log_audit(f"Port bounce ESEGUITO su '{payload.switch_ip}' porta "
              f"'{payload.interface}': "
              f"{'porta riaccesa' if res.get('up_ok') else 'PORTA RIMASTA GIU'}.")
    return res
