# -*- coding: utf-8 -*-
"""Router diagnosi client: un referto solo per L2 e L3.

Sottile per scelta, come gli altri: qui stanno routing, auth e scoping per
sede; la composizione delle sezioni sta in ``services/client_diagnosis.py``.
"""

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from routers.deps import get_current_user, user_group_scope
from security.security_manager import log_audit
from services import client_diagnosis

router = APIRouter(tags=["Diagnosis"])


class ClientDiagnosisSchema(BaseModel):
    client: str                    # IP o MAC del client da diagnosticare
    dest: Optional[str] = None     # destinazione (IP/FQDN) per il policy lookup
    dest_port: int = 443
    protocol: str = "TCP"


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
    # Il servizio blocca su SSH e REST verso gli apparati: fuori dal loop, come
    # ogni altra chiamata agli apparati in questo progetto.
    result = await asyncio.to_thread(
        client_diagnosis.diagnose, payload.client, payload.dest,
        payload.dest_port, payload.protocol, scope)
    log_audit(f"Diagnosi client '{payload.client}'"
              + (f" verso '{payload.dest}'" if payload.dest else "")
              + f" richiesta da {current_user.get('sub')}.")
    return result
