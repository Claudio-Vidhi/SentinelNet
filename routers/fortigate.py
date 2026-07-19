# -*- coding: utf-8 -*-
"""Router FortiGate LIVE: osservabilità in tempo reale (REST API + fallback
SSH). Estratto da app_server.py (fase 2.2): percorsi, metodi, parametri e
risposte identici al monolite. La logica di business resta in
fortigate_service.py; qui solo routing, auth e scoping per sede."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from services import fortigate_service
from security.security_manager import log_audit
from routers.deps import (
    get_current_user, require_admin, require_operator, assert_device_allowed,
)

router = APIRouter(tags=["FortiGate"])


# --- Schemi (usati solo da questi endpoint) ---

class FgtTokenSchema(BaseModel):
    ip: str
    token: str = ""                # vuoto = rimuove il token
    port: int = 443
    # Verifica TLS del certificato del FortiGate: default False, perché i
    # FortiGate usano quasi sempre un certificato self-signed appena messi in
    # produzione (con default True la connessione di test fallirebbe sempre
    # con SSLCertVerificationError). Abilitare esplicitamente solo se sul
    # FortiGate è installato un certificato attendibile.
    verify_tls: bool = False
    name: str = ""                  # nome descrittivo (multi-target manager)

class FgtActiveTargetSchema(BaseModel):
    ip: str

class FgtTargetUpdateSchema(BaseModel):
    # Aggiornamento parziale: solo i campi forniti vengono modificati.
    # token omesso/vuoto = il token cifrato esistente resta invariato
    # ("•••• invariato" lato UI, ora veritiero).
    name: Optional[str] = None
    port: Optional[int] = None
    verify_tls: Optional[bool] = None
    token: Optional[str] = None

class FgtPolicyLookupSchema(BaseModel):
    src_ip: str
    dest: str                      # IP o FQDN di destinazione
    protocol: str = "TCP"
    dest_port: int = 443
    srcintf: Optional[str] = None

class FgtSessionQuerySchema(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    count: int = 100

class FgtLogQuerySchema(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    action: Optional[str] = None   # accept | deny | ...
    count: int = 100
    log_device: str = "disk"       # disk | memory

class FgtDiagnoseClientSchema(BaseModel):
    client: str                    # IP o MAC del client da diagnosticare
    dest: Optional[str] = None     # destinazione (IP/FQDN) per il policy lookup
    dest_port: int = 443
    protocol: str = "TCP"


def _fgt_device(ip: str, current_user) -> dict:
    """Risolve un IP in un dispositivo FortiGate dell'inventario, con verifica
    di scoping per sede. 404 se assente, 400 se il vendor non è fortinet."""
    device = assert_device_allowed(current_user, ip)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device {ip} not found in inventory.")
    if (device.get('Vendor') or '').lower() != 'fortinet':
        raise HTTPException(status_code=400,
                            detail=f"Device {ip} is not a FortiGate (vendor='{device.get('Vendor')}').")
    return device


def _fgt_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except fortigate_service.FortiGateError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/api/fortigate/tokens")
def fgt_token_status(current_user = Depends(require_admin)):
    """IP con token API configurato (i token non vengono mai restituiti)."""
    return fortigate_service.token_status()

@router.post("/api/fortigate/token")
def fgt_set_token(payload: FgtTokenSchema, current_user = Depends(require_admin)):
    """Salva (cifrato) il token REST API di un FortiGate; token vuoto lo rimuove."""
    _fgt_device(payload.ip, current_user)
    fortigate_service.set_api_token(payload.ip, payload.token,
                                    port=payload.port, verify_tls=payload.verify_tls,
                                    name=payload.name)
    action = "configurato" if payload.token else "rimosso"
    log_audit(f"Token API FortiGate {action} per '{payload.ip}' da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.get("/api/fortigate/targets")
def fgt_list_targets(current_user = Depends(require_admin)):
    """Elenco dei target FortiGate configurati (nome, porta, TLS, attivo);
    i token non vengono mai restituiti."""
    return fortigate_service.list_targets()

@router.post("/api/fortigate/targets/active")
def fgt_set_active_target(payload: FgtActiveTargetSchema, current_user = Depends(require_admin)):
    """Imposta il target FortiGate attivo per la tab LIVE."""
    _fgt_device(payload.ip, current_user)
    fortigate_service.set_active_target(payload.ip)
    log_audit(f"Target FortiGate attivo impostato su '{payload.ip}' da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/fortigate/targets/{ip}/test")
def fgt_test_target(ip: str, current_user = Depends(require_admin)):
    """Testa la connessione REST API verso un target FortiGate (timeout breve)."""
    _fgt_device(ip, current_user)
    return fortigate_service.test_connection(ip)

@router.put("/api/fortigate/targets/{ip}")
def fgt_update_target(ip: str, payload: FgtTargetUpdateSchema,
                      current_user = Depends(require_admin)):
    """Aggiornamento parziale di un target FortiGate esistente (nome, porta,
    verifica TLS, token). Token omesso/vuoto = resta quello già salvato."""
    _fgt_device(ip, current_user)
    try:
        fortigate_service.update_target(ip, name=payload.name, port=payload.port,
                                        verify_tls=payload.verify_tls,
                                        token=payload.token)
    except KeyError:
        raise HTTPException(status_code=404,
                            detail=f"Nessun target FortiGate configurato per {ip}.")
    log_audit(f"Target FortiGate '{ip}' aggiornato da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.get("/api/fortigate/{ip}/status")
def fgt_status(ip: str, current_user = Depends(get_current_user)):
    return _fgt_call(fortigate_service.get_system_status, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/interfaces")
def fgt_interfaces(ip: str, current_user = Depends(get_current_user)):
    return _fgt_call(fortigate_service.get_interfaces, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/arp")
def fgt_arp(ip: str, current_user = Depends(get_current_user)):
    return _fgt_call(fortigate_service.get_arp_table, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/dhcp-leases")
def fgt_dhcp_leases(ip: str, current_user = Depends(get_current_user)):
    return _fgt_call(fortigate_service.get_dhcp_leases, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/device-inventory")
def fgt_device_inventory(ip: str, current_user = Depends(get_current_user)):
    """Device identification FortiOS: MAC/IP/hostname/OS per client rilevato."""
    return _fgt_call(fortigate_service.get_device_inventory, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/policies")
def fgt_policies(ip: str, current_user = Depends(get_current_user)):
    return _fgt_call(fortigate_service.get_firewall_policies, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/policy-stats")
def fgt_policy_stats(ip: str, current_user = Depends(get_current_user)):
    return _fgt_call(fortigate_service.get_policy_stats, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/firewall/addresses")
def fgt_firewall_addresses(ip: str, current_user = Depends(get_current_user)):
    """Oggetti indirizzo firewall (address book), sola lettura."""
    return _fgt_call(fortigate_service.get_firewall_addresses, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/firewall/policy-objects")
def fgt_firewall_policy_objects(ip: str, current_user = Depends(get_current_user)):
    """Policy firewall (cmdb) con soli campi rilevanti per l'osservabilità."""
    return _fgt_call(fortigate_service.get_firewall_policy_objects, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/firewall/services")
def fgt_firewall_services(ip: str, current_user = Depends(get_current_user)):
    """Servizi custom (firewall.service/custom), sola lettura."""
    return _fgt_call(fortigate_service.get_firewall_custom_services, _fgt_device(ip, current_user))

@router.post("/api/fortigate/{ip}/policy-lookup")
def fgt_policy_lookup(ip: str, payload: FgtPolicyLookupSchema,
                      current_user = Depends(get_current_user)):
    """Chiede al FortiGate quale policy matcherebbe il flusso indicato."""
    return _fgt_call(fortigate_service.policy_lookup, _fgt_device(ip, current_user),
                     payload.src_ip, payload.dest, protocol=payload.protocol,
                     dest_port=payload.dest_port, srcintf=payload.srcintf)

@router.post("/api/fortigate/{ip}/sessions")
def fgt_sessions(ip: str, payload: FgtSessionQuerySchema,
                 current_user = Depends(get_current_user)):
    return _fgt_call(fortigate_service.get_sessions, _fgt_device(ip, current_user),
                     src_ip=payload.src_ip, dst_ip=payload.dst_ip,
                     dst_port=payload.dst_port, count=payload.count)

@router.get("/api/fortigate/{ip}/routes")
def fgt_routes(ip: str, current_user = Depends(get_current_user)):
    return _fgt_call(fortigate_service.get_routes, _fgt_device(ip, current_user))

@router.post("/api/fortigate/{ip}/logs")
def fgt_logs(ip: str, payload: FgtLogQuerySchema,
             current_user = Depends(get_current_user)):
    return _fgt_call(fortigate_service.get_traffic_logs, _fgt_device(ip, current_user),
                     src_ip=payload.src_ip, dst_ip=payload.dst_ip,
                     action=payload.action, count=payload.count,
                     log_device=payload.log_device)

@router.get("/api/fortigate/{ip}/wifi/clients")
def fgt_wifi_clients(ip: str, current_user = Depends(get_current_user)):
    return _fgt_call(fortigate_service.get_wifi_clients, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/wifi/aps")
def fgt_wifi_aps(ip: str, current_user = Depends(get_current_user)):
    return _fgt_call(fortigate_service.get_managed_aps, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/full-config")
def fgt_full_config(ip: str, current_user = Depends(require_operator)):
    """Configurazione completa LIVE (contiene segreti: solo ruolo operator+)."""
    log_audit(f"Full-config FortiGate richiesta per '{ip}' da '{current_user.get('sub')}'.")
    return _fgt_call(fortigate_service.get_full_config, _fgt_device(ip, current_user))

@router.post("/api/fortigate/{ip}/diagnose-client")
def fgt_diagnose_client(ip: str, payload: FgtDiagnoseClientSchema,
                        current_user = Depends(get_current_user)):
    """Diagnosi aggregata di un client (IP o MAC): inventario device, ARP,
    DHCP, sessioni, policy match verso una destinazione e ultimi log."""
    device = _fgt_device(ip, current_user)
    log_audit(f"Diagnosi client '{payload.client}' su FortiGate '{ip}' da '{current_user.get('sub')}'.")
    return fortigate_service.diagnose_client(device, payload.client,
                                             dest=payload.dest,
                                             dest_port=payload.dest_port,
                                             protocol=payload.protocol)
