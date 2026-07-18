# -*- coding: utf-8 -*-
"""Router Provisioner. Estratto da app_server.py (fase 6.6)."""

import json
import uuid
import os
from typing import Optional, List, Dict, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import Response
from pydantic import BaseModel, Field

from security_manager import log_audit
from routers.deps import require_operator
import switch_provisioner
import fortigate_provisioner
import provisioning_secrets

router = APIRouter(tags=["Provisioner"])

class AaaServerSchema(BaseModel):
    """Voce di server AAA (RADIUS/TACACS+) per il wizard 'Switch da Zero'."""
    ip: str
    key: str = ""
    auth_port: Optional[int] = None
    acct_port: Optional[int] = None

class SwitchProvisionSchema(BaseModel):
    """Parametri del wizard 'Switch da Zero'. Vedi switch_provisioner.build_config
    per il significato di ciascun campo (tutti opzionali salvo hostname)."""
    hostname: str = "Switch"
    role: str = "access"                  # access | distribution
    domain: str = ""
    mgmt_vlan: Optional[int] = None
    mgmt_ip: str = ""
    mgmt_mask: str = ""
    mgmt_gw: str = ""
    admin_user: str = ""
    admin_password: str = ""
    enable_secret: str = ""
    ssh_only: bool = True
    banner: str = ""
    ntp_servers: List[str] = []
    syslog_server: str = ""
    snmpv3: dict = {}
    vlans: List[dict] = []
    vtp_mode: str = "transparent"
    stp_mode: str = "rapid-pvst"
    bpduguard: bool = True
    port_security: bool = False
    dhcp_snooping: bool = False
    dhcp_snooping_vlans: str = ""
    cdp_enabled: bool = True
    lldp_enabled: bool = True
    access_ports: List[str] = []
    access_vlan: Optional[int] = None
    trunk_ports: List[str] = []
    trunk_allowed_vlans: str = ""
    uplink_pc_id: Optional[int] = None
    login_block: bool = True
    storm_control: bool = False
    errdisable_recovery: bool = True
    no_vstack: bool = True
    svis: List[dict] = []
    enable_routing: bool = True
    default_route_gw: str = ""
    aaa_protocol: Literal["none", "radius", "tacacs"] = "none"
    aaa_servers: List[AaaServerSchema] = Field(default_factory=list, max_length=3)

class SwitchProvisionSSHSchema(SwitchProvisionSchema):
    ssh_host: str
    ssh_port: int = 22
    ssh_username: str
    ssh_password: str
    ssh_secret: str = ""
    save_after: bool = True

class SwitchProvisionSerialSchema(SwitchProvisionSchema):
    com_port: str
    baudrate: int = 9600

class FortiGateProvisionSchema(BaseModel):
    """Parametri del wizard ZTP FortiGate. Vedi fortigate_provisioner.build_config."""
    hostname: str = "FortiGate"
    timezone: str = "Europe/Rome"
    admin_user: str = ""
    admin_password: str = ""
    admin_timeout: int = 10
    lockout: bool = True
    strong_crypto: bool = True
    mgmt_interface: str = ""
    mgmt_ip: str = ""
    mgmt_mask: str = ""
    mgmt_allowaccess: str = "ping https ssh"
    wan_interface: str = ""
    wan_mode: str = "dhcp"
    wan_ip: str = ""
    wan_mask: str = ""
    wan_gw: str = ""
    lan_interface: str = ""
    lan_ip: str = ""
    lan_mask: str = ""
    dhcp_server: bool = False
    dhcp_start: str = ""
    dhcp_end: str = ""
    dns_primary: str = ""
    dns_secondary: str = ""
    ntp_servers: List[str] = []
    syslog_server: str = ""
    snmpv3: dict = {}
    lan_to_wan_policy: bool = True
    disable_wan_admin: bool = True
    banner: str = ""
    # Elementi ZTP (FortiOS 7.4 Admin Guide)
    api_user: dict = {}            # {name, accprofile, trusthosts: [..]}
    central_mgmt: dict = {}        # {type: fortiguard|fortimanager, fmg_ip}
    csf_group: str = ""
    netflow_collector: str = ""
    rest_api_logging: bool = True
    ha: dict = {}                  # {group_name, mode, password, hbdev, priority, mgmt_interface, mgmt_ip, mgmt_mask}
    aaa_protocol: Literal["none", "radius", "tacacs"] = "none"
    aaa_server_ip: str = ""
    aaa_key: str = ""

class FortiGateProvisionSSHSchema(FortiGateProvisionSchema):
    ssh_host: str
    ssh_port: int = 22
    ssh_username: str
    ssh_password: str

class FortiGateProvisionSerialSchema(FortiGateProvisionSchema):
    com_port: str
    baudrate: int = 9600
    console_user: str = "admin"
    console_password: str = ""

def _provision_cfg(payload_dict: dict, materialized: bool, current_user, vendor: str) -> dict:
    """Prepara il payload del provisioner per la generazione testo (finding I-2):
    di default i segreti sono sostituiti da placeholder {{VAULT:...}}; la
    materializzazione completa richiede flag esplicito e viene auditata."""
    if not materialized:
        return provisioning_secrets.mask_secrets(payload_dict)
    log_audit(
        f"ATTENZIONE: config day-0 {vendor} generata MATERIALIZZATA (segreti in chiaro) "
        f"per '{payload_dict.get('hostname')}' da '{current_user.get('sub')}'."
    )
    return payload_dict

@router.post("/api/provisioner/generate")
def provisioner_generate(payload: SwitchProvisionSchema, materialized: bool = False,
                         current_user = Depends(require_operator)):
    """Genera la running-config e la restituisce come testo (view/copy nella UI).
    Di default i segreti sono placeholder; ``?materialized=true`` per il testo
    completo (auditato)."""
    cfg = _provision_cfg(payload.dict(), materialized, current_user, "switch")
    config_text = switch_provisioner.build_config(cfg)
    return {"status": "success", "config": config_text, "materialized": materialized}

@router.post("/api/provisioner/download")
def provisioner_download(payload: SwitchProvisionSchema, materialized: bool = False,
                         current_user = Depends(require_operator)):
    """Genera la running-config e la restituisce come file .txt scaricabile."""
    cfg = _provision_cfg(payload.dict(), materialized, current_user, "switch")
    config_text = switch_provisioner.build_config(cfg)
    from fastapi.responses import Response as FastResponse
    filename = f"{(payload.hostname or 'switch').strip()}-day0.txt"
    log_audit(f"Config day-0 generata (download) per '{payload.hostname}' da '{current_user.get('sub')}'.")
    return FastResponse(
        content=config_text,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.post("/api/provisioner/push-ssh")
def provisioner_push_ssh(payload: SwitchProvisionSSHSchema, current_user = Depends(require_operator)):
    """Genera la config e la applica via SSH (Netmiko) su un apparato raggiungibile."""
    config_text = switch_provisioner.build_config(payload.dict())
    result = switch_provisioner.push_via_ssh(
        host=payload.ssh_host,
        username=payload.ssh_username,
        password=payload.ssh_password,
        secret=payload.ssh_secret,
        config_text=config_text,
        port=payload.ssh_port,
        save=payload.save_after,
    )
    log_audit(
        f"Push SSH config day-0 su '{payload.ssh_host}' (hostname target: "
        f"'{payload.hostname}') da '{current_user.get('sub')}': {result.get('status')}."
    )
    # La config materializzata resta solo in memoria per il push: nella
    # risposta torna la versione con placeholder (finding I-2).
    result["config"] = switch_provisioner.build_config(provisioning_secrets.mask_secrets(payload.dict()))
    return result

@router.post("/api/provisioner/push-serial")
def provisioner_push_serial(payload: SwitchProvisionSerialSchema, current_user = Depends(require_operator)):
    """Genera la config e la applica via console/seriale (pyserial) per il
    provisioning day-0 senza connettivita' di rete."""
    config_text = switch_provisioner.build_config(payload.dict())
    result = switch_provisioner.push_via_serial(
        com_port=payload.com_port,
        config_text=config_text,
        baudrate=payload.baudrate,
    )
    log_audit(
        f"Push seriale ({payload.com_port}) config day-0 (hostname target: "
        f"'{payload.hostname}') da '{current_user.get('sub')}': {result.get('status')}."
    )
    result["config"] = switch_provisioner.build_config(provisioning_secrets.mask_secrets(payload.dict()))
    return result

@router.get("/api/provisioner/serial-ports")
def provisioner_serial_ports(current_user = Depends(require_operator)):
    """Elenca le porte COM/seriali disponibili sull'host del server."""
    return {"ports": switch_provisioner.list_serial_ports()}

@router.post("/api/provisioner/fgt/generate")
def fgt_provisioner_generate(payload: FortiGateProvisionSchema, materialized: bool = False,
                             current_user = Depends(require_operator)):
    """Genera la configurazione FortiOS day-0 e la restituisce come testo."""
    cfg = _provision_cfg(payload.dict(), materialized, current_user, "FortiGate")
    config_text = fortigate_provisioner.build_config(cfg)
    log_audit(f"Config FortiGate day-0 generata per '{payload.hostname}' da '{current_user.get('sub')}'.")
    return {"status": "success", "config": config_text, "materialized": materialized}

@router.post("/api/provisioner/fgt/download")
def fgt_provisioner_download(payload: FortiGateProvisionSchema, materialized: bool = False,
                             current_user = Depends(require_operator)):
    """Genera la configurazione FortiOS e la restituisce come file .txt."""
    cfg = _provision_cfg(payload.dict(), materialized, current_user, "FortiGate")
    config_text = fortigate_provisioner.build_config(cfg)
    from fastapi.responses import Response as FastResponse
    filename = f"{(payload.hostname or 'fortigate').strip()}-day0.txt"
    log_audit(f"Config FortiGate day-0 (download) per '{payload.hostname}' da '{current_user.get('sub')}'.")
    return FastResponse(
        content=config_text,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.post("/api/provisioner/fgt/push-ssh")
def fgt_provisioner_push_ssh(payload: FortiGateProvisionSSHSchema, current_user = Depends(require_operator)):
    """Genera la config FortiOS e la applica via SSH (Netmiko 'fortinet')."""
    config_text = fortigate_provisioner.build_config(payload.dict())
    result = fortigate_provisioner.push_via_ssh(
        host=payload.ssh_host,
        username=payload.ssh_username,
        password=payload.ssh_password,
        config_text=config_text,
        port=payload.ssh_port,
    )
    log_audit(
        f"Push SSH config FortiGate day-0 su '{payload.ssh_host}' (hostname target: "
        f"'{payload.hostname}') da '{current_user.get('sub')}': {result.get('status')}."
    )
    result["config"] = fortigate_provisioner.build_config(provisioning_secrets.mask_secrets(payload.dict()))
    return result

@router.post("/api/provisioner/fgt/push-serial")
def fgt_provisioner_push_serial(payload: FortiGateProvisionSerialSchema, current_user = Depends(require_operator)):
    """Genera la config FortiOS e la applica via console/seriale (day-0)."""
    config_text = fortigate_provisioner.build_config(payload.dict())
    result = fortigate_provisioner.push_via_serial(
        com_port=payload.com_port,
        config_text=config_text,
        baudrate=payload.baudrate,
        username=payload.console_user,
        password=payload.console_password,
    )
    log_audit(
        f"Push seriale ({payload.com_port}) config FortiGate day-0 (hostname target: "
        f"'{payload.hostname}') da '{current_user.get('sub')}': {result.get('status')}."
    )
    result["config"] = fortigate_provisioner.build_config(provisioning_secrets.mask_secrets(payload.dict()))
    return result

# ── Identita' tenant (profili credenziali riusabili) ────────────────────────
import identity_manager

class IdentitySchema(BaseModel):
    name: str
    tenant: str
    username: str
    password: str
    enable_secret: str = ""

@router.get("/api/identities")
def identities_list(tenant: Optional[str] = None, current_user = Depends(require_operator)):
    """Lista identita' (senza segreti), opzionalmente filtrate per tenant."""
    return {"identities": identity_manager.get_identities(tenant=tenant)}

@router.post("/api/identities")
def identities_create(payload: IdentitySchema, current_user = Depends(require_operator)):
    if not payload.name.strip() or not payload.username or not payload.password:
        raise HTTPException(status_code=400, detail="Nome, username e password sono obbligatori.")
    ident = identity_manager.add_identity(payload.name, payload.tenant,
                                          payload.username, payload.password,
                                          payload.enable_secret)
    log_audit(f"Identita' '{payload.name}' (tenant '{payload.tenant}') creata da '{current_user.get('sub')}'.")
    return {"status": "success", "id": ident["id"]}

@router.put("/api/identities/{identity_id}")
def identities_update(identity_id: str, payload: IdentitySchema,
                      current_user = Depends(require_operator)):
    if not payload.name.strip() or not payload.username or not payload.password:
        raise HTTPException(status_code=400, detail="Nome, username e password sono obbligatori.")
    if not identity_manager.update_identity(identity_id, payload.name, payload.tenant,
                                            payload.username, payload.password,
                                            payload.enable_secret):
        raise HTTPException(status_code=404, detail="Identita' non trovata.")
    log_audit(f"Identita' '{payload.name}' aggiornata da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.delete("/api/identities/{identity_id}")
def identities_delete(identity_id: str, current_user = Depends(require_operator)):
    ok, devices = identity_manager.delete_identity(identity_id)
    if not ok:
        raise HTTPException(status_code=409,
                            detail={"error": "in_use", "devices": devices})
    log_audit(f"Identita' '{identity_id}' eliminata da '{current_user.get('sub')}'.")
    return {"status": "success"}

