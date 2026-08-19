# -*- coding: utf-8 -*-
"""Router Inventario: CRUD dispositivi (aggiunta, rinomina, eliminazione,
import/export CSV, promozione da scoperta, riassegnazione sede). Estratto da
app_server.py (fase 6.6): percorsi, metodi, parametri e risposte identici al
monolite."""

from typing import Optional, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from services import inventory_manager, site_manager
from security.security_manager import log_audit
from routers.deps import (
    get_current_user, require_operator, user_group_scope,
    assert_group_allowed, assert_device_allowed,
)

router = APIRouter(tags=["Inventory"])


class DeviceSchema(BaseModel):
    ip: str = Field(..., pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    vendor: str
    profile: str
    # Vuoto su un dispositivo esistente = lascia invariate le credenziali
    # salvate (vedi add_or_update_device); in creazione i default di
    # core_engine valgono comunque a runtime via get_device_credentials.
    username: str = ""
    password: str = ""
    enable_secret: str = ""
    group: str = "Generale"
    site: str = "central"
    ssh_port: int = Field(22, ge=1, le=65535)
    # §11.6: mappa trasporti per-device {protocollo: porta|None}. None = legacy
    # (deriva ssh-only dalla porta SSH). Validazione in inventory_manager.
    transports: Optional[Dict[str, Optional[int]]] = None
    # Community SNMP v2c in sola lettura (poller di stato). None = lascia
    # invariata quella già salvata; "" = rimuovila.
    snmp_community: Optional[str] = Field(None, max_length=128)
    snmp_disabled: Optional[bool] = None

class DeviceDelete(BaseModel):
    ip: str

class DeviceRenameSchema(BaseModel):
    ip: str
    hostname: str

class CSVImportRequest(BaseModel):
    csv_data: str

class DeviceReassignSchema(BaseModel):
    ip: str
    new_group: str

class DeviceSiteSchema(BaseModel):
    ip: str
    new_site: str

class PromoteDeviceSchema(BaseModel):
    node_id: str
    ip: str = Field(..., pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    vendor: str = "cisco"
    group: str = "Generale"
    # Dati ereditati da CDP/LLDP da preservare sul dispositivo promosso.
    model: Optional[str] = None
    version: Optional[str] = None
    device_type: Optional[str] = None
    hostname: Optional[str] = None

# --- ROTTE DISPOSITIVI (INVENTARIO) ---

@router.get("/api/local-devices")
def get_devices_and_versions(current_user = Depends(get_current_user)):
    from redundancy import service as redundancy_service
    scope = user_group_scope(current_user)
    devices = inventory_manager.get_all_devices()
    versions = inventory_manager.get_detected_versions()
    groups = inventory_manager.get_all_groups()
    if scope is not None:
        devices = [d for d in devices if d.get('Group') in scope]
        allowed_ips = {d['IP'] for d in devices}
        versions = {ip: v for ip, v in versions.items() if ip in allowed_ips}
        groups = {g: v for g, v in groups.items() if g in scope}
    from security.snmp_defaults import tenants_with_default
    _snmp_default_tenants = tenants_with_default()
    devices_enriched = []
    for d in devices:
        dev_copy = dict(d)
        # Stesso principio della community qui sotto, applicato alle credenziali
        # SSH: cifrate o no, non hanno motivo di arrivare al browser. La UI non
        # le legge (l'export CSV si costruisce la sua whitelist di colonne), e
        # un viewer non deve poter scaricare il cifrato dell'intera flotta.
        dev_copy.pop("Password", None)
        dev_copy.pop("Enable Secret", None)
        dev_copy["redundancy"] = redundancy_service.device_redundancy_badge(d["IP"])
        # ICMP cannot cross the bastion tunnel of a jump site: the inventory
        # table's status cell must not paint one of its devices "offline" from
        # a ping it never actually ran (see services.site_manager.has_direct_path).
        dev_copy["icmp_reachable"] = site_manager.has_direct_path(d.get("Site"))
        # La community non esce mai da qui, nemmeno cifrata: alla UI serve
        # sapere SE il polling SNMP è configurato, non quale sia il segreto.
        # Alla UI serve sapere SE il polling e' configurato e DA DOVE arriva
        # la community: senza il secondo campo, un apparato che eredita e uno
        # con la sua sembrano identici, e l'admin non sa cosa sta modificando.
        own = bool(dev_copy.pop("SNMP Community", ""))
        disabled = str(dev_copy.get("SNMP Disabled") or "").strip() in ("1", "true", "True")
        inherited = (not own) and (not disabled) and \
            (d.get("Group") or "Generale") in _snmp_default_tenants
        dev_copy["snmp_enabled"] = (own or inherited) and not disabled
        dev_copy["snmp_inherited"] = inherited
        v_info = versions.get(d["IP"], {})
        dev_copy["Version"] = d.get("Version") or v_info.get("version") or "Non Rilevata"
        dev_copy["Model"] = d.get("Model") or v_info.get("model") or "Non Rilevato"
        devices_enriched.append(dev_copy)
    return {
        "devices": devices_enriched,
        "detected_versions": versions,
        "groups": groups
    }

# Excel e LibreOffice eseguono come formula qualunque cella che cominci per
# questi caratteri. Hostname e versione li scrive l'APPARATO, quindi chi
# controlla un apparato scriverebbe una formula nel foglio di chi esporta
# l'inventario. La quotatura CSV non c'entra e non basta: sono due problemi
# diversi, e il modulo csv risolve solo il primo.
_CSV_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value):
    """Neutralizza una cella che il foglio di calcolo eseguirebbe.

    L'apostrofo in testa e' la neutralizzazione standard: il foglio mostra il
    testo e non lo valuta."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in _CSV_FORMULA_LEADERS else s


@router.get("/api/export/devices")
def export_devices_csv(current_user = Depends(get_current_user)):
    import csv, io
    scope = user_group_scope(current_user)
    devices = inventory_manager.get_all_devices()
    if scope is not None:
        devices = [d for d in devices if d.get('Group') in scope]
    versions = inventory_manager.get_detected_versions()
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["Hostname", "IP", "Vendor", "Group", "Version", "Status"],
        extrasaction="ignore"
    )
    writer.writeheader()
    for d in devices:
        scan = versions.get(d["IP"], {})
        writer.writerow({k: _csv_cell(v) for k, v in {
            "Hostname": d.get("Hostname") or d.get("IP"),
            "IP":       d["IP"],
            "Vendor":   d.get("Vendor", ""),
            "Group":    d.get("Group", ""),
            "Version":  scan.get("version", "Non Scansionato"),
            "Status":   scan.get("status", "unknown"),
        }.items()})
    content = output.getvalue()
    log_audit(f"Export CSV dispositivi richiesto dall'utente '{current_user.get('sub')}'.")
    from fastapi.responses import Response as FastResponse
    return FastResponse(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinelnet-devices.csv"}
    )

@router.post("/api/add-device")
def add_device(device: DeviceSchema, current_user = Depends(require_operator)):
    assert_group_allowed(current_user, device.group)
    # Impedisce di modificare un dispositivo esistente in una sede non consentita
    existing = next((d for d in inventory_manager.get_all_devices() if d['IP'] == device.ip), None)
    if existing:
        assert_group_allowed(current_user, existing.get('Group', 'Generale'))

    site_val = (device.site or 'central').strip()
    all_sites = {s['id'] for s in site_manager.list_sites()}
    if site_val not in all_sites:
        raise HTTPException(status_code=400, detail=f"Sede '{site_val}' inesistente")

    try:
        inventory_manager.add_or_update_device(
            device.ip, device.vendor, device.profile,
            device.username, device.password, device.enable_secret, device.group,
            site=site_val,
            ssh_port=device.ssh_port, transports=device.transports,
            snmp_community=device.snmp_community,
            snmp_disabled=device.snmp_disabled,
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    log_audit(f"Dispositivo '{device.ip}' (vendor: '{device.vendor}', gruppo: '{device.group}', sede: '{site_val}') aggiunto/aggiornato dall'utente '{current_user.get('sub')}'.")
    # §11.6: Telnet è in chiaro — traccia esplicitamente l'abilitazione.
    if device.transports and 'telnet' in device.transports:
        log_audit(f"ATTENZIONE: Telnet (trasmissione in chiaro) abilitato per il dispositivo '{device.ip}' dall'utente '{current_user.get('sub')}'.")
    return {"status": "success", "message": "Dispositivo salvato"}

@router.post("/api/delete-device")
def delete_device(payload: DeviceDelete, current_user = Depends(require_operator)):
    assert_device_allowed(current_user, payload.ip)
    inventory_manager.delete_device(payload.ip)
    log_audit(f"Dispositivo '{payload.ip}' eliminato dall'inventario dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/rename-device")
def rename_device(payload: DeviceRenameSchema, current_user = Depends(require_operator)):
    """Rinomina un dispositivo gestito impostandone manualmente l'hostname (il
    nome mostrato in inventario e sulla mappa). admin/operator, con scoping."""
    assert_device_allowed(current_user, payload.ip)
    if not next((d for d in inventory_manager.get_all_devices() if d['IP'] == payload.ip), None):
        raise HTTPException(status_code=404, detail="Dispositivo non trovato in inventario.")
    hostname = payload.hostname.strip()
    inventory_manager.update_device_hostname(payload.ip, hostname)
    log_audit(f"Dispositivo '{payload.ip}' rinominato in '{hostname or '(vuoto)'}' dall'utente '{current_user.get('sub')}'.")
    return {"status": "success"}

# La lettura tollerante del CSV vive in inventory_manager: la usa anche
# l'agente di sede, che gira senza FastAPI. Qui resta il nome storico.
_CSV_ALIASES = inventory_manager._CSV_ALIASES
_canonical_header = inventory_manager._canonical_header
_read_inventory_csv = inventory_manager._read_inventory_csv


@router.post("/api/import-csv")
def import_csv(payload: CSVImportRequest, current_user = Depends(require_operator)):
    try:
        parsed = _read_inventory_csv(payload.csv_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    results = {"imported": [], "failed": []}
    scope = user_group_scope(current_user)

    for i, row in parsed:
        try:
            ip = row.get('IP')
            if not ip or not ip.strip():
                raise ValueError("IP mancante o vuoto")
            ip = ip.strip()

            # Se il campo Group è presente e non vuoto, chiama immediatamente inventory_manager.add_group(row['Group'])
            group_name = (row.get('Group') or '').strip() or 'Generale'
            # Scoping: un operatore limitato non può importare in sedi non consentite
            if scope is not None and group_name not in scope:
                raise ValueError(f"Sede '{group_name}' non consentita per il tuo profilo")
            if group_name != 'Generale':
                inventory_manager.add_group(group_name)

            username = (row.get('Username') or '').strip()
            password = (row.get('Password') or '').strip()
            enable_secret = (row.get('Enable Secret') or '').strip()

            hostname = (row.get('Hostname') or '').strip()

            vendor = (row.get('Vendor') or '').strip() or 'cisco'

            # Site (sede fisica) è cosa diversa da Group (tenant): la colonna
            # veniva letta e buttata via, quindi un inventario esportato e
            # reimportato perdeva l'assegnazione alle sedi con agente.
            # Non si crea al volo come si fa con il tenant: una sede ha una
            # modalità e un token, inventarla qui produrrebbe un apparato che
            # nessun agente raccoglierà mai. Meglio un errore sulla riga.
            site_name = (row.get('Site') or '').strip()
            if site_name and site_name not in {s['id'] for s in site_manager.list_sites()}:
                raise ValueError(f"Sede '{site_name}' inesistente: creala nella "
                                 f"scheda Sedi prima di importare")

            # Rimozione Profile: passa forzatamente il valore "custom" come parametro profile
            inventory_manager.add_or_update_device(
                ip, vendor, "custom",
                username, password, enable_secret,
                group_name, site=site_name or None
            )
            # L'hostname del CSV veniva letto e buttato via: chi compilava la
            # colonna vedeva l'inventario restare senza nomi e non capiva
            # perche'. Si scrive dopo perche' add_or_update_device non ha il
            # parametro, e sovrascriverlo li' cambierebbe la firma per tutti.
            if hostname:
                inventory_manager.update_device_hostname(ip, hostname)
            results["imported"].append(ip)
        except Exception as e:
            results["failed"].append({
                "row": i,
                "ip": (row.get('IP') or '?').strip() or '?',
                "error": str(e)
            })

    log_audit(f"Importazione massiva da CSV completata dall'utente '{current_user.get('sub')}'. Importati: {len(results['imported'])}, Falliti: {len(results['failed'])}.")
    return results

@router.post("/api/promote-device")
def promote_device(payload: PromoteDeviceSchema, current_user = Depends(require_operator)):
    """Promuove un dispositivo scoperto (CDP/LLDP) a dispositivo gestito,
    aggiungendolo all'inventario così da poter essere sottoposto a triage.
    Le credenziali vanno completate dopo, nella pagina Inventario."""
    assert_group_allowed(current_user, payload.group)
    if payload.group not in inventory_manager.get_all_groups():
        raise HTTPException(status_code=400, detail=f"Sede '{payload.group}' inesistente.")
    existing = next((d for d in inventory_manager.get_all_devices() if d['IP'] == payload.ip), None)
    if existing:
        raise HTTPException(status_code=400, detail=f"Dispositivo {payload.ip} già in inventario.")
    inventory_manager.add_or_update_device(
        payload.ip, payload.vendor, "custom", "", "", "", payload.group
    )
    # Trasferisce l'eventuale classificazione manuale dal nodo scoperto all'IP.
    # Il nodo scoperto sta sotto 'Generale' (non era in inventario, quindi non
    # aveva una sede); da qui in poi appartiene alla sede in cui è stato promosso.
    inventory_manager.migrate_assignment(payload.node_id, payload.ip,
                                         new_tenant=payload.group)
    # Eredita ciò che è già stato scoperto via CDP/LLDP: categoria, modello,
    # versione e hostname, così il dispositivo promosso non riparte "vuoto".
    meta = {}
    if payload.device_type:
        meta["category"] = payload.device_type
    if payload.model:
        meta["model"] = payload.model
    # Eredita il nome scelto: sia come hostname CSV (tabella/triage) sia come
    # override 'name' (etichetta su mappa e tab Categorie), così resta coerente.
    if payload.hostname:
        meta["name"] = payload.hostname
    if meta:
        inventory_manager.set_device_meta(payload.ip, **meta)
    if payload.version:
        inventory_manager.update_version_inventory(
            payload.ip, payload.vendor, payload.version, "discovered"
        )
    if payload.hostname:
        inventory_manager.update_device_hostname(payload.ip, payload.hostname)
    log_audit(
        f"Dispositivo scoperto '{payload.node_id}' promosso a gestito "
        f"(IP {payload.ip}, vendor {payload.vendor}, sede {payload.group}) "
        f"da '{current_user.get('sub')}'."
    )
    return {"status": "success"}

@router.post("/api/reassign-device")
def reassign_device(payload: DeviceReassignSchema, current_user = Depends(require_operator)):
    """Sposta un dispositivo in un gruppo diverso aggiornando solo il campo Group nel CSV."""
    devices = inventory_manager.get_all_devices()
    groups  = inventory_manager.get_all_groups()

    target = next((d for d in devices if d['IP'] == payload.ip), None)
    if not target:
        raise HTTPException(status_code=404, detail="Dispositivo non trovato in inventario.")
    if payload.new_group not in groups:
        raise HTTPException(
            status_code=400,
            detail=f"Gruppo '{payload.new_group}' non esiste. Crealo prima."
        )

    # Scoping: la sede di origine e quella di destinazione devono essere consentite
    assert_group_allowed(current_user, target.get('Group', 'Generale'))
    assert_group_allowed(current_user, payload.new_group)

    old_group = target.get('Group', 'Generale')
    target['Group'] = payload.new_group
    inventory_manager.safe_write_hosts_csv(devices)

    log_audit(
        f"Dispositivo '{payload.ip}' spostato dal gruppo '{old_group}' "
        f"al gruppo '{payload.new_group}' dall'utente '{current_user.get('sub')}'."
    )
    return {"status": "success", "message": f"Dispositivo spostato in '{payload.new_group}'"}

@router.post("/api/reassign-device-site")
def reassign_device_site(payload: DeviceSiteSchema, current_user = Depends(require_operator)):
    """Sposta un dispositivo in un'altra sede aggiornando solo il campo Site.

    Separata da /api/reassign-device perche' cambia una cosa diversa: il
    tenant e' il confine di autorizzazione, la sede decide COME si raggiunge
    l'apparato (diretto, agente, tunnel sul bastione). Spostarlo su una sede
    jump lo toglie dal ping ICMP e lo mette dietro il bastione al giro dopo.
    """
    from services import site_manager
    if not site_manager.get_site(payload.new_site):
        raise HTTPException(status_code=400,
                            detail=f"Sede '{payload.new_site}' non esiste.")
    devices = inventory_manager.get_all_devices()
    target = next((d for d in devices if d['IP'] == payload.ip), None)
    if not target:
        raise HTTPException(status_code=404, detail="Dispositivo non trovato in inventario.")
    # Il tenant resta il confine di scoping: chi non puo' gestire il tenant del
    # dispositivo non ne cambia nemmeno la sede.
    assert_group_allowed(current_user, target.get('Group', 'Generale'))

    old_site = target.get('Site', 'central')
    target['Site'] = payload.new_site
    inventory_manager.safe_write_hosts_csv(devices)

    log_audit(
        f"Dispositivo '{payload.ip}' spostato dalla sede '{old_site}' "
        f"alla sede '{payload.new_site}' dall'utente '{current_user.get('sub')}'."
    )
    return {"status": "success", "message": f"Dispositivo spostato nella sede '{payload.new_site}'"}
