import json
import logging
import os
import csv
import re
import threading
from typing import Any, Dict
from security import crypto_vault
from core import data_config

logger = logging.getLogger(__name__)

_DEFAULT_HOSTS_CSV = data_config.get_path("network_hosts.csv")
_DEFAULT_GROUPS_JSON = data_config.get_path("groups.json")
_DEFAULT_VERSION_DATA_FILE = data_config.get_path("detected_versions.json")
_DEFAULT_VENDORS_FILE = data_config.get_path("vendors.json")

HOSTS_CSV = _DEFAULT_HOSTS_CSV
GROUPS_JSON = _DEFAULT_GROUPS_JSON
VERSION_DATA_FILE = _DEFAULT_VERSION_DATA_FILE
VENDORS_FILE = _DEFAULT_VENDORS_FILE

def get_hosts_csv() -> str:
    if HOSTS_CSV != _DEFAULT_HOSTS_CSV:
        return HOSTS_CSV
    return data_config.get_path("network_hosts.csv")

def get_groups_json() -> str:
    if GROUPS_JSON != _DEFAULT_GROUPS_JSON:
        return GROUPS_JSON
    return data_config.get_path("groups.json")

def get_version_data_file() -> str:
    if VERSION_DATA_FILE != _DEFAULT_VERSION_DATA_FILE:
        return VERSION_DATA_FILE
    return data_config.get_path("detected_versions.json")

def get_vendors_file() -> str:
    if VENDORS_FILE != _DEFAULT_VENDORS_FILE:
        return VENDORS_FILE
    return data_config.get_path("vendors.json")

IP_PATTERN = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

# --- Trasporti per-device (§11.6) ---
# Protocolli di connessione dichiarabili per apparato e relativa porta di
# default (null nella mappa = usa questa porta di default del protocollo).
# tcp/udp: protocolli generici senza porta di default, la sceglie l'utente.
ALLOWED_TRANSPORTS = ("ssh", "telnet", "netconf", "restconf", "tcp", "udp")
TRANSPORT_DEFAULT_PORTS = {"ssh": 22, "telnet": 23, "netconf": 830, "restconf": 443}


def parse_transports(device) -> dict:
    """Ritorna la mappa trasporti dichiarati {protocollo: porta|None} di un
    device. Inventari legacy senza colonna 'Transports': sintetizza uno
    ssh-only {'ssh': <SSH Port>|22} per retrocompatibilità."""
    raw = device.get('Transports') if isinstance(device, dict) else None
    if raw:
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            data = None
        if isinstance(data, dict):
            out = {k: v for k, v in data.items() if k in ALLOWED_TRANSPORTS}
            if out:
                return out
    # Legacy: ssh-only derivato dalla colonna 'SSH Port'.
    try:
        p = int(str(device.get('SSH Port') or '').strip() or 22)
    except (ValueError, AttributeError):
        p = 22
    return {"ssh": p}


def _validate_transports(transports):
    """Valida/normalizza una mappa {protocollo: porta|None}. Lancia ValueError
    (messaggi in italiano) su chiave o porta non valide. None => None."""
    if transports is None:
        return None
    if not isinstance(transports, dict):
        raise ValueError("Trasporti non validi: atteso un oggetto protocollo→porta.")
    clean = {}
    for proto, port in transports.items():
        if proto not in ALLOWED_TRANSPORTS:
            raise ValueError(f"Protocollo di trasporto non supportato: '{proto}'.")
        if port is None or port == "":
            clean[proto] = None
            continue
        try:
            p = int(port)
        except (TypeError, ValueError):
            raise ValueError(f"Porta non valida per il protocollo '{proto}': {port}.")
        if not (1 <= p <= 65535):
            raise ValueError(f"Porta non valida per il protocollo '{proto}': {port}.")
        clean[proto] = p
    return clean

# Lock rientrante che serializza le sequenze read-modify-write sui file di stato
# condivisi (CSV inventario e JSON versioni/gruppi). Necessario perché il triage
# e la scansione subnet eseguono fino a 50 worker concorrenti che altrimenti
# sovrascriverebbero gli aggiornamenti reciproci (lost update).
_io_lock = threading.RLock()

def safe_json_write(filepath: str, data: dict):
    """Scrittura atomica con pattern temp-then-rename e fallback Windows."""
    temp = filepath + ".tmp"
    try:
        with open(temp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        try:
            os.replace(temp, filepath)
        except PermissionError:
            # Fallback per sistemi Windows concorrentemente bloccati
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4)
            except Exception as fallback_err:
                raise RuntimeError(
                    f"Scrittura fallita su '{filepath}': {fallback_err}"
                ) from fallback_err
            finally:
                if os.path.exists(temp):
                    try:
                        os.remove(temp)
                    except OSError:
                        pass
    except Exception as e:
        if os.path.exists(temp):
            try:
                os.remove(temp)
            except OSError:
                pass
        raise e

def get_all_groups():
    groups_json = get_groups_json()
    if not os.path.exists(groups_json):
        default_groups = {"Generale": {"description": "Sede Principale predefinita"}}
        save_groups(default_groups)
        return default_groups
    with open(groups_json, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            if isinstance(data, list):
                # Convert legacy list to dictionary format
                new_dict = {}
                for g in data:
                    new_dict[g] = {"description": "Sede Principale predefinita" if g == "Generale" else f"Sede secondaria {g}"}
                save_groups(new_dict)
                return new_dict
            return data
        except Exception:
            default_groups = {"Generale": {"description": "Sede Principale predefinita"}}
            save_groups(default_groups)
            return default_groups

def save_groups(groups_dict):
    safe_json_write(get_groups_json(), groups_dict)

# --- Lettura tollerante di un CSV di inventario ---
# Vive qui e non nel router perché la usano due chiamanti: l'import CSV di
# central (routers/inventory.py) e il salvataggio dell'inventario remoto
# dell'agente di sede (services/site_agent.py), che gira senza FastAPI.

# Intestazioni accettate per ciascun campo. Un CSV di inventario viene quasi
# sempre da un foglio di calcolo passato di mano in mano, e arriva con
# maiuscole diverse, underscore al posto degli spazi o le colonne tradotte.
# Rifiutarlo per questo significa che l'utente deve indovinare la grafia esatta
# leggendo un riquadro di esempio: e' il motivo per cui l'import "non funziona".
_CSV_ALIASES: Dict[str, str] = {
    "ip": "IP", "indirizzo": "IP", "indirizzoip": "IP", "host": "IP",
    "mgmtip": "IP", "ipaddress": "IP",
    "username": "Username", "user": "Username", "utente": "Username",
    "login": "Username",
    "password": "Password", "pass": "Password", "pwd": "Password",
    "enablesecret": "Enable Secret", "enable": "Enable Secret",
    "secret": "Enable Secret", "enablepassword": "Enable Secret",
    "hostname": "Hostname", "nome": "Hostname", "name": "Hostname",
    "device": "Hostname", "nomeapparato": "Hostname",
    # DUE concetti distinti, non sinonimi — vedi il riquadro della scheda
    # Import, che li spiega all'utente con le stesse parole:
    #   Group  = TENANT. Il confine RBAC: chi vede cosa. E' la colonna su cui
    #            filtra ogni vista, ed e' il `tenant` di ogni riga di
    #            osservabilita'.
    #   Site   = SEDE FISICA. Da dove si raggiunge l'apparato: 'central'
    #            (polling diretto) oppure l'id di una sede con agente.
    #
    # Prima 'site' e 'sede' finivano su Group, mentre l'export scriveva
    # ENTRAMBE le colonne: reimportare un file esportato riscriveva il tenant
    # di ogni apparato con il suo id di sede, in silenzio. Un round-trip deve
    # restituire l'inventario che ha esportato.
    "group": "Group", "gruppo": "Group", "tenant": "Group",
    "site": "Site", "sede": "Site",
    "vendor": "Vendor", "marca": "Vendor", "produttore": "Vendor",
    "brand": "Vendor",
    # Colonne canoniche restanti: senza questi alias un round-trip
    # lettura → scrittura le perdeva silenziosamente.
    "profile": "Profile", "profilo": "Profile",
    "sshport": "SSH Port", "porta": "SSH Port", "portassh": "SSH Port",
    "transports": "Transports", "trasporti": "Transports",
    "snmpcommunity": "SNMP Community", "communitysnmp": "SNMP Community",
    "snmpdisabled": "SNMP Disabled", "snmpescluso": "SNMP Disabled",
}


def _canonical_header(name: str) -> "str | None":
    """Nome canonico della colonna, o ``None`` se non riconosciuta."""
    key = "".join(ch for ch in (name or "").lower() if ch.isalnum())
    return _CSV_ALIASES.get(key)


def _read_inventory_csv(raw: str):
    """Righe del CSV come dizionari a chiavi canoniche.

    Tollerante su tre cose che fanno fallire OGNI riga senza dire perche':

    - il BOM che Excel scrive in testa al file, che rinomina la prima colonna
      in ``\\ufeffIP`` e la rende irriconoscibile;
    - il separatore, che nei fogli di calcolo con impostazioni italiane e' ``;``
      e non ``,`` — con la virgola l'intero file diventa una colonna sola;
    - la grafia delle intestazioni (vedi ``_CSV_ALIASES``).

    Solleva ``ValueError`` con un messaggio azionabile quando manca la colonna
    IP, che e' l'unica davvero indispensabile.
    """
    text = (raw or "").lstrip("﻿").strip()
    if not text:
        raise ValueError("File CSV vuoto.")

    header_line = text.splitlines()[0]
    # Sniffer di csv: comodo ma sbaglia sui file a colonna singola. Qui si
    # sceglie il separatore piu' presente nell'intestazione, che e' la riga in
    # cui i separatori ci sono per definizione.
    delimiter = max((",", ";", "\t", "|"), key=header_line.count)
    if header_line.count(delimiter) == 0:
        delimiter = ","

    reader = csv.reader(text.splitlines(), delimiter=delimiter)
    rows = list(reader)
    if not rows:
        raise ValueError("File CSV vuoto.")

    header = [_canonical_header(h) for h in rows[0]]
    if "IP" not in header:
        raise ValueError(
            "Colonna IP non trovata. Intestazioni lette: %s. "
            "La prima riga deve contenere i nomi delle colonne, "
            "almeno 'IP'." % (", ".join(h.strip() for h in rows[0]) or "(nessuna)"))

    out = []
    for line_no, values in enumerate(rows[1:], start=2):
        if not any((v or "").strip() for v in values):
            continue                      # riga vuota: non e' un errore
        record = {}
        for col, value in zip(header, values):
            if col:
                record[col] = (value or "").strip()
        out.append((line_no, record))
    return out


def safe_write_hosts_csv(devices):
    invalidate_device_ip_cache()  # l'inventario cambia: la cache IP→device decade
    from ai import config_analyzer
    # idem: Vendor/tenant/hostname dell'inventario pilotano analyze_device, e
    # la chiave del memo e' solo (ip, mtime del backup) — un Vendor corretto
    # qui non la farebbe decadere da sola. Import locale per evitare un ciclo.
    config_analyzer._analyze_device_at.cache_clear()
    hosts_csv = get_hosts_csv()
    temp_filename = hosts_csv + ".tmp"
    # 'Site' identifica la sede multi-sede (default 'central'); 'extrasaction=ignore'
    # tollera dizionari con chiavi extra (retrocompatibilità).
    _fieldnames = ['IP', 'Vendor', 'Profile', 'Username', 'Password', 'Enable Secret', 'Group', 'Hostname', 'Site', 'SSH Port', 'Transports', 'SNMP Community', 'SNMP Disabled']
    try:
        with open(temp_filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=_fieldnames, extrasaction='ignore')
            writer.writeheader()
            for d in devices:
                writer.writerow(d)
        try:
            os.replace(temp_filename, hosts_csv)
        except PermissionError:
            # Fallback per sistemi Windows
            with open(hosts_csv, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=_fieldnames, extrasaction='ignore')
                writer.writeheader()
                for d in devices:
                    writer.writerow(d)
            if os.path.exists(temp_filename):
                try:
                    os.remove(temp_filename)
                except OSError:
                    pass
    except Exception as e:
        if os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
            except OSError:
                pass
        raise e

def get_all_devices():
    devices = []
    hosts_csv = get_hosts_csv()
    if not os.path.exists(hosts_csv):
        return devices
    with open(hosts_csv, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Inventari legacy senza colonna 'Site': default alla sede centrale.
            if not row.get('Site'):
                row['Site'] = 'central'
            # Inventari legacy senza colonna 'SSH Port': default 22.
            if not row.get('SSH Port'):
                row['SSH Port'] = '22'
            devices.append(row)
    return devices

# --- Cache IP → device per l'attribuzione tenant all'ingest (fase 3.5) ---
# Invalidata a ogni scrittura dell'inventario (safe_write_hosts_csv).

_device_ip_cache = None
_device_ip_cache_lock = threading.Lock()


def invalidate_device_ip_cache():
    global _device_ip_cache
    with _device_ip_cache_lock:
        _device_ip_cache = None


def get_device_by_ip(ip: str):
    """Risolve un IP in (hostname, gruppo/tenant) per l'attribuzione dei
    flussi all'ingest. Ritorna dict {'ip','hostname','tenant'} oppure None se
    sconosciuto. Se PIÙ device condividono lo stesso IP ritorna il sentinella
    {'collision': True} (attribuzione rifiutata, anomalia da auditare)."""
    global _device_ip_cache
    with _device_ip_cache_lock:
        if _device_ip_cache is None:
            cache: Dict[str, Dict[str, Any]] = {}
            for d in get_all_devices():
                key = d.get('IP')
                if not key:
                    continue
                if key in cache:
                    cache[key] = {"collision": True}
                    continue
                cache[key] = {
                    "ip": key,
                    "hostname": d.get('Hostname') or "",
                    "tenant": d.get('Group') or 'Generale',
                    "site": d.get('Site') or 'central',
                }
            _device_ip_cache = cache
        return _device_ip_cache.get(ip)


def add_or_update_device(ip, vendor, profile, username, password, enable_secret, group, site=None, ssh_port=None, transports=None, snmp_community=None, snmp_disabled=None):
    # Validazione IP robusta
    match = IP_PATTERN.match(ip)
    if not match or not all(0 <= int(octet) <= 255 for octet in match.groups()):
        raise ValueError(f"IP non valido: {ip}")
    # ssh_port=None = preserva la porta del dispositivo esistente (o 22).
    if ssh_port is not None:
        try:
            ssh_port = int(ssh_port)
        except (TypeError, ValueError):
            raise ValueError(f"Porta SSH non valida: {ssh_port}")
        if not (1 <= ssh_port <= 65535):
            raise ValueError(f"Porta SSH non valida: {ssh_port}")
    # Mappa trasporti esplicita (§11.6): validata; None = deriva da esistente/legacy.
    transports = _validate_transports(transports)

    with _io_lock:
        devices = get_all_devices()
        # Preserva l'hostname già rilevato sul dispositivo esistente
        existing = next((d for d in devices if d['IP'] == ip), None)

        # Credenziali: su un dispositivo GIÀ ESISTENTE un valore vuoto vuole
        # dire "lascia quelle che ci sono", non "cancellale" — stessa regola
        # della community SNMP qui sotto. Senza, ogni salvataggio parziale le
        # azzerava: la modifica da UI obbligava a ridigitare la password per
        # non perderla, e ogni sync dell'agente di sede (routers/agent.py, che
        # le credenziali non le conosce e manda stringhe vuote) riportava ai
        # default i dispositivi che annunciava.
        # In creazione si scrive quello che arriva: il vuoto è già gestito a
        # valle da get_device_credentials, che ricade sui default.
        # ponytail: non c'è modo esplicito di SVUOTARE un enable secret. Se
        # servisse, la strada è la spunta dedicata che la community SNMP ha
        # già, non un sentinel diverso da queste due.
        if existing is not None:
            username = username or existing.get('Username') or ''
            enc_password = crypto_vault.encrypt_password(password) if password \
                else (existing.get('Password') or '')
            enc_secret = crypto_vault.encrypt_password(enable_secret) if enable_secret \
                else (existing.get('Enable Secret') or '')
        else:
            enc_password = crypto_vault.encrypt_password(password)
            enc_secret = crypto_vault.encrypt_password(enable_secret)
        existing_hostname = existing.get('Hostname') if existing else None
        # Preserva la sede esistente se non ne viene indicata una nuova.
        resolved_site = site or (existing.get('Site') if existing else None) or 'central'
        resolved_port = ssh_port if ssh_port is not None else \
            ((existing.get('SSH Port') if existing else None) or 22)
        # Trasporti: esplicito > esistente (se già migrato) > sintesi ssh-only.
        if transports is not None:
            resolved_transports = transports
        elif existing is not None and existing.get('Transports'):
            resolved_transports = parse_transports(existing)
        else:
            resolved_transports = {"ssh": int(resolved_port)}
        # Rispecchia la porta SSH nella colonna legacy 'SSH Port' per
        # retrocompatibilità di lettura (get_device_port, is_reachable).
        ssh_mirror = resolved_transports.get('ssh')
        if ssh_mirror is None:
            ssh_mirror = resolved_port
        # Community SNMP: None = preserva quella esistente (i moduli che
        # aggiornano un device per altri motivi non devono cancellarla),
        # stringa vuota = rimuovila. Cifrata nel vault come le altre credenziali.
        if snmp_community is None:
            enc_community = (existing.get('SNMP Community') if existing else '') or ''
        else:
            enc_community = crypto_vault.encrypt_password(snmp_community) \
                if snmp_community else ''
        # Esclusione SNMP: None = lascia com'e' (i moduli che aggiornano un
        # device per altri motivi non devono cambiarla), come per la community.
        if snmp_disabled is None:
            disabled_val = (existing.get('SNMP Disabled') if existing else '') or ''
        else:
            disabled_val = '1' if snmp_disabled else ''
        devices = [d for d in devices if d['IP'] != ip]

        new_device = {
            'IP': ip, 'Vendor': vendor.lower(), 'Profile': profile,
            'Username': username, 'Password': enc_password, 'Enable Secret': enc_secret,
            'Group': group if group in get_all_groups() else 'Generale',
            'Site': resolved_site,
            'SSH Port': str(ssh_mirror),
            'Transports': json.dumps(resolved_transports, separators=(',', ':')),
            'SNMP Community': enc_community,
            'SNMP Disabled': disabled_val,
        }
        if existing_hostname:
            new_device['Hostname'] = existing_hostname
        devices.append(new_device)
        safe_write_hosts_csv(devices)

def delete_device(ip):
    with _io_lock:
        devices = get_all_devices()
        devices = [d for d in devices if d['IP'] != ip]
        safe_write_hosts_csv(devices)

VENDOR_ALIASES = {
    "fotinet": "fortinet",
    "forti": "fortinet",
    "fortigate": "fortinet",
    "fortios": "fortinet",
    "palo-alto": "paloalto",
    "palo_alto": "paloalto",
    "palo": "paloalto",
    "panos": "paloalto",
    "hp": "hpe",
    "procurve": "hpe",
    "junos": "juniper",
    "juniper_junos": "juniper",
    "cisco_ios": "cisco",
    # Un CSV scritto a mano dice "Ubuntu", non "linux": le distro convergono
    # tutte sullo stesso driver, perche' cambia il packaging, non la CLI.
    "ubuntu": "linux",
    "debian": "linux",
    "rhel": "linux",
    "redhat": "linux",
    "centos": "linux",
    "rocky": "linux",
    "almalinux": "linux",
    "suse": "linux",
    "proxmox": "linux",
}

def normalize_vendor(raw_vendor: str) -> str:
    """Canonicalizza un nome vendor traducendo alias e refusi comuni."""
    v = (raw_vendor or "").lower().strip()
    return VENDOR_ALIASES.get(v, v)

def get_all_vendors() -> dict:
    """Returns {display_name: {euvd_term: str, driver: str|None}}"""
    defaults = {
        "cisco":   {"euvd_term": "cisco",                    "driver": "cisco_ios"},
        "cisco_cbs":{"euvd_term": "cisco",                   "driver": "cisco_s300"},
        "hpe":     {"euvd_term": "hpe",                      "driver": "hp_procurve"},
        "juniper": {"euvd_term": "juniper",                  "driver": "juniper_junos"},
        "aruba":   {"euvd_term": "aruba",                    "driver": "aruba_os"},
        "fortinet":{"euvd_term": "fortinet",                 "driver": "fortinet"},
        "paloalto":{"euvd_term": "palo alto",                "driver": "paloalto_panos"},
        "cisco_wlc":{"euvd_term": "cisco",                   "driver": "cisco_wlc"},
        "cisco_9800":{"euvd_term": "cisco",                  "driver": "cisco_9800"},
        "linux":   {"euvd_term": "linux",                    "driver": "linux"},
    }
    vendors_file = get_vendors_file()
    if not os.path.exists(vendors_file):
        safe_json_write(vendors_file, defaults)
        return defaults
    try:
        with open(vendors_file, "r") as f:
            stored = json.load(f)
        merged = {**defaults, **stored}
        # Canonicalize legacy multi-word EUVD terms into clean NVD keywords
        for vname, vmeta in merged.items():
            if isinstance(vmeta, dict) and "euvd_term" in vmeta:
                vmeta["euvd_term"] = resolve_euvd_term(vmeta["euvd_term"])
        return merged
    except Exception:
        return defaults

def save_vendors(vendors: dict):
    safe_json_write(get_vendors_file(), vendors)

# --- CATEGORIE DISPOSITIVI (classificazione manuale + categorie custom) ---

CATEGORIES_FILE = data_config.get_path("device_categories.json")

# Categorie predefinite riconosciute dalla classificazione automatica. Restano
# sempre presenti; l'utente può aggiungerne di custom e definire sottocategorie.
BUILTIN_CATEGORIES = {
    "ap":       "Access Point",
    "wlc":      "Wireless LAN Controller",
    "firewall": "Firewall",
    "router":   "Router",
    "switch":   "Switch",
    "server":   "Server",
    "phone":    "Telefono IP",
    "camera":   "Telecamera IP",
    "pc":       "PC / Workstation",
    "other":    "Altro",
}

def _norm_cat_key(key: str) -> str:
    return re.sub(r'[^a-z0-9_-]', '', (key or '').strip().lower().replace(' ', '-'))

def _tenant_key(value) -> str:
    """Same normalization used by the diagnosis join: empty tenant is
    'Generale', so an installation without groups produces one label and not
    two for the same network."""
    return (value or "").strip() or "Generale"


def _akey(tenant, node_id: str) -> str:
    """Key of a manual assignment: tenant AND node, never the node alone.

    Keyed by node alone, two customers on the same RFC 1918 address shared one
    label: whoever classified 192.0.2.50 in one site renamed it in every other
    site too. A tenant is a network of its own, exactly as in mac_sightings.
    """
    return f"{_tenant_key(tenant)}|{node_id}"


def tenant_for_node(node_id: str) -> str:
    """The site a node belongs to, from inventory. A node that is not a managed
    device (discovered via CDP/LLDP and never promoted) has no site of its own
    and lands in 'Generale'."""
    d = next((d for d in get_all_devices() if d['IP'] == node_id), None)
    return _tenant_key(d.get('Group') if d else None)


def _load_categories() -> dict:
    if os.path.exists(CATEGORIES_FILE):
        try:
            with open(CATEGORIES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    else:
        data = {}
    data.setdefault("categories", {})
    data.setdefault("assignments", {})
    # Assignments written before the key carried the tenant. Resolved once,
    # from the site the device has in inventory; the rewritten file has no bare
    # keys left, so this does not run again.
    legacy = [k for k in data["assignments"] if "|" not in k]
    if legacy:
        for old in legacy:
            data["assignments"][_akey(tenant_for_node(old), old)] = \
                data["assignments"].pop(old)
        safe_json_write(CATEGORIES_FILE, data)
    return data

def get_device_categories() -> dict:
    """Ritorna {categories: {key: {label, builtin, subcategories[]}}, assignments}.
    Le categorie predefinite sono sempre incluse."""
    data = _load_categories()
    stored = data["categories"]
    categories = {}
    for key, label in BUILTIN_CATEGORIES.items():
        s = stored.get(key, {})
        categories[key] = {
            # Le categorie predefinite usano sempre l'etichetta di sistema (non
            # quella eventualmente salvata, che poteva essere corrotta col key).
            "label": label,
            "builtin": True,
            "subcategories": sorted(s.get("subcategories", [])),
        }
    for key, s in stored.items():
        if key in BUILTIN_CATEGORIES:
            continue
        categories[key] = {
            "label": s.get("label", key),
            "builtin": False,
            "subcategories": sorted(s.get("subcategories", [])),
        }
    return {"categories": categories, "assignments": data["assignments"]}

def get_category_assignments() -> dict:
    return _load_categories().get("assignments", {})

def add_category(key: str, label: str, subcategory: str = "") -> bool:
    """Crea una categoria custom (o aggiunge una sottocategoria a una esistente)."""
    key = _norm_cat_key(key)
    if not key:
        return False
    with _io_lock:
        data = _load_categories()
        cats = data["categories"]
        default_label = BUILTIN_CATEGORIES.get(key, label.strip() or key)
        entry = cats.setdefault(key, {
            "label": default_label,
            "subcategories": [],
        })
        if label.strip() and key not in BUILTIN_CATEGORIES:
            entry["label"] = label.strip()
        sub = subcategory.strip()
        if sub and sub not in entry["subcategories"]:
            entry["subcategories"].append(sub)
        safe_json_write(CATEGORIES_FILE, data)
        return True

def delete_category(key: str) -> bool:
    """Elimina una categoria custom e libera i dispositivi ad essa assegnati.
    Le categorie predefinite non sono eliminabili."""
    key = _norm_cat_key(key)
    if key in BUILTIN_CATEGORIES:
        return False
    with _io_lock:
        data = _load_categories()
        if key not in data["categories"]:
            return False
        data["categories"].pop(key, None)
        data["assignments"] = {
            n: a for n, a in data["assignments"].items() if a.get("category") != key
        }
        safe_json_write(CATEGORIES_FILE, data)
        return True

def delete_subcategory(category: str, subcategory: str) -> bool:
    """Rimuove una sottocategoria da una categoria e la sgancia dai dispositivi
    che la usavano."""
    category = _norm_cat_key(category)
    subcategory = (subcategory or '').strip()
    if not category or not subcategory:
        return False
    with _io_lock:
        data = _load_categories()
        entry = data["categories"].get(category)
        if not entry or subcategory not in entry.get("subcategories", []):
            return False
        entry["subcategories"].remove(subcategory)
        for a in data["assignments"].values():
            if a.get("subcategory") == subcategory:
                a.pop("subcategory", None)
        safe_json_write(CATEGORIES_FILE, data)
        return True

_META_FIELDS = ("category", "subcategory", "vendor", "model", "ha_group", "name", "ver")

def migrate_assignment(old_id: str, new_id: str, old_tenant=None, new_tenant=None):
    """Sposta l'assegnazione manuale da un id-nodo a un altro (es. quando un
    dispositivo scoperto viene promosso a gestito e cambia id in IP).

    Il nodo scoperto non ha una sede propria, quindi di norma parte da
    'Generale' e arriva nella sede in cui il dispositivo viene promosso."""
    with _io_lock:
        data = _load_categories()
        a = data["assignments"].pop(_akey(old_tenant, old_id), None)
        if a:
            data["assignments"][_akey(new_tenant, new_id)] = a
            safe_json_write(CATEGORIES_FILE, data)

def set_device_meta(node_id: str, tenant=None, **fields) -> bool:
    """Aggiorna in modo incrementale gli attributi manuali di un dispositivo
    (category/subcategory/vendor/model). Stringa vuota = rimuove quel campo.
    category='' riporta il dispositivo alla classificazione automatica.

    ``tenant`` non indicato = si ricava dalla sede che il dispositivo ha in
    inventario, cosi' il chiamante non deve conoscerla."""
    node_id = (node_id or '').strip()
    if not node_id:
        return False
    provided = {k: v for k, v in fields.items() if k in _META_FIELDS and v is not None}
    if not provided:
        return False
    key = _akey(tenant if tenant is not None else tenant_for_node(node_id), node_id)
    with _io_lock:
        data = _load_categories()
        entry = dict(data["assignments"].get(key, {}))
        for k, v in provided.items():
            v = v.strip() if isinstance(v, str) else v
            if k == "category" and v:
                cat = _norm_cat_key(v)
                valid = set(BUILTIN_CATEGORIES) | set(data["categories"])
                if cat not in valid:
                    return False
                entry["category"] = cat
            elif v:
                entry[k] = v
            else:
                entry.pop(k, None)
        if entry:
            data["assignments"][key] = entry
        else:
            data["assignments"].pop(key, None)
        safe_json_write(CATEGORIES_FILE, data)
        return True

# --- REGISTRO MODELLI (per vendor) ---

MODELS_FILE = data_config.get_path("device_models.json")

def get_models() -> dict:
    """Ritorna {vendor_key: [model, ...]}."""
    if os.path.exists(MODELS_FILE):
        try:
            with open(MODELS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            logger.exception("Registro modelli illeggibile: %s", MODELS_FILE)
            return {}
    return {}

def add_model(vendor: str, model: str) -> bool:
    vendor = (vendor or '').strip().lower()
    model = (model or '').strip()
    if not vendor or not model:
        return False
    with _io_lock:
        data = get_models()
        lst = data.setdefault(vendor, [])
        if model not in lst:
            lst.append(model)
            lst.sort()
            safe_json_write(MODELS_FILE, data)
        return True

def delete_model(vendor: str, model: str) -> bool:
    vendor = (vendor or '').strip().lower()
    model = (model or '').strip()
    with _io_lock:
        data = get_models()
        if vendor in data and model in data[vendor]:
            data[vendor].remove(model)
            if not data[vendor]:
                data.pop(vendor)
            safe_json_write(MODELS_FILE, data)
            return True
    return False

VENDOR_NVD_MAP = {
    "hewlett packard enterprise": "hpe",
    "hewlett-packard": "hpe",
    "hewlett packard": "hpe",
    "hp": "hpe",
    "hpe": "hpe",
    "aruba networks": "aruba",
    "aruba": "aruba",
    "juniper networks": "juniper",
    "juniper": "juniper",
    "palo alto networks": "palo alto",
    "paloalto": "palo alto",
    "palo alto": "palo alto",
    "linux kernel": "linux",
    "linux": "linux",
    "cisco systems": "cisco",
    "cisco": "cisco",
    "cisco_cbs": "cisco",
    "cisco_wlc": "cisco",
    "cisco_9800": "cisco",
    "fortinet": "fortinet",
}

def resolve_euvd_term(vendor_display: str) -> str:
    """Maps a vendor display name to the correct NVD search term."""
    key = (vendor_display or "").strip().lower()
    if key in VENDOR_NVD_MAP:
        return VENDOR_NVD_MAP[key]
    for k, v in VENDOR_NVD_MAP.items():
        if k in key:
            return v
    return key

# --- UTILITIES PER RILEVAMENTO VERSIONI (Richieste dal Core Engine e Server) ---

def _clean_version(v):
    """Normalizza una versione: estrae il token versione pulito conservando
    lettere e parentesi."""
    if not v or not isinstance(v, str):
        return v
    try:
        from core.core_engine import extract_version
        ext = extract_version(v)
        if ext:
            return ext
    except Exception:
        pass
    first = v.splitlines()[0].strip()
    m = re.match(r'^([\w().\-/]+)', first)
    return m.group(1) if m else first

def get_detected_versions():
    if os.path.exists(VERSION_DATA_FILE):
        try:
            with open(VERSION_DATA_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for info in data.values():
                if isinstance(info, dict):
                    if info.get('version'):
                        info['version'] = _clean_version(info['version'])
                    if not info.get('model'):
                        info['model'] = 'Non Rilevato'
            return data
        except (OSError, ValueError):
            # Un file corrotto azzera le versioni rilevate di ogni apparato:
            # in UI sembra un'installazione nuova, non una perdita di dati.
            logger.exception("Inventario versioni illeggibile: %s",
                             VERSION_DATA_FILE)
            return {}
    return {}

def update_version_inventory(ip, vendor, version, status="online", model=None):
    with _io_lock:
        data = get_detected_versions()
        entry = data.get(ip, {})
        if not isinstance(entry, dict):
            entry = {}
        entry.update({"vendor": vendor, "version": version, "status": status})
        if model and model != "Non Rilevato":
            entry["model"] = model
        elif "model" not in entry:
            entry["model"] = "Non Rilevato"
        data[ip] = entry
        safe_json_write(VERSION_DATA_FILE, data)

def update_device_hostname(ip: str, hostname: str):
    with _io_lock:
        devices = get_all_devices()
        changed = False
        for d in devices:
            if d['IP'] == ip:
                if d.get('Hostname') != hostname:
                    d['Hostname'] = hostname
                    changed = True
                break
        if changed:
            safe_write_hosts_csv(devices)

def bulk_assign_profile(ips: list, profile: str):
    """Assegna il valore Profile (es. 'identity:<id>' o 'default') a più
    dispositivi in un'unica scrittura di hosts.csv. Ritorna
    (assigned, not_found): liste di IP."""
    wanted = set(ips)
    assigned, not_found = [], []
    with _io_lock:
        devices = get_all_devices()
        by_ip = {d['IP']: d for d in devices}
        for ip in wanted:
            d = by_ip.get(ip)
            if d is None:
                not_found.append(ip)
                continue
            d['Profile'] = profile
            assigned.append(ip)
        if assigned:
            safe_write_hosts_csv(devices)
    return assigned, not_found

# --- UTILITIES GESTIONE GRUPPI (CRUD) ---

def add_group(group_name: str, description: str = "") -> bool:
    """Aggiunge un nuovo gruppo se non esistente."""
    group_name = group_name.strip()
    if not group_name:
        return False
    with _io_lock:
        groups = get_all_groups()
        if group_name not in groups:
            groups[group_name] = {"description": description or f"Sede {group_name}"}
            save_groups(groups)
            return True
    return False

def update_group(old_name: str, new_name: str, description: str = "") -> bool:
    """Rinomina un gruppo ed aggiorna tutti i dispositivi ad esso associati."""
    old_name = old_name.strip()
    new_name = new_name.strip()
    if not old_name or not new_name or old_name == "Generale":
        return False

    with _io_lock:
        groups = get_all_groups()
        if old_name in groups:
            info = groups.pop(old_name)
            if description:
                info["description"] = description
            groups[new_name] = info
            save_groups(groups)

            # Aggiorna i dispositivi
            devices = get_all_devices()
            updated = False
            for d in devices:
                if d.get('Group') == old_name:
                    d['Group'] = new_name
                    updated = True
            if updated:
                safe_write_hosts_csv(devices)
            return True
    return False

def delete_group(group_name: str) -> bool:
    """Rimuove un gruppo e riassegna i dispositivi associati a 'Generale'."""
    group_name = group_name.strip()
    if not group_name or group_name == "Generale":
        return False

    with _io_lock:
        groups = get_all_groups()
        if group_name in groups:
            groups.pop(group_name)
            save_groups(groups)

            # Riassegna i dispositivi
            devices = get_all_devices()
            updated = False
            for d in devices:
                if d.get('Group') == group_name:
                    d['Group'] = "Generale"
                    updated = True
            if updated:
                safe_write_hosts_csv(devices)
            return True
    return False
