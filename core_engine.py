import os
import re
import logging
import socket
from netmiko import ConnectHandler
from inventory_manager import (
    update_version_inventory, get_all_devices, get_detected_versions,
    update_device_hostname, get_all_vendors, get_category_assignments,
)
from drivers.cisco_ios import CiscoIosDriver
from drivers.cisco_cbs import CiscoCbsDriver
from drivers.hp_procurve import HpProcurveDriver
from drivers.juniper_junos import JuniperJunosDriver
from drivers.aruba_os import ArubaOsDriver
from drivers.fortinet import FortinetDriver
from drivers.paloalto_panos import PaloAltoDriver
from crypto_vault import decrypt_password
from security_manager import log_audit
import data_config

BACKUP_FOLDER = data_config.get_path('backup-config')
logging.basicConfig(filename=data_config.get_path('error_log.txt'), level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

if not os.path.exists(BACKUP_FOLDER):
    os.makedirs(BACKUP_FOLDER)

DEFAULT_USERNAME = os.getenv("SENTINELNET_ADMIN_USER", "Admin")
DEFAULT_PASSWORD = os.getenv("SENTINELNET_ADMIN_PASS", "admin")
DEFAULT_SECRET   = os.getenv("SENTINELNET_ADMIN_SECRET", "admin")

DANGEROUS_COMMANDS = ["write erase", "reload", "delete", "format", "no boot", "erase"]

def sanitize_filename(filename: str) -> str:
    sanitized = ''.join(
        '_' if char in r'\/:*?"<>| ' else char
        for char in filename
        if ord(char) > 31
    )
    return sanitized or "device_unknown"

def group_backup_dir(group: str) -> str:
    """Cartella di backup dedicata a un gruppo/sede (creata se assente)."""
    path = os.path.join(BACKUP_FOLDER, sanitize_filename(group or "Generale"))
    os.makedirs(path, exist_ok=True)
    return path

def remove_stale_backups(ip: str):
    """Elimina i backup precedenti dello stesso IP in qualunque sottocartella,
    così un apparato che cambia gruppo non resta duplicato nella mappa."""
    if not os.path.exists(BACKUP_FOLDER):
        return
    for root, _dirs, files in os.walk(BACKUP_FOLDER):
        for f in files:
            if f.endswith(f"-{ip}.txt") or f.endswith(f"_{ip}.txt") or f == f"{ip}.txt":
                try:
                    os.remove(os.path.join(root, f))
                except Exception:
                    pass

def get_device_credentials(device):
    profile = device.get('Profile', 'custom').lower()
    if profile == 'default':
        return DEFAULT_USERNAME, DEFAULT_PASSWORD, DEFAULT_SECRET
    username = device.get('Username') or DEFAULT_USERNAME
    password = decrypt_password(device.get('Password')) or DEFAULT_PASSWORD
    secret   = decrypt_password(device.get('Enable Secret')) or DEFAULT_SECRET
    return username, password, secret

# --- REGISTRY DRIVER ↔ NETMIKO ---
# Mappa il nome-driver (campo 'driver' del registro vendor) alla classe driver e
# al device_type netmiko corrispondente. Aggiungere qui un nuovo driver è
# sufficiente per renderlo selezionabile da tutto il sistema.
DRIVER_REGISTRY = {
    'cisco_ios':      (CiscoIosDriver,   'cisco_ios'),
    'cisco_s300':     (CiscoCbsDriver,   'cisco_s300'),
    'hp_procurve':    (HpProcurveDriver, 'hp_procurve'),
    'juniper_junos':  (JuniperJunosDriver, 'juniper_junos'),
    'aruba_os':       (ArubaOsDriver,    'aruba_os'),
    'fortinet':       (FortinetDriver,   'fortinet'),
    'paloalto_panos': (PaloAltoDriver,   'paloalto_panos'),
}

# Fallback nome-vendor → nome-driver, usato quando il registro vendor non
# specifica un driver (es. installazioni con vendors.json legacy o 'driver': null).
VENDOR_DRIVER_DEFAULTS = {
    'cisco':    'cisco_ios',
    'cisco_cbs': 'cisco_s300',
    'hpe':      'hp_procurve',
    'hp':       'hp_procurve',
    'juniper':  'juniper_junos',
    'aruba':    'aruba_os',
    'fortinet': 'fortinet',
    'paloalto': 'paloalto_panos',
}

def resolve_driver(vendor):
    """Risolve un vendor nella coppia (classe driver, device_type netmiko).

    Ordine di risoluzione:
      1. campo 'driver' del registro vendor (get_all_vendors)
      2. fallback nome-vendor → driver (VENDOR_DRIVER_DEFAULTS)
    Solleva ValueError se nessun driver è associato al vendor.
    """
    vendor = (vendor or '').lower().strip()

    driver_name = None
    try:
        vendors = get_all_vendors()
        entry = vendors.get(vendor)
        if entry:
            driver_name = entry.get('driver')
    except Exception:
        pass

    if not driver_name:
        driver_name = VENDOR_DRIVER_DEFAULTS.get(vendor)

    spec = DRIVER_REGISTRY.get(driver_name) if driver_name else None
    if not spec:
        raise ValueError(
            f"Vendor '{vendor}' non supportato: nessun driver associato "
            f"(driver='{driver_name}')."
        )
    return spec

def driver_factory(vendor, connection):
    driver_cls, _ = resolve_driver(vendor)
    return driver_cls(connection)

def is_reachable(ip: str, port: int = 22, timeout: int = 2) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def run_backup_and_triage(device):
    ip     = device['IP']
    vendor = device['Vendor'].lower()

    if not is_reachable(ip):
        update_version_inventory(ip, vendor, "Non Rilevata", "offline")
        log_audit(f"Triage fallito per dispositivo '{ip}': non raggiungibile sulla porta 22 (SSH).")
        return {"status": "error", "message": f"Device {ip} non raggiungibile sulla porta 22 (SSH)"}

    username, password, secret = get_device_credentials(device)

    # Risolve driver e device_type netmiko PRIMA di connettersi: un vendor senza
    # driver associato fallisce subito, senza aprire inutilmente la sessione SSH.
    try:
        driver_cls, netmiko_type = resolve_driver(vendor)
    except ValueError as ve:
        log_audit(f"Vendor non supportato per '{ip}': {ve}")
        update_version_inventory(ip, vendor, "Non Rilevata", "error")
        return {"status": "error", "message": str(ve)}

    device_params = {
        'device_type': netmiko_type,
        'host': ip,
        'username': username,
        'password': password,
        'secret': secret,
        'timeout': 15,
        'auth_timeout': 10,
        'banner_timeout': 10,
    }

    try:
        with ConnectHandler(**device_params) as net_connect:
            net_connect.enable()
            live_hostname = net_connect.find_prompt().strip().rstrip('#>').strip()

            driver = driver_cls(net_connect)

            version    = driver.get_version()
            backup_cmd = driver.get_backup_command()

            update_version_inventory(ip, vendor, version, "online")

            config_out = net_connect.send_command(backup_cmd)

            config_out += "\n\n=== NEIGHBOR DISCOVERY ===\n"
            if vendor == 'cisco':
                for cmd, tag in [
                    ("show cdp neighbors",        "--- SHOW CDP NEIGHBORS ---"),
                    ("show cdp neighbors detail",  "--- SHOW CDP NEIGHBORS DETAIL ---"),
                    ("show lldp neighbors",        "--- SHOW LLDP NEIGHBORS ---"),
                    ("show lldp neighbors detail", "--- SHOW LLDP NEIGHBORS DETAIL ---"),
                ]:
                    try:
                        out = net_connect.send_command(cmd)
                        config_out += f"\n{tag}\n{out}"
                    except Exception:
                        pass
            elif vendor == 'hpe':
                for cmd, tag in [
                    ("show lldp info remote-device",        "--- SHOW LLDP NEIGHBORS ---"),
                    ("show lldp info remote-device detail", "--- SHOW LLDP NEIGHBORS DETAIL ---"),
                ]:
                    try:
                        out = net_connect.send_command(cmd)
                        config_out += f"\n{tag}\n{out}"
                    except Exception:
                        pass

            # Comandi diagnostici/inventario aggiuntivi (solo Cisco): salvati nel
            # backup per avere una fotografia completa dell'apparato.
            if vendor == 'cisco':
                config_out += "\n\n=== DEVICE DIAGNOSTICS ===\n"
                for cmd, tag in [
                    ("show vlan",                  "--- SHOW VLAN ---"),
                    ("show spanning-tree summary", "--- SHOW SPANNING-TREE SUMMARY ---"),
                    ("show vtp status",            "--- SHOW VTP STATUS ---"),
                    ("show mac address-table",     "--- SHOW MAC ADDRESS-TABLE ---"),
                    ("show etherchannel summary",  "--- SHOW ETHERCHANNEL SUMMARY ---"),
                    ("show version",               "--- SHOW VERSION ---"),
                    ("show switch",                "--- SHOW SWITCH ---"),
                    ("show inventory",             "--- SHOW INVENTORY ---"),
                    ("show environment all",       "--- SHOW ENVIRONMENT ALL ---"),
                    ("show license all",           "--- SHOW LICENSE ALL ---"),
                ]:
                    try:
                        out = net_connect.send_command(cmd, read_timeout=30)
                        config_out += f"\n{tag}\n{out}"
                    except Exception:
                        pass

            hostname_from_cfg = extract_hostname_from_config(config_out)
            sys_name = hostname_from_cfg or live_hostname or f"{vendor}_{ip}"

            update_device_hostname(ip, sys_name)

            # Backup salvato nella sottocartella del gruppo/sede dell'apparato.
            # Prima si rimuovono copie residue (in radice o in altri gruppi).
            remove_stale_backups(ip)
            group_dir = group_backup_dir(device.get('Group', 'Generale'))
            file_path = os.path.join(group_dir, f"{sanitize_filename(sys_name)}-{ip}.txt")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(config_out)

            log_audit(f"Triage e backup completati con successo per dispositivo '{ip}' (Firmware: '{version}').")
            return {"status": "success", "version": version, "hostname": sys_name, "file": file_path}

    except Exception as e:
        logging.error(f"Errore su {ip}: {str(e)}")
        st = "auth_failed" if "auth" in str(e).lower() or "credentials" in str(e).lower() else "offline"
        update_version_inventory(ip, vendor, "Non Rilevata", st)
        log_audit(f"Triage fallito per dispositivo '{ip}': errore di connessione/autenticazione ({str(e)}).")
        return {"status": "error", "message": str(e)}


def send_custom_command(device, command: str):
    if any(cmd in command.lower() for cmd in DANGEROUS_COMMANDS):
        return {"status": "error", "message": "Comando non consentito dalla policy di sicurezza aziendale (Blacklisted)"}

    vendor = device['Vendor'].lower()
    try:
        _, netmiko_type = resolve_driver(vendor)
    except ValueError as e:
        return {"status": "error", "message": str(e)}

    username, password, secret = get_device_credentials(device)
    device_params = {
        'device_type': netmiko_type,
        'host': device['IP'],
        'username': username,
        'password': password,
        'secret': secret,
        'timeout': 15,
        'auth_timeout': 10,
        'banner_timeout': 10,
    }
    try:
        with ConnectHandler(**device_params) as net_connect:
            net_connect.enable()
            output = net_connect.send_command(command)
            log_audit(f"Comando CLI '{command}' eseguito con successo sul dispositivo '{device['IP']}'.")
            return {"status": "success", "output": output}
    except Exception as e:
        log_audit(f"Esecuzione comando CLI '{command}' fallita sul dispositivo '{device['IP']}': {str(e)}")
        return {"status": "error", "message": str(e)}


def run_bulk_command(device, commands, config_mode=False, save_after=False):
    """Esegue la stessa lista di comandi su un dispositivo.

    - config_mode=False: comandi operativi (show/exec), uno per uno.
    - config_mode=True:  spinge i comandi in configuration mode (send_config_set),
      ed eventualmente salva la config (save_after) — usato per applicare modifiche
      in massa a più apparati.
    La blacklist dei comandi distruttivi è applicata a monte (lato API).
    """
    ip = device['IP']
    if not is_reachable(ip):
        return {"status": "error", "message": f"Device {ip} non raggiungibile sulla porta 22 (SSH)"}

    vendor = device['Vendor'].lower()
    try:
        _, netmiko_type = resolve_driver(vendor)
    except ValueError as e:
        return {"status": "error", "message": str(e)}

    username, password, secret = get_device_credentials(device)
    device_params = {
        'device_type': netmiko_type,
        'host': ip,
        'username': username,
        'password': password,
        'secret': secret,
        'timeout': 20,
        'auth_timeout': 10,
        'banner_timeout': 10,
    }

    try:
        with ConnectHandler(**device_params) as net_connect:
            net_connect.enable()
            if config_mode:
                output = net_connect.send_config_set(commands)
                if save_after:
                    try:
                        output += "\n" + net_connect.save_config()
                    except Exception as se:
                        output += f"\n[Salvataggio configurazione non supportato/fallito: {se}]"
                log_audit(
                    f"Configurazione massiva ({len(commands)} comandi, save={save_after}) "
                    f"applicata con successo su '{ip}'."
                )
            else:
                parts = []
                for cmd in commands:
                    parts.append(f"=== {cmd} ===\n" + net_connect.send_command(cmd))
                output = "\n\n".join(parts)
                log_audit(
                    f"Comandi operativi massivi ({len(commands)}) eseguiti con successo su '{ip}'."
                )
            return {"status": "success", "output": output}
    except Exception as e:
        log_audit(f"Invio comandi massivo fallito su '{ip}': {str(e)}")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------------------------------------
# NETWORK MAPPING ENGINE
# ---------------------------------------------------------------------------

def extract_hostname_from_config(content: str) -> str:
    """Estrae l'hostname dalle righe di configurazione (Cisco e HPE)."""
    match = re.search(r'^\s*hostname\s+(\S+)', content, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1).strip().strip('"')
    match = re.search(r'^\s*hostname\s+"([^"]+)"', content, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def _parse_sys_description(block: str) -> str | None:
    """
    Estrae la System Description da un blocco LLDP detail.

    Il formato IOS-XE ha la descrizione su righe NON indentate dopo il tag:

        System Description:
        Cisco IOS Software [IOSXE]... Version 17.16.1a ...
        Technical Support: ...

    Il formato Ubuntu/Linux e' analogo:

        System Description:
        Ubuntu 24.04.2 LTS Linux 6.8.0-59-generic ...

    Strategia: cattura tutto il testo tra "System Description:" e il prossimo
    campo chiave riconoscibile o fine blocco. Collassa gli spazi, tronca a 200 char.
    """
    terminators = (
        r'Time remaining|System Capabilities|Enabled Capabilities|'
        r'Management Addresses|Auto Negotiation|Physical media|'
        r'Media Attachment|Vlan ID|Peer Source MAC|Port id|Local Intf|'
        r'Chassis id|Port Description|System Name'
    )
    pattern = re.compile(
        r'System Description:\s*\n'
        r'(.*?)'
        r'(?=\n\s*(?:' + terminators + r')|\Z)',
        re.IGNORECASE | re.DOTALL
    )
    m = pattern.search(block)
    if m:
        raw = m.group(1).strip()
        if raw:
            return re.sub(r'\s+', ' ', raw)[:200]

    # Fallback: descrizione sulla stessa riga (HPE, vecchio IOS)
    m2 = re.search(r'System Description:\s*([^\n\r]+)', block, re.IGNORECASE)
    if m2:
        return m2.group(1).strip()

    return None


# Parole chiave per classificare il tipo di apparato a partire da hostname,
# System Description (LLDP), Platform e Capabilities (CDP). L'ordine di
# valutazione in classify_device_type stabilisce la priorità.
_TYPE_SUBSTRINGS = {
    "firewall": ("fortigate", "fortinet", "fortiwifi", "fortios", "palo alto",
                 "paloalto", "pan-os", "panos", "firepower", "sonicwall",
                 "checkpoint", "check point", "firewall"),
    "wlc":      ("air-ct", "wism", "wireless lan controller", "wireless controller",
                 "mobility controller", "c9800", "vwlc", "wlc"),
    "ap":       ("air-ap", "aironet", "accesspoint", "access-point", "access point",
                 "wifi", "wlan"),
    "router":   ("router", "isr", "asr", "csr"),
    "phone":    ("ipphone", "ip phone", "phone", "voip"),
    "server":   ("server", "esxi", "vmware", "nas", "ubuntu", "debian",
                 "linux", "windows server", "proxmox"),
    "pc":       ("workstation", "desktop", "laptop", "client"),
}
# Parole chiave brevi/ambigue: cercate solo come token isolati per evitare falsi
# positivi (es. "ap" dentro "naples", "fw" dentro "software").
_TYPE_TOKENS = {
    "firewall": ("asa", "ftd", "srx", "fw", "pa"),
    "router":   ("rtr",),
    "ap":       ("ap",),
    "phone":    ("tel",),
    "server":   ("srv", "host"),
    "pc":       ("pc",),
}
_TYPE_ORDER = ("firewall", "wlc", "ap", "router", "phone", "server", "pc")


def _has_token(text: str, token: str) -> bool:
    return bool(re.search(r'(?:^|[^a-z0-9])' + re.escape(token) + r'(?:[^a-z0-9]|$)', text))


def classify_device_type(hostname: str = "", description: str = "",
                         platform: str = "", capabilities: str = "") -> str:
    """Deduce il tipo di apparato combinando hostname, System Description (LLDP),
    Platform e Capabilities (CDP). Ritorna: firewall|wlc|ap|router|phone|server|
    pc|switch."""
    text = " ".join(filter(None, [hostname, description, platform])).lower()
    if not text.strip():
        return "switch"
    for t in _TYPE_ORDER:
        if any(s in text for s in _TYPE_SUBSTRINGS.get(t, ())):
            return t
        if any(_has_token(text, tok) for tok in _TYPE_TOKENS.get(t, ())):
            return t
    # Capabilities CDP come ultimo indizio: "Switch" → switch, solo "Router" → router.
    caps = (capabilities or "").lower()
    if "switch" in caps:
        return "switch"
    if "router" in caps:
        return "router"
    return "switch"


# Versioni firmware: estrae un numero di versione pulito da una stringa libera
# (System Description LLDP/CDP), utile per il controllo CVE.
#   "FortiGate-120G v7.4.11, ..."            -> "7.4.11"
#   "...IOS Software ... Version 17.16.1a ..." -> "17.16.1a"
def extract_version(text: str) -> str | None:
    if not text:
        return None
    m = re.search(r'\bv(?:ersion)?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-z0-9().]*)',
                  text, re.IGNORECASE)
    if not m:
        m = re.search(r'\b([0-9]+\.[0-9]+(?:\.[0-9]+)+[a-z0-9().]*)', text)
    if not m:
        return None
    return m.group(1).strip().strip('.,);')


# Indizi vendor da Platform/Description/hostname (CDP/LLDP). Ritorna la chiave
# vendor (coerente con il registro vendors) oppure None.
def guess_vendor(platform: str = "", description: str = "", hostname: str = "") -> str | None:
    text = " ".join(filter(None, [platform, description, hostname])).lower()
    if not text.strip():
        return None
    if "forti" in text:
        return "fortinet"
    if "palo" in text or "pan-os" in text or "panos" in text or re.search(r'\bpa-\d', text):
        return "paloalto"
    if "aruba" in text:
        return "aruba"
    if "procurve" in text or "hpe" in text or re.search(r'\bhp\b', text):
        return "hpe"
    if "juniper" in text or "junos" in text or re.search(r'\b(srx|ex\d|mx\d|qfx)\b', text):
        return "juniper"
    if ("cisco" in text or "catalyst" in text or "nexus" in text
            or re.search(r'\b(air-|ws-c|c9\d|n9k)', text)):
        return "cisco"
    return None


# Modello apparato da Platform (CDP) o System Description (LLDP).
#   "cisco WS-C3750E-24TD"  -> "WS-C3750E-24TD"
#   "AIR-CT3504-K9"         -> "AIR-CT3504-K9"
#   "FortiGate-120G v7.4.11" -> "FortiGate-120G"
def extract_model(platform: str = "", description: str = "") -> str | None:
    if platform:
        p = re.sub(r'^(cisco|juniper|aruba|hpe|hp|fortinet|palo\s?alto)\s+',
                   '', platform.strip(), flags=re.IGNORECASE)
        p = p.split(',')[0].strip()
        if p:
            return p
    if description:
        m = re.search(r'\b([A-Za-z][A-Za-z0-9]*-[A-Za-z0-9][\w/-]*)', description)
        if m:
            return m.group(1)
    return None


# Modello dal backup dell'apparato stesso (best-effort, multi-vendor).
def extract_model_from_backup(content: str) -> str | None:
    for pat in (
        r'Model [Nn]umber\s*:\s*(\S+)',
        r'^\s*Model\s*:\s*(\S+)',
        r'cisco\s+(\S+)\s*\([^)]*\)\s*processor',
        r'Hardware:\s*(\S+)',
    ):
        m = re.search(pat, content, re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1).strip().strip(',')
    return None


def parse_vtp_status(content: str) -> tuple[str | None, str | None]:
    """Estrae (vtp_mode, vtp_domain) dall'apparato stesso: prima da
    'show vtp status', poi dalla running-config, infine dal dominio VTP più
    frequente annunciato dai vicini CDP (utile per stimare l'estensione)."""
    mode = domain = None

    sec = re.search(r'--- SHOW VTP STATUS ---\s*\n(.*?)(?=\n--- |\n===|\Z)',
                    content, re.DOTALL | re.IGNORECASE)
    if sec:
        block = sec.group(1)
        mm = re.search(r'VTP Operating Mode\s*:\s*(\S+)', block, re.IGNORECASE)
        dm = re.search(r'VTP Domain Name\s*:\s*(\S+)', block, re.IGNORECASE)
        if mm:
            mode = mm.group(1).strip()
        if dm:
            domain = dm.group(1).strip()

    if not mode:
        cm = re.search(r'^\s*vtp\s+mode\s+(\S+)', content, re.MULTILINE | re.IGNORECASE)
        if cm:
            mode = cm.group(1).strip().capitalize()
    if not domain:
        cd = re.search(r'^\s*vtp\s+domain\s+(\S+)', content, re.MULTILINE | re.IGNORECASE)
        if cd:
            domain = cd.group(1).strip().strip("'\"")

    if not domain:
        cdp_doms = re.findall(r"VTP Management Domain:\s*'([^']+)'", content, re.IGNORECASE)
        if cdp_doms:
            domain = max(set(cdp_doms), key=cdp_doms.count)

    return mode, domain


def parse_cdp_lldp_neighbors(content: str) -> list:
    """
    Parsa le tabelle di vicini CDP e LLDP presenti nel file di backup.
    Restituisce una lista di dict con chiavi:
        neighbor_id, neighbor_ip, local_port, remote_port, version
    """
    neighbors = []

    # ------------------------------------------------------------------
    # 1. CDP Neighbors Detail (Cisco) — parsing a blocchi per catturare anche
    #    Platform/Capabilities (tipo apparato), Version e VTP Management Domain.
    # ------------------------------------------------------------------
    cdp_detail_section = re.search(
        r'--- SHOW CDP NEIGHBORS DETAIL ---\s*\n(.*?)(?=\n--- [A-Z]|\n===|\Z)',
        content, re.DOTALL | re.IGNORECASE
    )
    cdp_detail_body = cdp_detail_section.group(1) if cdp_detail_section else content
    for block in re.split(r'-{15,}', cdp_detail_body):
        dev_m = re.search(r'Device ID:\s*([^\n\r]+)', block, re.IGNORECASE)
        if not dev_m:
            continue
        ip_m       = re.search(r'IP address:\s*([0-9.]+)', block, re.IGNORECASE)
        iface_m    = re.search(r'Interface:\s*([^,\n]+),\s*Port ID \(outgoing port\):\s*([^\n\r]+)',
                               block, re.IGNORECASE)
        plat_m     = re.search(r'Platform:\s*([^,\n]+?)\s*,\s*Capabilities:\s*([^\n\r]*)',
                               block, re.IGNORECASE)
        ver_m      = re.search(r'Version\s*:\s*\n?(.*?)(?=\n\s*(?:Technical Support|advertisement|Copyright|VTP|Native VLAN|Duplex|Management|Holdtime)|\Z)',
                               block, re.IGNORECASE | re.DOTALL)
        vtp_m      = re.search(r"VTP Management Domain:\s*'?([^'\n\r]+)'?", block, re.IGNORECASE)
        platform     = plat_m.group(1).strip() if plat_m else None
        capabilities = plat_m.group(2).strip() if plat_m else None
        ver_text     = ver_m.group(1).strip() if ver_m else None
        neighbors.append({
            "neighbor_id": dev_m.group(1).strip(),
            "neighbor_ip": ip_m.group(1).strip() if ip_m else None,
            "local_port":  iface_m.group(1).strip() if iface_m else "Unknown",
            "remote_port": iface_m.group(2).strip() if iface_m else "Unknown",
            "version":     extract_version(ver_text) if ver_text else None,
            "platform":    platform,
            "capabilities": capabilities,
            "vtp_domain":  vtp_m.group(1).strip().strip("'") if vtp_m else None,
        })

    # ------------------------------------------------------------------
    # 2. CDP Neighbors summary (fallback se no detail)
    # ------------------------------------------------------------------
    if not neighbors:
        cdp_section = re.search(
            r'--- SHOW CDP NEIGHBORS ---\s*\n(.*?)(\n---|\Z)', content, re.DOTALL | re.IGNORECASE
        )
        if cdp_section:
            lines   = cdp_section.group(1).strip().split('\n')
            started = False
            for line in lines:
                if "Device ID" in line or "Local Intrfce" in line:
                    started = True
                    continue
                if not started or not line.strip() or line.startswith("Capability") or line.startswith("---"):
                    continue
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) >= 5:
                    neighbors.append({
                        "neighbor_id": parts[0].strip(),
                        "neighbor_ip": None,
                        "local_port":  parts[1].strip(),
                        "remote_port": parts[-1].strip(),
                        "version": None,
                    })

    # ------------------------------------------------------------------
    # 3. LLDP remote-device table (HPE)
    # ------------------------------------------------------------------
    lldp_section = re.search(
        r'Local Port\s+\|\s+Chassis ID.*?\n(.*?)(?=\n---|\Z)', content, re.DOTALL | re.IGNORECASE
    )
    if lldp_section:
        for line in lldp_section.group(1).strip().split('\n'):
            if '-' in line and '+' in line:
                continue
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 5:
                local_port = parts[0]
                port_id    = parts[2]
                sys_name   = parts[4]
                if sys_name and sys_name not in ('System Name', '----------'):
                    neighbors.append({
                        "neighbor_id": sys_name,
                        "neighbor_ip": None,
                        "local_port":  local_port,
                        "remote_port": port_id,
                        "version": None,
                    })

    # ------------------------------------------------------------------
    # 4. LLDP detail IP harvest (vecchi formati Cisco)
    # ------------------------------------------------------------------
    lldp_details_old = re.findall(
        r'System Name\s*:\s*([^\n\r]+).*?PortId\s*:\s*([^\n\r]+).*?IPv4 Address\s*:\s*([^\n\r]+)',
        content, re.DOTALL | re.IGNORECASE
    )
    for sys_name, port_id, ip in lldp_details_old:
        neighbors.append({
            "neighbor_id": sys_name.strip(),
            "neighbor_ip": ip.strip(),
            "local_port":  "Unknown",
            "remote_port": port_id.strip(),
            "version": None,
        })

    # ------------------------------------------------------------------
    # 5. LLDP neighbors summary — Cisco "show lldp neighbors"
    # ------------------------------------------------------------------
    lldp_cisco_section = re.search(
        r'--- SHOW LLDP NEIGHBORS ---\s*\n(.*?)(\n---|\Z)', content, re.DOTALL | re.IGNORECASE
    )
    if lldp_cisco_section:
        lines   = lldp_cisco_section.group(1).strip().split('\n')
        started = False
        for line in lines:
            if "Device ID" in line or "Local Intf" in line:
                started = True
                continue
            if (not started or not line.strip() or line.startswith("Capability")
                    or line.startswith("---") or "Total entries" in line):
                continue
            parts = re.split(r'\s{2,}', line.strip())
            if len(parts) >= 5:
                neighbors.append({
                    "neighbor_id": parts[0].strip(),
                    "neighbor_ip": None,
                    "local_port":  parts[1].strip(),
                    "remote_port": parts[-1].strip(),
                    "version": None,
                })

    # ------------------------------------------------------------------
    # 6. LLDP neighbors detail — Cisco IOS / IOS-XE
    #
    #  Formato reale IOS-XE:
    #    ------------------------------------------------
    #    Local Intf: Et0/1
    #    System Name: sw2.lab.local
    #    System Description:
    #    Cisco IOS Software [IOSXE]... Version 17.16.1a ...   <- NON indentato
    #    Technical Support: ...
    #    Management Addresses:
    #        IP: 192.168.31.183                               <- 4 spazi
    #    ------------------------------------------------
    #
    #  Formato Ubuntu LLDP:
    #    System Description:
    #    Ubuntu 24.04.2 LTS Linux 6.8.0-59-generic ...       <- NON indentato
    # ------------------------------------------------------------------
    lldp_detail_section = re.search(
        r'--- SHOW LLDP NEIGHBORS DETAIL ---\s*\n(.*?)(?=\n--- [A-Z]|\n===|\Z)',
        content, re.DOTALL | re.IGNORECASE
    )
    if lldp_detail_section:
        raw_blocks = re.split(r'-{20,}', lldp_detail_section.group(1))

        for block in raw_blocks:
            if not block.strip():
                continue

            local_port_m = re.search(r'Local Intf:\s*([^\n\r]+)',      block, re.IGNORECASE)
            port_id_m    = re.search(r'Port id:\s*([^\n\r]+)',          block, re.IGNORECASE)
            port_desc_m  = re.search(r'Port Description:\s*([^\n\r]+)', block, re.IGNORECASE)
            sys_name_m   = re.search(r'System Name:\s*([^\n\r]+)',      block, re.IGNORECASE)

            # IP management: indentato IOS-XE oppure formati alternativi
            ip_m = (
                re.search(
                    r'Management Addresses?:.*?^\s+IP:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
                    block, re.IGNORECASE | re.MULTILINE | re.DOTALL
                )
                or re.search(
                    r'(?:Management Address\s*[-\u2013]\s*IPv4|Management Address|IP Address):\s*'
                    r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
                    block, re.IGNORECASE
                )
            )

            # System Description — gestisce sia indentato che non indentato
            version_str = _parse_sys_description(block)

            if not sys_name_m:
                continue

            remote_port = "Unknown"
            if port_desc_m:
                remote_port = port_desc_m.group(1).strip()
            elif port_id_m:
                remote_port = port_id_m.group(1).strip()

            neighbors.append({
                "neighbor_id": sys_name_m.group(1).strip(),
                "neighbor_ip": ip_m.group(1).strip() if ip_m else None,
                "local_port":  local_port_m.group(1).strip() if local_port_m else "Unknown",
                "remote_port": remote_port,
                "version":     extract_version(version_str) or version_str,
                "description": version_str,
            })

    # ------------------------------------------------------------------
    # Deduplicazione intelligente — mantiene l'entry piu' ricca
    # per coppia (local_port, base_hostname).
    # ------------------------------------------------------------------
    merged: dict = {}
    for n in neighbors:
        neigh_id = n["neighbor_id"]
        base_id  = neigh_id.split('.')[0] if '.' in neigh_id else neigh_id
        key      = (n["local_port"].lower(), base_id.lower())

        if key not in merged:
            merged[key] = dict(n)
        else:
            existing = merged[key]
            if n.get("neighbor_ip") and not existing.get("neighbor_ip"):
                existing["neighbor_ip"] = n["neighbor_ip"]
            if n.get("version") and not existing.get("version"):
                existing["version"] = n["version"]
            for fld in ("platform", "capabilities", "vtp_domain", "description"):
                if n.get(fld) and not existing.get(fld):
                    existing[fld] = n[fld]
            if (n.get("remote_port") and n["remote_port"] != "Unknown"
                    and (existing.get("remote_port") == "Unknown"
                         or len(n["remote_port"]) < len(existing.get("remote_port", "")))):
                existing["remote_port"] = n["remote_port"]

    # ------------------------------------------------------------------
    # Consolidamento per PORTA FISICA: CDP e LLDP sulla stessa porta descrivono
    # lo STESSO vicino, a volte con nomi diversi (es. hostname via LLDP,
    # MAC/seriale via CDP). Si fondono in un'unica entry per non duplicare il
    # nodo, registrando i nomi/versioni alternativi (name_options) per l'eventuale
    # scelta dell'utente. Le porte aggregate o sconosciute non si consolidano.
    by_port: dict = {}
    singles: list = []
    for n in merged.values():
        lp = (n.get("local_port") or "").strip()
        # La chiave usa l'interfaccia NORMALIZZATA così "GigabitEthernet1/0/34"
        # (CDP) e "Gi1/0/34" (LLDP) ricadono sulla stessa porta fisica.
        norm = _normalize_iface(lp)
        if not lp or lp.lower() == "unknown" or _is_portchannel_port(lp):
            singles.append(n)
        else:
            by_port.setdefault(norm, []).append(n)

    def _looks_like_mac(name: str) -> bool:
        s = re.sub(r'[.:\-]', '', (name or '')).lower()
        return bool(re.fullmatch(r'[0-9a-f]{12}', s))

    final: list = []
    for group in by_port.values():
        if len(group) == 1:
            final.append(group[0])
            continue
        # Canonico: preferisci un hostname leggibile (non MAC), poi chi ha versione/IP.
        group.sort(
            key=lambda e: (
                0 if _looks_like_mac(e["neighbor_id"]) else 1,
                1 if e.get("version") else 0,
                1 if e.get("neighbor_ip") else 0,
            ),
            reverse=True,
        )
        canonical = dict(group[0])
        options = {}  # nome -> versione (dedup per nome, mantiene la prima versione utile)
        for e in group:
            nm = e["neighbor_id"]
            if nm not in options or (not options[nm] and e.get("version")):
                options[nm] = e.get("version")
        for other in group[1:]:
            for fld in ("neighbor_ip", "version", "platform", "capabilities",
                        "vtp_domain", "description", "remote_port"):
                if other.get(fld) and not canonical.get(fld):
                    canonical[fld] = other[fld]
        # Conflitto reale solo se i NOMI differiscono: in tal caso l'utente sceglie.
        if len(options) > 1:
            canonical["name_options"] = [{"name": k, "version": v} for k, v in options.items()]
        final.append(canonical)

    final.extend(singles)
    return final


# Pattern dei nomi di interfaccia aggregata (Port-Channel / LAG / bundle) per i
# principali vendor. Usato per evidenziare i link aggregati nella mappa.
PORTCHANNEL_RE = re.compile(
    r'^(?:'
    r'po\d+|'                     # Cisco IOS short:  Po1
    r'port-?channel\d*|'          # Cisco IOS long:   Port-channel1
    r'trk\d+|'                    # HP ProCurve:      Trk1
    r'lag\s*\d+|'                 # Aruba/generico:   lag 1
    r'ae\d+|'                     # Juniper:          ae0
    r'bridge-aggregation\d*|'     # HPE Comware:      Bridge-Aggregation1
    r'bagg\d+|'                   # HPE Comware short: BAGG1
    r'bundle-ether\d*|'           # Cisco IOS-XR:     Bundle-Ether1
    r'eth-trunk\d*'               # Huawei:           Eth-Trunk1
    r')',
    re.IGNORECASE,
)


def _is_portchannel_port(port: str) -> bool:
    """True se il nome dell'interfaccia indica un aggregato (Port-Channel/LAG)."""
    return bool(port and PORTCHANNEL_RE.match(port.strip()))


def _looks_like_ip(value: str) -> bool:
    """True se la stringa è un IPv4 dotted-quad (e non un hostname)."""
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', (value or '').strip()))


# Abbreviazioni di interfaccia note (Cisco-like) → codice canonico, per far
# combaciare le forme lunghe della config ("Ethernet0/1") con quelle brevi
# annunciate da CDP/LLDP ("Et0/1").
_IFACE_ALIASES = {
    'ethernet': 'et', 'eth': 'et', 'et': 'et',
    'gigabitethernet': 'gi', 'gigabit': 'gi', 'gig': 'gi', 'gi': 'gi', 'ge': 'gi',
    'tengigabitethernet': 'te', 'tengige': 'te', 'tengig': 'te', 'te': 'te',
    'twentyfivegige': 'twe', 'twe': 'twe',
    'fortygigabitethernet': 'fo', 'fortygige': 'fo', 'fo': 'fo',
    'hundredgige': 'hu', 'hu': 'hu',
    'fastethernet': 'fa', 'fast': 'fa', 'fa': 'fa',
    'portchannel': 'po', 'port-channel': 'po', 'po': 'po',
}


def _normalize_iface(name: str) -> str:
    """Normalizza un nome di interfaccia a 'codice+numero' (es. Et0/1 → et0/1)."""
    if not name:
        return ''
    name = name.strip()
    m = re.match(r'^([A-Za-z][A-Za-z\-]*?)\s*([\d/\.:]+)\s*$', name)
    if not m:
        return name.lower().replace(' ', '')
    prefix = m.group(1).lower().replace('-', '')
    return f"{_IFACE_ALIASES.get(prefix, prefix)}{m.group(2)}"


def parse_channel_groups(config: str) -> dict:
    """Mappa interfaccia fisica → nome Port-channel leggendo 'channel-group N'
    nei blocchi interface della running-config (Cisco IOS/IOS-XE).

    Es.:  interface Ethernet0/1 / channel-group 10 mode active
          →  {'et0/1': 'Port-channel10'}
    """
    mapping: dict = {}
    current_iface = None
    for line in config.splitlines():
        m = re.match(r'^interface\s+(\S+)', line)
        if m:
            current_iface = m.group(1)
            continue
        if current_iface:
            cg = re.search(r'channel-group\s+(\d+)', line)
            if cg:
                mapping[_normalize_iface(current_iface)] = f"Port-channel{cg.group(1)}"
    return mapping


# Pattern di interfacce fisiche (escludono SVI/Vlan/Loopback/Tunnel/Port-channel).
_PHYS_IFACE_RE = re.compile(
    r'^(?:Gigabit|TenGigabit|TwentyFiveGig|FortyGigabit|HundredGig|Fast|TwoGigabit)?'
    r'Ethernet[\d/.]+$|^(?:Gi|Te|Twe|Fo|Hu|Fa|Eth|Et)[\d/.]+$',
    re.IGNORECASE,
)


def parse_portchannel_summary(config: str) -> dict:
    """Riassume i Port-channel di un apparato (Cisco IOS/IOS-XE):
      - portchannels: {nome Po: [interfacce membro]}
      - singles: interfacce fisiche NON in alcun Port-channel
    Letto dai blocchi 'interface' della running-config (channel-group N)."""
    portchannels: dict = {}
    singles: list = []
    members_seen: set = set()
    current_iface = None
    for line in config.splitlines():
        m = re.match(r'^interface\s+(\S+)', line)
        if m:
            current_iface = m.group(1)
            continue
        if current_iface:
            cg = re.search(r'channel-group\s+(\d+)', line)
            if cg:
                po = f"Port-channel{cg.group(1)}"
                portchannels.setdefault(po, []).append(current_iface)
                members_seen.add(current_iface)
    # Seconda passata: interfacce fisiche dichiarate ma non membri di un aggregato.
    for line in config.splitlines():
        m = re.match(r'^interface\s+(\S+)', line)
        if m:
            name = m.group(1)
            if name in members_seen:
                continue
            if _PHYS_IFACE_RE.match(name) and name not in singles:
                singles.append(name)
    return {"portchannels": portchannels, "singles": singles}


def parse_etherchannel_status(content: str) -> dict:
    """Stato operativo dei Port-channel da 'show etherchannel summary'.
    Ritorna {NumeroPo: {status, up, total, issue, issue_msg, members:{iface:flag}}}.
    Flag membro: P=aggregato, D=down, s=sospeso, I=stand-alone, w=in attesa...
    Flag Po: U=in uso, D=down."""
    sec = re.search(r'--- SHOW ETHERCHANNEL SUMMARY ---\s*\n(.*?)(?=\n--- |\n===|\Z)',
                    content, re.DOTALL | re.IGNORECASE)
    if not sec:
        return {}
    result = {}
    for m in re.finditer(r'^\s*\d+\s+Po(\d+)\(([A-Za-z]+)\)\s+\S+\s+(.*)$',
                         sec.group(1), re.MULTILINE):
        num, po_flags, ports = m.group(1), m.group(2), m.group(3)
        members = re.findall(r'(\S+?)\((\w+)\)', ports)
        total = len(members)
        up = sum(1 for _, fl in members if fl == 'P')
        po_up = ('U' in po_flags) and ('D' not in po_flags)
        issue = (not po_up) or (up < total)
        if not po_up:
            issue_msg = "Port-channel DOWN"
        elif up < total:
            issue_msg = f"{total - up}/{total} interfacce non aggregate"
        else:
            issue_msg = ""
        result[num] = {
            "status": "up" if po_up else "down",
            "up": up, "total": total,
            "issue": issue, "issue_msg": issue_msg,
            "members": {ifc: fl for ifc, fl in members},
        }
    return result


def get_portchannel_report(group_filter=None) -> list:
    """Report Port-channel per apparato (per il tab Adjacency List). Legge i backup
    e ritorna [{ip, hostname, group, portchannels, singles}], filtrato per gruppo."""
    devices = get_all_devices()
    ip_to_device = {d['IP']: d for d in devices}
    report = []
    if not os.path.exists(BACKUP_FOLDER):
        return report
    for root, _dirs, files in os.walk(BACKUP_FOLDER):
        for fn in files:
            if not fn.endswith('.txt'):
                continue
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', fn)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            dev = ip_to_device.get(ip, {})
            group = dev.get('Group', 'Generale')
            if group_filter and group_filter != "all" and group != group_filter:
                continue
            try:
                with open(os.path.join(root, fn), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception:
                continue
            summary = parse_portchannel_summary(content)
            hostname = extract_hostname_from_config(content) or fn[:-4].rsplit('-', 1)[0]

            # Vicino connesso a ciascuna interfaccia (da CDP/LLDP), per attribuire
            # un nome di device al Port-channel.
            neigh_by_port = {}
            for nb in parse_cdp_lldp_neighbors(content):
                lp = _normalize_iface(nb.get("local_port") or "")
                if lp and nb.get("neighbor_id"):
                    neigh_by_port.setdefault(lp, nb["neighbor_id"])

            ec_status = parse_etherchannel_status(content)
            pcs = []
            for po, members in summary["portchannels"].items():
                neighbors = []
                for m in members:
                    nm = neigh_by_port.get(_normalize_iface(m))
                    base = nm.split('.')[0] if nm and '.' in nm else nm
                    if base and base not in neighbors:
                        neighbors.append(base)
                num = re.sub(r'\D', '', po)  # "Port-channel8" -> "8"
                st = ec_status.get(num, {})
                pcs.append({
                    "name": po,
                    "members": members,
                    "neighbors": neighbors,
                    "status": st.get("status"),           # up|down|None(sconosciuto)
                    "up": st.get("up"),
                    "total": st.get("total"),
                    "issue": st.get("issue", False),
                    "issue_msg": st.get("issue_msg", ""),
                })

            report.append({
                "ip": ip,
                "hostname": hostname,
                "group": group,
                "portchannels": pcs,
                "singles": summary["singles"],
            })
    report.sort(key=lambda r: r["hostname"].lower())
    return report


def generate_network_map(group_filter=None) -> dict:
    """Scansiona backup-config e genera nodi + link per la mappa topologica."""
    devices      = get_all_devices()
    ip_to_device = {d['IP']: d for d in devices}
    hostname_to_ip: dict = {}
    nodes_map: dict      = {}
    links: list          = []

    # Override manuali di categoria (assegnazioni utente) per id-nodo: hanno la
    # precedenza sulla classificazione automatica da hostname/CDP/LLDP.
    try:
        category_assignments = get_category_assignments()
    except Exception:
        category_assignments = {}

    def apply_category(node_id, auto_type):
        a = category_assignments.get(node_id)
        return a.get("category", auto_type) if a and a.get("category") else auto_type

    # Leggi backup files. I backup sono organizzati in sottocartelle per gruppo
    # (feature: backup separati per sede), quindi la scansione è ricorsiva e
    # continua a riconoscere i file legacy salvati nella radice.
    backup_files = []
    if os.path.exists(BACKUP_FOLDER):
        for root, _dirs, files in os.walk(BACKUP_FOLDER):
            for f in files:
                if f.endswith('.txt'):
                    backup_files.append(os.path.join(root, f))

    parsed_devices: dict = {}
    for file_path in backup_files:
        filename = os.path.basename(file_path)
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', filename)
        if not ip_match:
            continue
        ip = ip_match.group(1)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue
        hostname = extract_hostname_from_config(content)
        if not hostname:
            parts    = filename[:-4].split('-')
            hostname = "-".join(parts[:-1]) if len(parts) >= 2 else filename[:-4]
        vtp_mode, vtp_domain = parse_vtp_status(content)
        parsed_devices[ip] = {
            "hostname": hostname,
            "content": content,
            "file": file_path,
            "iface_pc": parse_channel_groups(content),
            "vtp_mode": vtp_mode,
            "vtp_domain": vtp_domain,
        }
        hostname_to_ip[hostname.lower()] = ip

    # Nodi inventariati
    versions = get_detected_versions()
    for ip, d in ip_to_device.items():
        pinfo  = parsed_devices.get(ip, {})
        label  = pinfo.get("hostname", ip)
        status = versions.get(ip, {}).get("status", "offline")
        vendor = d.get('Vendor', 'cisco')
        # Il vendor partecipa alla classificazione: un apparato Fortinet/Palo Alto
        # è un firewall anche se l'hostname non lo dice.
        auto_type = classify_device_type(label, description=vendor)
        nodes_map[ip] = {
            "id":          ip,
            "label":       label,
            "group":       d.get('Group', 'Generale'),
            "status":      status,
            "device_type": apply_category(ip, auto_type),
            "vendor":      vendor,
            "version":     versions.get(ip, {}).get("version"),
            "vtp_mode":    pinfo.get("vtp_mode"),
            "vtp_domain":  pinfo.get("vtp_domain"),
            "model":       extract_model_from_backup(pinfo.get("content", "")) if pinfo else None,
        }

    # Arricchisci la mappa hostname→IP con gli hostname noti dall'inventario
    # (campo Hostname del CSV) e con le forme "base" senza dominio FQDN. Serve a
    # far collassare un vicino sul nodo reale anche quando CDP/LLDP annuncia l'IP
    # di una SVI qualsiasi (es. Vlan1) diverso dall'IP di management con cui
    # l'apparato è censito.
    for ip, d in ip_to_device.items():
        hn = (d.get('Hostname') or '').strip()
        if hn:
            hostname_to_ip.setdefault(hn.lower(), ip)
            hostname_to_ip.setdefault(hn.split('.')[0].lower(), ip)
    for hn_key in list(hostname_to_ip.keys()):
        hostname_to_ip.setdefault(hn_key.split('.')[0], hostname_to_ip[hn_key])

    # Link + nodi scoperti. I link vengono accumulati per coppia di nodi così da
    # collassare i membri fisici di un aggregato (Port-Channel/LACP) in un unico
    # collegamento logico: CDP/LLDP annuncia le interfacce membro (Et0/1, Et0/2),
    # non l'interfaccia Port-channel, quindi l'aggregato si riconosce solo
    # incrociando la config (channel-group) e/o la presenza di più link fisici.
    link_acc: dict = {}   # link_key -> {source, target, members{key:{ports,is_pc_name}}, pc_names}
    for ip, info in parsed_devices.items():
        iface_pc_local = info.get("iface_pc", {})

        for neigh in parse_cdp_lldp_neighbors(info["content"]):
            neigh_id    = neigh["neighbor_id"]
            neigh_ip    = neigh["neighbor_ip"]
            local_port  = neigh["local_port"]
            remote_port = neigh["remote_port"]
            neigh_ver   = neigh.get("version")
            neigh_desc  = neigh.get("description")
            neigh_plat  = neigh.get("platform")
            neigh_caps  = neigh.get("capabilities")
            neigh_dom   = neigh.get("vtp_domain")

            base_neigh_id = neigh_id.split('.')[0] if '.' in neigh_id else neigh_id

            # --- Risoluzione robusta del nodo target (fix IP + dedup duplicati) ---
            # 1. Hostname → IP di management noto. Ha PRIORITÀ sull'IP annunciato da
            #    CDP/LLDP: il vicino può annunciare l'IP di una SVI qualsiasi (es.
            #    Vlan1) e non quello con cui è in inventario; affidarsi a esso
            #    creerebbe un nodo duplicato con l'indirizzo sbagliato.
            target_ip = (hostname_to_ip.get(neigh_id.lower())
                         or hostname_to_ip.get(base_neigh_id.lower()))

            # 2. IP annunciato, solo se corrisponde a un nodo reale già noto.
            if not target_ip and neigh_ip and neigh_ip in nodes_map:
                target_ip = neigh_ip

            # 3. Vicino esterno: chiave per hostname (così lo stesso switch
            #    annunciato con IP di VLAN diverse da più apparati non duplica),
            #    altrimenti per IP annunciato.
            if not target_ip:
                if base_neigh_id and not _looks_like_ip(base_neigh_id):
                    target_ip = f"discovered_{sanitize_filename(base_neigh_id)}"
                else:
                    target_ip = neigh_ip or f"discovered_{sanitize_filename(base_neigh_id)}"

            if target_ip not in nodes_map:
                # Crea nodo scoperto: tipo dedotto da Platform/Capabilities (CDP) e
                # System Description (LLDP), version e dominio VTP se disponibili.
                # Il nodo eredita il gruppo/sede dell'apparato che lo ha scoperto.
                auto_type = classify_device_type(
                    base_neigh_id, neigh_desc or "", neigh_plat or "", neigh_caps or ""
                )
                source_group = ip_to_device.get(ip, {}).get('Group', 'Generale')
                nodes_map[target_ip] = {
                    "id":          target_ip,
                    "label":       base_neigh_id,
                    "group":       source_group,
                    "status":      "discovered",
                    "device_type": apply_category(target_ip, auto_type),
                    "vendor":      guess_vendor(neigh_plat or "", neigh_desc or "", base_neigh_id) or "discovered",
                    "version":     neigh_ver,
                    # IP annunciato via CDP/LLDP (può differire dall'IP del nodo)
                    "reported_ip": neigh_ip,
                    "vtp_domain":  neigh_dom,
                    "platform":    neigh_plat,
                    "model":       extract_model(neigh_plat or "", neigh_desc or ""),
                    "name_options": neigh.get("name_options"),
                }
            else:
                node = nodes_map[target_ip]
                # Aggiorna version se il nodo esiste ma non ha ancora una versione valida
                existing_ver = node.get("version")
                if neigh_ver and (not existing_ver
                                  or existing_ver in ("Non Rilevata", "Unknown", "")):
                    node["version"] = neigh_ver
                # Segnala l'IP annunciato se diverso dall'IP di management reale:
                # è la spia del problema "IP sbagliato" che il workaround corregge.
                if neigh_ip and neigh_ip != target_ip and not node.get("reported_ip"):
                    node["reported_ip"] = neigh_ip
                if neigh_dom and not node.get("vtp_domain"):
                    node["vtp_domain"] = neigh_dom
                # Modello/piattaforma di un nodo inventariato ricavati dal CDP di un
                # vicino (un apparato non annuncia la propria platform a se stesso).
                if neigh_plat and not node.get("platform"):
                    node["platform"] = neigh_plat
                if not node.get("model"):
                    mdl = extract_model(neigh_plat or "", neigh_desc or "")
                    if mdl:
                        node["model"] = mdl

            # --- Riconoscimento aggregato (Port-Channel) sul membro corrente ---
            # Si conta SOLO l'interfaccia locale del dispositivo che riporta: è
            # l'unico dato affidabile. La "outgoing port" del vicino è una stima e
            # può non combaciare col nome reale dall'altro lato (di qui il rischio
            # di falsi aggregati se si appaiano gli endpoint a coppie).
            ln = _normalize_iface(local_port)
            rn = _normalize_iface(remote_port)
            local_pc  = iface_pc_local.get(ln)
            remote_pc = parsed_devices.get(target_ip, {}).get("iface_pc", {}).get(rn)

            link_key = tuple(sorted([ip, target_ip]))
            acc = link_acc.get(link_key)
            if not acc:
                acc = {
                    "source": ip, "target": target_ip,
                    "src_ports": {}, "tgt_ports": {},      # iface locali affidabili per lato
                    "src_guess": {}, "tgt_guess": {},      # iface stimate (outgoing port del vicino)
                    "pc_names": set(), "name_pc": False,
                }
                link_acc[link_key] = acc

            if _is_portchannel_port(local_port) or _is_portchannel_port(remote_port):
                acc["name_pc"] = True

            # Assegna le interfacce al lato corretto in base a chi sta riportando.
            if ip == acc["source"]:
                acc["src_ports"][ln] = local_port
                acc["tgt_guess"][rn] = remote_port
            else:  # ip == acc["target"]
                acc["tgt_ports"][ln] = local_port
                acc["src_guess"][rn] = remote_port

            if local_pc:
                acc["pc_names"].add(local_pc)
            if remote_pc:
                acc["pc_names"].add(remote_pc)

    # Emissione dei link. Un link è un aggregato (Port-Channel/LAG) se:
    #  - la config dichiara un channel-group (pc_names), oppure
    #  - un'interfaccia annunciata è già una Port-channel (name_pc), oppure
    #  - ENTRAMBI i lati riportano ≥2 interfacce locali distinte verso lo stesso
    #    vicino (bundle simmetrico). La simmetria evita il falso positivo del
    #    singolo cavo con nomi di "outgoing port" discordanti tra i due estremi.
    for acc in link_acc.values():
        src, tgt = acc["source"], acc["target"]
        # Interfacce affidabili (riportate dal lato stesso); fallback alle stime.
        src_list = list((acc["src_ports"] or acc["src_guess"]).values())
        tgt_list = list((acc["tgt_ports"] or acc["tgt_guess"]).values())

        symmetric_bundle = len(acc["src_ports"]) > 1 and len(acc["tgt_ports"]) > 1
        pc_names = sorted(acc["pc_names"])
        is_pc = bool(pc_names) or acc["name_pc"] or symmetric_bundle

        # Nome del Port-channel da mostrare: dalla config se nota, altrimenti
        # l'eventuale interfaccia Port-channel annunciata direttamente.
        pc_name = pc_names[0] if pc_names else None
        if not pc_name and acc["name_pc"]:
            pc_name = next((p for p in src_list + tgt_list if _is_portchannel_port(p)), None)

        member_count = max(len(src_list), len(tgt_list)) or 1
        links.append({
            "source":         src,
            "target":         tgt,
            "local_port":     src_list[0] if src_list else "Unknown",
            "remote_port":    tgt_list[0] if tgt_list else "Unknown",
            "local_ports":    src_list,
            "remote_ports":   tgt_list,
            "is_portchannel": is_pc,
            "pc_name":        pc_name,
            "pc_names":       pc_names,
            "member_count":   member_count,
        })

    # Override manuali scelti dall'utente (nome/versione per risolvere i conflitti
    # CDP/LLDP, ma anche vendor/modello riclassificati a mano nel tab Categorie):
    # devono riflettersi sul nodo della mappa così che, ad es., il vendor usato
    # dalla query EUVD sia quello reale e non l'hostname del dispositivo.
    for node_id, a in category_assignments.items():
        node = nodes_map.get(node_id)
        if not node:
            continue
        if a.get("name"):
            node["label"] = a["name"]
        if a.get("ver"):
            node["version"] = a["ver"]
        if a.get("vendor"):
            node["vendor"] = a["vendor"]
        if a.get("model"):
            node["model"] = a["model"]

    nodes = list(nodes_map.values())

    # Filtro per gruppo
    if group_filter and group_filter != "all":
        group_node_ids = {n["id"] for n in nodes if n["group"] == group_filter}
        boundary_ids   = set()
        for link in links:
            if link["source"] in group_node_ids:
                boundary_ids.add(link["target"])
            if link["target"] in group_node_ids:
                boundary_ids.add(link["source"])

        valid_node_ids = group_node_ids | boundary_ids
        nodes = []
        for n in nodes_map.values():
            if n["id"] in group_node_ids:
                nodes.append(n)
            elif n["id"] in boundary_ids:
                boundary_node                = dict(n)
                boundary_node["is_boundary"] = True
                nodes.append(boundary_node)

        links = [l for l in links
                 if l["source"] in valid_node_ids and l["target"] in valid_node_ids]

    return {"nodes": nodes, "links": links}
