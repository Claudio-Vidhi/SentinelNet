import os
import re
import time
import logging
import socket
from typing import Optional, Any, Dict, List, Tuple
from core.net_ssh import ConnectHandler
from services.inventory_manager import (
    update_version_inventory, get_all_devices, get_detected_versions,
    update_device_hostname, get_all_vendors, get_category_assignments,
    parse_transports, CATEGORIES_FILE,
)
from drivers.cisco_ios import CiscoIosDriver
from drivers.cisco_cbs import CiscoCbsDriver
from drivers.hp_procurve import HpProcurveDriver
from drivers.juniper_junos import JuniperJunosDriver
from drivers.aruba_os import ArubaOsDriver
from drivers.fortinet import FortinetDriver
from drivers.cisco_wlc import CiscoWlcDriver
from drivers.paloalto_panos import PaloAltoDriver
from drivers.linux import LinuxDriver, sanitize_session
from security.crypto_vault import decrypt_password
from services import site_manager
from security.security_manager import log_audit
from core import data_config

BACKUP_FOLDER = data_config.get_path('backup-config')
logging.basicConfig(filename=data_config.get_path('error_log.txt'), level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

if not os.path.exists(BACKUP_FOLDER):
    os.makedirs(BACKUP_FOLDER)

DEFAULT_USERNAME = os.getenv("SENTINELNET_ADMIN_USER", "admin")
DEFAULT_PASSWORD = os.getenv("SENTINELNET_ADMIN_PASS", "admin")
DEFAULT_SECRET   = os.getenv("SENTINELNET_ADMIN_SECRET", "admin")

# Substring blacklist applied to commands sent by an operator.
# This is not a sandbox — it is a parachute against a destructive command typed
# by mistake on twenty devices at once; an admin can override it.
# ponytail: substring matching, so it does not cover variants ('rm -fr',
# '--recursive'). If real coverage were needed, the path is a per-vendor
# allowlist, not a longer blacklist.
DANGEROUS_COMMANDS = [
    # Network CLI
    "write erase", "reload", "delete", "format", "no boot", "erase",
    # Linux: without these, a managed host has no protection net.
    # 'shutdown' is NOT included: on Cisco it is the normal command to shut down a
    # port, and blocking it would break everyday use.
    "rm -rf", "mkfs", "dd if=", "shred ", "reboot", "poweroff", ":(){",
]

def sanitize_filename(filename: str) -> str:
    sanitized = ''.join(
        '_' if char in r'\/:*?"<>| ' else char
        for char in filename
        if ord(char) > 31
    )
    return sanitized or "device_unknown"

def group_backup_dir(group: str, vendor: Optional[str] = None) -> str:
    """Backup folder dedicated to a group/site, with subfolder per
    vendor (backup-config/<group>/<vendor>/), created if absent."""
    path = os.path.join(BACKUP_FOLDER, sanitize_filename(group or "Generale"))
    if vendor:
        path = os.path.join(path, sanitize_filename(vendor.lower()))
    os.makedirs(path, exist_ok=True)
    return path

def save_backup(device, sys_name: str, config_out: str) -> str:
    """Saves the text backup in backup-config/<group>/<vendor>/<name>-<ip>.txt,
    moving first any residual copies of the same IP elsewhere."""
    ip = device['IP']
    group_dir = group_backup_dir(device.get('Group', 'Generale'),
                                 device.get('Vendor', ''))
    remove_stale_backups(ip, new_dir=group_dir)
    file_path = os.path.join(group_dir, f"{sanitize_filename(sys_name)}-{ip}.txt")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(config_out)
    return file_path

def remove_stale_backups(ip: str, new_dir: Optional[str] = None):
    """Move a device's backup and its history when it changes group/vendor.

    This used to delete every file for the IP found anywhere in the tree. With
    a config archive beside the backup, deleting would throw away the device's
    whole history because someone re-assigned it to another tenant — a normal
    operational event. Files move to ``new_dir`` instead; with no destination
    there is nothing to preserve them for and they are removed, as before.
    """
    if not os.path.exists(BACKUP_FOLDER):
        return
    for root, _dirs, files in os.walk(BACKUP_FOLDER):
        if new_dir and os.path.abspath(root) == os.path.abspath(new_dir):
            continue
        for f in files:
            if not (f.endswith(f"-{ip}.txt") or f.endswith(f"_{ip}.txt") or f == f"{ip}.txt"):
                continue
            src = os.path.join(root, f)
            try:
                if new_dir:
                    os.makedirs(new_dir, exist_ok=True)
                    os.replace(src, os.path.join(new_dir, f))
                else:
                    os.remove(src)
            except OSError as e:
                logging.warning(f"Backup obsoleto non spostato ({f}): {e}")
        _move_history(root, ip, new_dir)


def _move_history(root: str, ip: str, new_dir: Optional[str]) -> None:
    """Carry the device's .history entries across with its current backup."""
    src_hist = os.path.join(root, ".history")
    if not new_dir or not os.path.isdir(src_hist):
        return
    dst_hist = os.path.join(new_dir, ".history")
    if os.path.abspath(src_hist) == os.path.abspath(dst_hist):
        return
    os.makedirs(dst_hist, exist_ok=True)
    for f in os.listdir(src_hist):
        if f"-{ip}." in f or f.startswith(f"{ip}-"):
            try:
                os.replace(os.path.join(src_hist, f), os.path.join(dst_hist, f))
            except OSError as e:
                logging.warning(f"Storico non spostato ({f}): {e}")

def _failure_status(exc) -> str:
    """Inventory status for a failed triage: 'auth_failed' or 'offline'.

    BastionAuthError is an authentication failure too, but of the SITE's
    bastion login; the message returned alongside says which hop refused, so
    the operator does not rotate the device credential for nothing.
    """
    from core.net_ssh import BastionAuthError
    if isinstance(exc, BastionAuthError):
        return "auth_failed"
    msg = str(exc).lower()
    return "auth_failed" if ("auth" in msg or "credentials" in msg
                             or "credenziali" in msg) else "offline"


def _fallback_credentials(device):
    """Credentials to use when the device row names none of its own.

    A site may declare a default identity for the devices behind it
    (site_manager: 'device_identity'). Without it the only fallback is the
    global admin account, which for a customer site behind a bastion means
    dialling that customer's devices with this installation's default
    login — the wrong credential, sent to the right device.
    """
    # hosts.csv rows carry 'Site'; the get_device_by_ip cache carries 'site'
    # (see services/inventory_manager.py). Both shapes reach this function.
    site_id = device.get('Site') or device.get('site') or ''
    if site_id:
        from services import site_manager
        from security import identity_manager
        site = site_manager.get_site(site_id)
        identity = (site or {}).get('device_identity')
        if identity:
            creds = identity_manager.get_identity_credentials(identity)
            if creds:
                return creds
    return DEFAULT_USERNAME, DEFAULT_PASSWORD, DEFAULT_SECRET


def get_device_credentials(device):
    profile = device.get('Profile', 'custom').lower()
    if profile == 'default':
        return _fallback_credentials(device)
    if profile.startswith('identity:'):
        # Tenant identity (identity_manager): fallback to the site default if
        # the identity no longer exists (it should not: delete is blocked if in use).
        from security import identity_manager
        creds = identity_manager.get_identity_credentials(
            device.get('Profile', '')[len('identity:'):])
        if creds:
            return creds
        return _fallback_credentials(device)
    fb_user, fb_pass, fb_secret = _fallback_credentials(device)
    username = device.get('Username') or fb_user
    password = decrypt_password(device.get('Password')) or fb_pass
    secret   = decrypt_password(device.get('Enable Secret')) or fb_secret
    return username, password, secret

# --- REGISTRY DRIVER ↔ NETMIKO ---
# Maps the driver-name (vendor registry 'driver' field) to the driver class and
# the corresponding netmiko device_type. Adding a new driver here is
# enough to make it selectable from the whole system.
DRIVER_REGISTRY = {
    'cisco_ios':      (CiscoIosDriver,   'cisco_ios'),
    'cisco_s300':     (CiscoCbsDriver,   'cisco_s300'),
    'hp_procurve':    (HpProcurveDriver, 'hp_procurve'),
    'juniper_junos':  (JuniperJunosDriver, 'juniper_junos'),
    'aruba_os':       (ArubaOsDriver,    'aruba_os'),
    'fortinet':       (FortinetDriver,   'fortinet'),
    'paloalto_panos': (PaloAltoDriver,   'paloalto_panos'),
    'cisco_wlc':      (CiscoWlcDriver,   'cisco_wlc_ssh'),   # AireOS
    'cisco_9800':     (CiscoIosDriver,   'cisco_xe'),        # Catalyst 9800 (IOS-XE)
    'linux':          (LinuxDriver,      'linux'),
}

# Fallback vendor-name → driver-name, used when the vendor registry does not
# specify a driver (e.g. installations with legacy vendors.json or 'driver': null).
VENDOR_DRIVER_DEFAULTS = {
    'cisco':    'cisco_ios',
    'cisco_cbs': 'cisco_s300',
    'hpe':      'hp_procurve',
    'hp':       'hp_procurve',
    'juniper':  'juniper_junos',
    'aruba':    'aruba_os',
    'fortinet': 'fortinet',
    'paloalto': 'paloalto_panos',
    'cisco_wlc': 'cisco_wlc',
    'cisco_9800': 'cisco_9800',
    'linux':    'linux',
}

def resolve_driver(vendor):
    """Resolves a vendor into the (driver class, netmiko device_type) pair.

    Resolution order:
      1. 'driver' field of the vendor registry (get_all_vendors)
      2. fallback vendor-name → driver (VENDOR_DRIVER_DEFAULTS)
    Raises ValueError if no driver is associated with the vendor.
    """
    from services import inventory_manager
    vendor = inventory_manager.normalize_vendor(vendor)

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

def get_device_port(device) -> int:
    """SSH port of the device from inventory ('SSH Port'), fallback 22."""
    try:
        port = int(str(device.get('SSH Port') or '').strip() or 22)
    except (ValueError, AttributeError):
        return 22
    return port if 1 <= port <= 65535 else 22

def get_cli_transport(device):
    """Declared CLI transport of the device (§11.6): returns (kind, port) where
    kind is 'ssh' or 'telnet'. Prefers SSH; uses Telnet only if SSH is not
    declared. For legacy ssh-only devices it preserves EXACTLY the
    historical behavior (ssh + port from 'SSH Port')."""
    try:
        transports = parse_transports(device)
    except Exception:
        transports = None
    if transports:
        if 'ssh' in transports:
            return 'ssh', transports['ssh'] or 22
        if 'telnet' in transports:
            return 'telnet', transports['telnet'] or 23
    return 'ssh', get_device_port(device)


def _cli_device_type(netmiko_type: str, kind: str) -> str:
    """Netmiko variant for Telnet ('_telnet' suffix); unchanged for SSH."""
    if kind == 'telnet' and not netmiko_type.endswith('_telnet'):
        return netmiko_type + '_telnet'
    return netmiko_type


def is_reachable(ip: str, port: int = 22, timeout: int = 2) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

FORTINET_VENDORS = ('fortinet', 'fortigate', 'fortiwifi', 'fortios')

def _fortigate_backup_and_triage(device):
    """FortiGate triage: full config via REST (with SSH fallback handled by
    fortigate_service.get_full_config), saved in backup-config like the
    other vendors; firmware version from monitor/system/status."""
    import json
    from services import fortigate_service  # lazy import to avoid cycle with get_device_credentials

    ip     = device['IP']
    vendor = device['Vendor'].lower()

    try:
        cfg = fortigate_service.get_full_config(device)
    except Exception as e:
        logging.error(f"Errore su {ip}: {str(e)}")
        st = _failure_status(e)
        update_version_inventory(ip, vendor, "Non Rilevata", st)
        log_audit(f"Triage fallito per FortiGate '{ip}': {str(e)}.")
        return {"status": "error", "message": str(e)}

    config_out = cfg["data"] if isinstance(cfg["data"], str) else json.dumps(cfg["data"], ensure_ascii=False)

    version = "Non Rilevata"
    fg_model = "FortiGate"
    fg_serial = ""
    try:
        status = fortigate_service.get_system_status(device)
        data = status.get("data")
        raw = None
        if isinstance(data, dict):
            results = data.get("results") if isinstance(data.get("results"), dict) else {}
            raw = data.get("version") or results.get("version")
            fg_model = data.get("platform") or results.get("platform") or results.get("model") or "FortiGate"
            fg_serial = data.get("serial") or results.get("serial") or ""
        elif isinstance(data, str):
            m = re.search(r'^Version:\s*(.+)$', data, re.MULTILINE)
            if m:
                raw = m.group(1).strip()
            m_mod = re.search(r'Version:\s*([A-Za-z0-9\-_]+)\s+v', data)
            if m_mod:
                fg_model = m_mod.group(1).strip()
            m_sn = re.search(r'Serial-Number:\s*(\S+)', data, re.IGNORECASE)
            if m_sn:
                fg_serial = m_sn.group(1).strip()
        if raw:
            # "FortiGate-VM64 v7.4.12,build2902,..." / "v7.4.12" -> "7.4.12"
            version = extract_version(raw) or raw
    except Exception:
        pass
    update_version_inventory(ip, vendor, version, "online", model=fg_model,
                             serial=fg_serial)

    sys_name = extract_hostname_from_config(config_out) or f"{vendor}_{ip}"
    update_device_hostname(ip, sys_name)

    file_path = save_backup(device, sys_name, config_out)
    # The single point every collected config flows through: no second
    # scheduler and no separate collection path for drift.
    try:
        from services.config_drift import history
        history.record_version(device, config_out)
    except Exception as e:
        # History is an observer. A failure here must never fail a backup
        # that succeeded.
        logging.warning(f"Storico config non aggiornato per {device.get('IP')}: {e}")
    log_audit(f"Triage e backup completati con successo per dispositivo '{ip}' "
              f"(Firmware: '{version}', fonte config: {cfg['source']}).")
    return {"status": "success", "version": version, "hostname": sys_name,
            "file": file_path, "source": cfg["source"]}

def run_backup_and_triage(device):
    ip     = device['IP']
    vendor = device['Vendor'].lower()

    # FortiGate: REST-primary (port 443) with internal SSH fallback in the service,
    # so no pre-check on port 22.
    if vendor in FORTINET_VENDORS:
        return _fortigate_backup_and_triage(device)

    cli_kind, ssh_port = get_cli_transport(device)
    # A jump-site device has no direct route from the central by design: the
    # session is tunnelled through the bastion by core.net_ssh. Probing the
    # direct path here would always fail and persist a false "offline".
    if site_manager.has_direct_path(device.get('Site')) and not is_reachable(ip, ssh_port):
        update_version_inventory(ip, vendor, "Non Rilevata", "offline")
        log_audit(f"Triage fallito per dispositivo '{ip}': non raggiungibile sulla porta {ssh_port} ({cli_kind.upper()}).")
        return {"status": "error", "message": f"Device {ip} non raggiungibile sulla porta {ssh_port} ({cli_kind.upper()})"}

    username, password, secret = get_device_credentials(device)

    # Resolves driver and netmiko device_type BEFORE connecting: a vendor without
    # an associated driver fails immediately, without uselessly opening the SSH session.
    try:
        driver_cls, netmiko_type = resolve_driver(vendor)
    except ValueError as ve:
        log_audit(f"Vendor non supportato per '{ip}': {ve}")
        update_version_inventory(ip, vendor, "Non Rilevata", "error")
        return {"status": "error", "message": str(ve)}

    device_params = {
        'device_type': _cli_device_type(netmiko_type, cli_kind),
        'host': ip,
        'port': ssh_port,
        'username': username,
        'password': password,
        'secret': secret,
        'timeout': 15,
        'auth_timeout': 10,
        'banner_timeout': 10,
    }

    try:
        with ConnectHandler(**device_params) as net_connect:
            if netmiko_type == 'linux':
                sanitize_session(net_connect)
            # Linux has no enable mode: netmiko translates enable() to `sudo -s`. It
            # only makes sense if the operator put the sudo password in Enable
            # Secret; otherwise the session stays non-privileged and non-root
            # commands suffice.
            if netmiko_type != 'linux' or secret:
                net_connect.enable()
            live_hostname = net_connect.find_prompt().strip().rstrip('#>').strip()

            driver = driver_cls(net_connect)

            version    = driver.get_version()
            model      = driver.get_model() if hasattr(driver, "get_model") else "Non Rilevato"
            serial     = driver.get_serial()
            backup_cmd = driver.get_backup_command()

            update_version_inventory(ip, vendor, version, "online", model=model,
                                     serial=serial)

            raw_out = net_connect.send_command(backup_cmd)
            config_out = raw_out if isinstance(raw_out, str) else str(raw_out or "")

            config_out += "\n\n=== NEIGHBOR DISCOVERY ===\n"
            if vendor == 'cisco':
                for cmd, tag in [
                    ("show cdp neighbors",        "--- SHOW CDP NEIGHBORS ---"),
                    ("show cdp neighbors detail",  "--- SHOW CDP NEIGHBORS DETAIL ---"),
                    ("show lldp neighbors",        "--- SHOW LLDP NEIGHBORS ---"),
                    ("show lldp neighbors detail", "--- SHOW LLDP NEIGHBORS DETAIL ---"),
                    ("show switch",                "--- SHOW SWITCH ---"),
                    ("show inventory",             "--- SHOW INVENTORY ---"),
                ]:
                    try:
                        out = net_connect.send_command(cmd)
                        out_str = out if isinstance(out, str) else str(out or "")
                        config_out += f"\n{tag}\n{out_str}"
                    except Exception:
                        pass
            elif vendor == 'hpe':
                for cmd, tag in [
                    ("show lldp info remote-device",        "--- SHOW LLDP NEIGHBORS ---"),
                    ("show lldp info remote-device detail", "--- SHOW LLDP NEIGHBORS DETAIL ---"),
                ]:
                    try:
                        out = net_connect.send_command(cmd)
                        out_str = out if isinstance(out, str) else str(out or "")
                        config_out += f"\n{tag}\n{out_str}"
                    except Exception:
                        pass
            elif vendor == 'cisco_9800':
                # Catalyst 9800 is IOS-XE: it answers the switch commands, and
                # 'show chassis' is where an HA pair names both of its members.
                for cmd, tag in [
                    ("show cdp neighbors detail",  "--- SHOW CDP NEIGHBORS DETAIL ---"),
                    ("show lldp neighbors detail", "--- SHOW LLDP NEIGHBORS DETAIL ---"),
                    ("show chassis",               "--- SHOW CHASSIS ---"),
                    ("show redundancy",            "--- SHOW REDUNDANCY ---"),
                    ("show inventory",             "--- SHOW INVENTORY ---"),
                ]:
                    try:
                        out = net_connect.send_command(cmd, read_timeout=30)
                        out_str = out if isinstance(out, str) else str(out or "")
                        config_out += f"\n{tag}\n{out_str}"
                    except Exception:
                        pass
            elif vendor == 'cisco_wlc':
                # AireOS: 'show redundancy summary' is the only place the HA
                # SSO pair is described, and it is not an IOS command.
                for cmd, tag in [
                    ("show system info",           "--- SYSTEM INFO ---"),
                    ("show inventory",             "--- SHOW INVENTORY ---"),
                    ("show redundancy summary",    "--- SHOW REDUNDANCY SUMMARY ---"),
                ]:
                    try:
                        out = net_connect.send_command(cmd, read_timeout=30)
                        out_str = out if isinstance(out, str) else str(out or "")
                        config_out += f"\n{tag}\n{out_str}"
                    except Exception:
                        pass
            elif vendor in ('fortinet', 'paloalto'):
                for cmd, tag in [
                    ("get system status",          "--- SYSTEM STATUS ---"),
                    ("show system info",           "--- SYSTEM INFO ---"),
                    ("show inventory",             "--- SHOW INVENTORY ---"),
                    ("show environment all",       "--- SHOW ENVIRONMENT ALL ---"),
                    ("show license all",           "--- SHOW LICENSE ALL ---"),
                ]:
                    try:
                        out = net_connect.send_command(cmd, read_timeout=30)
                        out_str = out if isinstance(out, str) else str(out or "")
                        config_out += f"\n{tag}\n{out_str}"
                    except Exception:
                        pass
            elif vendor == 'linux':
                # `hostname` comes out as a bare name: it is written in the form
                # `hostname <name>` so extract_hostname_from_config recognizes it
                # without a dedicated parser (the Linux prompt
                # 'user@host:~$' is not usable).
                linux_cmds = [
                    ("hostname",           "--- HOSTNAME ---"),
                    ("uname -srm",         "--- UNAME ---"),
                    ("uptime -p",          "--- UPTIME ---"),
                    ("uptime -s",          "--- BOOT TIME ---"),
                    ("ip -br a",           "--- IP ADDRESS ---"),
                    # Counters and MTU per interface in one shot: status,
                    # RX-TX bytes/packets, errors and discards.
                    ("ip -s link",         "--- LINK STATS ---"),
                    # Speed/duplex from sysfs instead of ethtool: same
                    # data, no dependency to install and no privilege
                    # (on lo and virtuals the files do not exist, hence 2>/dev/null).
                    ('for i in /sys/class/net/*; do echo "$(basename $i)'
                     ' $(cat $i/speed 2>/dev/null) $(cat $i/duplex 2>/dev/null)"; done',
                     "--- LINK SPEED ---"),
                    ("ip route",           "--- IP ROUTE ---"),
                    ("lsblk",              "--- LSBLK ---"),
                    ("lsblk -dno NAME,MODEL,SERIAL,SIZE", "--- DISKS ---"),
                    ("lscpu",              "--- LSCPU ---"),
                    ("df -hT",             "--- DF ---"),
                    ("systemctl --failed", "--- SYSTEMCTL FAILED ---"),
                    ("systemctl list-unit-files --state=enabled --no-legend --no-pager",
                     "--- SYSTEMCTL ENABLED ---"),
                    ("ss -tuln",           "--- LISTENING SOCKETS ---"),
                    # Containers: they stay in the non-privileged tier because an
                    # operator in the 'docker' group sees them without sudo, and with
                    # the privileged tier the session is already root. If docker is
                    # not present, 2>/dev/null simply leaves the section empty.
                    ("docker ps --format "
                     "'{{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}' 2>/dev/null",
                     "--- CONTAINERS ---"),
                    ("docker version --format '{{.Server.Version}}' 2>/dev/null",
                     "--- DOCKER VERSION ---"),
                    # kubelet is installed on every cluster node, control
                    # plane or worker: it answers even where kubectl has no
                    # kubeconfig usable from this session.
                    ("kubelet --version 2>/dev/null", "--- KUBELET VERSION ---"),
                    ("lldpctl",            "--- SHOW LLDP NEIGHBORS ---"),
                ]
                if secret:
                    # Privileged tier: available only if the operator declared
                    # the sudo password (Enable Secret).
                    linux_cmds += [
                        ("ss -tulpn",       "--- LISTENING SOCKETS PID ---"),
                        ("stat -c '%a %U %G %n' /etc/shadow /etc/passwd /etc/group",
                         "--- FILE PERMISSIONS ---"),
                        ("sshd -T",         "--- SSHD EFFECTIVE CONFIG ---"),
                        ("cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null",
                         "--- SUDOERS ---"),
                        # dmidecode -s one key at a time: the output becomes
                        # "key: value", same form as lscpu, a single parser.
                        ('for k in system-manufacturer system-product-name'
                         ' system-serial-number bios-version bios-release-date;'
                         ' do echo "$k: $(dmidecode -s $k 2>/dev/null)"; done',
                         "--- DMIDECODE ---"),
                        ("dmidecode -t 17", "--- MEMORY DEVICES ---"),
                        ("nft list ruleset 2>/dev/null || iptables -S 2>/dev/null",
                         "--- FIREWALL RULES ---"),
                    ]
                for cmd, tag in linux_cmds:
                    try:
                        out = net_connect.send_command(cmd)
                        out_str = out if isinstance(out, str) else str(out or "")
                        if tag == "--- HOSTNAME ---":
                            out_str = f"hostname {out_str.strip()}"
                        config_out += f"\n{tag}\n{out_str}"
                    except Exception:
                        pass

            hostname_from_cfg = extract_hostname_from_config(config_out)
            sys_name = hostname_from_cfg or live_hostname or f"{vendor}_{ip}"

            update_device_hostname(ip, sys_name)

            file_path = save_backup(device, sys_name, config_out)
            # The single point every collected config flows through: no second
            # scheduler and no separate collection path for drift.
            try:
                from services.config_drift import history
                history.record_version(device, config_out)
            except Exception as e:
                # History is an observer. A failure here must never fail a backup
                # that succeeded.
                logging.warning(f"Storico config non aggiornato per {device.get('IP')}: {e}")

            # Redundancy detection: updates/dissolves the group associated
            # with this management IP. A switch stack and a controller HA pair
            # are the same slot on the same key, so exactly ONE upsert runs
            # per device -- see parse_device_redundancy.
            try:
                from redundancy import service as redundancy_service
                group_type, redundancy_members = parse_device_redundancy(config_out, vendor)
                redundancy_service.upsert_redundancy_from_cli(
                    device.get("Group", "Generale"), ip, sys_name,
                    redundancy_members, group_type,
                )
            except Exception as stack_err:
                logging.warning(f"Rilevamento ridondanza fallito per {ip}: {stack_err}")

            log_audit(f"Triage e backup completati con successo per dispositivo '{ip}' (Firmware: '{version}').")
            return {"status": "success", "version": version, "hostname": sys_name, "file": file_path}

    except Exception as e:
        logging.error(f"Errore su {ip}: {str(e)}")
        st = _failure_status(e)
        update_version_inventory(ip, vendor, "Non Rilevata", st)
        log_audit(f"Triage fallito per dispositivo '{ip}': errore di connessione/autenticazione ({str(e)}).")
        return {"status": "error", "message": str(e)}


def probe_device(device):
    """Discovery probe: connects, verifies credentials, reads the hostname.

    Deliberately NOT run_backup_and_triage. A subnet scan touches every host
    with port 22 open, and the full backup is 22+ commands, each with its own
    read timeout: a single host that answers on 22 without being the declared
    vendor costs minutes, and the whole scan looks frozen. Here the cost per
    host is bounded by the connection plus one command.

    Returns {"status": "success", "hostname": str|None} or
            {"status": "error", "message": str}.
    """
    vendor = device['Vendor'].lower()
    try:
        _, netmiko_type = resolve_driver(vendor)
    except ValueError as e:
        return {"status": "error", "message": str(e)}

    username, password, secret = get_device_credentials(device)
    cli_kind, cli_port = get_cli_transport(device)
    device_params = {
        'device_type': _cli_device_type(netmiko_type, cli_kind),
        'host': device['IP'],
        'port': cli_port,
        'username': username,
        'password': password,
        'secret': secret,
        'timeout': 15,
        'auth_timeout': 10,
        'banner_timeout': 10,
    }
    try:
        with ConnectHandler(**device_params) as net_connect:
            if netmiko_type == 'linux':
                # Senza questa, le sequenze di "shell integration" cambiano il
                # prompt a ogni comando e ogni lettura va in timeout.
                sanitize_session(net_connect)
                out = net_connect.send_command("hostname", read_timeout=10)
                hostname = (out if isinstance(out, str) else str(out or "")).strip()
            else:
                hostname = net_connect.find_prompt().strip().rstrip('#>').strip()
        return {"status": "success", "hostname": hostname or None}
    except Exception as e:
        # Senza questa riga la scansione dice "0 SSH ok" e nient'altro:
        # credenziali sbagliate e "non e' un server SSH" diventano lo stesso
        # esito muto. Una riga per host con la 22 aperta, non per host vivo.
        logging.warning("Probe di %s fallito: %s", device['IP'], e)
        return {"status": "error", "message": str(e)}


def send_custom_command(device, command: str, bypass_blacklist: bool = False):
    # bypass_blacklist=True when the caller (API) has already authorized the
    # command based on role (admin, or blacklist disabled for operators).
    if not bypass_blacklist and any(cmd in command.lower() for cmd in DANGEROUS_COMMANDS):
        return {"status": "error", "message": "Comando non consentito dalla policy di sicurezza aziendale (Blacklisted)"}

    vendor = device['Vendor'].lower()
    try:
        _, netmiko_type = resolve_driver(vendor)
    except ValueError as e:
        return {"status": "error", "message": str(e)}

    username, password, secret = get_device_credentials(device)
    cli_kind, cli_port = get_cli_transport(device)
    device_params = {
        'device_type': _cli_device_type(netmiko_type, cli_kind),
        'host': device['IP'],
        'port': cli_port,
        'username': username,
        'password': password,
        'secret': secret,
        'timeout': 15,
        'auth_timeout': 10,
        'banner_timeout': 10,
    }
    try:
        with ConnectHandler(**device_params) as net_connect:
            if netmiko_type == 'linux':
                sanitize_session(net_connect)
            if netmiko_type != 'linux' or secret:
                net_connect.enable()
            output = net_connect.send_command(command)
            log_audit(f"Comando CLI '{command}' eseguito con successo sul dispositivo '{device['IP']}'.")
            return {"status": "success", "output": output}
    except Exception as e:
        log_audit(f"Esecuzione comando CLI '{command}' fallita sul dispositivo '{device['IP']}': {str(e)}")
        return {"status": "error", "message": str(e)}


def run_bulk_command(device, commands, config_mode=False, save_after=False):
    """Runs the same list of commands on a device.

    - config_mode=False: operational commands (show/exec), one by one.
    - config_mode=True:  pushes commands into configuration mode (send_config_set),
      and optionally saves the config (save_after) — used to apply changes
      in bulk across multiple devices.
    The destructive-commands blacklist is applied upstream (API side).
    """
    ip = device['IP']
    cli_kind, ssh_port = get_cli_transport(device)
    # See run_backup_and_triage: no direct probe for a bastion-only site.
    if site_manager.has_direct_path(device.get('Site')) and not is_reachable(ip, ssh_port):
        return {"status": "error", "message": f"Device {ip} non raggiungibile sulla porta {ssh_port} ({cli_kind.upper()})"}

    vendor = device['Vendor'].lower()
    try:
        _, netmiko_type = resolve_driver(vendor)
    except ValueError as e:
        return {"status": "error", "message": str(e)}

    username, password, secret = get_device_credentials(device)
    device_params = {
        'device_type': _cli_device_type(netmiko_type, cli_kind),
        'host': ip,
        'port': ssh_port,
        'username': username,
        'password': password,
        'secret': secret,
        'timeout': 20,
        'auth_timeout': 10,
        'banner_timeout': 10,
    }

    try:
        with ConnectHandler(**device_params) as net_connect:
            if netmiko_type == 'linux':
                sanitize_session(net_connect)
            if netmiko_type != 'linux' or secret:
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
                    res = net_connect.send_command(cmd)
                    res_str = res if isinstance(res, str) else str(res or "")
                    parts.append(f"=== {cmd} ===\n" + res_str)
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

def extract_hostname_from_config(content: str) -> Optional[str]:
    """Extracts the hostname from configuration lines (Cisco and HPE)."""
    match = re.search(r'^\s*hostname\s+(\S+)', content, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1).strip().strip('"')
    match = re.search(r'^\s*hostname\s+"([^"]+)"', content, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    # FortiOS: `set hostname "X"` inside config system global
    match = re.search(r'^\s*set\s+hostname\s+"?([^"\n]+)"?', content, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def extract_mgmt_vlan(content: str, mgmt_ip: str) -> str | None:
    """Deduces the management VLAN: looks for the SVI interface (interface VlanN)
    whose `ip address` matches the node's management IP. If the management
    IP sits on a routed interface (e.g. GigabitEthernet0/0 in Mgmt-vrf)
    there is no VLAN and None is returned (the frontend shows only the IP)."""
    if not content or not mgmt_ip:
        return None
    # "interface Vlan<N> ... ip address <ip>" blocks: the exact IP is matched.
    for m in re.finditer(r'^\s*interface\s+Vlan(\d+)\s*$(.*?)(?=^\s*interface\s|\Z)',
                         content, re.MULTILINE | re.IGNORECASE | re.DOTALL):
        vlan_id, block = m.group(1), m.group(2)
        if re.search(r'^\s*ip address\s+' + re.escape(mgmt_ip) + r'\b',
                     block, re.MULTILINE | re.IGNORECASE):
            return vlan_id
    return None


def _parse_sys_description(block: str) -> str | None:
    """
    Extracts the System Description from an LLDP detail block.

    The IOS-XE format has the description on NON-indented lines after the tag:

        System Description:
        Cisco IOS Software [IOSXE]... Version 17.16.1a ...
        Technical Support: ...

    The Ubuntu/Linux format is analogous:

        System Description:
        Ubuntu 24.04.2 LTS Linux 6.8.0-59-generic ...

    Strategy: captures all text between "System Description:" and the next
    recognizable key field or end of block. Collapses whitespace, truncates to 200 chars.
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

    # Fallback: description on the same line (HPE, old IOS)
    m2 = re.search(r'System Description:\s*([^\n\r]+)', block, re.IGNORECASE)
    if m2:
        return m2.group(1).strip()

    return None


# Keywords to classify the device type from hostname,
# System Description (LLDP), Platform and Capabilities (CDP). The evaluation
# order in classify_device_type establishes the priority.
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
    "camera":   ("camera", "nvr", "videosorveglianza"),
    "server":   ("server", "esxi", "vmware", "nas", "ubuntu", "debian",
                 "linux", "windows server", "proxmox"),
    "pc":       ("workstation", "desktop", "laptop", "client"),
}
# Short/ambiguous keywords: matched only as isolated tokens to avoid false
# positives (e.g. "ap" inside "naples", "fw" inside "software").
_TYPE_TOKENS = {
    "firewall": ("asa", "ftd", "srx", "fw", "pa"),
    "router":   ("rtr",),
    "phone":    ("tel",),
    "server":   ("srv", "host"),
    "pc":       ("pc",),
}
_TYPE_ORDER = ("firewall", "wlc", "ap", "router", "phone", "camera", "server", "pc")
# Positive keywords for "switch", searched ONLY in description/platform (never
# in the hostname: a hostname like "sw-wifi-floor2" must not be confused with an
# AP). This evidence takes precedence over "ap" keywords based on hostname.
_SWITCH_SUBSTRINGS = ("catalyst", "ws-c", "c9200", "c9300", "c9500", "switch")
# Direct evidence of access point from description/platform. Cisco lightweight
# APs announce CDP Capabilities "Router Trans-Bridge": without this check the
# Capabilities (which take precedence) classify them as "router".
# "ap software" comes from the LLDP System Description; the model pattern
# covers the CDP-only case, where the only signal is the Platform.
_AP_SUBSTRINGS = ("ap software", "air-ap", "air-cap", "aironet")
_AP_MODEL_RE = re.compile(r'\b(?:c9\d{3}ax|cw91\d{2})')
# Router models: an L3 router announces CDP Capabilities "Router Switch IGMP"
# exactly like a multilayer switch, so Capabilities alone would classify it
# as "switch". The model in the Platform is more specific.
_ROUTER_MODEL_RE = re.compile(r'\b(?:isr|asr|csr)\d')


def _has_token(text: str, token: str) -> bool:
    return bool(re.search(r'(?:^|[^a-z0-9])' + re.escape(token) + r'(?:[^a-z0-9]|$)', text))


def classify_device_type(hostname: str = "", description: str = "",
                         platform: str = "", capabilities: str = "") -> str:
    """Deduces the device type by combining hostname, System Description (LLDP),
    Platform and Capabilities (CDP). Returns: firewall|wlc|ap|router|phone|camera|
    server|pc|switch."""
    text = " ".join(filter(None, [hostname, description, platform])).lower()
    caps = (capabilities or "").lower()
    if not text.strip() and not caps.strip():
        return "client"
    # A precise model in Platform/System Description beats the Capabilities:
    # CDP bits are coarse (a lightweight AP declares "Router Trans-Bridge",
    # an L3 router "Router Switch IGMP" like any multilayer switch).
    _dp = " ".join(filter(None, [description, platform])).lower()
    # CDP/LLDP Capabilities are the most reliable signal: a device that
    # declares itself "Switch" must not be reclassified for a keyword in the name
    # (e.g. hostname with "wifi" or an "AP" segment).
    if ("switch" in caps and "access point" not in caps and "wlan" not in caps
            and not _ROUTER_MODEL_RE.search(_dp)):
        return "switch"
    if any(s in _dp for s in _AP_SUBSTRINGS) or _AP_MODEL_RE.search(_dp):
        return "ap"
    # Capabilities take absolute precedence over hostname/description/platform:
    # e.g. "Router" Capabilities must not lose to a hostname with a weak token
    # like "srv-core-01" (site naming convention), which otherwise would
    # match "server" before even looking at the capabilities.
    if caps.strip():
        for t in _TYPE_ORDER:
            if any(s in caps for s in _TYPE_SUBSTRINGS.get(t, ())):
                return t
    # "switch" evidence from description/platform (CDP/LLDP), NEVER from hostname:
    # beats "ap" keywords based only on the hostname (e.g. "sw-wifi-floor2"
    # with platform "Cisco Catalyst 9300" -> switch, not ap).
    desc_plat = " ".join(filter(None, [description, platform])).lower()
    switch_evidence = any(s in desc_plat for s in _SWITCH_SUBSTRINGS)
    # Platform+Description (CDP/LLDP) take precedence over the hostname, which is
    # the weakest signal: e.g. hostname "fw-edge1" with platform "Cisco ISR4321"
    # is a router, not a firewall just because the name contains the "fw" token.
    # Evaluated FIRST and SEPARATELY from the hostname (never merged into a single
    # string), otherwise a weak token in the name would beat real evidence.
    for t in _TYPE_ORDER:
        if t == "ap" and switch_evidence:
            return "switch"
        if any(s in desc_plat for s in _TYPE_SUBSTRINGS.get(t, ())):
            return t
        if any(_has_token(desc_plat, tok) for tok in _TYPE_TOKENS.get(t, ())):
            return t
    if switch_evidence:
        return "switch"
    # Last: the hostname alone, the weakest signal.
    hostname_l = (hostname or "").lower()
    for t in _TYPE_ORDER:
        if any(s in hostname_l for s in _TYPE_SUBSTRINGS.get(t, ())):
            return t
        if any(_has_token(hostname_l, tok) for tok in _TYPE_TOKENS.get(t, ())):
            return t
    # No reliable clue: generic type, never guess "switch".
    return "client"


# Firmware versions: extracts a clean version number from a free-form string
# (LLDP/CDP System Description), useful for CVE checking.
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


# Vendor clues from Platform/Description/hostname (CDP/LLDP). Returns the vendor
# key (consistent with the vendors registry) or None.
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


# Device model from Platform (CDP) or System Description (LLDP).
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


# Model from the device's own backup (best-effort, multi-vendor).
# dmidecode returns these placeholders when the manufacturer has not written
# anything into SMBIOS: they are literal strings, not models.
_DMI_PLACEHOLDERS = ("not specified", "to be filled by o.e.m.", "system product name",
                     "default string", "unknown", "none", "n/a")


def _linux_model(content: str) -> str | None:
    """Model of a Linux host: the hardware product, or the hypervisor if it is a VM.

    On a VM there is no machine model, and leaving the column empty says
    less than the hypervisor name: "VM (VMware)" is what the operator also
    sees in the virtualization console.
    """
    dmi = _backup_section(content, 'DMIDECODE') or ""
    m = re.search(r'^system-product-name:\s*(.+)$', dmi, re.IGNORECASE | re.MULTILINE)
    if m:
        value = m.group(1).strip()
        if value and value.lower() not in _DMI_PLACEHOLDERS:
            return value
    # Without the privileged tier dmidecode does not run: lscpu still declares
    # the hypervisor, which on a VM is the only hardware identity that exists.
    lscpu = _backup_section(content, 'LSCPU') or ""
    m = re.search(r'^Hypervisor vendor:\s*(.+)$', lscpu, re.IGNORECASE | re.MULTILINE)
    if m and m.group(1).strip():
        return f"VM ({m.group(1).strip()})"
    return None


def extract_model_from_backup(content: str) -> str | None:
    # A Linux artifact is recognized by the files the driver writes into it.
    # It must be intercepted BEFORE the Cisco patterns: 'Model:' in lscpu is the
    # CPU model number (e.g. "186"), and it ended up in the column instead of the machine.
    if _backup_section(content, '/etc/os-release') is not None:
        return _linux_model(content)

    # CDP/LLDP blocks describe OTHER devices (phones, APs, peer switches):
    # their 'Model:'/'Platform:' must never end up in the chassis model.
    neighbor_sections = (
        'SHOW CDP NEIGHBORS',
        'SHOW CDP NEIGHBORS DETAIL',
        'SHOW LLDP NEIGHBORS',
        'SHOW LLDP NEIGHBORS DETAIL',
    )
    filtered_lines = []
    skipping = False
    for line in content.splitlines():
        header = re.match(r'^---\s*(.*?)\s*---\s*$', line)
        if header:
            section = header.group(1).strip().strip('-').strip()
            if section:
                skipping = section.upper() in neighbor_sections
                if not skipping:
                    filtered_lines.append(line)
                continue
        if not skipping:
            filtered_lines.append(line)
    filtered = '\n'.join(filtered_lines)

    for pat in (
        r'Model [Nn]umber\s*:\s*(\S+)',
        r'^\s*Model\s*:\s*(\S+)',
        r'cisco\s+(\S+)\s*\([^)]*\)\s*processor',
        r'Hardware:\s*(\S+)',
    ):
        m = re.search(pat, filtered, re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1).strip().strip(',')

    # If no explicit pattern survives, the first PID is read from the
    # SHOW INVENTORY block: it is the chassis product id (not of modules/SFPs).
    inventory = _backup_section(content, 'SHOW INVENTORY')
    if inventory is not None:
        m = re.search(r'^\s*PID\s*:\s*(.*)$', inventory, re.IGNORECASE | re.MULTILINE)
        if m:
            pid = m.group(1).split(',', 1)[0].strip().strip(',')
            if pid:
                return pid
    return None


def _backup_section(content: str, tag: str) -> str | None:
    """Returns the text block appended to the backup under '--- <TAG> ---'."""
    sec = re.search(rf'--- {tag} ---\s*\n(.*?)(?=\n--- |\n===|\Z)',
                    content, re.DOTALL | re.IGNORECASE)
    return sec.group(1) if sec else None


# Stack unit state (Cisco) -> MemberState of redundancy.models
_STACK_STATE_MAP = {
    'ready': 'ready',
    'provisioned': 'provisioned',
    'v-mismatch': 'version_mismatch',
    'version mismatch': 'version_mismatch',
    'removed': 'rp_down',
}


def _parse_stack_cisco(content: str) -> list[dict]:
    """Units of a StackWise stack from 'show switch' + 'show inventory'."""
    members: dict[int, dict] = {}

    block = _backup_section(content, 'SHOW SWITCH')
    if block:
        # E.g.: "*1       Active   0c6e.e2xx.xxxx     15     V02     Ready"
        # The middle columns (mac/priority/hw) vary by platform: only
        # index, role and final state are anchored, without leaving the row.
        for m in re.finditer(
            r'^[ \t]*\*?[ \t]*(\d+)[ \t]+(Active|Standby|Member|Master|Slave)[ \t]+'
            r'(?:\S+[ \t]+)*?(Ready|Provisioned|V-Mismatch|Version Mismatch|Removed)[ \t]*$',
            block, re.MULTILINE | re.IGNORECASE,
        ):
            idx = int(m.group(1))
            role_raw = m.group(2).lower()
            members[idx] = {
                'member_index': idx,
                'role': 'master' if role_raw in ('active', 'master') else 'member',
                'serial': None,
                'model': None,
                'state': _STACK_STATE_MAP.get(m.group(3).lower(), 'ready'),
            }

    # 'show inventory': NAME: "Switch 1" ... PID: WS-C3850-24XS-S , VID: V02, SN: FOCxxxx
    # The FIRST occurrence per unit counts: subsequent entries with the same
    # prefix are components (power supplies, fans), not the chassis.
    inv = _backup_section(content, 'SHOW INVENTORY')
    if inv:
        for m in re.finditer(
            r'NAME:\s*"(?:Switch|Chassis)?\s*(\d+)[^"]*".{0,200}?'
            r'PID:\s*(\S+).{0,120}?SN:\s*(\S+)',
            inv, re.DOTALL | re.IGNORECASE,
        ):
            idx = int(m.group(1))
            unit = members.setdefault(idx, {
                'member_index': idx, 'role': 'member', 'state': 'ready',
                'serial': None, 'model': None,
            })
            if unit['serial'] is None:
                unit['model'] = m.group(2).strip().strip(',')
                unit['serial'] = m.group(3).strip().strip(',')

    return [members[i] for i in sorted(members)]


_STACK_PARSERS = {'cisco': _parse_stack_cisco}


def parse_switch_stack(content: str, vendor: str) -> list[dict] | None:
    """Physical units of a stack from the backup text, or None if the device
    is not a stack (or the vendor is not supported)."""
    parser = _STACK_PARSERS.get(str(vendor or '').lower())
    if not parser:
        return None
    members = parser(content)
    return members if len(members) >= 2 else None


def parse_device_redundancy(content: str, vendor: str):
    """(group_type, members) for this device's redundancy, members None if none.

    A device is a switch stack OR a controller HA pair, never both, and the
    group is keyed on its management IP. Deciding here keeps the triage to a
    single upsert: running both would make the second one dissolve the group
    the first had just written.
    """
    from redundancy.models import GroupType
    from redundancy.parsers.cisco_wlc import SSO_PARSERS, parse_wlc_sso
    if str(vendor or '').lower() in SSO_PARSERS:
        return GroupType.SSO, parse_wlc_sso(content, vendor)
    return GroupType.STACK, parse_switch_stack(content, vendor)


def parse_vtp_status(content: str) -> tuple[str | None, str | None]:
    """Extracts (vtp_mode, vtp_domain) from the device itself: first from
    'show vtp status', then from the running-config, finally from the most
    frequent VTP domain announced by CDP neighbors (useful to estimate the extent)."""
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
    Parses the CDP and LLDP neighbor tables present in the backup file.
    Returns a list of dicts with keys:
        neighbor_id, neighbor_ip, local_port, remote_port, version
    """
    neighbors = []

    # ------------------------------------------------------------------
    # 1. CDP Neighbors Detail (Cisco) — block parsing to also capture
    #    Platform/Capabilities (device type), Version and VTP Management Domain.
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
    # 2. CDP Neighbors summary (fallback if no detail)
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
    # 4. LLDP detail IP harvest (legacy Cisco formats)
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
    #  Real IOS-XE format:
    #    ------------------------------------------------
    #    Local Intf: Et0/1
    #    System Name: sw2.lab.local
    #    System Description:
    #    Cisco IOS Software [IOSXE]... Version 17.16.1a ...   <- NOT indented
    #    Technical Support: ...
    #    Management Addresses:
    #        IP: 192.168.31.183                               <- 4 spaces
    #    ------------------------------------------------
    #
    #  Ubuntu LLDP format:
    #    System Description:
    #    Ubuntu 24.04.2 LTS Linux 6.8.0-59-generic ...       <- NOT indented
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

            # Management IP: indented IOS-XE or alternative formats
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

            # System Description — handles both indented and non-indented
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
                "version":     extract_version(version_str or "") or version_str,
                "description": version_str,
            })

    # ------------------------------------------------------------------
    # Smart deduplication — keeps the richest entry
    # per (local_port, base_hostname) pair.
    # ------------------------------------------------------------------
    merged: dict = {}
    for n in neighbors:
        neigh_id = str(n.get("neighbor_id") or "")
        local_port = str(n.get("local_port") or "")
        base_id  = neigh_id.split('.')[0] if '.' in neigh_id else neigh_id
        key      = (local_port.lower(), base_id.lower())

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
    # Consolidation by PHYSICAL PORT: CDP and LLDP on the same port describe
    # the SAME neighbor, sometimes with different names (e.g. hostname via LLDP,
    # MAC/serial via CDP). They are merged into a single entry so as not to duplicate the
    # node, recording alternative names/versions (name_options) for the user's
    # possible choice. Aggregated or unknown ports are not consolidated.
    by_port: dict = {}
    singles: list = []
    for n in merged.values():
        lp = (n.get("local_port") or "").strip()
        # The key uses the NORMALIZED interface so "GigabitEthernet1/0/34"
        # (CDP) and "Gi1/0/34" (LLDP) fall on the same physical port.
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
        # Canonical: prefer a readable hostname (not MAC), then whoever has version/IP.
        group.sort(
            key=lambda e: (
                0 if _looks_like_mac(e["neighbor_id"]) else 1,
                1 if e.get("version") else 0,
                1 if e.get("neighbor_ip") else 0,
            ),
            reverse=True,
        )
        canonical = dict(group[0])
        options = {}  # name -> version (dedup by name, keeps the first useful version)
        for e in group:
            nm = e["neighbor_id"]
            if nm not in options or (not options[nm] and e.get("version")):
                options[nm] = e.get("version")
        for other in group[1:]:
            for fld in ("neighbor_ip", "version", "platform", "capabilities",
                        "vtp_domain", "description", "remote_port"):
                if other.get(fld) and not canonical.get(fld):
                    canonical[fld] = other[fld]
        # Real conflict only if the NAMES differ: in that case the user chooses.
        if len(options) > 1:
            canonical["name_options"] = [{"name": k, "version": v} for k, v in options.items()]
        final.append(canonical)

    final.extend(singles)
    return final


# Aggregated interface name patterns (Port-Channel / LAG / bundle) for the
# main vendors. Used to highlight aggregated links on the map.
PORTCHANNEL_RE = re.compile(
    r'^(?:'
    r'po\d+|'                     # Cisco IOS short:  Po1
    r'port-?channel\d*|'          # Cisco IOS long:   Port-channel1
    r'trk\d+|'                    # HP ProCurve:      Trk1
    r'lag\s*\d+|'                 # Aruba/generic:    lag 1
    r'ae\d+|'                     # Juniper:          ae0
    r'bridge-aggregation\d*|'     # HPE Comware:      Bridge-Aggregation1
    r'bagg\d+|'                   # HPE Comware short: BAGG1
    r'bundle-ether\d*|'           # Cisco IOS-XR:     Bundle-Ether1
    r'eth-trunk\d*'               # Huawei:           Eth-Trunk1
    r')',
    re.IGNORECASE,
)


def _is_portchannel_port(port: str) -> bool:
    """True if the interface name indicates an aggregate (Port-Channel/LAG)."""
    return bool(port and PORTCHANNEL_RE.match(port.strip()))


def _looks_like_ip(value: str) -> bool:
    """True if the string is an IPv4 dotted-quad (and not a hostname)."""
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', (value or '').strip()))


# Known interface abbreviations (Cisco-like) → canonical code, to make the
# long forms of the config ("Ethernet0/1") match the short ones
# announced by CDP/LLDP ("Et0/1").
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
    """Normalizes an interface name to 'code+number' (e.g. Et0/1 → et0/1)."""
    if not name:
        return ''
    name = name.strip()
    m = re.match(r'^([A-Za-z][A-Za-z\-]*?)\s*([\d/\.:]+)\s*$', name)
    if not m:
        return name.lower().replace(' ', '')
    prefix = m.group(1).lower().replace('-', '')
    return f"{_IFACE_ALIASES.get(prefix, prefix)}{m.group(2)}"


def parse_channel_groups(config: str) -> dict:
    """Maps physical interface → Port-channel name by reading 'channel-group N'
    in the interface blocks of the running-config (Cisco IOS/IOS-XE).

    E.g.:  interface Ethernet0/1 / channel-group 10 mode active
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


# Physical interface patterns (exclude SVI/Vlan/Loopback/Tunnel/Port-channel).
_PHYS_IFACE_RE = re.compile(
    r'^(?:Gigabit|TenGigabit|TwentyFiveGig|FortyGigabit|HundredGig|Fast|TwoGigabit)?'
    r'Ethernet[\d/.]+$|^(?:Gi|Te|Twe|Fo|Hu|Fa|Eth|Et)[\d/.]+$',
    re.IGNORECASE,
)


def parse_shutdown_interfaces(config: str) -> set:
    """Interfaces with ``shutdown`` in the running-config.

    This is the portion of truth the backup already contains and that the
    report ignored: a shut-down member remains a member of the aggregate, but does not compose it.
    Showing it green next to the others makes one believe the bundle is intact.
    """
    shut: set = set()
    current = None
    for line in config.splitlines():
        m = re.match(r'^interface\s+(\S+)', line)
        if m:
            current = m.group(1)
            continue
        if current and re.match(r'^\s+shutdown\s*$', line):
            shut.add(current)
            current = None      # a single line is enough to mark it
    return shut


def parse_portchannel_summary(config: str) -> dict:
    """Summarizes the Port-channels of a device (Cisco IOS/IOS-XE):
      - portchannels: {Po name: [member interfaces]}
      - singles: physical interfaces NOT in any Port-channel
    Read from the 'interface' blocks of the running-config (channel-group N)."""
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
    # Second pass: physical interfaces declared but not members of an aggregate.
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
    """Operational state of Port-channels from 'show etherchannel summary'.
    Returns {PoNumber: {status, up, total, issue, issue_msg, members:{iface:flag}}}.
    Member flag: P=in aggregate, D=down, s=suspended, I=stand-alone, w=waiting...
    Po flag: U=in use, D=down."""
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
    """Port-channel report per device (for the Adjacency List tab). Reads the
    backups and returns [{ip, hostname, group, portchannels, singles}], filtered by group."""
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
            dev = ip_to_device.get(ip)
            if dev is None:
                # Backup of a device no longer in inventory: without this
                # filter it would reappear as a duplicate of the same switch at an
                # old IP, with data from weeks ago and tenant 'Generale' —
                # therefore not even hideable with the tenant filter.
                continue
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

            # Neighbor connected to each interface (from CDP/LLDP), to attribute
            # a device name to the Port-channel.
            neigh_by_port = {}
            for nb in parse_cdp_lldp_neighbors(content):
                lp = _normalize_iface(nb.get("local_port") or "")
                if lp and nb.get("neighbor_id"):
                    neigh_by_port.setdefault(lp, nb["neighbor_id"])

            ec_status = parse_etherchannel_status(content)
            shut = parse_shutdown_interfaces(content)
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
                    # Members shut down by configuration: separate field so as
                    # not to change the shape of ``members``, which has other readers.
                    "shut_members": [m for m in members if m in shut],
                    "neighbors": neighbors,
                    "status": st.get("status"),           # up|down|None(unknown)
                    "up": st.get("up"),
                    "total": st.get("total"),
                    "issue": st.get("issue", False),
                    "issue_msg": st.get("issue_msg", ""),
                })

            try:
                backup_ts = int(os.path.getmtime(os.path.join(root, fn)))
            except OSError:
                backup_ts = None
            report.append({
                "ip": ip,
                "hostname": hostname,
                "group": group,
                # When the backup was taken: without it, a "2/2 UP" from two
                # weeks ago and one from three minutes ago read the same.
                "backup_ts": backup_ts,
                "portchannels": pcs,
                "singles": summary["singles"],
            })
    report.sort(key=lambda r: r["hostname"].lower())
    return report


# Cache of generate_network_map: the recursive scan of BACKUP_FOLDER with
# regex parsing of every .txt file is expensive and is invoked on every request
# from multiple endpoints (device-classification, topology, network-map, mac uplinks).
# The cache is invalidated by an economical "signature" (count + max mtime of the
# backups, mtime of the category-assignments file) computed with a single
# os.walk/stat pass, much lighter than the full scan it replaces.
_netmap_cache: dict = {"sig": None, "by_filter": {}, "sig_ts": 0.0, "last_sig": None}

def _netmap_signature():
    now = time.time()
    if _netmap_cache.get("last_sig") is not None and (now - _netmap_cache.get("sig_ts", 0)) < 4.0:
        return _netmap_cache["last_sig"]
    count = 0
    max_mtime = 0.0
    if os.path.exists(BACKUP_FOLDER):
        for root, _dirs, files in os.walk(BACKUP_FOLDER):
            for f in files:
                if not f.endswith('.txt'):
                    continue
                count += 1
                try:
                    mtime = os.path.getmtime(os.path.join(root, f))
                except OSError:
                    continue
                if mtime > max_mtime:
                    max_mtime = mtime
    try:
        cat_mtime = os.path.getmtime(CATEGORIES_FILE)
    except OSError:
        cat_mtime = 0.0
    sig = (count, max_mtime, cat_mtime)
    _netmap_cache["last_sig"] = sig
    _netmap_cache["sig_ts"] = now
    return sig


def _enrich_map_with_redundancy(data: dict) -> dict:
    from redundancy import service as redundancy_service
    from services.inventory_manager import get_detected_versions
    try:
        from services import ping_monitor
        pm_status = ping_monitor.get_status()
        pm_devices = {d["ip"]: d for d in pm_status.get("devices", [])}
    except Exception:
        pm_devices = {}
    versions = get_detected_versions()

    nodes = data.get("nodes", [])
    links = list(data.get("links", []))
    nodes_decorated = []
    for n in nodes:
        node_copy = dict(n)
        nid = n.get("id")
        # Live status: continuous ping monitor is authoritative when available,
        # otherwise detected_versions, otherwise preserve discovered/parsed status.
        if nid in pm_devices:
            # Tri-state: "up" is None for a jump-site device (bastion tunnel,
            # no ICMP) — not measurable, must not render as a false "offline".
            pm_up = pm_devices[nid].get("up")
            node_copy["status"] = "online" if pm_up is True else "offline" if pm_up is False else "unknown"
        elif nid in versions and versions[nid].get("status"):
            node_copy["status"] = versions[nid].get("status")
        elif n.get("status") != "discovered":
            node_copy["status"] = versions.get(nid, {}).get("status", n.get("status", "offline"))

        if nid in versions:
            v_info = versions[nid]
            if v_info.get("version"):
                node_copy["version"] = v_info.get("version")
            if v_info.get("vendor"):
                node_copy["vendor"] = v_info.get("vendor")

        node_copy["redundancy"] = redundancy_service.device_redundancy_badge(n["id"])
        nodes_decorated.append(node_copy)

    node_ids = {n["id"] for n in nodes_decorated}
    all_groups = redundancy_service.list_groups()
    for g in all_groups:
        if g.get("group_type") == "ha_pair":
            members = g.get("members", [])
            ips = [m.get("device_ip") for m in members if m.get("device_ip") and m.get("device_ip") in node_ids]
            if len(ips) == 2:
                links.append({
                    "source": ips[0],
                    "target": ips[1],
                    "kind": "redundancy_heartbeat",
                    "local_port": "HA",
                    "remote_port": "HA",
                    "is_portchannel": False,
                    "member_count": 1,
                })
    return {"nodes": nodes_decorated, "links": links}


def generate_network_map(group_filter=None) -> dict:
    """Cached wrapper: see _generate_network_map for the real logic.
    Callers (routers/catalog.py, topology.py, mac.py) only read the
    result without mutating it, so it is safe to share the cache object."""
    sig = _netmap_signature()
    if _netmap_cache["sig"] != sig:
        _netmap_cache["sig"] = sig
        _netmap_cache["by_filter"] = {}
    key = group_filter or "all"
    cached = _netmap_cache["by_filter"].get(key)
    if cached is None:
        cached = _generate_network_map(group_filter)
        if _netmap_cache["sig"] == sig:
            _netmap_cache["by_filter"][key] = cached
    return _enrich_map_with_redundancy(cached)


def _generate_network_map(group_filter=None) -> dict:
    """Scans backup-config and generates nodes + links for the topological map."""
    devices      = get_all_devices()
    ip_to_device = {d['IP']: d for d in devices}
    hostname_to_ip: dict = {}
    nodes_map: dict      = {}
    links: list          = []

    # Manual category overrides (user assignments) per node-id: they take
    # precedence over automatic classification from hostname/CDP/LLDP.
    try:
        category_assignments = get_category_assignments()
    except Exception:
        category_assignments = {}

    def apply_category(node_id, auto_type, tenant=None):
        from services.inventory_manager import _akey
        a = category_assignments.get(_akey(tenant, node_id))
        return a.get("category", auto_type) if a and a.get("category") else auto_type

    # Read backup files. Backups are organized in subfolders per group
    # (feature: separate backups per site), so the scan is recursive and
    # continues to recognize legacy files saved in the root.
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

    # Pre-scan of CDP/LLDP announcements from all backups to build a lookup
    # hostname/ip -> {platform, capabilities, description}. It serves to pass
    # real platform/capabilities to the classification of inventoried nodes:
    # without this, a switch announced as a neighbor by another device but
    # with "wifi"/"wlan" in the hostname (e.g. "SW-WIFI-01") would be classified
    # as an AP for lack of better signals (only hostname+vendor).
    neighbor_info: dict = {}
    for _ip, _info in parsed_devices.items():
        for _n in parse_cdp_lldp_neighbors(_info["content"]):
            _nid  = _n["neighbor_id"]
            _base = _nid.split('.')[0] if '.' in _nid else _nid
            _entry = {
                "platform":     _n.get("platform") or "",
                "capabilities": _n.get("capabilities") or "",
                "description":  _n.get("description") or "",
            }
            for _key in (_nid.lower(), _base.lower(), _n.get("neighbor_ip")):
                if _key:
                    neighbor_info.setdefault(_key, _entry)

    # Nodi inventariati
    versions = get_detected_versions()
    for ip, d in ip_to_device.items():
        pinfo  = parsed_devices.get(ip, {})
        label  = pinfo.get("hostname", ip)
        status = versions.get(ip, {}).get("status", "offline")
        vendor = d.get('Vendor', 'cisco')
        # The vendor participates in classification: a Fortinet/Palo Alto device
        # is a firewall even if the hostname does not say so. If the node was
        # announced as a CDP/LLDP neighbor by another device, also use
        # real platform/capabilities/System Description (see neighbor_info).
        _ninfo = (neighbor_info.get(label.lower())
                  or neighbor_info.get(label.split('.')[0].lower())
                  or neighbor_info.get(ip)
                  or {})
        auto_type = classify_device_type(
            label,
            description=_ninfo.get("description") or vendor,
            platform=_ninfo.get("platform", ""),
            capabilities=_ninfo.get("capabilities", ""),
        )
        nodes_map[ip] = {
            "id":          ip,
            "label":       label,
            "group":       d.get('Group', 'Generale'),
            "status":      status,
            "device_type": apply_category(ip, auto_type, d.get('Group')),
            "vendor":      vendor,
            "version":     versions.get(ip, {}).get("version"),
            "vtp_mode":    pinfo.get("vtp_mode"),
            "vtp_domain":  pinfo.get("vtp_domain"),
            "model":       extract_model_from_backup(pinfo.get("content", "")) if pinfo else None,
            # Management IP and VLAN shown inside the box on the minimalist
            # map. The IP is the inventory one (node id); the VLAN is
            # deduced from the SVI with that IP (None if on a routed interface).
            "mgmt_ip":     ip,
            "mgmt_vlan":   extract_mgmt_vlan(pinfo.get("content", ""), ip) if pinfo else None,
        }

    # Enrich the hostname→IP map with the hostnames known from the inventory
    # (CSV Hostname field) and with the "base" forms without FQDN domain. It serves to
    # collapse a neighbor onto the real node even when CDP/LLDP announces the
    # IP of any SVI (e.g. Vlan1) different from the management IP with which
    # the device is inventoried.
    for ip, d in ip_to_device.items():
        hn = (d.get('Hostname') or '').strip()
        if hn:
            hostname_to_ip.setdefault(hn.lower(), ip)
            hostname_to_ip.setdefault(hn.split('.')[0].lower(), ip)
    for hn_key in list(hostname_to_ip.keys()):
        hostname_to_ip.setdefault(hn_key.split('.')[0], hostname_to_ip[hn_key])

    # Links + discovered nodes. Links are accumulated per node pair so as to
    # collapse the physical members of an aggregate (Port-Channel/LACP) into a single
    # logical link: CDP/LLDP announces the member interfaces (Et0/1, Et0/2),
    # not the Port-channel interface, so the aggregate is recognized only
    # by cross-referencing the config (channel-group) and/or the presence of multiple physical links.
    link_acc: Dict[Tuple[str, str], Any] = {}
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

            # --- Robust target node resolution (IP fix + duplicate dedup) ---
            # 1. Hostname → known management IP. It has PRIORITY over the IP announced by
            #    CDP/LLDP: the neighbor may announce the IP of any SVI (e.g.
            #    Vlan1) and not the one with which it is inventoried; relying on it
            #    would create a duplicate node with the wrong address.
            target_ip = (hostname_to_ip.get(neigh_id.lower())
                         or hostname_to_ip.get(base_neigh_id.lower()))

            # 2. Announced IP, only if it matches an already-known real node.
            if not target_ip and neigh_ip and neigh_ip in nodes_map:
                target_ip = neigh_ip

            # 3. External neighbor: key by hostname (so the same switch
            #    announced with different VLAN IPs by multiple devices does not duplicate),
            #    otherwise by announced IP.
            if not target_ip:
                if base_neigh_id and not _looks_like_ip(base_neigh_id):
                    target_ip = f"discovered_{sanitize_filename(base_neigh_id)}"
                else:
                    target_ip = neigh_ip or f"discovered_{sanitize_filename(base_neigh_id)}"

            if target_ip not in nodes_map:
                # Create discovered node: type deduced from Platform/Capabilities (CDP) and
                # System Description (LLDP), version and VTP domain if available.
                # The node inherits the group/site of the device that discovered it.
                auto_type = classify_device_type(
                    base_neigh_id, neigh_desc or "", neigh_plat or "", neigh_caps or ""
                )
                source_group = ip_to_device.get(ip, {}).get('Group', 'Generale')
                nodes_map[target_ip] = {
                    "id":          target_ip,
                    "label":       base_neigh_id,
                    "group":       source_group,
                    "status":      "discovered",
                    # Not the neighbour's site: a discovered node is not in
                    # inventory, so tenant_for_node() files it under 'Generale'
                    # and it must be read back from there. It acquires a site
                    # when it is promoted, and migrate_assignment moves it.
                    "device_type": apply_category(target_ip, auto_type),
                    "vendor":      guess_vendor(neigh_plat or "", neigh_desc or "", base_neigh_id) or "discovered",
                    "version":     neigh_ver,
                    # IP announced via CDP/LLDP (may differ from the node IP)
                    "reported_ip": neigh_ip,
                    "vtp_domain":  neigh_dom,
                    "platform":    neigh_plat,
                    "model":       extract_model(neigh_plat or "", neigh_desc or ""),
                    "name_options": neigh.get("name_options"),
                }
            else:
                node = nodes_map[target_ip]
                # Update version if the node exists but does not yet have a valid version
                existing_ver = node.get("version")
                if neigh_ver and (not existing_ver
                                  or existing_ver in ("Non Rilevata", "Unknown", "")):
                    node["version"] = neigh_ver
                # Report the announced IP if different from the real management IP:
                # it is the indicator of the "wrong IP" problem that the workaround fixes.
                if neigh_ip and neigh_ip != target_ip and not node.get("reported_ip"):
                    node["reported_ip"] = neigh_ip
                if neigh_dom and not node.get("vtp_domain"):
                    node["vtp_domain"] = neigh_dom
                # Model/platform of an inventoried node obtained from a neighbor's
                # CDP (a device does not announce its own platform to itself).
                if neigh_plat and not node.get("platform"):
                    node["platform"] = neigh_plat
                if not node.get("model"):
                    mdl = extract_model(neigh_plat or "", neigh_desc or "")
                    if mdl:
                        node["model"] = mdl

            # --- Aggregate (Port-Channel) recognition on the current member ---
            # ONLY the local interface of the reporting device is counted: it is
            # the only reliable data. The neighbor's "outgoing port" is an estimate and
            # may not match the real name on the other side (hence the risk
            # of false aggregates if endpoints are paired up).
            ln = _normalize_iface(local_port)
            rn = _normalize_iface(remote_port)
            local_pc  = iface_pc_local.get(ln)
            remote_pc = parsed_devices.get(target_ip, {}).get("iface_pc", {}).get(rn)

            link_key: Tuple[str, str] = (min(ip, target_ip), max(ip, target_ip))
            existing_acc = link_acc.get(link_key)
            acc: Dict[str, Any]
            if existing_acc is None:
                acc = {
                    "source": ip, "target": target_ip,
                    "src_ports": {}, "tgt_ports": {},      # reliable local interfaces per side
                    "src_guess": {}, "tgt_guess": {},      # estimated interfaces (neighbor's outgoing port)
                    "src_pc": set(), "tgt_pc": set(),      # aggregate name per-side (Po may differ between A and B)
                    "pc_names": set(), "name_pc": False,
                }
                link_acc[link_key] = acc
            else:
                acc = existing_acc

            if _is_portchannel_port(local_port) or _is_portchannel_port(remote_port):
                acc["name_pc"] = True

            # Assign the interfaces to the correct side based on who is reporting.
            if ip == acc["source"]:
                acc["src_ports"][ln] = local_port
                acc["tgt_guess"][rn] = remote_port
                # local_pc belongs to the source, remote_pc (estimate) to the target.
                if local_pc:  acc["src_pc"].add(local_pc)
                if remote_pc: acc["tgt_pc"].add(remote_pc)
            else:  # ip == acc["target"]
                acc["tgt_ports"][ln] = local_port
                acc["src_guess"][rn] = remote_port
                if local_pc:  acc["tgt_pc"].add(local_pc)
                if remote_pc: acc["src_pc"].add(remote_pc)

            if local_pc:
                acc["pc_names"].add(local_pc)
            if remote_pc:
                acc["pc_names"].add(remote_pc)

    # Link emission. A link is an aggregate (Port-Channel/LAG) if:
    #  - the config declares a channel-group (pc_names), or
    #  - an announced interface is already a Port-channel (name_pc), or
    #  - BOTH sides report ≥2 distinct local interfaces toward the same
    #    neighbor (symmetric bundle). The symmetry avoids the false positive of a
    #    single cable with discordant "outgoing port" names between the two ends.
    for acc in link_acc.values():
        src, tgt = acc["source"], acc["target"]
        # Reliable interfaces (reported by the side itself); fallback to estimates.
        src_list = list((acc["src_ports"] or acc["src_guess"]).values())
        tgt_list = list((acc["tgt_ports"] or acc["tgt_guess"]).values())

        symmetric_bundle = len(acc["src_ports"]) > 1 and len(acc["tgt_ports"]) > 1
        pc_names = sorted(acc["pc_names"])
        is_pc = bool(pc_names) or acc["name_pc"] or symmetric_bundle

        # Port-channel name to show: from the config if known, otherwise
        # any Port-channel interface announced directly.
        pc_name = pc_names[0] if pc_names else None
        if not pc_name and acc["name_pc"]:
            pc_name = next((p for p in src_list + tgt_list if _is_portchannel_port(p)), None)

        member_count = max(len(src_list), len(tgt_list)) or 1

        # Aggregate name per-side: the Port-channel can have a different id on the two
        # devices (e.g. Po1 on A, Po4 on B). Each side is kept separately
        # to label the two ends of the bundle independently.
        local_pc  = sorted(acc["src_pc"])[0] if acc["src_pc"] else None
        remote_pc = sorted(acc["tgt_pc"])[0] if acc["tgt_pc"] else None
        # Fallback: if a side has no channel-group in config but announces a
        # Port-channel, use that; otherwise fall back to the common pc_name.
        if not local_pc:
            local_pc = next((p for p in src_list if _is_portchannel_port(p)), None) or pc_name
        if not remote_pc:
            remote_pc = next((p for p in tgt_list if _is_portchannel_port(p)), None) or pc_name

        links.append({
            "source":         src,
            "target":         tgt,
            "local_port":     src_list[0] if src_list else "Unknown",
            "remote_port":    tgt_list[0] if tgt_list else "Unknown",
            "local_ports":    src_list,
            "remote_ports":   tgt_list,
            "is_portchannel": is_pc,
            "pc_name":        pc_name,
            "local_pc":       local_pc if is_pc else None,
            "remote_pc":      remote_pc if is_pc else None,
            "pc_names":       pc_names,
            "member_count":   member_count,
        })

    # Manual overrides chosen by the user (name/version to resolve CDP/LLDP
    # conflicts, but also vendor/model reclassified by hand in the Categories tab):
    # they must be reflected on the map node so that, e.g., the vendor used
    # by the EUVD query is the real one and not the device hostname.
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

    # Filter by group
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


def invalidate_netmap_cache():
    _netmap_cache["by_filter"] = {}

