import os
import re
import logging
from netmiko import ConnectHandler
from ping3 import ping
from inventory_manager import update_version_inventory, get_all_devices

BACKUP_FOLDER = 'backup-config'
logging.basicConfig(filename='error_log.txt', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

if not os.path.exists(BACKUP_FOLDER):
    os.makedirs(BACKUP_FOLDER)

def sanitize_filename(filename):
    return ''.join('_' if char in r'\/:*?"<>|' else char for char in filename)

def run_backup_and_triage(device):
    """Esegue ping, backup e recupero della versione software di un apparato."""
    ip = device['IP']
    vendor = device['Vendor'].lower()
    
    if ping(ip) is None:
        return {"status": "error", "message": f"Device {ip} non raggiungibile via ping"}

    netmiko_type = 'cisco_ios' if vendor == 'cisco' else 'hp_procurve'
    device_params = {
        'device_type': netmiko_type,
        'host': ip,
        'username': device['Username'],
        'password': device['Password'],
        'secret': device['Enable Secret'],
    }

    try:
        with ConnectHandler(**device_params) as net_connect:
            net_connect.enable()
            
            if vendor == 'cisco':
                version_out = net_connect.send_command("show version")
                match = re.search(r', Version\s+([^,]+)', version_out, re.IGNORECASE)
                version = match.group(1).strip() if match else "Unknown"
                config_cmd = "show running-config"
            else:  # HPE
                system_out = net_connect.send_command("show system")
                match = re.search(r'Firmware revision\s+:\s+(\S+)', system_out, re.IGNORECASE)
                version = match.group(1).strip() if match else "Unknown"
                config_cmd = "show run"
            
            # Registra la versione per l'EUVD Vulnerability Check
            update_version_inventory(ip, vendor, version)
            
            # Esegue il backup della configurazione
            config_out = net_connect.send_command(config_cmd)
            hostname_match = re.search(r'hostname\s+(\S+)', config_out, re.IGNORECASE | re.MULTILINE)
            sys_name = hostname_match.group(1).strip() if hostname_match else f"{vendor}_{ip}"
            
            file_path = os.path.join(BACKUP_FOLDER, f"{sanitize_filename(sys_name)}-{ip}.txt")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(config_out)
                
            return {"status": "success", "version": version, "file": file_path}
            
    except Exception as e:
        logging.error(f"Errore su {ip}: {str(e)}")
        return {"status": "error", "message": str(e)}

def send_custom_command(device, command):
    """Invia un comando CLI arbitrario da Web UI al dispositivo."""
    vendor = device['Vendor'].lower()
    netmiko_type = 'cisco_ios' if vendor == 'cisco' else 'hp_procurve'
    
    device_params = {
        'device_type': netmiko_type,
        'host': device['IP'],
        'username': device['Username'],
        'password': device['Password'],
        'secret': device['Enable Secret'],
    }
    try:
        with ConnectHandler(**device_params) as net_connect:
            net_connect.enable()
            output = net_connect.send_command(command)
            return {"status": "success", "output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}
