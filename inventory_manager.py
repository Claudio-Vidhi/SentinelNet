import json
import os
import csv

HOSTS_CSV = "network_hosts.csv"
VERSION_DATA_FILE = "detected_versions.json"

def get_all_devices():
    """Legge i dispositivi dal file CSV di inventario."""
    devices = []
    if not os.path.exists(HOSTS_CSV):
        return devices
    with open(HOSTS_CSV, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            devices.append(row)
    return devices

def add_device_to_csv(ip, username, password, enable_secret, vendor):
    """Aggiunge o aggiorna un dispositivo nel file CSV."""
    devices = get_all_devices()
    
    # Rimuove il dispositivo se esiste già lo stesso IP per evitare duplicati
    devices = [d for d in devices if d['IP'] != ip]
    
    new_device = {
        'IP': ip, 
        'Username': username, 
        'Password': password,
        'Enable Secret': enable_secret, 
        'Vendor': vendor.lower()
    }
    devices.append(new_device)
    
    with open(HOSTS_CSV, mode='w', newline='', encoding='utf-8') as f:
        fieldnames = ['IP', 'Username', 'Password', 'Enable Secret', 'Vendor']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in devices:
            writer.writerow(d)

def get_detected_versions():
    """Ritorna le versioni firmware scansionate e salvate."""
    if os.path.exists(VERSION_DATA_FILE):
        try:
            with open(VERSION_DATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}

def update_version_inventory(ip, vendor, software_version):
    """Aggiorna il database JSON locale con la versione rilevata."""
    data = get_detected_versions()
    data[ip] = {"vendor": vendor, "version": software_version}
    with open(VERSION_DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)
