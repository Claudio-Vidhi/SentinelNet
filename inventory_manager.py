import json
import os
import csv

HOSTS_CSV = "network_hosts.csv"
VERSION_DATA_FILE = "detected_versions.json"

def get_all_devices():
    devices = []
    if not os.path.exists(HOSTS_CSV):
        return devices
    with open(HOSTS_CSV, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Assicuriamo la presenza dei nuovi campi logici
            if 'Group' not in row: row['Group'] = 'Generale'
            devices.append(row)
    return devices

def save_all_devices(devices):
    with open(HOSTS_CSV, mode='w', newline='', encoding='utf-8') as f:
        fieldnames = ['IP', 'Vendor', 'Profile', 'Username', 'Password', 'Enable Secret', 'Group']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in devices:
            # Valori di fallback se mancano chiavi
            writer.writerow({
                'IP': d.get('IP', ''),
                'Vendor': d.get('Vendor', 'cisco').lower(),
                'Profile': d.get('Profile', 'default'),
                'Username': d.get('Username', 'Admin'),
                'Password': d.get('Password', 'admin'),
                'Enable Secret': d.get('Enable Secret', 'admin'),
                'Group': d.get('Group', 'Generale')
            })

def add_or_update_device(ip, vendor, profile, username, password, enable_secret, group):
    devices = get_all_devices()
    # Rimuove se esistente per fare update, altrimenti aggiunge
    devices = [d for d in devices if d['IP'] != ip]
    
    new_device = {
        'IP': ip, 'Vendor': vendor.lower(), 'Profile': profile,
        'Username': username, 'Password': password, 'Enable Secret': enable_secret,
        'Group': group if group.strip() else 'Generale'
    }
    devices.append(new_device)
    save_all_devices(devices)

def delete_device(ip):
    devices = get_all_devices()
    devices = [d for d in devices if d['IP'] != ip]
    save_all_devices(devices)

def get_detected_versions():
    if os.path.exists(VERSION_DATA_FILE):
        try:
            with open(VERSION_DATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}

def update_version_inventory(ip, vendor, version, status="online"):
    data = get_detected_versions()
    data[ip] = {"vendor": vendor, "version": version, "status": status}
    with open(VERSION_DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)
