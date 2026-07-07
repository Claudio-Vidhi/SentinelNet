import json
import os
import csv
import re
import threading
import crypto_vault
import data_config

HOSTS_CSV = data_config.get_path("network_hosts.csv")
GROUPS_JSON = data_config.get_path("groups.json")
VERSION_DATA_FILE = data_config.get_path("detected_versions.json")
VENDORS_FILE = data_config.get_path("vendors.json")

IP_PATTERN = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

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
                    except:
                        pass
    except Exception as e:
        if os.path.exists(temp):
            try:
                os.remove(temp)
            except:
                pass
        raise e

def get_all_groups():
    if not os.path.exists(GROUPS_JSON):
        default_groups = {"Generale": {"description": "Sede Principale predefinita"}}
        save_groups(default_groups)
        return default_groups
    with open(GROUPS_JSON, "r", encoding="utf-8") as f:
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
    safe_json_write(GROUPS_JSON, groups_dict)

def safe_write_hosts_csv(devices):
    temp_filename = HOSTS_CSV + ".tmp"
    # 'Site' identifica la sede multi-sede (default 'central'); 'extrasaction=ignore'
    # tollera dizionari con chiavi extra (retrocompatibilità).
    _fieldnames = ['IP', 'Vendor', 'Profile', 'Username', 'Password', 'Enable Secret', 'Group', 'Hostname', 'Site']
    try:
        with open(temp_filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=_fieldnames, extrasaction='ignore')
            writer.writeheader()
            for d in devices:
                writer.writerow(d)
        try:
            os.replace(temp_filename, HOSTS_CSV)
        except PermissionError:
            # Fallback per sistemi Windows
            with open(HOSTS_CSV, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=_fieldnames, extrasaction='ignore')
                writer.writeheader()
                for d in devices:
                    writer.writerow(d)
            if os.path.exists(temp_filename):
                try:
                    os.remove(temp_filename)
                except:
                    pass
    except Exception as e:
        if os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
            except:
                pass
        raise e

def get_all_devices():
    devices = []
    if not os.path.exists(HOSTS_CSV):
        return devices
    with open(HOSTS_CSV, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Inventari legacy senza colonna 'Site': default alla sede centrale.
            if not row.get('Site'):
                row['Site'] = 'central'
            devices.append(row)
    return devices

def add_or_update_device(ip, vendor, profile, username, password, enable_secret, group, site=None):
    # Validazione IP robusta
    match = IP_PATTERN.match(ip)
    if not match or not all(0 <= int(octet) <= 255 for octet in match.groups()):
        raise ValueError(f"IP non valido: {ip}")

    enc_password = crypto_vault.encrypt_password(password)
    enc_secret = crypto_vault.encrypt_password(enable_secret)

    with _io_lock:
        devices = get_all_devices()
        # Preserva l'hostname già rilevato sul dispositivo esistente
        existing = next((d for d in devices if d['IP'] == ip), None)
        existing_hostname = existing.get('Hostname') if existing else None
        # Preserva la sede esistente se non ne viene indicata una nuova.
        resolved_site = site or (existing.get('Site') if existing else None) or 'central'
        devices = [d for d in devices if d['IP'] != ip]

        new_device = {
            'IP': ip, 'Vendor': vendor.lower(), 'Profile': profile,
            'Username': username, 'Password': enc_password, 'Enable Secret': enc_secret,
            'Group': group if group in get_all_groups() else 'Generale',
            'Site': resolved_site,
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

# --- VENDORS REGISTRY ---

def get_all_vendors() -> dict:
    """Returns {display_name: {euvd_term: str, driver: str|None}}"""
    defaults = {
        "cisco":   {"euvd_term": "cisco",                    "driver": "cisco_ios"},
        "cisco_cbs":{"euvd_term": "cisco",                   "driver": "cisco_s300"},
        "hpe":     {"euvd_term": "hewlett packard enterprise","driver": "hp_procurve"},
        "juniper": {"euvd_term": "juniper networks",          "driver": "juniper_junos"},
        "aruba":   {"euvd_term": "aruba networks",            "driver": "aruba_os"},
        "fortinet":{"euvd_term": "fortinet",                  "driver": "fortinet"},
        "paloalto":{"euvd_term": "palo alto networks",        "driver": "paloalto_panos"},
    }
    if not os.path.exists(VENDORS_FILE):
        safe_json_write(VENDORS_FILE, defaults)
        return defaults
    try:
        with open(VENDORS_FILE, "r") as f:
            stored = json.load(f)
        # I vendor di sistema sono sempre disponibili (lo stored ha la precedenza),
        # così driver come 'cisco_s300' (CBS) restano selezionabili.
        return {**defaults, **stored}
    except Exception:
        return defaults

def save_vendors(vendors: dict):
    safe_json_write(VENDORS_FILE, vendors)

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
    "pc":       "PC / Workstation",
    "other":    "Altro",
}

def _norm_cat_key(key: str) -> str:
    return re.sub(r'[^a-z0-9_-]', '', (key or '').strip().lower().replace(' ', '-'))

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

def set_device_category(node_id: str, category: str, subcategory: str = "") -> bool:
    """Assegna manualmente un dispositivo (per id-nodo) a una categoria.
    Categoria vuota = rimuove l'assegnazione (torna alla classificazione auto)."""
    node_id = (node_id or '').strip()
    if not node_id:
        return False
    with _io_lock:
        data = _load_categories()
        if not category:
            data["assignments"].pop(node_id, None)
        else:
            cat = _norm_cat_key(category)
            valid = set(BUILTIN_CATEGORIES) | set(data["categories"])
            if cat not in valid:
                return False
            data["assignments"][node_id] = {
                "category": cat,
                "subcategory": subcategory.strip(),
            }
        safe_json_write(CATEGORIES_FILE, data)
        return True

_META_FIELDS = ("category", "subcategory", "vendor", "model", "ha_group", "name", "ver")

def migrate_assignment(old_id: str, new_id: str):
    """Sposta l'assegnazione manuale da un id-nodo a un altro (es. quando un
    dispositivo scoperto viene promosso a gestito e cambia id in IP)."""
    with _io_lock:
        data = _load_categories()
        a = data["assignments"].pop(old_id, None)
        if a:
            data["assignments"][new_id] = a
            safe_json_write(CATEGORIES_FILE, data)

def set_device_meta(node_id: str, **fields) -> bool:
    """Aggiorna in modo incrementale gli attributi manuali di un dispositivo
    (category/subcategory/vendor/model). Stringa vuota = rimuove quel campo.
    category='' riporta il dispositivo alla classificazione automatica."""
    node_id = (node_id or '').strip()
    if not node_id:
        return False
    provided = {k: v for k, v in fields.items() if k in _META_FIELDS and v is not None}
    if not provided:
        return False
    with _io_lock:
        data = _load_categories()
        entry = dict(data["assignments"].get(node_id, {}))
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
            data["assignments"][node_id] = entry
        else:
            data["assignments"].pop(node_id, None)
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
        except Exception:
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

def resolve_euvd_term(vendor_display: str) -> str:
    """Maps a vendor display name to the correct EUVD search term."""
    vendors = get_all_vendors()
    key = vendor_display.strip().lower()
    if key in vendors:
        return vendors[key].get("euvd_term", key)
    for k, v in vendors.items():
        if k in key or key in k:
            return v.get("euvd_term", key)
    return key

# --- UTILITIES PER RILEVAMENTO VERSIONI (Richieste dal Core Engine e Server) ---

def _clean_version(v):
    """Normalizza una versione: tiene solo il primo token della prima riga, così
    valori storici sporchi (es. '17.03.03\\nCisco IOS Software [Amsterdam]')
    diventano '17.03.03'. Conserva parentesi/lettere ('15.2(4)E7')."""
    if not v or not isinstance(v, str):
        return v
    first = v.splitlines()[0].strip()
    m = re.match(r'^([\w().\-/]+)', first)
    return m.group(1) if m else first

def get_detected_versions():
    if os.path.exists(VERSION_DATA_FILE):
        try:
            with open(VERSION_DATA_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for info in data.values():
                if isinstance(info, dict) and info.get('version'):
                    info['version'] = _clean_version(info['version'])
            return data
        except:
            return {}
    return {}

def update_version_inventory(ip, vendor, version, status="online"):
    with _io_lock:
        data = get_detected_versions()
        data[ip] = {"vendor": vendor, "version": version, "status": status}
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
