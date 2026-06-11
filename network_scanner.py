import ipaddress
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import crypto_vault
import inventory_manager
from core_engine import is_reachable, run_backup_and_triage


def parse_network(address: str) -> list[str]:
    """
    Accepts any of:
      "192.168.1.0/24"
      "192.168.1.0/255.255.255.0"
      "192.168.1.0 255.255.255.0"
    Returns all usable host IPs (network address and broadcast excluded).
    Raises ValueError with a human-readable message on invalid input.
    """
    address = address.strip()

    if ' ' in address and '/' not in address:
        parts = address.split()
        if len(parts) != 2:
            raise ValueError(
                f"Formato non valido: '{address}'. "
                "Atteso: 'IP/PREFIX', 'IP/MASK', oppure 'IP MASK'."
            )
        address = f"{parts[0]}/{parts[1]}"

    try:
        network = ipaddress.IPv4Network(address, strict=False)
    except ValueError as exc:
        raise ValueError(
            f"Indirizzo di rete non valido '{address}': {exc}"
        ) from exc

    return [str(ip) for ip in network.hosts()]


def _ping(ip: str) -> bool:
    if sys.platform == 'win32':
        cmd = ['ping', '-n', '1', '-w', '1000', ip]
    else:
        cmd = ['ping', '-c1', '-W1', ip]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_subnet(
    address: str,
    vendor_hint: str,
    credentials: dict,
    max_workers: int = 50,
    progress_cb=None,
) -> list[dict]:
    """
    1. parse_network() to enumerate host IPs.
    2. Ping all hosts concurrently; collect alive set.
    3. For each alive IP: check port 22, then run run_backup_and_triage().
    4. Return list of dicts with keys:
         ip, reachable, ssh_ok, hostname, vendor, added.

    credentials must contain: username, password, secret (plain text).
    progress_cb, if given, is called with the number of hosts pinged so far.
    """
    hosts = parse_network(address)

    # Phase 1 — concurrent ping
    alive: set[str] = set()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        ping_futures = {pool.submit(_ping, ip): ip for ip in hosts}
        done = 0
        for fut in as_completed(ping_futures):
            done += 1
            if fut.result():
                alive.add(ping_futures[fut])
            if progress_cb:
                progress_cb(done)

    # Seed result table for every host
    results: dict[str, dict] = {
        ip: {
            "ip":        ip,
            "reachable": ip in alive,
            "ssh_ok":    False,
            "hostname":  None,
            "vendor":    vendor_hint,
            "added":     False,
        }
        for ip in hosts
    }

    if not alive:
        return list(results.values())

    # Pre-encrypt once; get_device_credentials() calls decrypt_password internally
    enc_password = crypto_vault.encrypt_password(credentials.get('password', ''))
    enc_secret   = crypto_vault.encrypt_password(credentials.get('secret', ''))

    def _triage(ip: str) -> tuple:
        if not is_reachable(ip, port=22):
            return ip, False, None, False

        device = {
            'IP':            ip,
            'Vendor':        vendor_hint,
            'Profile':       'custom',
            'Username':      credentials.get('username', ''),
            'Password':      enc_password,
            'Enable Secret': enc_secret,
            'Group':         'Discovered',
        }
        res      = run_backup_and_triage(device)
        hostname = res.get('hostname')
        return ip, True, hostname, False

    # Phase 2 — SSH + triage on alive hosts
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        triage_futures = {pool.submit(_triage, ip): ip for ip in alive}
        for fut in as_completed(triage_futures):
            ip, ssh_ok, hostname, added = fut.result()
            results[ip]['ssh_ok']   = ssh_ok
            results[ip]['hostname'] = hostname
            results[ip]['added']    = added

    # Phase 3 — optional inventory registration
    if credentials.get('auto_add'):
        existing_ips = {d['IP'] for d in inventory_manager.get_all_devices()}
        for r in results.values():
            if not r['ssh_ok'] or r['ip'] in existing_ips:
                continue
            try:
                inventory_manager.add_or_update_device(
                    r['ip'],
                    vendor_hint,
                    'default',
                    credentials.get('username', ''),
                    credentials.get('password', ''),
                    credentials.get('secret', ''),
                    credentials.get('group', 'Discovered'),
                )
                if r.get('hostname'):
                    inventory_manager.update_device_hostname(r['ip'], r['hostname'])
                r['added'] = True
            except Exception:
                pass
    else:
        for r in results.values():
            r['added'] = False

    return list(results.values())
