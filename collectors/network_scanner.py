import ipaddress
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from security import crypto_vault
from core.core_engine import is_reachable, probe_device


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
    progress_cb, if given, is called as cb(done, total) for every completed
    unit of work. The triage of phase 2 is far slower than the ping of phase 1
    and counts too: stopping at the end of the ping leaves the caller pinned at
    100% for the whole scan.
    """
    hosts = parse_network(address)

    # Phase 1 — concurrent ping
    alive: set[str] = set()
    done = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        ping_futures = {pool.submit(_ping, ip): ip for ip in hosts}
        for fut in as_completed(ping_futures):
            done += 1
            if fut.result():
                alive.add(ping_futures[fut])
            if progress_cb:
                progress_cb(done, len(hosts))

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
        res = probe_device(device)
        # La 22 aperta non e' una credenziale valida: ssh_ok segue l'esito del
        # login, altrimenti auto_add mette in inventario apparati inaccessibili.
        if res.get('status') != 'success':
            return ip, False, None, False
        return ip, True, res.get('hostname'), False

    # Phase 2 — SSH + triage on alive hosts
    total = len(hosts) + len(alive)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        triage_futures = {pool.submit(_triage, ip): ip for ip in alive}
        for fut in as_completed(triage_futures):
            ip, ssh_ok, hostname, added = fut.result()
            results[ip]['ssh_ok']   = ssh_ok
            results[ip]['hostname'] = hostname
            results[ip]['added']    = added
            done += 1
            if progress_cb:
                progress_cb(done, total)

    # La registrazione in inventario vive in routers/scan.py, unico chiamante,
    # che non passa mai 'auto_add' qui dentro: il ramo era morto e ingoiava in
    # silenzio i fallimenti di add_or_update_device.
    return list(results.values())
