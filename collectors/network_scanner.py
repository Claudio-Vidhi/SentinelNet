import ipaddress
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.core_engine import is_reachable


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
    ports: list[int],
    max_workers: int = 50,
    progress_cb=None,
) -> list[dict]:
    """Discovery only: no credentials, no login, no vendor guessing.

    1. parse_network() to enumerate host IPs.
    2. For every host concurrently: ping, then a TCP connect per requested port.
    3. Return the hosts that answered anything, sorted by IP:
         {"ip": str, "alive": bool, "open_ports": list[int]}

    A host that drops ICMP but has a port open still counts as found: firewalls
    that discard ping are the norm, so a ping pre-filter would hide real devices.

    ports is already validated by the caller (routers/scan.py); an empty list is
    a legitimate ping-only sweep.

    progress_cb, if given, is called as cb(done, len(hosts)) once per host.
    """
    hosts = parse_network(address)
    ports = list(ports)

    def _probe_host(ip: str) -> dict:
        alive = _ping(ip)
        # timeout=1 explicitly: is_reachable defaults to 2s, and this runs
        # len(hosts) * len(ports) times.
        open_ports = [p for p in ports if is_reachable(ip, p, timeout=1)]
        return {"ip": ip, "alive": alive, "open_ports": open_ports}

    found: list[dict] = []
    done = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_probe_host, ip) for ip in hosts]
        for fut in as_completed(futures):
            row = fut.result()
            done += 1
            if progress_cb:
                progress_cb(done, len(hosts))
            if row["alive"] or row["open_ports"]:
                found.append(row)

    # as_completed yields in completion order; the table must not reshuffle.
    found.sort(key=lambda r: ipaddress.IPv4Address(r["ip"]))
    return found
