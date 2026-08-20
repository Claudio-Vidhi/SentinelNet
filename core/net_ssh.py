# -*- coding: utf-8 -*-
"""netmiko entry point that is aware of jump (bastion) sites.

Import ConnectHandler from here instead of from netmiko. For a device that
belongs to a site in 'jump' mode the connection is tunnelled through one SSH
session to the bastion: paramiko opens a 'direct-tcpip' channel towards the
device and netmiko drives that channel through its own sock= parameter. For
every other device this is netmiko unchanged.

One transport is kept per site and reused by all its devices; a dead transport
is rebuilt on the next call.

Locking is per-site, not global: a black-holed bastion (firewall silently
dropping SYN, or accepting the TCP connection but never speaking SSH) must
only stall the threads dialling THAT site, not every jump-mode connection in
the process. The registry lock below only ever guards a dict lookup, never
network I/O, so it is held for microseconds.
"""
import socket
import threading

import paramiko
import netmiko

# Bounds on connecting to a bastion. Without them, paramiko.Transport handed a
# bare (host, port) tuple uses a blocking socket with no timeout, and a dead
# bastion (SYN black-holed, or TCP up but nothing ever speaks SSH) hangs the
# calling thread for the OS TCP retransmit ceiling — minutes.
CONNECT_TIMEOUT = 10  # seconds: raw TCP connect to the bastion
BANNER_TIMEOUT = 15   # seconds: SSH banner exchange once the socket is up

class BastionAuthError(Exception):
    """The BASTION refused our login — the device was never contacted.

    Without a distinct type both hops collapse into one paramiko
    AuthenticationException, and a wrong bastion password is reported as a
    device with bad credentials: the operator then rotates the credential on
    the wrong machine.
    """


_transports: "dict[str, paramiko.Transport]" = {}
_site_locks: "dict[str, threading.Lock]" = {}
_registry_lock = threading.Lock()  # guards _site_locks/_transports lookups only, never I/O


def _lock_for(site_id: str) -> threading.Lock:
    """Return the per-site lock, creating it if needed. Two different sites
    never wait on each other here; two threads for the same site do."""
    with _registry_lock:
        lock = _site_locks.get(site_id)
        if lock is None:
            lock = threading.Lock()
            _site_locks[site_id] = lock
        return lock


def _dial(site: dict) -> paramiko.Transport:
    """Open and authenticate one transport to the site's bastion. No caching."""
    from security import identity_manager
    site_id = site["id"]
    creds = identity_manager.get_identity_credentials(site["jump_identity"])
    if not creds:
        raise ValueError(f"Identita' {site['jump_identity']} non trovata.")
    username, password = creds[0], creds[1]
    sock = socket.create_connection(
        (site["jump_host"], int(site.get("jump_port") or 22)),
        timeout=CONNECT_TIMEOUT)
    tr = None
    try:
        tr = paramiko.Transport(sock)
        tr.banner_timeout = BANNER_TIMEOUT
        tr.connect(username=username, password=password)
    except Exception as e:
        # paramiko only owns/closes the socket when handed a (host, port)
        # tuple; handing it an already-open socket (needed for
        # CONNECT_TIMEOUT above) makes that socket ours to close on
        # failure. Without this, a site polled on a schedule with bad or
        # rotated bastion credentials leaks one fd (plus a half-started
        # Transport) per attempt until the process runs out of them.
        if tr is not None:
            tr.close()
        sock.close()
        if isinstance(e, paramiko.AuthenticationException):
            raise BastionAuthError(
                f"Il bastione {site['jump_host']} della sede "
                f"'{site_id}' ha rifiutato l'utente '{username}': "
                f"credenziali del bastione, non del dispositivo.") from e
        raise
    return tr


def _transport(site: dict) -> paramiko.Transport:
    """Return a live SSH transport to the site's bastion, opening it if needed."""
    site_id = site["id"]
    with _lock_for(site_id):
        tr = _transports.get(site_id)
        if tr is not None and tr.is_active():
            return tr
        try:
            tr = _dial(site)
        except Exception:
            _transports.pop(site_id, None)
            raise
        _transports[site_id] = tr
        return tr


def invalidate_site(site_id: str) -> None:
    """Drop the cached transport for a site so the next call re-authenticates.

    One transport per site is kept and reused. It was opened with the bastion
    credentials as they were at dial time and stays usable afterwards, so
    editing the identity changed nothing for a site that already had a live
    session: the old login kept working until the transport happened to die.
    Called whenever the bastion address, port or identity is edited.
    """
    with _lock_for(site_id):
        tr = _transports.pop(site_id, None)
    if tr is not None:
        try:
            tr.close()
        except Exception:
            # Already dead. The point was to stop reusing it, and it is out of
            # the registry either way.
            pass


def probe_bastion(site: dict) -> None:
    """Dial the bastion with the site's current identity and hang up.

    Deliberately does NOT go through _transport: the point is to test the
    credential as configured now, and a cached transport opened with the
    previous one would answer 'fine'. Raises BastionAuthError on a refused
    login, or the underlying socket/SSH error otherwise.
    """
    _dial(site).close()


def _netmiko_connect(**params):
    """Call netmiko.ConnectHandler at runtime to support test patching.

    netmiko.ConnectHandler must be looked up at call time, not at import time,
    so that tests patching netmiko.ConnectHandler globally can intercept the
    call. If this were an import-time alias (from netmiko import ConnectHandler
    as _netmiko_connect), the patch would not affect this module's already-bound
    reference, and SSH connection tests would attempt real connections."""
    return netmiko.ConnectHandler(**params)


def jump_channel(site: dict, host: str, port: int) -> paramiko.Channel:
    """Open a direct-tcpip channel from the bastion to host:port."""
    return _transport(site).open_channel(
        "direct-tcpip", (host, int(port)), ("127.0.0.1", 0))


def jump_site_for(host: str):
    """Return the jump site owning this device IP, or None.

    get_device_by_ip's cache entry carries "site" (lowercase — see
    services/inventory_manager.py:get_device_by_ip), not the raw CSV row's
    "Site" column. The collision sentinel {"collision": True} has no "site"
    key, so a duplicated IP falls through here to a direct connection rather
    than risking a tunnel to the wrong customer.
    """
    from services import inventory_manager, site_manager
    device = inventory_manager.get_device_by_ip(host)
    if not device:
        return None
    site = site_manager.get_site(device.get("site") or "")
    return site if site and site.get("mode") == "jump" else None


def ConnectHandler(site_id: "str | None" = None, **params):
    """netmiko.ConnectHandler, tunnelled when the device sits behind a bastion.

    site_id names the site explicitly, for callers whose target is not in the
    inventory yet (day-0 provisioning): the default path is still the
    inventory lookup, and site_id is only consulted when that finds nothing.
    """
    host = params.get("host") or params.get("ip")
    site = jump_site_for(host) if host else None
    if site is None and site_id:
        from services import site_manager
        candidate = site_manager.get_site(site_id)
        site = candidate if candidate and candidate.get("mode") == "jump" else None
    if not (host and site):
        return _netmiko_connect(**params)
    chan = jump_channel(site, host, int(params.get("port") or 22))
    try:
        return _netmiko_connect(sock=chan, **params)
    except Exception:
        # The channel lives on the shared, long-lived per-site transport, so
        # nothing reclaims it on failure: `with ConnectHandler(...)` at the
        # call sites cannot help, because the context manager never binds
        # when the constructor raises. Without this, a site polled on a
        # schedule with wrong credentials piles channels onto the transport
        # until the process restarts. Same leak class as the bastion socket
        # in _transport, one layer up.
        chan.close()
        raise


def close_all() -> None:
    """Close every cached bastion transport (application shutdown)."""
    with _registry_lock:
        transports = list(_transports.values())
        _transports.clear()
    for tr in transports:
        tr.close()
