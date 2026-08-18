# -*- coding: utf-8 -*-
"""netmiko entry point that is aware of jump (bastion) sites.

Import ConnectHandler from here instead of from netmiko. For a device that
belongs to a site in 'jump' mode the connection is tunnelled through one SSH
session to the bastion: paramiko opens a 'direct-tcpip' channel towards the
device and netmiko drives that channel through its own sock= parameter. For
every other device this is netmiko unchanged.

One transport is kept per site and reused by all its devices; a dead transport
is rebuilt on the next call.
"""
import threading

import paramiko
from netmiko import ConnectHandler as _netmiko_connect

_transports: "dict[str, paramiko.Transport]" = {}
_lock = threading.Lock()


def _transport(site: dict) -> paramiko.Transport:
    """Return a live SSH transport to the site's bastion, opening it if needed."""
    from security import identity_manager
    site_id = site["id"]
    with _lock:
        tr = _transports.get(site_id)
        if tr is not None and tr.is_active():
            return tr
        creds = identity_manager.get_identity_credentials(site["jump_identity"])
        if not creds:
            raise ValueError(f"Identita' {site['jump_identity']} non trovata.")
        username, password = creds[0], creds[1]
        tr = paramiko.Transport((site["jump_host"], int(site.get("jump_port") or 22)))
        tr.connect(username=username, password=password)
        _transports[site_id] = tr
        return tr


def jump_channel(site: dict, host: str, port: int) -> paramiko.Channel:
    """Open a direct-tcpip channel from the bastion to host:port."""
    return _transport(site).open_channel(
        "direct-tcpip", (host, int(port)), ("127.0.0.1", 0))


def _jump_site_for(host: str):
    """Return the jump site owning this device IP, or None."""
    from services import inventory_manager, site_manager
    device = inventory_manager.get_device_by_ip(host)
    if not device:
        return None
    site = site_manager.get_site(device.get("Site") or "")
    return site if site and site.get("mode") == "jump" else None


def ConnectHandler(**params):
    """netmiko.ConnectHandler, tunnelled when the device sits behind a bastion."""
    host = params.get("host") or params.get("ip")
    site = _jump_site_for(host) if host else None
    if host and site:
        params["sock"] = jump_channel(site, host, int(params.get("port") or 22))
    return _netmiko_connect(**params)


def close_all() -> None:
    """Close every cached bastion transport (application shutdown)."""
    with _lock:
        for tr in _transports.values():
            tr.close()
        _transports.clear()
