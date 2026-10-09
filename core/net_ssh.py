# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""netmiko entry point that is aware of jump (bastion) sites.

Import ConnectHandler from here instead of from netmiko. For a device that
belongs to a site in 'jump' mode the connection is tunnelled through one SSH
session to the bastion: paramiko opens a 'direct-tcpip' channel towards the
device and netmiko drives that channel through its own sock= parameter. For
every other device this is netmiko unchanged.

One transport is kept per site and reused by all its devices; a dead transport
is rebuilt on the next call.

Locking is per-probe, not global: a black-holed bastion (firewall silently
dropping SYN, or accepting the TCP connection but never speaking SSH) must
only stall the threads dialling THAT site, not every jump-mode connection in
the process. The registry lock below only ever guards a dict lookup, never
network I/O, so it is held for microseconds.
"""
import base64
import hashlib
import logging
import os
import socket
import threading
import time

import functools

import paramiko
import netmiko
from core import ssh_legacy
from netmiko.base_connection import BaseConnection
from opentelemetry import trace

logger = logging.getLogger("sentinelnet.ssh")
_tracer = trace.get_tracer("sentinelnet.ssh")


def _traced_command(method):
    """One ssh.command span per CLI call, on every netmiko connection.

    Patched on the base class rather than per call site: commands are sent
    from 20-odd modules and every driver, and a class-level wrapper leaves the
    MagicMock connections of the tests untouched. Without an OTLP endpoint the
    tracer is the no-op one and this costs a function call.

    Only the first three words of a command are recorded: enough to tell
    "show running-config" from "show mac address-table", short of a custom
    command that carries a secret. Config sets record their line count only."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        first = args[0] if args else (kwargs.get("command_string")
                                      or kwargs.get("config_commands"))
        attrs = {"server.address": str(getattr(self, "host", "") or ""),
                 "netmiko.method": method.__name__,
                 "netmiko.device_type": str(getattr(self, "device_type", "") or "")}
        if method.__name__ == "send_config_set":
            if isinstance(first, (list, tuple)):
                attrs["cli.lines"] = len(first)
        elif isinstance(first, str):
            attrs["cli.command"] = " ".join(first.split()[:3])
        with _tracer.start_as_current_span("ssh.command", attributes=attrs):
            return method(self, *args, **kwargs)
    return wrapper


for _name in ("send_command", "send_command_timing", "send_config_set"):
    setattr(BaseConnection, _name, _traced_command(getattr(BaseConnection, _name)))

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
_probe_locks: "dict[str, threading.Lock]" = {}
_registry_lock = threading.Lock()  # guards _probe_locks/_transports lookups only, never I/O


def _lock_for(probe_id: str) -> threading.Lock:
    """Return the per-probe lock, creating it if needed. Two different sites
    never wait on each other here; two threads for the same site do."""
    with _registry_lock:
        lock = _probe_locks.get(probe_id)
        if lock is None:
            lock = threading.Lock()
            _probe_locks[probe_id] = lock
        return lock


class BastionHostKeyError(Exception):
    """The bastion presented a different host key than the one we pinned.

    Either the bastion was rebuilt or someone is sitting on the path. Both
    need a human: the fix is to delete the stale line from ssh_known_hosts,
    never to reconnect anyway.
    """


class DeviceHostKeyError(Exception):
    """A DEVICE presented a different SSH host key than the one recorded.

    Same class of event as the bastion: either the device was reimaged or
    someone is on the path. The stale line in ssh_known_hosts must be
    removed by a human, never automatically.
    """


def _known_hosts_path(scope: "str | None" = None) -> str:
    """The same known_hosts the WS terminal pins to, created if missing.

    paramiko.HostKeys.save() does not create the parent file's directory tree
    but does need the file to exist to be re-read; the terminal path in
    routers/commands.py bootstraps it the same way.
    """
    from core import data_config
    path = data_config.get_path("ssh_known_hosts")
    if scope:
        # Devices behind a bastion get their own file, one per bastion.
        # Two tenants may legitimately run the same private IP behind two
        # different bastions; a single file keyed by bare IP would make the
        # second one look like a key change (and paramiko rejects on the
        # name it loads, so scoping our own bookkeeping alone is not enough).
        path += "." + "".join(c if c.isalnum() or c in "-_." else "_"
                              for c in scope)
    if not os.path.exists(path):
        open(path, "a").close()
    return path


def _host_key_id(host: str, port: int) -> str:
    """known_hosts entry name: bare host on 22, '[host]:port' otherwise —
    the OpenSSH convention paramiko's SSHClient also writes."""
    return host if port == 22 else f"[{host}]:{port}"


def _load_host_keys(scope: "str | None" = None) -> paramiko.HostKeys:
    """HostKeys from the shared file; a corrupt file must not crash every
    SSH connection in the app. It degrades to 'no pin' with a loud error
    instead — the alternative, a hard failure, would take down collection,
    backups and terminals together."""
    try:
        return paramiko.HostKeys(_known_hosts_path(scope))
    except Exception as e:
        logger.error("ssh_known_hosts illeggibile (%s): i pin esistenti sono "
                     "ignorati finche' il file non viene riparato.", e)
        return paramiko.HostKeys()


def _pinned_host_key(host: str, port: int, scope: "str | None" = None):
    """The key pinned for this host, or None on first contact."""
    entry = _load_host_keys(scope).lookup(_host_key_id(host, port))
    if not entry:
        return None
    return next(iter(entry.values()))


def _pin_host_key(host: str, port: int, key, scope: "str | None" = None) -> None:
    """Trust on first use: record the key so a later change is detectable."""
    path = _known_hosts_path(scope)
    keys = _load_host_keys(scope)
    keys.add(_host_key_id(host, port), key.get_name(), key)
    keys.save(path)


def _dial(probe: dict, pin: bool = True) -> paramiko.Transport:
    """Open and authenticate one transport to the site's bastion. No caching.

    pin=False is the site wizard's draft test: the key is shown to the
    operator first and pinned only by pin_confirmed().
    """
    from security import identity_manager
    probe_id = probe["id"]
    creds = identity_manager.get_identity_credentials(probe["jump_identity"])
    if not creds:
        raise ValueError(f"Identita' {probe['jump_identity']} non trovata.")
    username, password = creds[0], creds[1]
    host = probe["jump_host"]
    port = int(probe.get("jump_port") or 22)
    sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    # Trust on first use, like the WS terminal: paramiko.Transport has no
    # policy hook, so the pinned key is handed to connect() (which then
    # refuses any other) and a first contact is recorded afterwards. Without
    # it every reconnection silently re-accepts whatever key answers, so a
    # MITM on the hop to the bastion leaves no trace — and every device
    # behind it is reached through that hop.
    pinned = _pinned_host_key(host, port)
    tr = None
    try:
        tr = paramiko.Transport(sock)
        tr.banner_timeout = BANNER_TIMEOUT
        tr.connect(username=username, password=password, hostkey=pinned)
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
                f"Il bastione {host} della sede "
                f"'{probe_id}' ha rifiutato l'utente '{username}': "
                f"credenziali del bastione, non del dispositivo.") from e
        if pinned is not None and isinstance(e, paramiko.SSHException) and                 "host key" in str(e).lower():
            raise BastionHostKeyError(
                f"Il bastione {host} della sede '{probe_id}' presenta una "
                f"chiave host diversa da quella registrata. Se il bastione e' "
                f"stato reinstallato, rimuovere la riga "
                f"'{_host_key_id(host, port)}' da ssh_known_hosts; "
                f"altrimenti la tratta non e' fidata.") from e
        raise
    if pinned is None and pin:
        _pin_host_key(host, port, tr.get_remote_server_key())
    return tr


def _transport(probe: dict) -> paramiko.Transport:
    """Return a live SSH transport to the site's bastion, opening it if needed."""
    probe_id = probe["id"]
    with _lock_for(probe_id):
        tr = _transports.get(probe_id)
        if tr is not None and tr.is_active():
            return tr
        try:
            tr = _dial(probe)
        except Exception:
            _transports.pop(probe_id, None)
            raise
        _transports[probe_id] = tr
        return tr


def invalidate_probe(probe_id: str) -> None:
    """Drop the cached transport for a site so the next call re-authenticates.

    One transport per site is kept and reused. It was opened with the bastion
    credentials as they were at dial time and stays usable afterwards, so
    editing the identity changed nothing for a site that already had a live
    session: the old login kept working until the transport happened to die.
    Called whenever the bastion address, port or identity is edited.
    """
    with _lock_for(probe_id):
        tr = _transports.pop(probe_id, None)
    if tr is not None:
        try:
            tr.close()
        except Exception:
            # Already dead. The point was to stop reusing it, and it is out of
            # the registry either way.
            pass


def probe_bastion(probe: dict) -> str:
    """Dial the bastion with the site's current identity and hang up.

    Deliberately does NOT go through _transport: the point is to test the
    credential as configured now, and a cached transport opened with the
    previous one would answer 'fine'. Returns the host key fingerprint.
    Raises BastionAuthError on a refused login, or the underlying socket/SSH
    error otherwise.
    """
    tr = _dial(probe)
    try:
        return fingerprint(tr.get_remote_server_key())
    finally:
        tr.close()


# Keys seen by a draft probe, waiting for the operator to confirm them.
# ponytail: in-process dict — a restart forgets pending confirmations, and
# the wizard then answers "test again", which is the safe direction.
PROBE_TTL = 600
_probed_keys: dict = {}


def fingerprint(key) -> str:
    """OpenSSH SHA256 fingerprint, the form `ssh-keygen -lf` prints."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def probe_bastion_draft(host: str, port: int, identity: str) -> dict:
    """Test an unsaved bastion. Pins nothing: the key waits in _probed_keys
    until the operator confirms its fingerprint (pin_confirmed)."""
    port = int(port)
    known = _pinned_host_key(host, port) is not None
    tr = _dial({"id": "(draft)", "jump_host": host, "jump_port": port,
                "jump_identity": identity}, pin=False)
    try:
        key = tr.get_remote_server_key()
    finally:
        tr.close()
    _probed_keys[(host, port)] = (key, time.time())
    return {"fingerprint": fingerprint(key), "key_type": key.get_name(), "known": known}


def pin_confirmed(host: str, port: int, fp: str) -> bool:
    """Pin the key a draft probe saw for (host, port) if fp is its fingerprint.

    The browser never sends key material: it sends back the fingerprint the
    operator confirmed, and this checks it against what the server saw.
    """
    port = int(port)
    entry = _probed_keys.get((host, port))
    if not entry or time.time() - entry[1] > PROBE_TTL:
        return False
    key = entry[0]
    if fingerprint(key) != fp:
        return False
    _pin_host_key(host, port, key)
    _probed_keys.pop((host, port), None)
    return True


def _netmiko_connect(**params):
    """Call netmiko.ConnectHandler at runtime to support test patching.

    netmiko.ConnectHandler must be looked up at call time, not at import time,
    so that tests patching netmiko.ConnectHandler globally can intercept the
    call. If this were an import-time alias (from netmiko import ConnectHandler
    as _netmiko_connect), the patch would not affect this module's already-bound
    reference, and SSH connection tests would attempt real connections."""
    return netmiko.ConnectHandler(**params)


def _device_ssh_params(params: dict, scope: "str | None" = None) -> dict:
    """Load the shared known_hosts into device sessions.

    Device SSH was the unpersisted TOFU link (app review P0-6): netmiko's
    default policy accepted whatever key answered, in memory only. With the
    known_hosts loaded, a pinned key that differs from the one presented
    fails the connection instead of being silently replaced."""
    if params.get("alt_host_keys") or params.get("ssh_strict"):
        return params
    params = dict(params)
    params["alt_host_keys"] = True
    params["alt_key_file"] = _known_hosts_path(scope)
    return params


def _raise_if_host_key_error(exc: Exception, host: str, port: int) -> None:
    """Translate a host-key mismatch (plain or vendor-wrapped) into the
    typed error an operator can act on."""
    if isinstance(exc, paramiko.BadHostKeyException) or \
            "host key" in str(exc).lower():
        raise DeviceHostKeyError(
            f"Il dispositivo {_host_key_id(host, port)} presenta una chiave "
            f"host SSH diversa da quella registrata in ssh_known_hosts. Se il "
            f"dispositivo e' stato reinstallato, rimuovere quella riga dal "
            f"file; altrimenti la tratta non e' fidata.") from exc


def _persist_device_key(host: "str | None", port: int, conn,
                        scope: "str | None" = None) -> None:
    """TOFU for device sessions: record the key on first use so a later
    change is detected. A session that yields no key is simply not pinned."""
    if not host or _pinned_host_key(host, port, scope) is not None:
        return
    try:
        key = conn.remote_conn.get_transport().get_remote_server_key()
    except Exception:
        return
    # Only a real key gets pinned: anything else (mocks, odd transports)
    # would write a line that poisons every later read of the file.
    if not isinstance(key, paramiko.pkey.PKey):
        return
    try:
        _pin_host_key(host, port, key, scope)
    except Exception:
        return
    from security.security_manager import log_audit
    log_audit(f"SSH: chiave host del dispositivo '{_host_key_id(host, port)}' "
              f"registrata al primo uso (TOFU).")


def jump_channel(probe: dict, host: str, port: int) -> paramiko.Channel:
    """Open a direct-tcpip channel from the bastion to host:port."""
    return _transport(probe).open_channel(
        "direct-tcpip", (host, int(port)), ("127.0.0.1", 0))


def bastion_probe_for(host: str, tenant: "str | None" = None):
    """Return the jump site owning this device IP, or None.

    get_device_by_ip's cache entry carries "probe" (lowercase — see
    services/inventory_manager.py:get_device_by_ip), not the raw CSV row's
    "Probe" column. The collision sentinel {"collision": True} has no "probe"
    key, so a duplicated IP without tenant falls through here to a direct connection
    rather than risking a tunnel to the wrong customer.
    """
    from services import inventory_manager, probe_manager
    device = inventory_manager.get_device_by_ip(host, tenant=tenant)
    if not device:
        return None
    probe = probe_manager.get_probe(device.get("probe") or "")
    return probe if probe and probe.get("mode") == "jump" else None


def ConnectHandler(probe_id: "str | None" = None, tenant: "str | None" = None, **params):
    """netmiko.ConnectHandler, tunnelled when the device sits behind a bastion.

    probe_id names the probe explicitly, for callers whose target is not in the
    inventory yet (day-0 provisioning): the default path is still the
    inventory lookup, and probe_id is only consulted when that finds nothing.

    The whole dial is one ssh.connect span: handshake, authentication and
    netmiko's prompt discovery, which is where a slow device spends its time.
    A failure is recorded on the span with its exception type.
    """
    attrs = {"server.address": str(params.get("host") or params.get("ip") or ""),
             "server.port": int(params.get("port") or 22),
             "netmiko.device_type": str(params.get("device_type") or "")}
    with _tracer.start_as_current_span("ssh.connect", attributes=attrs):
        return _connect(probe_id, tenant, **params)


def _connect(probe_id: "str | None", tenant: "str | None", **params):
    host = params.get("host") or params.get("ip")
    probe = bastion_probe_for(host, tenant=tenant) if host else None
    if probe is None and probe_id:
        from services import probe_manager
        candidate = probe_manager.get_probe(probe_id)
        probe = candidate if candidate and candidate.get("mode") == "jump" else None
    if probe:
        trace.get_current_span().set_attribute("sentinelnet.bastion_probe",
                                               str(probe.get("id") or ""))
    port = int(params.get("port") or 22)
    # Host keys of devices behind a bastion are pinned in that bastion's own
    # file: private IPs are only unique within their site.
    scope = (_host_key_id(probe.get("jump_host") or "", int(probe.get("jump_port") or 22))
             if probe else None)
    if host:
        params = _device_ssh_params(params, scope)
    caller_disabled = params.pop("disabled_algorithms", None)
    if not (host and probe):
        def direct(extra):
            return _netmiko_connect(
                **params, **_disabled_kw(ssh_legacy.merged(caller_disabled, extra)))
        try:
            conn = ssh_legacy.with_fallback(direct, host or "")
        except Exception as e:
            if host and _pinned_host_key(host, port) is not None:
                _raise_if_host_key_error(e, host, port)
            raise
        _persist_device_key(host, port, conn)
        return conn

    def tunnelled(extra):
        # One channel per attempt: a refused handshake leaves its channel
        # unusable, so the fallback cannot reuse it.
        chan = jump_channel(probe, host, port)
        try:
            return _netmiko_connect(
                sock=chan, **params, **_disabled_kw(ssh_legacy.merged(caller_disabled, extra)))
        except Exception:
            # The channel lives on the shared, long-lived per-probe transport, so
            # nothing reclaims it on failure: `with ConnectHandler(...)` at the
            # call sites cannot help, because the context manager never binds
            # when the constructor raises. Without this, a site polled on a
            # schedule with wrong credentials piles channels onto the transport
            # until the process restarts. Same leak class as the bastion socket
            # in _transport, one layer up.
            chan.close()
            raise
    try:
        conn = ssh_legacy.with_fallback(tunnelled, host)
    except Exception as e:
        if _pinned_host_key(host, port, scope) is not None:
            _raise_if_host_key_error(e, host, port)
        raise
    _persist_device_key(host, port, conn, scope)
    return conn


def _disabled_kw(disabled: "dict | None") -> dict:
    """netmiko kwarg only when there is something to disable."""
    return {"disabled_algorithms": disabled} if disabled else {}


def close_all() -> None:
    """Close every cached bastion transport (application shutdown)."""
    with _registry_lock:
        transports = list(_transports.values())
        _transports.clear()
    for tr in transports:
        tr.close()
