# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Demo mode keeps every packet on this machine.

The demo workspace holds synthetic devices whose addresses may well exist on
the network the app runs in. Guarding each route that can reach a device would
be a list nobody keeps complete, so the guard sits where every one of them
ends up:

- ``install()`` wraps ``socket.socket.connect/connect_ex/sendto`` and
  ``socket.getaddrinfo``: SSH (paramiko/netmiko), REST (requests/urllib),
  SMTP, NVD/KEV feeds, webhooks. Only loopback passes.
- ``refuse()`` is called by the few paths that leave the process without a
  Python socket: the ICMP ``ping``/``traceroute`` subprocesses and pysnmp,
  whose asyncio UDP transport on Windows (proactor) bypasses the socket class.
- ``BLOCKED_ROUTES`` answers 409 up front for the operations that start a
  background job, where the error above would only surface inside the job.
"""
import fnmatch
import ipaddress
import socket

from core import data_config

MESSAGE = ("Demo mode: SentinelNet is running on synthetic data and does not "
           "contact any device or network.")


class DemoModeError(ConnectionRefusedError):
    """An OSError on purpose: code that already handles an unreachable device
    treats the demo the same way instead of crashing."""


def refuse() -> None:
    if data_config.DEMO_MODE:
        raise DemoModeError(MESSAGE)


def _local(host) -> bool:
    if host is None or host == "localhost":
        return True
    try:
        return ipaddress.ip_address(str(host).split("%")[0]).is_loopback
    except ValueError:
        return False


def _address_ok(address) -> bool:
    # AF_UNIX paths and other non-tuple addresses never leave the machine.
    return not isinstance(address, tuple) or _local(address[0])


def install() -> None:
    """Idempotent. Checks DEMO_MODE at call time, so installing is harmless."""
    if getattr(socket.socket, "_demo_guard", False):
        return
    for name in ("connect", "connect_ex"):
        orig = getattr(socket.socket, name)

        def guarded(self, address, _orig=orig):
            if data_config.DEMO_MODE and not _address_ok(address):
                raise DemoModeError(MESSAGE)
            return _orig(self, address)
        setattr(socket.socket, name, guarded)

    orig_sendto = socket.socket.sendto

    def sendto(self, data, *args):
        if data_config.DEMO_MODE and args and not _address_ok(args[-1]):
            raise DemoModeError(MESSAGE)
        return orig_sendto(self, data, *args)
    setattr(socket.socket, "sendto", sendto)

    orig_gai = socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):
        # A hostname is refused before it costs a DNS query; an IP literal
        # resolves locally and meets the connect check above.
        if data_config.DEMO_MODE and not _local(host):
            try:
                ipaddress.ip_address(str(host).split("%")[0])
            except ValueError:
                raise DemoModeError(MESSAGE) from None
        return orig_gai(host, *args, **kwargs)
    socket.getaddrinfo = getaddrinfo
    setattr(socket.socket, "_demo_guard", True)


# (method, fnmatch pattern; ``*`` also spans "/") of the operations that
# contact devices from a background job or a long-running request. Everything
# else that tries is stopped by the socket guard.
BLOCKED_ROUTES = (
    ("POST", "/api/scan-subnet"), ("POST", "/api/scan-verify"),
    ("POST", "/api/run-triage"), ("POST", "/api/triage/[0-9]*"),
    ("POST", "/api/triage/schedules/*/run"),
    ("POST", "/api/bulk-command"), ("POST", "/api/send-command"),
    ("POST", "/api/verify-device"), ("POST", "/api/ping-check"),
    ("POST", "/api/arp/scan"), ("POST", "/api/mac/scan"),
    ("POST", "/api/mac/port-control"),
    ("POST", "/api/provisioner/push-*"),
    ("POST", "/api/probes"), ("POST", "/api/probes/test-bastion*"),
    ("POST", "/api/probes/*/agent/*"), ("POST", "/api/probes/*/command"),
    ("POST", "/api/diagnose/*"), ("POST", "/api/interface-errors/read"),
    ("POST", "/api/routes/trace/probe"), ("POST", "/api/observability/api-poll"),
    ("POST", "/api/firewall-traffic/snapshot"),
    ("POST", "/api/fortigate/*"), ("DELETE", "/api/fortigate/*"),
    ("PUT", "/api/fortigate/*"),
    ("POST", "/api/cve/ot/sync"), ("POST", "/api/cve/*/refresh"),
    ("POST", "/api/cloud-backup/run"), ("POST", "/api/cloud-backup/test"),
    ("POST", "/api/settings/smtp/test"), ("POST", "/api/settings/update"),
    ("POST", "/api/notifications/*/test"),
)


def blocked(method: str, path: str) -> bool:
    return data_config.DEMO_MODE and any(
        method == m and fnmatch.fnmatchcase(path, p) for m, p in BLOCKED_ROUTES)
