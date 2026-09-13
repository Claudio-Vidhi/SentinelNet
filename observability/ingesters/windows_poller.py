# -*- coding: utf-8 -*-
"""Live CPU, memory and disk for managed Windows hosts, over SSH.

The sibling of ``linux_poller``, and driven by its loop: the same
``linux_poll_s`` interval polls both platforms, and the snapshot lands in the
same ``api_observations`` with ``kind='windows_health'``. ``DEVICE_LOAD_001``
reads ``cpu_pct``/``memory_pct``/``disk_pct`` from the ``metrics`` branch and
never learns which platform produced them.

WHY SSH AND NOT SNMP — the SNMP service on Windows is a deprecated optional
feature, while the OpenSSH server is already a prerequisite of the platform
(``drivers/windows.py``).

WHY RAW COUNTERS AND NOT PERCENTAGES — the output is localised, and so is the
decimal separator of a formatted number. The command prints integers only
(``LoadPercentage``, kilobytes, bytes) joined with '|', the same rule the
driver follows, and the percentages are computed here.
"""

import json
import logging

from drivers.windows import prepare_session, ps

logger = logging.getLogger("sentinelnet.obs.windows_poller")

_MAX_SUMMARY = 20_000

# One line: per-processor loads (comma-joined, one entry per socket) |
# TotalVisibleMemorySize KB | FreePhysicalMemory KB | system drive Size B |
# system drive FreeSpace B. The system drive comes from Win32_OperatingSystem,
# not from a hard-coded 'C:', and is compared inside a script block so the
# command needs no quote nested in a quote.
PROBE_COMMAND = ps(
    "$o = Get-CimInstance Win32_OperatingSystem; "
    "$l = (Get-CimInstance Win32_Processor | ForEach-Object "
    "{ [string]$_.LoadPercentage }) -join ','; "
    "$d = Get-CimInstance Win32_LogicalDisk | Where-Object "
    "{ $_.DeviceID -eq $o.SystemDrive }; "
    "'LOAD|' + $l + '|' + [string]$o.TotalVisibleMemorySize + '|' + "
    "[string]$o.FreePhysicalMemory + '|' + [string]$d.Size + '|' + "
    "[string]$d.FreeSpace")


def _int(value: str):
    value = (value or "").strip()
    return int(value) if value.isdigit() else None


def _used_pct(total, free):
    """Used share of ``total``; None when either side is missing."""
    if total is None or free is None or total <= 0 or free > total:
        return None
    return round((total - free) * 100.0 / total, 1)


def parse_health(output: str) -> dict:
    """Metrics from the ``LOAD|...`` line. A missing field is absent, not zero:
    a threshold rule reading zero would stay silent exactly where it is blind.
    """
    line = next((l.strip() for l in reversed((output or "").splitlines())
                 if l.strip().startswith("LOAD|")), "")
    fields = line.split("|")[1:]
    if len(fields) < 5:
        return {}
    loads = [v for v in (_int(p) for p in fields[0].split(",")) if v is not None]
    metrics = {
        "cpu_pct": round(sum(loads) / len(loads), 1) if loads else None,
        "memory_pct": _used_pct(_int(fields[1]), _int(fields[2])),
        "disk_pct": _used_pct(_int(fields[3]), _int(fields[4])),
    }
    return {k: v for k, v in metrics.items() if v is not None}


def poll_device(device: dict) -> list:
    """[(kind, summary_json)] for one host. Empty list when it does not answer."""
    from core.net_ssh import ConnectHandler
    from core import core_engine
    from services import site_manager

    ip = str(device.get("IP") or "")
    cli_kind, port = core_engine.get_cli_transport(device)
    # A jump-site host is reached only through the bastion tunnel (core.net_ssh).
    if site_manager.has_direct_path(device.get("Site")) and not core_engine.is_reachable(ip, port):
        return []
    username, password, _ = core_engine.get_device_credentials(device)
    try:
        with ConnectHandler(device_type=core_engine._cli_device_type("generic", cli_kind),
                            host=ip, port=port, username=username,
                            password=password, timeout=15, auth_timeout=10,
                            banner_timeout=10) as conn:
            prepare_session(conn)
            output = conn.send_command(PROBE_COMMAND, read_timeout=30)
    except Exception as e:
        logger.debug("Windows %s: poll failed (%s)", ip, e)
        return []

    metrics = parse_health(output if isinstance(output, str) else str(output or ""))
    if not metrics:
        return []
    text = json.dumps({"results": {}, "metrics": metrics}, ensure_ascii=False)
    return [("windows_health", text[:_MAX_SUMMARY])]
