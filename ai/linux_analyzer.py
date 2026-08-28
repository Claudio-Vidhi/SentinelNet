# -*- coding: utf-8 -*-
"""Linux backup artifact -> section envelope for the Config Analyzer.

Same shape as the firewall envelope (``fw_analyzers``): ``sections`` with
``columns``/``rows``, so the UI derives sub-pills from the data and does not
need to know anything about Linux.

WHY IT DOESN'T REUSE THE IOS PARSER — ``detect_config_type`` falls back to
``'ios'`` for every vendor it doesn't recognize. On a Linux host that fallback
isn't an approximation, it's a made-up result: the parser looks for VLANs, ACLs,
and interfaces inside ``/etc/fstab`` and the device card comes out as a switch
with no VLANs. Better one extra platform than a misdescribed device.

WHAT IT READS — the artifact written by ``drivers/linux.py`` plus the sections
the triage appends (``ip -br a``, ``ip route``, ``ss -tuln``, ``df -hT``,
``systemctl --failed``). The section splitting is already done by
``netsec_audit.linux_parser``: here we only interpret the content.

Tolerant like the other analyzers: no malformed line raises, a missing section
produces an empty table, not an error.
"""

import logging
import re
from typing import Any, Dict, List

from services.netsec_audit.linux_parser import (
    SSHD_EFFECTIVE, LinuxConfig, parse_linux)

logger = logging.getLogger(__name__)

# Artifact sections produced by the extra triage commands.
_S_HOSTNAME = "HOSTNAME"
_S_UNAME = "UNAME"
_S_UPTIME = "UPTIME"
_S_BOOT = "BOOT TIME"
_S_ADDR = "IP ADDRESS"
_S_LINK_STATS = "LINK STATS"
_S_LINK_SPEED = "LINK SPEED"
_S_ROUTE = "IP ROUTE"
_S_SOCKETS = "LISTENING SOCKETS"
_S_SOCKETS_PID = "LISTENING SOCKETS PID"
_S_DF = "DF"
_S_DISKS = "DISKS"
_S_LSCPU = "LSCPU"
_S_DMIDECODE = "DMIDECODE"
_S_DIMMS = "MEMORY DEVICES"
_S_FAILED = "SYSTEMCTL FAILED"
_S_ENABLED = "SYSTEMCTL ENABLED"
_S_SUDOERS = "SUDOERS"
_S_FIREWALL = "FIREWALL RULES"
_S_CONTAINERS = "CONTAINERS"
_S_DOCKER = "DOCKER VERSION"
_S_KUBELET = "KUBELET VERSION"

_F_OS_RELEASE = "/etc/os-release"
_F_FSTAB = "/etc/fstab"
_F_LOGIN_DEFS = "/etc/login.defs"
_F_SSHD = "/etc/ssh/sshd_config"
_F_PASSWD = "/etc/passwd"
_F_GROUP = "/etc/group"

# sshd settings shown in the device card. This is not the audit (that lives in
# netsec_audit and produces verdicts): here we show HOW it's configured, without judgment.
_SSHD_KEYS = ("port", "permitrootlogin", "passwordauthentication",
              "pubkeyauthentication", "permitemptypasswords",
              "hostbasedauthentication", "ignorerhosts", "maxauthtries",
              "logingracetime", "clientaliveinterval", "clientalivecountmax",
              "disableforwarding", "x11forwarding", "loglevel", "banner",
              "usepam", "allowusers", "allowgroups")

_LOGIN_DEFS_KEYS = ("pass_max_days", "pass_min_days", "pass_warn_age",
                    "pass_min_len", "encrypt_method", "umask",
                    "uid_min", "gid_min", "login_retries", "login_timeout")


def _col(key: str) -> Dict[str, str]:
    return {"key": key, "label_key": f"srv.col.{key}"}


def _section(sid: str, columns: List[str], rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "id": sid,
        "label_key": f"srv.sec.{sid}",
        "columns": [_col(k) for k in columns],
        "rows": rows,
    }


def _lines(cfg: LinuxConfig, name: str) -> List[str]:
    return [l.text for l in cfg.files.get(name, [])]


def _system_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """Host identity: distribution, kernel, hostname, uptime."""
    rows = []

    def add(prop, value):
        if value:
            rows.append({"property": prop, "value": value})

    pretty = ""
    for line in _lines(cfg, _F_OS_RELEASE):
        m = re.match(r'PRETTY_NAME="?([^"]+)"?', line)
        if m:
            pretty = m.group(1).strip()
            break
    add("os", pretty)

    hostname = ""
    for line in _lines(cfg, _S_HOSTNAME):
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == "hostname":
            hostname = parts[1]
            break
    add("hostname", hostname)

    # ``uname -srm`` -> "Linux <kernel> <arch>": kernel and architecture are
    # words 2 and 3, the rest of the line is not needed.
    uname = _lines(cfg, _S_UNAME)[:1]
    if uname:
        parts = uname[0].split()
        add("kernel", parts[1] if len(parts) > 1 else "")
        add("architecture", parts[2] if len(parts) > 2 else "")

    uptime = " ".join(_lines(cfg, _S_UPTIME)[:1])
    add("uptime", uptime)
    add("boot_time", " ".join(_lines(cfg, _S_BOOT)[:1]))

    dns = [l.split(None, 1)[1] for l in _lines(cfg, "/etc/resolv.conf")
           if l.lower().startswith("nameserver") and len(l.split()) > 1]
    add("dns", ", ".join(dns))

    # Container runtime: system rows, not a separate table. If the
    # command doesn't exist the section is empty and the row won't appear,
    # which is the right answer: there isn't one on this host.
    add("docker", " ".join(_lines(cfg, _S_DOCKER)[:1]))
    # ``kubelet --version`` -> "Kubernetes v1.29.0": we care about the version.
    kubelet = _lines(cfg, _S_KUBELET)[:1]
    if kubelet:
        add("kubernetes", kubelet[0].split()[-1])
    return rows


def _after(parts: List[str], token: str) -> str:
    """Word that follows ``token`` in an already-split line, "" if absent."""
    return parts[parts.index(token) + 1] if token in parts \
        and parts.index(token) + 1 < len(parts) else ""


_LINK_HEAD = re.compile(r'^\d+:\s+([^:@\s]+)[@:]')


def _link_stats(cfg: LinuxConfig) -> Dict[str, Dict[str, str]]:
    """``ip -s link`` -> per interface: MTU, state, and RX/TX counters.

    Counters are on the line AFTER the ``RX:``/``TX:`` header, so you can't
    read one line at a time in isolation: the header arms the read and the
    next line consumes it.
    """
    out: Dict[str, Dict[str, str]] = {}
    cur: Dict[str, str] = {}
    pending = ""
    for line in _lines(cfg, _S_LINK_STATS):
        head = _LINK_HEAD.match(line)
        if head:
            parts = line.split()
            cur = {"mtu": _after(parts, "mtu"), "state": _after(parts, "state")}
            out[head.group(1)] = cur
            pending = ""
            continue
        if not cur:
            continue
        if line.startswith("RX:") or line.startswith("TX:"):
            pending = line[:2].lower()
            continue
        if pending:
            fields = line.split()
            if len(fields) >= 4:
                cur[f"{pending}_bytes"] = fields[0]
                cur[f"{pending}_packets"] = fields[1]
                cur[f"{pending}_errors"] = fields[2]
                cur[f"{pending}_dropped"] = fields[3]
            pending = ""
    return out


def _link_speed(cfg: LinuxConfig) -> Dict[str, Dict[str, str]]:
    """``/sys/class/net/*/speed`` and ``duplex``. The kernel writes -1 for a down
    interface: it's "I don't know", not a speed, and it shouldn't be shown."""
    out = {}
    for line in _lines(cfg, _S_LINK_SPEED):
        parts = line.split()
        if not parts:
            continue
        speed = parts[1] if len(parts) > 1 else ""
        out[parts[0]] = {"speed": "" if speed in ("-1", "") else speed,
                         "duplex": parts[2] if len(parts) > 2 else ""}
    return out


def _interface_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``ip -br a`` for addresses and state, enriched with MTU (``ip -s link``)
    and speed/duplex (sysfs)."""
    stats = _link_stats(cfg)
    speeds = _link_speed(cfg)
    rows = []
    for line in _lines(cfg, _S_ADDR):
        parts = line.split()
        if len(parts) < 2:
            continue
        st = stats.get(parts[0], {})
        sp = speeds.get(parts[0], {})
        rows.append({
            "name": parts[0],
            "state": parts[1],
            "mtu": st.get("mtu", ""),
            "speed": sp.get("speed", ""),
            "duplex": sp.get("duplex", ""),
            # List, not string: the UI expands multi-value cells.
            "addresses": parts[2:] or [],
        })
    return rows


def _counter_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """Per-interface counters. Separate table from interfaces: merging them
    would give a thirteen-column row where the two halves are read for
    different reasons (how it's configured / how it's performing)."""
    rows = []
    for name, st in _link_stats(cfg).items():
        rows.append({
            "name": name,
            "rx_bytes": st.get("rx_bytes", ""),
            "rx_packets": st.get("rx_packets", ""),
            "rx_errors": st.get("rx_errors", ""),
            "rx_dropped": st.get("rx_dropped", ""),
            "tx_bytes": st.get("tx_bytes", ""),
            "tx_packets": st.get("tx_packets", ""),
            "tx_errors": st.get("tx_errors", ""),
            "tx_dropped": st.get("tx_dropped", ""),
        })
    return rows


def _route_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``ip route``: destination, gateway, interface, metric."""
    rows = []
    for line in _lines(cfg, _S_ROUTE):
        parts = line.split()
        if not parts:
            continue
        rows.append({
            "destination": parts[0],
            "via": _after(parts, "via"),
            "dev": _after(parts, "dev"),
            "proto": _after(parts, "proto"),
            "metric": _after(parts, "metric"),
            "src": _after(parts, "src"),
        })
    return rows


_PROCESS = re.compile(r'\("([^"]+)",pid=(\d+)')


def _socket_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``ss -tuln`` (or ``-tulpn`` on the privileged tier): listening ports.

    This is the section that really tells what the host exposes: a service on
    ``0.0.0.0`` is reachable from the whole network, one on ``127.0.0.1`` is
    not, and the difference is not visible anywhere else in the application.
    """
    rows = []
    # The privileged section also has the process: when it's present, it wins.
    lines = _lines(cfg, _S_SOCKETS_PID) or _lines(cfg, _S_SOCKETS)
    for line in lines:
        parts = line.split()
        if len(parts) < 5 or parts[0].lower() in ("netid", "state"):
            continue
        local = parts[4]
        address, _, port = local.rpartition(":")
        process = ""
        m = _PROCESS.search(line)
        if m:
            process = f"{m.group(1)} ({m.group(2)})"
        rows.append({
            "protocol": parts[0],
            "address": address or local,
            "port": port,
            # 0.0.0.0 and :: mean "all interfaces": it's worth saying it here
            # instead of leaving it to be inferred.
            "scope": "any" if address in ("0.0.0.0", "[::]", "*") else "local"
            if address in ("127.0.0.1", "[::1]") else "bound",
            "process": process,
        })
    return rows


def _fstab_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``/etc/fstab`` enriched with usage from ``df -hT``.

    Two separate tables would tell the same things half-way: mount options
    matter precisely on the filesystems that are filling up.
    """
    used = {}
    for line in _lines(cfg, _S_DF):
        parts = line.split()
        if len(parts) >= 7 and parts[5].endswith("%"):
            used[parts[6]] = {"size": parts[2], "used_pct": parts[5]}

    rows = []
    for line in _lines(cfg, _F_FSTAB):
        parts = line.split()
        if len(parts) < 4:
            continue
        extra = used.get(parts[1], {})
        rows.append({
            "device": parts[0],
            "mount": parts[1],
            "fstype": parts[2],
            "options": parts[3].split(","),
            "size": extra.get("size", ""),
            "used_pct": extra.get("used_pct", ""),
        })
    # Filesystems mounted but not declared in fstab (tmpfs, overlay): they exist
    # and consume space, omitting them would make the table a half-truth.
    declared = {r["mount"] for r in rows}
    for line in _lines(cfg, _S_DF):
        parts = line.split()
        if len(parts) >= 7 and parts[5].endswith("%") and parts[6] not in declared:
            rows.append({"device": parts[0], "mount": parts[6],
                         "fstype": parts[1], "options": [],
                         "size": parts[2], "used_pct": parts[5]})
    return rows


def _service_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``systemctl --failed``: units the system couldn't start."""
    rows = []
    for line in _lines(cfg, _S_FAILED):
        parts = line.split(None, 4)
        if len(parts) < 4 or not parts[0].endswith(
                (".service", ".timer", ".mount", ".socket", ".target")):
            continue
        rows.append({"unit": parts[0], "load": parts[1], "active": parts[2],
                     "sub": parts[3],
                     "description": parts[4] if len(parts) > 4 else ""})
    return rows


# Unit types that represent something someone decided to start.
# .mount units are auto-generated by every installed snap: there are dozens,
# they're all "enabled" by construction, and they drown the few rows that
# actually tell what runs on this machine.
_ENABLED_UNIT_TYPES = (".service", ".socket", ".timer", ".path")


def _enabled_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``systemctl list-unit-files --state=enabled``: what starts on its own at boot.

    The state is not shown: the query already filters on ``--state=enabled``, so
    the column would read "enabled" on every row. We show the PRESET, i.e. what
    the distribution expected: ``preset=disabled`` on an enabled unit means
    someone turned it on by hand, and that's the only piece of information in
    the table that distinguishes one row from another.
    """
    rows = []
    for line in _lines(cfg, _S_ENABLED):
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(_ENABLED_UNIT_TYPES):
            rows.append({"unit": parts[0],
                         "preset": parts[2] if len(parts) > 2 else ""})
    return rows


# Shells that do NOT give interactive access: a service account with one of
# these is not an entry point, one with /bin/bash is. This is the only column
# in the user table that requires a judgment call, and it's worth computing it
# here instead of leaving the operator to recognize paths by eye.
_NOLOGIN_SHELLS = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false",
                   "/usr/bin/false", "/bin/sync", "")


def _user_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``/etc/passwd``: local users, with an indication of who can log in."""
    rows = []
    for line in _lines(cfg, _F_PASSWD):
        f = line.split(":")
        if len(f) < 7:
            continue
        shell = f[6].strip()
        rows.append({"user": f[0], "uid": f[2], "gid": f[3], "home": f[5],
                     "shell": shell,
                     "login": "no" if shell in _NOLOGIN_SHELLS else "yes"})
    return rows


def _group_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``/etc/group``: local groups and secondary members."""
    rows = []
    for line in _lines(cfg, _F_GROUP):
        f = line.split(":")
        if len(f) < 4:
            continue
        members = [m for m in f[3].split(",") if m]
        rows.append({"group": f[0], "gid": f[2], "members": members})
    return rows


def _sudoers_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``/etc/sudoers`` and ``/etc/sudoers.d/*``: who can become root.

    No interpretation of the sudoers grammar: the line is shown in full, with
    the subject (user, ``%group``, or ``Defaults``) up front, because that's
    what you search on.
    """
    rows = []
    for line in _lines(cfg, _S_SUDOERS):
        parts = line.split(None, 1)
        if not parts:
            continue
        rows.append({"principal": parts[0],
                     "rule": parts[1] if len(parts) > 1 else ""})
    return rows


def _container_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``docker ps``, TAB-separated fields.

    The separator is not space because STATUS contains it ("Up 3 hours") and
    PORTS does too: splitting on spaces would break two out of four columns.
    """
    rows = []
    for line in _lines(cfg, _S_CONTAINERS):
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        rows.append({"name": fields[0].strip(), "image": fields[1].strip(),
                     "status": fields[2].strip() if len(fields) > 2 else "",
                     "ports": fields[3].strip() if len(fields) > 3 else ""})
    return rows


def _firewall_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``nft list ruleset`` or ``iptables -S``: host firewall.

    The two syntaxes are not normalized into a third: each line is shown as-is,
    and that's also how you paste it into a shell to verify it.
    """
    return [{"rule": line} for line in _lines(cfg, _S_FIREWALL)]


def _colon_keyed(lines: List[str], keys: tuple) -> Dict[str, str]:
    """``Key: value`` lines (lscpu, dmidecode -s) reduced to known keys."""
    found = {}
    for line in lines:
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() in keys:
            found[key.strip().lower()] = value.strip()
    return found


_LSCPU_KEYS = ("model name", "architecture", "cpu(s)", "socket(s)",
               "core(s) per socket", "thread(s) per core", "vendor id",
               "hypervisor vendor", "virtualization type")
_DMI_KEYS = ("system-manufacturer", "system-product-name",
             "system-serial-number", "bios-version", "bios-release-date")


def _hardware_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """CPU (``lscpu``) and machine identity (``dmidecode -s``, sudo tier)."""
    rows = []
    for key, value in _colon_keyed(_lines(cfg, _S_LSCPU), _LSCPU_KEYS).items():
        rows.append({"property": key, "value": value})
    for key in _DMI_KEYS:
        value = _colon_keyed(_lines(cfg, _S_DMIDECODE), _DMI_KEYS).get(key)
        if value:
            rows.append({"property": key, "value": value})
    return rows


def _disk_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``lsblk -dno NAME,MODEL,SERIAL,SIZE``: physical disks, not partitions.

    The model may contain spaces, so we grab size from the end and serial from
    the second-to-last position: splitting from the left would break the model
    name on every disk that has a long one.
    """
    rows = []
    for line in _lines(cfg, _S_DISKS):
        parts = line.split()
        if len(parts) < 2:
            continue
        rows.append({
            "name": parts[0],
            "size": parts[-1],
            "serial": parts[-2] if len(parts) >= 4 else "",
            "model": " ".join(parts[1:-2]) if len(parts) >= 4 else "",
        })
    return rows


_DIMM_KEYS = {"size": "size", "locator": "locator", "type": "type",
              "speed": "speed", "manufacturer": "manufacturer",
              "part number": "part_number"}


def _dimm_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``dmidecode -t 17``: memory banks.

    Records are separated by blank lines, which the parser already discarded:
    the start of a bank is recognized by the ``Memory Device`` header.
    Empty slots ("No Module Installed") are omitted.
    """
    rows: List[Dict[str, Any]] = []
    cur: Dict[str, Any] = {}
    for line in _lines(cfg, _S_DIMMS):
        if line == "Memory Device":
            cur = {}
            rows.append(cur)
            continue
        if not rows:
            continue
        key, sep, value = line.partition(":")
        field = _DIMM_KEYS.get(key.strip().lower())
        if sep and field:
            cur[field] = value.strip()
    return [r for r in rows
            if r.get("size") and "no module" not in r["size"].lower()]


def _keyed_rows(lines: List[str], keys: tuple, separator: bool = False
                ) -> List[Dict[str, Any]]:
    """``key value`` lines filtered to known keys, last occurrence wins."""
    found: Dict[str, str] = {}
    for line in lines:
        text = line.replace("=", " ", 1) if separator else line
        parts = text.split(None, 1)
        if len(parts) < 2:
            continue
        key = parts[0].lower()
        if key in keys:
            found[key] = parts[1].strip()
    return [{"setting": k, "value": found[k]} for k in keys if k in found]


def _sshd_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    # sshd -T is the EFFECTIVE configuration (accounts for Include directives):
    # when the privileged triage collected it, it wins over the file.
    lines = _lines(cfg, SSHD_EFFECTIVE) or _lines(cfg, _F_SSHD)
    return _keyed_rows(lines, _SSHD_KEYS)


def analyze(text) -> Dict[str, Any]:
    """Linux artifact -> section envelope. Pure and tolerant."""
    try:
        return _analyze(text)
    except Exception:
        # See fw_analyzers.fortios.analyze: an empty envelope alone cannot be
        # told apart from a clean host, so a crash must be marked as such.
        logger.exception("Linux analysis failed")
        return {"vendor": "linux", "sections": [], "error": True}


def _analyze(text) -> Dict[str, Any]:
    cfg = parse_linux(text)
    sections = [
        _section("system", ["property", "value"], _system_rows(cfg)),
        _section("hardware", ["property", "value"], _hardware_rows(cfg)),
        _section("interfaces", ["name", "state", "mtu", "speed", "duplex",
                                "addresses"], _interface_rows(cfg)),
        _section("counters", ["name", "rx_bytes", "rx_packets", "rx_errors",
                              "rx_dropped", "tx_bytes", "tx_packets",
                              "tx_errors", "tx_dropped"], _counter_rows(cfg)),
        _section("routes", ["destination", "via", "dev", "proto", "metric", "src"],
                 _route_rows(cfg)),
        _section("sockets", ["protocol", "address", "port", "scope", "process"],
                 _socket_rows(cfg)),
        _section("firewall", ["rule"], _firewall_rows(cfg)),
        _section("storage", ["device", "mount", "fstype", "options", "size",
                             "used_pct"], _fstab_rows(cfg)),
        _section("disks", ["name", "model", "serial", "size"], _disk_rows(cfg)),
        _section("dimms", ["locator", "size", "type", "speed", "manufacturer",
                           "part_number"], _dimm_rows(cfg)),
        _section("containers", ["name", "image", "status", "ports"],
                 _container_rows(cfg)),
        _section("services", ["unit", "load", "active", "sub", "description"],
                 _service_rows(cfg)),
        _section("enabled_units", ["unit", "preset"], _enabled_rows(cfg)),
        _section("ssh", ["setting", "value"], _sshd_rows(cfg)),
        _section("accounts", ["setting", "value"],
                 _keyed_rows(_lines(cfg, _F_LOGIN_DEFS), _LOGIN_DEFS_KEYS)),
        _section("users", ["user", "uid", "gid", "home", "shell", "login"],
                 _user_rows(cfg)),
        _section("groups", ["group", "gid", "members"], _group_rows(cfg)),
        _section("sudoers", ["principal", "rule"], _sudoers_rows(cfg)),
    ]
    return {"vendor": "linux", "sections": sections}
