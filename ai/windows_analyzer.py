# -*- coding: utf-8 -*-
"""Windows backup artifact -> section envelope for the Config Analyzer.

Same shape as the Linux and firewall envelopes: ``sections`` with
``columns``/``rows``, so the UI derives its sub-pills from the data and needs
to know nothing about Windows.

WHY IT IS SHORTER THAN ``linux_analyzer`` — it does not have to read ``ip -s
link``, ``lsblk`` or ``df`` output. ``drivers/windows.py`` builds every line
itself from object properties joined with '|', because the textual output of
Windows commands is localised and a parser written against an English box
reads nothing on an Italian one. Owning the format means one splitter serves
almost every table.

SECTION IDS ARE PREFIXED ``win_`` — the Config Analyzer derives both the pill
label and its help line from the section id (``srv.sec.X`` -> ``srv.help.X``),
and the Linux help texts name ``/etc/os-release`` and ``systemctl``. Sharing
the ids would put those words under a Windows host. The COLUMN keys are shared
on purpose: a column called "Nome" is the same column on either platform.

Tolerant like the other analyzers: no malformed line raises, a missing section
produces an empty table rather than an error.
"""

import logging
from typing import Any, Dict, List, Optional, Sequence

from services.netsec_audit.linux_parser import LinuxConfig, parse_linux

logger = logging.getLogger(__name__)

# Artifact sections, as written by drivers/windows.py.
_S_HOSTNAME = "HOSTNAME"
_S_OS = "OS INFO"
_S_COMPUTER = "COMPUTER INFO"
_S_BIOS = "BIOS"
_S_CPU = "CPU"
_S_ADAPTERS = "NET ADAPTERS"
_S_ADDRESSES = "IP ADDRESSES"
_S_ROUTES = "NET ROUTES"
_S_PORTS = "LISTENING PORTS"
_S_SVC_DOWN = "SERVICES DOWN"
_S_SVC_AUTO = "SERVICES AUTO"
_S_USERS = "LOCAL USERS"
_S_GROUPS = "LOCAL GROUPS"
_S_ADMINS = "LOCAL ADMINS"
_S_DISKS = "DISKS"
_S_VOLUMES = "VOLUMES"
_S_FIREWALL = "FIREWALL PROFILES"
_S_REMOTE = "REMOTE ACCESS"
_S_SMB = "SMB CONFIG"
_S_SHARES = "SMB SHARES"

# Addresses whose reachability is what the reader actually needs to know.
_ANY_ADDRESSES = {"0.0.0.0", "::", "*"}
_LOCAL_ADDRESSES = {"127.0.0.1", "::1"}


def _col(key: str) -> Dict[str, str]:
    return {"key": key, "label_key": f"srv.col.{key}"}


def _section(sid: str, columns: List[str],
             rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "id": sid,
        "label_key": f"srv.sec.{sid}",
        "columns": [_col(k) for k in columns],
        "rows": rows,
    }


def _lines(cfg: LinuxConfig, name: str) -> List[str]:
    return [l.text for l in cfg.files.get(name, [])]


def _split(cfg: LinuxConfig, section: str,
           keys: Sequence[str]) -> List[Dict[str, str]]:
    """Pipe-delimited section -> one dict per line.

    A line with fewer fields than expected is padded rather than dropped: a
    property that came back empty on the host (a VM with no BIOS serial) is
    still a row worth showing. The split is bounded by the number of keys, so
    a value that legitimately contains '|' stays whole in the last column.
    """
    out = []
    for line in _lines(cfg, section):
        if "|" not in line:
            continue
        parts = line.split("|", len(keys) - 1) if len(keys) > 1 else [line]
        parts += [""] * (len(keys) - len(parts))
        out.append({k: parts[i].strip() for i, k in enumerate(keys)})
    return out


def _kv(cfg: LinuxConfig, section: str) -> Dict[str, str]:
    """``key|value`` section -> dict. Used by the registry-style sections."""
    out = {}
    for row in _split(cfg, section, ("k", "v")):
        if row["k"]:
            out[row["k"]] = row["v"]
    return out


def _first(cfg: LinuxConfig, section: str,
           keys: Sequence[str]) -> Dict[str, str]:
    rows = _split(cfg, section, keys)
    return rows[0] if rows else {k: "" for k in keys}


def _human_bytes(raw: str) -> str:
    """Bytes as reported by CIM -> "465.8 GB". Empty stays empty."""
    try:
        value = float((raw or "").strip())
    except (TypeError, ValueError):
        return (raw or "").strip()
    if value <= 0:
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if value < 1024 or unit == "PB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return ""


def _used_pct(size: str, free: str) -> str:
    try:
        total, available = float(size), float(free)
    except (TypeError, ValueError):
        return ""
    if total <= 0:
        return ""
    return f"{(total - available) / total * 100:.0f}%"


def _bool_word(raw: str) -> str:
    """PowerShell prints booleans as True/False whatever the system language,
    which is why they are compared here and not translated on the host."""
    value = (raw or "").strip().lower()
    if value in ("true", "1"):
        return "True"
    if value in ("false", "0"):
        return "False"
    return (raw or "").strip()


def _system_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """Host identity: edition, build, domain membership, boot time."""
    rows: List[Dict[str, Any]] = []

    def add(prop: str, value: Optional[str]):
        if value:
            rows.append({"property": prop, "value": value})

    hostname = ""
    for line in _lines(cfg, _S_HOSTNAME):
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == "hostname":
            hostname = parts[1]
            break
    add("hostname", hostname)

    os_info = _first(cfg, _S_OS, ("caption", "version", "build", "arch",
                                  "installed", "booted"))
    add("os", os_info["caption"])
    version = " ".join(p for p in (
        os_info["version"],
        f"build {os_info['build']}" if os_info["build"] else "") if p)
    add("kernel", version)
    add("architecture", os_info["arch"])
    # The two timestamps are shown verbatim: CIM returns a DateTime and
    # PowerShell renders it in the host's culture, so parsing it here would
    # mean guessing a date format per installation.
    add("boot_time", os_info["booted"])
    add("installed", os_info["installed"])

    computer = _first(cfg, _S_COMPUTER, ("manufacturer", "model", "domain",
                                         "in_domain", "memory", "cpus"))
    # "domain" on a workgroup machine holds the workgroup name, so the flag
    # is what says which of the two it is.
    if computer["domain"]:
        add("domain" if _bool_word(computer["in_domain"]) == "True"
            else "workgroup", computer["domain"])
    add("memory", _human_bytes(computer["memory"]))
    add("cpus", computer["cpus"])
    return rows


def _hardware_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    def add(prop: str, value: Optional[str]):
        if value:
            rows.append({"property": prop, "value": value})

    computer = _first(cfg, _S_COMPUTER, ("manufacturer", "model", "domain",
                                         "in_domain", "memory", "cpus"))
    add("manufacturer", computer["manufacturer"])
    add("model", computer["model"])

    bios = _first(cfg, _S_BIOS, ("manufacturer", "version", "release",
                                 "serial"))
    add("bios_version", bios["version"])
    add("bios_date", bios["release"])
    add("serial", bios["serial"])

    for cpu in _split(cfg, _S_CPU, ("name", "cores", "threads", "mhz")):
        detail = ", ".join(p for p in (
            f"{cpu['cores']} core" if cpu["cores"] else "",
            f"{cpu['threads']} thread" if cpu["threads"] else "",
            f"{cpu['mhz']} MHz" if cpu["mhz"] else "") if p)
        add("cpu", f"{cpu['name']} ({detail})" if detail else cpu["name"])
    return rows


def _interface_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """Adapters joined with their addresses, keyed by the interface alias."""
    by_alias: Dict[str, List[str]] = {}
    for addr in _split(cfg, _S_ADDRESSES, ("alias", "ip", "prefix", "family",
                                           "origin")):
        if not addr["ip"]:
            continue
        cidr = f"{addr['ip']}/{addr['prefix']}" if addr["prefix"] else addr["ip"]
        by_alias.setdefault(addr["alias"], []).append(cidr)

    rows = []
    for nic in _split(cfg, _S_ADAPTERS, ("name", "description", "state",
                                         "speed", "address", "mtu")):
        rows.append({
            "name": nic["name"],
            "description": nic["description"],
            "state": nic["state"],
            "speed": nic["speed"],
            "address": nic["address"],
            "mtu": nic["mtu"],
            "addresses": ", ".join(by_alias.get(nic["name"], [])),
        })
    return rows


def _route_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    return [{"destination": r["destination"], "via": r["via"],
             "dev": r["dev"], "metric": r["metric"]}
            for r in _split(cfg, _S_ROUTES,
                            ("destination", "via", "dev", "metric"))
            if r["destination"]]


def _socket_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    rows = []
    for s in _split(cfg, _S_PORTS, ("protocol", "address", "port", "pid",
                                    "process")):
        if not s["port"]:
            continue
        address = s["address"]
        # The exposure is the column that matters: 'any' is reachable from
        # the whole network, 'local' only from the host itself.
        scope = ("any" if address in _ANY_ADDRESSES
                 else "local" if address in _LOCAL_ADDRESSES
                 else address)
        process = s["process"]
        if process and s["pid"]:
            process = f"{process} ({s['pid']})"
        rows.append({"protocol": s["protocol"], "address": address,
                     "port": s["port"], "scope": scope, "process": process})
    return rows


def _service_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """Automatic services that are not running. An empty table is the normal
    condition, exactly like ``systemctl --failed`` on Linux."""
    return [{"name": s["name"], "description": s["description"],
             "status": s["status"], "type": s["type"]}
            for s in _split(cfg, _S_SVC_DOWN,
                            ("name", "description", "status", "type"))
            if s["name"]]


def _enabled_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    return [{"name": s["name"], "description": s["description"],
             "status": s["status"], "type": s["type"]}
            for s in _split(cfg, _S_SVC_AUTO,
                            ("name", "description", "status", "type"))
            if s["name"]]


def _user_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    rows = []
    for u in _split(cfg, _S_USERS, ("name", "enabled", "expires", "required",
                                    "last_logon", "description")):
        if not u["name"]:
            continue
        rows.append({
            "name": u["name"],
            "active": _bool_word(u["enabled"]),
            # An account whose password never expires is worth seeing next
            # to the account, not only in an audit report. The marker is the
            # bare token and not a sentence, because a row is DATA: prose here
            # would show Italian in an English dashboard, next to the
            # platform's own untranslated values ('Up', 'Running').
            "setting": u["expires"] or "never",
            "login": u["last_logon"],
            "description": u["description"],
        })
    return rows


def _group_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    return [{"name": g["name"], "members": g["members"]}
            for g in _split(cfg, _S_GROUPS, ("name", "members"))
            if g["name"]]


def _admin_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """Members of the local Administrators group: the counterpart of sudoers."""
    return [{"name": a["name"], "type": a["type"], "principal": a["principal"]}
            for a in _split(cfg, _S_ADMINS, ("name", "type", "principal"))
            if a["name"]]


def _volume_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    rows = []
    for v in _split(cfg, _S_VOLUMES, ("device", "name", "fstype", "size",
                                      "free")):
        if not v["device"]:
            continue
        rows.append({"device": v["device"], "name": v["name"],
                     "fstype": v["fstype"], "size": _human_bytes(v["size"]),
                     "used_pct": _used_pct(v["size"], v["free"])})
    return rows


def _disk_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    return [{"device": d["device"], "model": d["model"],
             "serial": d["serial"], "size": _human_bytes(d["size"])}
            for d in _split(cfg, _S_DISKS,
                            ("device", "model", "serial", "size"))
            if d["device"]]


def _firewall_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """The three profiles and their default actions. A disabled profile is the
    finding: the rules under it stop applying."""
    return [{"name": p["name"], "active": _bool_word(p["enabled"]),
             "inbound": p["inbound"], "outbound": p["outbound"]}
            for p in _split(cfg, _S_FIREWALL,
                            ("name", "enabled", "inbound", "outbound", "log"))
            if p["name"]]


def _remote_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """RDP and SMB in one table: on Windows these are what sshd_config is on
    Linux — how the host can be reached, stated without a verdict."""
    rows = []
    for section in (_S_REMOTE, _S_SMB):
        for key, value in _kv(cfg, section).items():
            rows.append({"setting": key, "value": _bool_word(value)})
    return rows


def _share_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    return [{"name": s["name"], "path": s["path"],
             "description": s["description"]}
            for s in _split(cfg, _S_SHARES, ("name", "path", "description"))
            if s["name"]]


def analyze(text) -> Dict[str, Any]:
    """Windows artifact -> section envelope. Pure and tolerant."""
    try:
        return _analyze(text)
    except Exception:
        # See linux_analyzer.analyze: an empty envelope alone cannot be told
        # apart from a clean host, so a crash must be marked as such.
        logger.exception("Windows analysis failed")
        return {"vendor": "windows", "sections": [], "error": True}


def _analyze(text) -> Dict[str, Any]:
    cfg = parse_linux(text)          # generic '--- marker ---' splitter
    sections = [
        _section("win_system", ["property", "value"], _system_rows(cfg)),
        _section("win_hardware", ["property", "value"], _hardware_rows(cfg)),
        _section("win_interfaces",
                 ["name", "description", "state", "speed", "address", "mtu",
                  "addresses"], _interface_rows(cfg)),
        _section("win_routes", ["destination", "via", "dev", "metric"],
                 _route_rows(cfg)),
        _section("win_sockets", ["protocol", "address", "port", "scope",
                                 "process"], _socket_rows(cfg)),
        _section("win_services", ["name", "description", "status", "type"],
                 _service_rows(cfg)),
        _section("win_enabled", ["name", "description", "status", "type"],
                 _enabled_rows(cfg)),
        _section("win_remote", ["setting", "value"], _remote_rows(cfg)),
        _section("win_firewall", ["name", "active", "inbound", "outbound"],
                 _firewall_rows(cfg)),
        _section("win_shares", ["name", "path", "description"],
                 _share_rows(cfg)),
        _section("win_admins", ["name", "type", "principal"],
                 _admin_rows(cfg)),
        _section("win_users", ["name", "active", "setting", "login",
                               "description"], _user_rows(cfg)),
        _section("win_groups", ["name", "members"], _group_rows(cfg)),
        _section("win_storage", ["device", "name", "fstype", "size",
                                 "used_pct"], _volume_rows(cfg)),
        _section("win_disks", ["device", "model", "serial", "size"],
                 _disk_rows(cfg)),
    ]
    # A section with no rows is dropped: an empty pill invites a click that
    # leads to an empty table, and on this platform an absent section usually
    # means the account was not an administrator.
    return {"vendor": "windows",
            "sections": [s for s in sections if s["rows"]]}
