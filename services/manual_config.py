# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Configs of devices SentinelNet cannot reach, uploaded by hand.

One rule: what is stored must be indistinguishable from what the triage
would have written, so every reader of backup-config/ (analyzer, drift, audit,
policy test, routes, map) works on it unchanged.

- guide(): the commands to run, per vendor — the triage's own list.
- to_backup(): a terminal session log -> the triage's backup layout.
- preview(): what an upload says about the device, for the review form.
"""
import ipaddress
import re

from core import core_engine
from drivers.linux import _ANSI_CSI, _SHELL_INTEGRATION
from services.config_drift.normalize import TRIAGE_MARKER

# Inventory vendor keys the guide offers (drivers/registry.VENDOR_DRIVER_DEFAULTS
# without its aliases).
GUIDE_VENDORS = (
    "cisco", "cisco_ie", "cisco_cbs", "cisco_9800", "cisco_wlc", "hpe", "aruba",
    "juniper", "fortinet", "paloalto",
    "siemens_scalance", "hirschmann", "moxa", "westermo", "phoenix_contact",
    "linux", "windows",
)

# The pager-off command a human types first; the triage gets the same effect
# from netmiko's session preparation.
PAGING = {
    "cisco": "terminal length 0",
    "cisco_ie": "terminal length 0",
    "cisco_9800": "terminal length 0",
    "cisco_cbs": "terminal datadump",
    "cisco_wlc": "config paging disable",
    "hpe": "no page",
    "aruba": "no paging",
    "juniper": "set cli screen-length 0",
    "fortinet": "config system console\n    set output standard\nend",
    "paloalto": "set cli pager off",
    "siemens_scalance": "terminal length 0",
    "hirschmann": "cli numlines 0",
    "moxa": "terminal length 0",
    "westermo": "terminal length 0",
    "phoenix_contact": "terminal length 0",
}

# One `show <section>` per section, for a console whose scrollback cannot hold
# `show full-configuration` (the FortiGate GUI CLI widget). Every section an
# analyzer, audit rule, policy test or traffic view reads; roughly the order
# FortiOS prints them, which is also the order the upload stores them in.
# Absent from it on purpose: `user local` (password hashes, nothing reads it).
# The ones listed still print ENC secrets (admin, ha, ldap, radius, tacacs+,
# snmp user, ipsec psk), exactly as show full-configuration does.
SECTION_COMMANDS = {
    "fortinet": [f"show {s}" for s in (
        "system global", "system interface", "system password-policy", "system ha",
        "system dns", "system snmp community", "system snmp user", "system admin",
        "system session-helper", "system auto-install", "system ntp", "system zone",
        "log disk setting", "log fortianalyzer setting", "log syslogd setting",
        "log eventfilter", "log fortiguard setting",
        "firewall address", "firewall addrgrp", "firewall service custom",
        "firewall service group", "firewall schedule recurring", "firewall schedule onetime",
        "ips sensor",
        "user radius", "user tacacs+", "user ldap", "user fsso", "user group",
        "vpn ssl web portal", "vpn ssl settings",
        "antivirus profile", "webfilter profile", "dnsfilter profile", "application list",
        "dlp profile", "emailfilter profile", "firewall ssl-ssh-profile",
        "vpn ipsec phase1-interface", "vpn ipsec phase2-interface",
        "vpn ipsec phase1", "vpn ipsec phase2",
        "firewall vip", "firewall vipgrp", "firewall ippool",
        "firewall policy", "firewall local-in-policy", "firewall DoS-policy",
        "firewall central-snat-map",
        "router static", "router policy", "router ospf", "router bgp",
    )],
}

# Per-vendor notes, as i18n keys the UI translates.
NOTES = {
    "fortinet": ["mcNoteFortiGui"],
    "linux": ["mcNoteLinuxRoot"],
    "windows": ["mcNoteWindowsCmd"],
}

# No "ios": it is detect_config_type's fallback, not a match. HPE, Aruba, CBS
# and 9800 logs all land there, so it says nothing certain about the vendor.
_VENDOR_BY_TYPE = {"fortios": "fortinet", "panos": "paloalto",
                   "wlc-aireos": "cisco_wlc", "linux": "linux", "windows": "windows"}
_JUNOS = re.compile(r"^set (system host-name|interfaces) ", re.MULTILINE)

# What each config type unlocks (spec §4); 'cve' is added only with a version.
_ANALYSES = {
    "ios": ["analyzer", "audit", "policy", "drift", "routes"],
    "fortios": ["analyzer", "audit", "policy", "drift", "routes"],
    "panos": ["analyzer", "drift"],
    "wlc-aireos": ["analyzer", "drift"],
    "linux": ["analyzer", "audit", "drift"],
    "windows": ["analyzer", "drift"],
}

# First prompt-looking prefix ending in #, > or $, then the command.
_ECHO = re.compile(r"^(?P<prompt>\S[^\r\n]*?[#>$])\s*(?P<cmd>\S.*?)\s*$")
_STEM = re.compile(r"[^\s(#>$]*")
_BARE = re.compile(r"^\S[^\r\n]*[#>$]\s*$")
_FORTI_HEAD = re.compile(r"^config system (global|interface)\s*$", re.MULTILINE)
_FORTI_HEADER = re.compile(r"^#config-version=([A-Za-z0-9]+)-(\d+\.\d+\.\d+)", re.MULTILINE)
_HOSTNAMES = (
    re.compile(r"^set deviceconfig system hostname (\S+)", re.MULTILINE),  # PAN-OS
    re.compile(r"^set system host-name (\S+)", re.MULTILINE),              # Junos
    re.compile(r"^config sysname (\S+)", re.MULTILINE),                    # AireOS
)
_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_IP_PATTERNS = (  # management-specific first
    re.compile(r"^set deviceconfig system ip-address " + _IP, re.MULTILINE),    # PAN-OS
    re.compile(r"^config interface address management " + _IP, re.MULTILINE),  # AireOS
    re.compile(r"^\s*ip address " + _IP + r"[ /]", re.MULTILINE),               # IOS, ProCurve
    re.compile(r"^\s*set ip " + _IP + r"[ /]", re.MULTILINE),                    # FortiOS
    re.compile(r"family inet address " + _IP + r"/"),                             # Junos
    re.compile(r"^\S+\s+UP\s+" + _IP + r"/", re.MULTILINE),                      # Linux `ip -br a`
)
_UNKNOWN = ("Unknown", "Non Rilevato", "Non Rilevata")


# Readline redraws a line that wraps at the terminal width as " \r"; the
# triage never sees it (netmiko reads the raw stream), a pasted log does.
_WRAP = re.compile(r" \r(?!\n)")
# SecureCRT "timestamp each line" (default format '%h%m%s.%t: ').
# ponytail: default format only; a custom one needs its own pattern here.
_LINE_STAMP = re.compile(r"^\d{6}\.\d{3}: ?", re.MULTILINE)


def _clean(text: str) -> str:
    """A terminal log as the triage's cleaned session would read: no escape
    sequences (colour, bracketed paste, shell integration), no wrap redraws,
    no per-line timestamps."""
    text = _WRAP.sub("", _ANSI_CSI.sub("", _SHELL_INTEGRATION.sub("", text or "")))
    return _LINE_STAMP.sub("", text)


def _norm(command: str) -> str:
    return " ".join((command or "").split())


class _Replay:
    """Connection stand-in for a driver: records what it is asked and answers
    from a captured session, so version, model and serial come from the
    driver's own parsers instead of a second copy of them."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.asked = []

    def send_command(self, command, *args, **kwargs):
        if command not in self.asked:
            self.asked.append(command)
        return self.answers.get(_norm(command), "")


def _driver_cls(vendor):
    driver_cls, _ = core_engine.resolve_driver(vendor)
    return driver_cls


def _commands(vendor):
    """(backup command, info commands, [(extra command, tag)]) for a vendor.

    The info commands are whatever the driver's get_version/get_model/
    get_serial send, recorded rather than listed by hand."""
    rec = _Replay()
    drv = _driver_cls(vendor)(rec)
    drv.get_version()
    drv.get_model()
    drv.get_serial()
    backup = drv.get_backup_command()
    extras = core_engine.triage_extra_commands(vendor, privileged=True)
    taken = {_norm(backup)} | {_norm(c) for c, _ in extras}
    info = [c for c in rec.asked if _norm(c) not in taken]
    return backup, info, extras


def guide() -> list:
    out = []
    for vendor in GUIDE_VENDORS:
        backup, info, extras = _commands(vendor)
        out.append({"vendor": vendor, "paging": PAGING.get(vendor, ""),
                    "commands": [backup, *info, *(c for c, _ in extras)],
                    "sections": SECTION_COMMANDS.get(vendor, []),
                    "notes": NOTES.get(vendor, [])})
    return out


def parse_session(text: str, known: list):
    """Split a terminal session log at the echo of each known command.

    Returns ({normalized command: output}, prompt). The prompt is the first one
    learned. An echo of a known command opens a section under any prompt, so
    a changed prompt (`R1>` then `R1#` after `enable`, FortiOS `FGT # ` then
    `FGT (global) # `) does not matter. A section closes at the next echo of
    any command or bare prompt: a line starting with the first prompt, or with
    its device-name stem (the leading run up to whitespace, '(', '#', '>' or
    '$') that looks like a prompt line."""
    wanted = {_norm(c) for c in known}
    sections, current, prompt, stem = {}, None, None, ""
    for line in (text or "").splitlines():
        m = _ECHO.match(line)
        if m and _norm(m["cmd"]) in wanted:
            if prompt is None:
                prompt = m["prompt"]
                stem = _STEM.findall(prompt)[0]
            current = _norm(m["cmd"])
            sections[current] = []
        elif prompt is not None and (
                line.startswith(prompt)
                or (stem and line.startswith(stem) and (m or _BARE.match(line)))):
            current = None
        elif current is not None:
            sections[current].append(line)
    return {k: "\n".join(v).strip("\n") for k, v in sections.items()}, prompt


def _known(value) -> str:
    v = (value or "").strip()
    return "" if v in _UNKNOWN else v


def _hostname(text: str, prompt) -> str:
    name = core_engine.extract_hostname_from_config(text)
    if name:
        return name
    for pattern in _HOSTNAMES:
        m = pattern.search(text)
        if m:
            return m.group(1).strip('"')
    if prompt:
        # 'admin@PA-01>' -> 'PA-01', 'switch-01#' -> 'switch-01',
        # '(Cisco Controller) >' -> '' (not a name).
        return re.sub(r"^.*@|[:(].*$|[\s#>$]+$", "", prompt)
    return ""


def to_backup(vendor: str, text: str) -> dict:
    """The upload as the triage would have stored it, plus what it says."""
    text = _clean(text)
    backup_cmd, info, extras = _commands(vendor)
    per_section = SECTION_COMMANDS.get(vendor, [])
    sections, prompt = parse_session(
        text, [backup_cmd, *info, *(c for c, _ in extras), *per_section])
    config = sections.get(_norm(backup_cmd))
    if config is None:
        # One command per section (GUI console): rejoined in guide order.
        parts = [sections[_norm(c)] for c in per_section if _norm(c) in sections]
        config = "\n".join(parts) if parts else None
    if config is None:
        # No echo of the backup command: a plain config file, stored as is.
        stored, structured = text, False
    else:
        stored, structured = config + f"\n\n{TRIAGE_MARKER}\n", True
        for cmd, tag in extras:
            body = sections.get(_norm(cmd))
            if body is None:
                continue
            if vendor == "linux" and tag == "--- HOSTNAME ---":
                # Same rewrite as core_engine._run_tagged(prefix_hostname=True).
                body = f"hostname {body.strip()}"
            stored += f"\n{tag}\n{body}"
    drv = _driver_cls(vendor)(_Replay(sections))
    header = _FORTI_HEADER.search(text)
    return {
        "backup": stored,
        "structured": structured,
        "hostname": _hostname(stored, prompt),
        "version": _known(drv.get_version()) or (header.group(2) if header else ""),
        "model": _known(drv.get_model()) or (header.group(1) if header else ""),
        "serial": _known(drv.get_serial()),
    }


_LAN_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"))


def _fortios_ip_candidates(text: str) -> list:
    """Interface IPs (secondaryip included), GUI-reachable first, then
    non-LAN ones, then file order.
    ponytail: a GUI published through upstream NAT is not in the config, so
    the public address it answers on cannot be proposed."""
    from fw_analyzers.fortios import _forti_tree
    root = _forti_tree(text)["children"]
    ifaces = (root.get("system interface")
              or root.get("global", {}).get("children", {}).get("system interface")
              or {"children": {}})
    nodes = []
    for iface in ifaces["children"].values():
        nodes.append(iface)
        nodes.extend(iface["children"].get("secondaryip", {}).get("children", {}).values())
    ranked, seen = [], set()
    for index, node in enumerate(nodes):
        ip = (node["sets"].get("ip") or [""])[0].split("/")[0]
        if not ip or ip in seen or ip.startswith(("127.", "0.")):
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        seen.add(ip)
        access = node["sets"].get("allowaccess", [])
        gui = "https" in access or "http" in access
        # Not is_global: that rejects the RFC 5737 ranges too.
        public = not any(addr in net for net in _LAN_NETS)
        ranked.append(((not gui, not public, index), ip))
    return [ip for _, ip in sorted(ranked)]


def ip_candidates(text: str) -> list:
    from ai.config_analyzer import detect_config_type
    if detect_config_type(text) == 'fortios':
        ranked = _fortios_ip_candidates(text)
        if ranked:
            return ranked
        # Partial paste without `config system interface`: generic regexes.
    out = []
    for pattern in _IP_PATTERNS:
        for ip in pattern.findall(text or ""):
            if ip in out or ip.startswith(("127.", "0.")):
                continue
            if all(int(octet) <= 255 for octet in ip.split(".")):
                out.append(ip)
    return out


def analyses_for(vendor: str, config_type: str, version: str) -> list:
    # Junos has a driver but no parser: detect_config_type calls it 'ios', and
    # the IOS analyzer reads nothing out of `set` lines.
    base = ["drift"] if vendor == "juniper" else list(_ANALYSES.get(config_type, ["drift"]))
    return base + (["cve"] if version else [])


def sniff_vendor(text: str) -> str:
    """The vendor the content itself certainly points to; '' when unsure."""
    from ai.config_analyzer import detect_config_type
    return "juniper" if _JUNOS.search(text or "") else \
        _VENDOR_BY_TYPE.get(detect_config_type(text), "")


def preview(text: str, vendor: str = "") -> dict:
    from ai.config_analyzer import detect_config_type
    sniffed = sniff_vendor(_clean(text))  # anchored patterns: no timestamps in front
    vendor = vendor or sniffed or "cisco"
    result = to_backup(vendor, text)
    backup = result.pop("backup")
    config_type = detect_config_type(backup, {"Vendor": vendor})
    # Neither global nor interfaces: the start of the config scrolled away.
    partial = config_type == "fortios" and not _FORTI_HEAD.search(backup)
    return {**result, "vendor": vendor, "sniffed_vendor": sniffed, "config_type": config_type,
            "warnings": ["mcWarnFortiPartial"] if partial else [],
            "ip_candidates": ip_candidates(backup),
            "analyses": analyses_for(vendor, config_type, result["version"])}
