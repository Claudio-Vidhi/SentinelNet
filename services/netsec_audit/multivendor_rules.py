# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Hardening audit rules for PAN-OS, Junos OS, Cisco NX-OS, and OT switches."""

from typing import List, Optional, Tuple

from .model import Evidence, FAIL, PASS, RuleOutcome, WARN, absent
from .multivendor_parser import MVConfig, MVLine


def _find_lines(cfg: MVConfig, *needles: str) -> List[MVLine]:
    out: List[MVLine] = []
    for ln in cfg.lines:
        if any(n in ln.lower for n in needles):
            out.append(ln)
    return out


def _ev_lines(lines: List[MVLine], context: str) -> List[Evidence]:
    return [Evidence(line=l.line, text=l.text, context=context) for l in lines[:8]]


# ---------------------------------------------------------------------------
# PAN-OS
# ---------------------------------------------------------------------------

def check_panos_mgmt_https(cfg: MVConfig) -> RuleOutcome:
    """Verify PAN-OS management profiles disable cleartext HTTP and Telnet."""
    if cfg.xml_root is not None:
        bad = []
        for el in cfg.xml_root.findall(".//interface-management-profile/entry"):
            name = el.attrib.get("name") or "?"
            for tag in ("http", "telnet"):
                if (el.findtext(tag) or "").strip().lower() == "yes":
                    bad.append(Evidence(1, f"{name}: <{tag}>yes</{tag}>", "interface-management-profile"))
        if bad:
            return RuleOutcome(FAIL, "mv.mgmt_insecure.found", bad, {"count": len(bad)})
        return RuleOutcome(PASS, "mv.mgmt_insecure.ok")

    bad_lines = [
        l for l in cfg.lines
        if "interface-management-profile" in l.lower and (" http yes" in l.lower or " telnet yes" in l.lower)
    ]
    if bad_lines:
        return RuleOutcome(FAIL, "mv.mgmt_insecure.found", _ev_lines(bad_lines, "interface-management-profile"),
                           {"count": len(bad_lines)})
    return RuleOutcome(PASS, "mv.mgmt_insecure.ok")


def check_panos_ntp(cfg: MVConfig) -> RuleOutcome:
    """Verify PAN-OS has at least one NTP server configured."""
    if cfg.xml_root is not None:
        p = cfg.xml_root.find(".//ntp-servers/primary-ntp-server/ntp-server-address")
        if p is not None and (p.text or "").strip():
            return RuleOutcome(PASS, "mv.ntp.ok")
        return RuleOutcome(FAIL, "mv.ntp.missing", [absent("ev.no_directive", "system", what="ntp-servers")])
    hits = _find_lines(cfg, "ntp-servers primary-ntp-server", "ntp-servers secondary-ntp-server")
    if hits:
        return RuleOutcome(PASS, "mv.ntp.ok")
    return RuleOutcome(FAIL, "mv.ntp.missing", [absent("ev.no_directive", "system", what="ntp-servers")])


def check_panos_syslog(cfg: MVConfig) -> RuleOutcome:
    """Verify PAN-OS defines remote syslog forwarding profiles."""
    if cfg.xml_root is not None:
        if cfg.xml_root.findall(".//log-settings/syslog/entry"):
            return RuleOutcome(PASS, "mv.syslog.ok")
        return RuleOutcome(FAIL, "mv.syslog.missing", [absent("ev.no_directive", "log-settings", what="syslog")])
    hits = _find_lines(cfg, "log-settings syslog", "log-setting ")
    if hits:
        return RuleOutcome(PASS, "mv.syslog.ok")
    return RuleOutcome(FAIL, "mv.syslog.missing", [absent("ev.no_directive", "log-settings", what="syslog")])


def check_panos_any_any_policy(cfg: MVConfig) -> RuleOutcome:
    """Flag enabled PAN-OS security rules allowing any source, destination, service, and zone."""
    from services.policy_test.panos import parse_panos_config
    env = parse_panos_config(cfg.raw_text)
    bad = [r for r in env.policies if not r.disabled and r.action == "permit" and r.fields.is_any_any()]
    if bad:
        ev = [Evidence(1, r.raw_text.splitlines()[0], "security rulebase") for r in bad[:6]]
        return RuleOutcome(FAIL, "mv.any_any.found", ev, {"count": len(bad)})
    return RuleOutcome(PASS, "mv.any_any.ok")


def check_panos_log_at_end(cfg: MVConfig) -> RuleOutcome:
    """Verify PAN-OS security rules do not disable log-end."""
    if cfg.xml_root is not None:
        rules = cfg.xml_root.findall(".//rulebase/security/rules/entry")
        unlogged = [r.attrib.get("name") or "?" for r in rules if (r.findtext("log-end") or "").strip().lower() == "no"]
        if unlogged:
            ev = [Evidence(1, f"rule {n}: log-end=no", "security rulebase") for n in unlogged[:6]]
            return RuleOutcome(WARN, "mv.log_end.missing", ev, {"count": len(unlogged)})
        return RuleOutcome(PASS, "mv.log_end.ok")
    bad = [l for l in cfg.lines if "rulebase security rules" in l.lower and "log-end no" in l.lower]
    if bad:
        return RuleOutcome(WARN, "mv.log_end.missing", _ev_lines(bad, "security rulebase"), {"count": len(bad)})
    return RuleOutcome(PASS, "mv.log_end.ok")


# ---------------------------------------------------------------------------
# Junos OS
# ---------------------------------------------------------------------------

def check_junos_no_telnet(cfg: MVConfig) -> RuleOutcome:
    """Verify Telnet service is not enabled on Junos."""
    bad = [l for l in cfg.lines if "system services telnet" in l.lower]
    if bad:
        return RuleOutcome(FAIL, "mv.mgmt_insecure.found", _ev_lines(bad, "system services"), {"count": len(bad)})
    return RuleOutcome(PASS, "mv.mgmt_insecure.ok")


def check_junos_ssh_root_login(cfg: MVConfig) -> RuleOutcome:
    """Verify Junos SSH configuration denies direct root login."""
    allow = [l for l in cfg.lines if "services ssh root-login allow" in l.lower]
    if allow:
        return RuleOutcome(FAIL, "mv.root_ssh.allowed", _ev_lines(allow, "system services ssh"))
    deny = [l for l in cfg.lines if "services ssh root-login deny" in l.lower]
    if deny:
        return RuleOutcome(PASS, "mv.root_ssh.ok")
    return RuleOutcome(WARN, "mv.root_ssh.unset", [absent("ev.no_directive", "system services ssh", what="root-login deny")])


def check_junos_ntp(cfg: MVConfig) -> RuleOutcome:
    """Verify Junos system NTP server configuration is present."""
    if _find_lines(cfg, "system ntp server", "system ntp boot-server"):
        return RuleOutcome(PASS, "mv.ntp.ok")
    return RuleOutcome(FAIL, "mv.ntp.missing", [absent("ev.no_directive", "system", what="system ntp server")])


def check_junos_syslog(cfg: MVConfig) -> RuleOutcome:
    """Verify Junos remote syslog destination or logging rules exist."""
    if _find_lines(cfg, "system syslog host", "system syslog file"):
        return RuleOutcome(PASS, "mv.syslog.ok")
    return RuleOutcome(FAIL, "mv.syslog.missing", [absent("ev.no_directive", "system", what="system syslog")])


def check_junos_any_any_policy(cfg: MVConfig) -> RuleOutcome:
    """Flag permissive Any-Any SRX security policies."""
    from services.policy_test.junos import parse_junos_config
    env = parse_junos_config(cfg.raw_text)
    bad = [r for r in env.policies if not r.disabled and r.action == "permit" and r.fields.is_any_any()]
    if bad:
        ev = [Evidence(1, r.raw_text.splitlines()[0], "security policies") for r in bad[:6]]
        return RuleOutcome(FAIL, "mv.any_any.found", ev, {"count": len(bad)})
    return RuleOutcome(PASS, "mv.any_any.ok")


# ---------------------------------------------------------------------------
# Cisco NX-OS
# ---------------------------------------------------------------------------

def check_nxos_no_telnet(cfg: MVConfig) -> RuleOutcome:
    """Verify Cisco NX-OS does not enable feature telnet."""
    bad = [l for l in cfg.lines if l.lower == "feature telnet"]
    if bad:
        return RuleOutcome(FAIL, "mv.mgmt_insecure.found", _ev_lines(bad, "features"), {"count": len(bad)})
    return RuleOutcome(PASS, "mv.mgmt_insecure.ok")


def check_nxos_aaa_auth(cfg: MVConfig) -> RuleOutcome:
    """Verify Cisco NX-OS configures AAA login authentication."""
    if _find_lines(cfg, "aaa authentication login"):
        return RuleOutcome(PASS, "mv.aaa.ok")
    return RuleOutcome(FAIL, "mv.aaa.missing", [absent("ev.no_directive", "aaa", what="aaa authentication login")])


def check_nxos_ntp(cfg: MVConfig) -> RuleOutcome:
    """Verify Cisco NX-OS has an NTP server configured."""
    if _find_lines(cfg, "ntp server "):
        return RuleOutcome(PASS, "mv.ntp.ok")
    return RuleOutcome(FAIL, "mv.ntp.missing", [absent("ev.no_directive", "system", what="ntp server")])


def check_nxos_syslog(cfg: MVConfig) -> RuleOutcome:
    """Verify Cisco NX-OS configures remote syslog server."""
    if _find_lines(cfg, "logging server "):
        return RuleOutcome(PASS, "mv.syslog.ok")
    return RuleOutcome(FAIL, "mv.syslog.missing", [absent("ev.no_directive", "logging", what="logging server")])


def check_nxos_snmp_v3(cfg: MVConfig) -> RuleOutcome:
    """Verify Cisco NX-OS has no default public/private SNMP community strings."""
    bad = [
        l for l in cfg.lines
        if l.lower.startswith("snmp-server community ")
        and any(tok in ("public", "private") for tok in l.lower.split()[2:3])
    ]
    if bad:
        return RuleOutcome(FAIL, "mv.snmp_default.found", _ev_lines(bad, "snmp"), {"count": len(bad)})
    return RuleOutcome(PASS, "mv.snmp_default.ok")


# ---------------------------------------------------------------------------
# OT L2/L3 Industrial Switches
# ---------------------------------------------------------------------------

def check_ot_mgmt_encrypted(cfg: MVConfig) -> RuleOutcome:
    """Verify OT switch management disables cleartext HTTP and Telnet."""
    bad = [
        l for l in cfg.lines
        if l.lower in ("ip http server", "telnet enable", "service telnet")
        or l.lower.startswith("transport input telnet")
        or ("transport input" in l.lower and "telnet" in l.lower)
    ]
    if bad:
        return RuleOutcome(FAIL, "mv.mgmt_insecure.found", _ev_lines(bad, "management"), {"count": len(bad)})
    return RuleOutcome(PASS, "mv.mgmt_insecure.ok")


def check_ot_snmp_secure(cfg: MVConfig) -> RuleOutcome:
    """Verify OT switch does not expose default public/private SNMP communities."""
    bad = [
        l for l in cfg.lines
        if ("snmp" in l.lower and "community" in l.lower)
        and any(w in l.lower.split() for w in ("public", "private"))
    ]
    if bad:
        return RuleOutcome(FAIL, "mv.snmp_default.found", _ev_lines(bad, "snmp"), {"count": len(bad)})
    return RuleOutcome(PASS, "mv.snmp_default.ok")


def check_ot_ntp_syslog(cfg: MVConfig) -> RuleOutcome:
    """Verify OT switch configures both NTP/SNTP and remote Syslog forwarding."""
    has_ntp = bool(_find_lines(cfg, "ntp server", "sntp server"))
    has_log = bool(_find_lines(cfg, "logging host", "logging server", "syslog server"))
    if has_ntp and has_log:
        return RuleOutcome(PASS, "mv.ot_time_log.ok")
    missing: List[Evidence] = []
    if not has_ntp:
        missing.append(absent("ev.no_directive", "system", what="ntp server"))
    if not has_log:
        missing.append(absent("ev.no_directive", "logging", what="logging server"))
    return RuleOutcome(FAIL, "mv.ot_time_log.missing", missing, {"count": len(missing)})


def check_ot_port_security(cfg: MVConfig) -> RuleOutcome:
    """Verify L2 access port protections (port-security, BPDU guard, or storm-control)."""
    hits = _find_lines(cfg, "switchport port-security", "port-security", "storm-control", "bpduguard")
    if hits:
        return RuleOutcome(PASS, "mv.ot_portsec.ok")
    return RuleOutcome(WARN, "mv.ot_portsec.missing", [absent("ev.no_directive", "switchport", what="port-security / bpduguard")])


def check_ot_acl_segmentation(cfg: MVConfig) -> RuleOutcome:
    """Verify industrial cell segmentation via VLAN, ACL, or VRF bindings."""
    hits = _find_lines(cfg, "ip access-group", "ip access-list", "vlan ", "vrf ")
    if hits:
        return RuleOutcome(PASS, "mv.ot_seg.ok")
    return RuleOutcome(WARN, "mv.ot_seg.missing", [absent("ev.no_directive", "segmentation", what="VLAN / ACL")])
