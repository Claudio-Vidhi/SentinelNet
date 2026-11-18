# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Multi-vendor CIS & IEC 62443 benchmark definitions (PAN-OS, Junos, NX-OS, OT Switch)."""

from typing import Any, Dict, List

from .. import multivendor_rules as mv
from .vendors import JUNOS, NXOS, OT_SWITCH, PANOS


class _BenchmarkDef:
    def __init__(self, key: str, title: str, group: str, rules: List[Dict[str, Any]]) -> None:
        self.KEY = key
        self.TITLE = title
        self.GROUP = group
        self.RULES = rules


cis_panos = _BenchmarkDef(
    key="cis-panos",
    title="CIS Palo Alto Firewall Benchmark",
    group="cis",
    rules=[
        {"id": "AUD-PA-01", "vendor": PANOS, "ref": "1.1.1", "level": 1, "automated": True,
         "title": {"it": "Profili di gestione esposti via HTTP/Telnet", "en": "Management profiles allowing HTTP/Telnet"},
         "severity": "CRITICAL", "category": "Hardening",
         "check": mv.check_panos_mgmt_https,
         "audit": "show config running | match interface-management-profile",
         "remediation": "set network profiles interface-management-profile <prof> http no telnet no"},
        {"id": "AUD-PA-02", "vendor": PANOS, "ref": "1.2.1", "level": 1, "automated": True,
         "title": {"it": "Sincronizzazione NTP configurata", "en": "NTP synchronization configured"},
         "severity": "MEDIUM", "category": "Logging",
         "check": mv.check_panos_ntp,
         "audit": "show ntp",
         "remediation": "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address <NTP-IP>"},
        {"id": "AUD-PA-03", "vendor": PANOS, "ref": "1.4.1", "level": 1, "automated": True,
         "title": {"it": "Inoltro log verso Syslog configurato", "en": "Syslog log forwarding configured"},
         "severity": "HIGH", "category": "Logging",
         "check": mv.check_panos_syslog,
         "audit": "show config running | match log-settings",
         "remediation": "set shared log-settings syslog <profile> server <SYSLOG-IP>"},
        {"id": "AUD-PA-04", "vendor": PANOS, "ref": "6.1", "level": 1, "automated": True,
         "title": {"it": "Regole di sicurezza Any-Any consentite", "en": "Permissive Any-Any security rules"},
         "severity": "CRITICAL", "category": "Access Rules",
         "check": mv.check_panos_any_any_policy,
         "audit": "show running security-policy",
         "remediation": "Restringere from/to/source/destination/application sulle rulebase security"},
        {"id": "AUD-PA-05", "vendor": PANOS, "ref": "6.2", "level": 1, "automated": True,
         "title": {"it": "Logging a fine sessione su tutte le rule", "en": "Log at session end on security rules"},
         "severity": "MEDIUM", "category": "Logging",
         "check": mv.check_panos_log_at_end,
         "audit": "show running security-policy",
         "remediation": "set rulebase security rules <rule> log-end yes"},
    ],
)

cis_junos = _BenchmarkDef(
    key="cis-junos",
    title="CIS Juniper Junos Benchmark",
    group="cis",
    rules=[
        {"id": "AUD-JUN-01", "vendor": JUNOS, "ref": "1.1.1", "level": 1, "automated": True,
         "title": {"it": "Servizio Telnet disabilitato", "en": "Telnet management service disabled"},
         "severity": "CRITICAL", "category": "Hardening",
         "check": mv.check_junos_no_telnet,
         "audit": "show configuration system services",
         "remediation": "delete system services telnet"},
        {"id": "AUD-JUN-02", "vendor": JUNOS, "ref": "1.1.2", "level": 1, "automated": True,
         "title": {"it": "Login SSH diretto come root negato", "en": "Direct SSH root login denied"},
         "severity": "HIGH", "category": "Identity",
         "check": mv.check_junos_ssh_root_login,
         "audit": "show configuration system services ssh",
         "remediation": "set system services ssh root-login deny"},
        {"id": "AUD-JUN-03", "vendor": JUNOS, "ref": "2.1.1", "level": 1, "automated": True,
         "title": {"it": "Server NTP configurato", "en": "NTP server configured"},
         "severity": "MEDIUM", "category": "Logging",
         "check": mv.check_junos_ntp,
         "audit": "show configuration system ntp",
         "remediation": "set system ntp server <NTP-IP>"},
        {"id": "AUD-JUN-04", "vendor": JUNOS, "ref": "2.2.1", "level": 1, "automated": True,
         "title": {"it": "Syslog remoto configurato", "en": "Remote syslog configured"},
         "severity": "HIGH", "category": "Logging",
         "check": mv.check_junos_syslog,
         "audit": "show configuration system syslog",
         "remediation": "set system syslog host <SYSLOG-IP> any info"},
        {"id": "AUD-JUN-05", "vendor": JUNOS, "ref": "3.1.1", "level": 1, "automated": True,
         "title": {"it": "Policy SRX Any-Any consentite", "en": "Permissive SRX Any-Any policies"},
         "severity": "CRITICAL", "category": "Access Rules",
         "check": mv.check_junos_any_any_policy,
         "audit": "show security policies",
         "remediation": "Restringere address-book e application sulle security policies"},
    ],
)

cis_nxos = _BenchmarkDef(
    key="cis-nxos",
    title="CIS Cisco NX-OS Benchmark",
    group="cis",
    rules=[
        {"id": "AUD-NX-01", "vendor": NXOS, "ref": "1.1", "level": 1, "automated": True,
         "title": {"it": "Feature Telnet disabilitata su NX-OS", "en": "Telnet feature disabled on NX-OS"},
         "severity": "CRITICAL", "category": "Hardening",
         "check": mv.check_nxos_no_telnet,
         "audit": "show feature | include telnet",
         "remediation": "no feature telnet"},
        {"id": "AUD-NX-02", "vendor": NXOS, "ref": "1.2", "level": 1, "automated": True,
         "title": {"it": "Autenticazione login AAA configurata", "en": "AAA login authentication configured"},
         "severity": "HIGH", "category": "Identity",
         "check": mv.check_nxos_aaa_auth,
         "audit": "show running-config | include aaa",
         "remediation": "aaa authentication login default group tacacs+ local"},
        {"id": "AUD-NX-03", "vendor": NXOS, "ref": "2.1", "level": 1, "automated": True,
         "title": {"it": "Server NTP configurato", "en": "NTP server configured"},
         "severity": "MEDIUM", "category": "Logging",
         "check": mv.check_nxos_ntp,
         "audit": "show ntp peers",
         "remediation": "ntp server <NTP-IP> use-vrf management"},
        {"id": "AUD-NX-04", "vendor": NXOS, "ref": "2.2", "level": 1, "automated": True,
         "title": {"it": "Logging remoto configurato", "en": "Remote logging server configured"},
         "severity": "HIGH", "category": "Logging",
         "check": mv.check_nxos_syslog,
         "audit": "show logging info",
         "remediation": "logging server <SYSLOG-IP> 5 use-vrf management"},
        {"id": "AUD-NX-05", "vendor": NXOS, "ref": "3.1", "level": 1, "automated": True,
         "title": {"it": "Nessuna community SNMP predefinita public/private", "en": "No default public/private SNMP community"},
         "severity": "HIGH", "category": "Hardening",
         "check": mv.check_nxos_snmp_v3,
         "audit": "show snmp community",
         "remediation": "no snmp-server community public"},
    ],
)

iec62443_ot = _BenchmarkDef(
    key="iec62443-ot",
    title="IEC 62443-4-2 Industrial Switch Hardening",
    group="vendor",
    rules=[
        {"id": "AUD-OT-01", "vendor": OT_SWITCH, "ref": "SR 3.1", "level": 1, "automated": True,
         "title": {"it": "Accesso di gestione OT solo cifrato (no HTTP/Telnet)", "en": "Encrypted OT management only (no HTTP/Telnet)"},
         "severity": "CRITICAL", "category": "Hardening",
         "check": mv.check_ot_mgmt_encrypted,
         "audit": "Verificare servizi HTTP/Telnet attivi sullo switch industriale",
         "remediation": "no ip http server / transport input ssh"},
        {"id": "AUD-OT-02", "vendor": OT_SWITCH, "ref": "SR 1.7", "level": 1, "automated": True,
         "title": {"it": "Nessuna community SNMP default public/private", "en": "No default public/private SNMP community"},
         "severity": "HIGH", "category": "Identity",
         "check": mv.check_ot_snmp_secure,
         "audit": "show snmp",
         "remediation": "Rimuovere public/private ed abilitare SNMPv3 authPriv"},
        {"id": "AUD-OT-03", "vendor": OT_SWITCH, "ref": "SR 2.8", "level": 1, "automated": True,
         "title": {"it": "NTP e Syslog configurati per correlazione eventi OT", "en": "NTP and Syslog configured for OT event correlation"},
         "severity": "HIGH", "category": "Logging",
         "check": mv.check_ot_ntp_syslog,
         "audit": "show ntp / show logging",
         "remediation": "Configurare ntp server e logging host verso SIEM di stabilimento"},
        {"id": "AUD-OT-04", "vendor": OT_SWITCH, "ref": "SR 3.5", "level": 1, "automated": True,
         "title": {"it": "Protezione porte L2 (Port Security / BPDU Guard / Storm Control)", "en": "L2 port hardening (Port Security / BPDU Guard / Storm Control)"},
         "severity": "MEDIUM", "category": "Hardening",
         "check": mv.check_ot_port_security,
         "audit": "show port-security / show spanning-tree summary",
         "remediation": "switchport port-security / spanning-tree bpduguard enable"},
        {"id": "AUD-OT-05", "vendor": OT_SWITCH, "ref": "SR 5.1", "level": 1, "automated": True,
         "title": {"it": "Segmentazione Zone/Conduit (VLAN / ACL / VRF)", "en": "Zones & Conduits segmentation (VLAN / ACL / VRF)"},
         "severity": "MEDIUM", "category": "Access Rules",
         "check": mv.check_ot_acl_segmentation,
         "audit": "show vlan / show access-lists",
         "remediation": "Segmentare celle PLC/SCADA su VLAN dedicate con ACL di ingresso"},
    ],
)

MODULES = (cis_panos, cis_junos, cis_nxos, iec62443_ot)
