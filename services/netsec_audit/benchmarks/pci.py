# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""PCI-DSS v4.0, requisiti di rete: controlli FortiOS e Cisco IOS XE."""

from typing import Any, Dict, List

from .. import ios_rules, rules
from .vendors import FORTIOS, IOS

KEY = "pci"
TITLE = "PCI-DSS v4.0"
# "cis": benchmark di prodotto, uno per piattaforma. "framework": standard
# trasversali che citano controlli di piu' piattaforme.
GROUP = "framework"

# --- PCI-DSS v4.0 -------------------------------------------------------------

RULES: List[Dict[str, Any]] = [
    {"id": "AUD-PCI-01", "vendor": FORTIOS, "ref": "1.2", "level": 1,
     "automated": False,
     "title": {"it": "Req 1.2 — Porte di amministrazione esposte (22, 3389)",
               "en": "Req 1.2 — Exposed administration ports (22, 3389)"},
     "severity": "CRITICAL", "category": "Access Rules",
     "check": rules.check_inbound_admin_ports,
     "audit": "show firewall policy",
     "remediation": {"it": "Bloccare SSH/RDP in ingresso da Internet; usare "
                           "VPN o bastion host.",
                     "en": "Block inbound SSH/RDP from the Internet; use a VPN "
                           "or a bastion host."}},
    {"id": "AUD-PCI-02", "vendor": FORTIOS, "ref": "1.3", "level": 1,
     "automated": False,
     "title": {"it": "Req 1.3 — Traffico diretto fra Internet e CDE",
               "en": "Req 1.3 — Direct traffic between the Internet and the "
                     "CDE"},
     "severity": "CRITICAL", "category": "Access Rules",
     "check": rules.check_any_any_policy,
     "audit": "show firewall policy",
     "remediation": {"it": "Isolare la rete cardholder dietro una DMZ.",
                     "en": "Isolate the cardholder network behind a DMZ."}},
    {"id": "AUD-PCI-03", "vendor": FORTIOS, "ref": "2.2", "level": 1,
     "automated": True,
     "title": {"it": "Req 2.2 — Default di fabbrica e policy password",
               "en": "Req 2.2 — Factory defaults and password policy"},
     "severity": "HIGH", "category": "Hardening",
     "check": rules.check_vendor_defaults,
     "audit": "show system admin / show system password-policy",
     "remediation": {"it": "Rimuovere l'account 'admin' di default e abilitare "
                           "la password policy.",
                     "en": "Remove the default 'admin' account and enable the "
                           "password policy."}},
    {"id": "AUD-PCI-04", "vendor": FORTIOS, "ref": "10.2", "level": 1,
     "automated": True,
     "title": {"it": "Req 10.2 — Audit trail automatici",
               "en": "Req 10.2 — Automated audit trails"},
     "severity": "MEDIUM", "category": "Logging",
     "check": rules.check_syslog,
     "audit": "show log syslogd setting",
     "remediation": {"it": "Configurare l'inoltro syslog verso il collector.",
                     "en": "Configure syslog forwarding to the collector."}},
    {"id": "AUD-PCI-05", "vendor": FORTIOS, "ref": "10.3", "level": 1,
     "automated": False,
     "title": {"it": "Req 10.3 — Registrazione di ogni accesso alla rete",
               "en": "Req 10.3 — Logging of every network access"},
     "severity": "HIGH", "category": "Logging",
     "check": rules.check_policy_logging,
     "audit": "show firewall policy | grep logtraffic",
     "remediation": "config firewall policy / edit <id> / "
                    "set logtraffic all"},
    {"id": "AUD-PCI-06", "vendor": FORTIOS, "ref": "8.3.6", "level": 1,
     "automated": True,
     "title": {"it": "Req 8.3.6 — Complessita' minima delle password",
               "en": "Req 8.3.6 — Minimum password complexity"},
     "severity": "HIGH", "category": "Identity",
     "check": rules.check_password_policy_strength,
     "audit": "show system password-policy",
     "remediation": "config system password-policy / set minimum-length 12"},
    {"id": "AUD-PCI-07", "vendor": FORTIOS, "ref": "8.3.4", "level": 1,
     "automated": True,
     "title": {"it": "Req 8.3.4 — Blocco dopo tentativi falliti",
               "en": "Req 8.3.4 — Lockout after failed attempts"},
     "severity": "HIGH", "category": "Identity",
     "check": rules.check_admin_lockout,
     "audit": "show system global | grep admin-lockout",
     "remediation": "config system global / set admin-lockout-threshold 3 / "
                    "set admin-lockout-duration 900"},
    {"id": "AUD-PCI-08", "vendor": FORTIOS, "ref": "4.2.1", "level": 1,
     "automated": True,
     "title": {"it": "Req 4.2.1 — Crittografia forte in transito su reti "
                     "pubbliche",
               "en": "Req 4.2.1 — Strong cryptography in transit over public "
                     "networks"},
     "severity": "HIGH", "category": "Encryption",
     "check": rules.check_sslvpn_tls,
     "audit": "show vpn ssl settings | grep ssl-min-proto-ver",
     "remediation": "config vpn ssl settings / set ssl-min-proto-ver tls1-2"},
    {"id": "AUD-PCI-09", "vendor": FORTIOS, "ref": "5.2", "level": 1,
     "automated": False,
     "title": {"it": "Req 5.2 — Protezione da software malevolo",
               "en": "Req 5.2 — Protection from malicious software"},
     "severity": "HIGH", "category": "Threat Prevention",
     "check": rules.check_policy_security_profiles,
     "audit": "show firewall policy",
     "remediation": "config firewall policy / edit <id> / "
                    "set av-profile default / set ips-sensor default"},
    # --- equivalenti Cisco IOS ---
    {"id": "AUD-PCI-IOS-01", "vendor": IOS, "ref": "2.2", "level": 1,
     "automated": True,
     "title": {"it": "Req 2.2 — Default di fabbrica (community SNMP)",
               "en": "Req 2.2 — Factory defaults (SNMP communities)"},
     "severity": "CRITICAL", "category": "Hardening",
     "check": ios_rules.check_ios_snmp_default_community,
     "audit": "show running-config | include snmp-server community",
     "remediation": "no snmp-server community public RO"},
    {"id": "AUD-PCI-IOS-02", "vendor": IOS, "ref": "2.2.7", "level": 1,
     "automated": True,
     "title": {"it": "Req 2.2.7 — Accesso amministrativo non-console cifrato",
               "en": "Req 2.2.7 — Encrypted non-console administrative access"},
     "severity": "CRITICAL", "category": "Encryption",
     "check": ios_rules.check_ios_vty_transport_ssh,
     "audit": "show running-config | section line vty",
     "remediation": "line vty 0 15 / transport input ssh"},
    {"id": "AUD-PCI-IOS-03", "vendor": IOS, "ref": "10.2", "level": 1,
     "automated": True,
     "title": {"it": "Req 10.2 — Audit trail automatici",
               "en": "Req 10.2 — Automated audit trails"},
     "severity": "MEDIUM", "category": "Logging",
     "check": ios_rules.check_ios_logging_host,
     "audit": "show running-config | include logging host",
     "remediation": "logging host <ip collector>"},
    {"id": "AUD-PCI-IOS-04", "vendor": IOS, "ref": "10.2.1.2", "level": 1,
     "automated": True,
     "title": {"it": "Req 10.2.1.2 — Registrazione delle azioni "
                     "amministrative",
               "en": "Req 10.2.1.2 — Logging of administrative actions"},
     "severity": "HIGH", "category": "Logging",
     "check": ios_rules.check_ios_aaa_accounting_commands,
     "audit": "show running-config | include aaa accounting commands",
     "remediation": "aaa accounting commands 15 default start-stop "
                    "group tacacs+"},
    {"id": "AUD-PCI-IOS-05", "vendor": IOS, "ref": "10.6", "level": 1,
     "automated": True,
     "title": {"it": "Req 10.6 — Sincronizzazione oraria",
               "en": "Req 10.6 — Time synchronisation"},
     "severity": "MEDIUM", "category": "Logging",
     "check": ios_rules.check_ios_ntp_servers,
     "audit": "show running-config | include ntp server",
     "remediation": "ntp server <ip primario> / ntp server <ip secondario>"},
    {"id": "AUD-PCI-IOS-06", "vendor": IOS, "ref": "8.3.6", "level": 1,
     "automated": True,
     "title": {"it": "Req 8.3.6 — Password non memorizzate in chiaro",
               "en": "Req 8.3.6 — Passwords not stored in cleartext"},
     "severity": "HIGH", "category": "Identity",
     "check": ios_rules.check_ios_username_secret,
     "audit": "show running-config | include ^username",
     "remediation": "username <utente> algorithm-type sha256 secret "
                    "<password>"},
]
