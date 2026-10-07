# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""NIST SP 800-53 Rev. 5: controlli FortiOS e Cisco IOS XE."""

from typing import Any, Dict, List

from .. import ios_rules, rules
from .vendors import FORTIOS, IOS

KEY = "nist"
TITLE = "NIST SP 800-53 Rev. 5"
# "cis": benchmark di prodotto, uno per piattaforma. "framework": standard
# trasversali che citano controlli di piu' piattaforme.
GROUP = "framework"

# --- NIST SP 800-53 Rev. 5 ----------------------------------------------------

RULES: List[Dict[str, Any]] = [
    {"id": "AUD-NIST-01", "vendor": FORTIOS, "ref": "SC-7", "level": 1,
     "automated": False,
     "title": {"it": "Protezione del perimetro (SC-7)",
               "en": "Boundary protection (SC-7)"},
     "severity": "CRITICAL", "category": "Access Rules",
     "check": rules.check_boundary_protection,
     "audit": "show firewall policy",
     "remediation": {"it": "Restringere le destinazioni delle policy in "
                           "ingresso da WAN.",
                     "en": "Narrow the destinations of the WAN-inbound "
                           "policies."}},
    {"id": "AUD-NIST-02", "vendor": FORTIOS, "ref": "AC-17", "level": 1,
     "automated": True,
     "title": {"it": "Restrizione dell'accesso amministrativo remoto (AC-17)",
               "en": "Restriction of remote administrative access (AC-17)"},
     "severity": "CRITICAL", "category": "Hardening",
     "check": rules.check_admin_trusthost,
     "audit": "show system admin",
     "remediation": "config system admin / edit <utente> / "
                    "set trusthost1 <subnet gestione> <netmask>"},
    {"id": "AUD-NIST-03", "vendor": FORTIOS, "ref": "SC-13", "level": 1,
     "automated": True,
     "title": {"it": "Protezione crittografica dei dati in transito (SC-13)",
               "en": "Cryptographic protection of data in transit (SC-13)"},
     "severity": "HIGH", "category": "Encryption",
     "check": rules.check_tls_version,
     "audit": "show system global | grep ssl",
     "remediation": {"it": "Imporre TLS 1.2+ e suite AES-256.",
                     "en": "Enforce TLS 1.2+ and AES-256 suites."}},
    {"id": "AUD-NIST-04", "vendor": FORTIOS, "ref": "AU-2 / AU-12", "level": 1,
     "automated": True,
     "title": {"it": "Audit trail centralizzato (AU-2 / AU-12)",
               "en": "Centralised audit trail (AU-2 / AU-12)"},
     "severity": "MEDIUM", "category": "Logging",
     "check": rules.check_syslog,
     "audit": "show log syslogd setting",
     "remediation": "config log syslogd setting / set status enable / "
                    "set server <IP syslog>"},
    {"id": "AUD-NIST-05", "vendor": FORTIOS, "ref": "IA-5", "level": 1,
     "automated": True,
     "title": {"it": "Robustezza degli autenticatori (IA-5)",
               "en": "Authenticator strength (IA-5)"},
     "severity": "HIGH", "category": "Identity",
     "check": rules.check_password_policy_strength,
     "audit": "show system password-policy",
     "remediation": "config system password-policy / set status enable / "
                    "set minimum-length 14"},
    {"id": "AUD-NIST-06", "vendor": FORTIOS, "ref": "AC-7", "level": 1,
     "automated": True,
     "title": {"it": "Blocco dopo tentativi di accesso falliti (AC-7)",
               "en": "Lockout after failed login attempts (AC-7)"},
     "severity": "HIGH", "category": "Identity",
     "check": rules.check_admin_lockout,
     "audit": "show system global | grep admin-lockout",
     "remediation": "config system global / set admin-lockout-threshold 3 / "
                    "set admin-lockout-duration 900"},
    {"id": "AUD-NIST-07", "vendor": FORTIOS, "ref": "AC-12", "level": 1,
     "automated": True,
     "title": {"it": "Terminazione della sessione (AC-12)",
               "en": "Session termination (AC-12)"},
     "severity": "MEDIUM", "category": "Hardening",
     "check": rules.check_idle_timeout,
     "audit": "show system global | grep admintimeout",
     "remediation": "config system global / set admintimeout 5"},
    {"id": "AUD-NIST-08", "vendor": FORTIOS, "ref": "AU-8", "level": 1,
     "automated": True,
     "title": {"it": "Marcatura temporale attendibile (AU-8)",
               "en": "Trustworthy time stamps (AU-8)"},
     "severity": "MEDIUM", "category": "Logging",
     "check": rules.check_ntp,
     "audit": "show system ntp",
     "remediation": "config system ntp / set ntpsync enable"},
    # --- equivalenti Cisco IOS ---
    {"id": "AUD-NIST-IOS-01", "vendor": IOS, "ref": "AC-17", "level": 1,
     "automated": True,
     "title": {"it": "Restrizione dell'accesso amministrativo remoto (AC-17)",
               "en": "Restriction of remote administrative access (AC-17)"},
     "severity": "CRITICAL", "category": "Access Rules",
     "check": ios_rules.check_ios_vty_access_class,
     "audit": "show running-config | section line vty",
     "remediation": "line vty 0 15 / access-class <ACL gestione> in"},
    {"id": "AUD-NIST-IOS-02", "vendor": IOS, "ref": "SC-8", "level": 1,
     "automated": True,
     "title": {"it": "Riservatezza della sessione di gestione (SC-8)",
               "en": "Confidentiality of the management session (SC-8)"},
     "severity": "CRITICAL", "category": "Encryption",
     "check": ios_rules.check_ios_vty_transport_ssh,
     "audit": "show running-config | section line vty",
     "remediation": "line vty 0 15 / transport input ssh"},
    {"id": "AUD-NIST-IOS-03", "vendor": IOS, "ref": "AU-2 / AU-12", "level": 1,
     "automated": True,
     "title": {"it": "Audit trail centralizzato (AU-2 / AU-12)",
               "en": "Centralised audit trail (AU-2 / AU-12)"},
     "severity": "MEDIUM", "category": "Logging",
     "check": ios_rules.check_ios_logging_host,
     "audit": "show running-config | include logging host",
     "remediation": "logging host <ip collector>"},
    {"id": "AUD-NIST-IOS-04", "vendor": IOS, "ref": "IA-5", "level": 1,
     "automated": True,
     "title": {"it": "Robustezza degli autenticatori (IA-5)",
               "en": "Authenticator strength (IA-5)"},
     "severity": "HIGH", "category": "Identity",
     "check": ios_rules.check_ios_username_secret,
     "audit": "show running-config | include ^username",
     "remediation": "username <utente> algorithm-type sha256 secret "
                    "<password>"},
    {"id": "AUD-NIST-IOS-05", "vendor": IOS, "ref": "AC-12", "level": 1,
     "automated": True,
     "title": {"it": "Terminazione della sessione (AC-12)",
               "en": "Session termination (AC-12)"},
     "severity": "MEDIUM", "category": "Hardening",
     "check": ios_rules.check_ios_vty_exec_timeout,
     "audit": "show running-config | section line vty",
     "remediation": "line vty 0 15 / exec-timeout 10 0"},
    {"id": "AUD-NIST-IOS-06", "vendor": IOS, "ref": "AU-8", "level": 1,
     "automated": True,
     "title": {"it": "Marcatura temporale attendibile (AU-8)",
               "en": "Trustworthy time stamps (AU-8)"},
     "severity": "MEDIUM", "category": "Logging",
     "check": ios_rules.check_ios_ntp_servers,
     "audit": "show running-config | include ntp server",
     "remediation": "ntp server <ip primario> / ntp server <ip secondario>"},
]
