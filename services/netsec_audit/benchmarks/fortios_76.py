# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Fortinet FortiOS 7.6 Best Practices (vendor ``fortios``).

CIS publishes no FortiOS 7.6 benchmark (the newest is 7.4.x v1.0.1, see
``cis_fortigate``). This set follows Fortinet's "Best Practices FortiOS
7.6.0" guide, revision of 2026-09-14: every recommendation that a backup
can prove or disprove. ``ref`` is the guide's page and section, so a report
can be checked against the PDF. Process advice (change management, DR,
migration) and anything the configuration cannot show is left out.
"""

from typing import Any, Dict, List

from .. import rules
from .vendors import FORTIOS

KEY = "fortios-76"
TITLE = "Fortinet FortiOS 7.6 Best Practices"
# "vendor": the vendor's own guide, not an independent standard.
GROUP = "vendor"


def _r(n, ref, level, title_it, title_en, severity, category, check, audit,
       remediation):
    return {"id": "AUD-F76-%02d" % n, "vendor": FORTIOS, "ref": ref,
            "level": level, "automated": True,
            "title": {"it": title_it, "en": title_en},
            "severity": severity, "category": category, "check": check,
            "audit": audit, "remediation": remediation}


_G = "config system global\n    show full-configuration | grep "

RULES: List[Dict[str, Any]] = [
    # --- Basic configuration (p.7) -------------------------------------------
    _r(1, "p.7 Basic configuration", 1, "Hostname significativo",
       "Meaningful hostname", "LOW", "Hardening",
       rules.check_hostname, _G + "hostname",
       "config system global / set hostname <nome>"),
    _r(2, "p.7 Basic configuration", 1, "Sincronizzazione NTP",
       "NTP synchronisation", "MEDIUM", "Hardening",
       rules.check_ntp, "show system ntp",
       "config system ntp / set ntpsync enable"),
    _r(3, "p.7 Basic configuration", 1, "Password policy degli amministratori",
       "Administrator password policy", "HIGH", "Hardening",
       rules.check_password_policy_strength, "show system password-policy",
       "config system password-policy / set status enable / "
       "set minimum-length 14"),
    # --- Administrator access (p.10-13) --------------------------------------
    _r(4, "p.10 Management network", 1,
       "Nessun servizio di gestione su interfacce WAN",
       "No management service on WAN interfaces", "CRITICAL", "Hardening",
       rules.check_admin_access_on_wan,
       "config system interface\n    show full-configuration | grep allowaccess",
       {"it": "Togliere https/ssh/http/telnet da allowaccess sulle WAN e "
              "amministrare da un'interfaccia di gestione o via VPN.",
        "en": "Remove https/ssh/http/telnet from allowaccess on WAN ports "
              "and manage from a management interface or over VPN."}),
    _r(5, "p.12 Administrative settings", 1,
       "Nessun Telnet/HTTP sulle interfacce",
       "No Telnet/HTTP on interfaces", "CRITICAL", "Hardening",
       rules.check_management_protocols,
       "config system interface\n    show full-configuration | grep allowaccess",
       "config system interface / edit <port> / set allowaccess ssh https"),
    _r(6, "p.11 User authentication", 1,
       "Accesso amministrativo ristretto (trusthost)",
       "Restricted admin access (trusthost)", "CRITICAL", "Hardening",
       rules.check_admin_trusthost, "show system admin",
       "config system admin / edit <utente> / "
       "set trusthost1 <subnet gestione> <netmask>"),
    _r(7, "p.11 User authentication", 1,
       "Autenticazione a due fattori degli amministratori",
       "Two-factor authentication for administrators", "HIGH", "Hardening",
       rules.check_admin_mfa, "show system admin",
       "config system admin / edit <utente> / set two-factor fortitoken"),
    _r(8, "p.12 Administrative settings", 1,
       "Timeout di inattivita' della console",
       "Idle timeout on the console", "MEDIUM", "Hardening",
       rules.check_idle_timeout, _G + "admintimeout",
       "config system global / set admintimeout 5"),
    _r(9, "p.12 Administrative settings", 1, "TLS della GUI di amministrazione",
       "TLS of the admin GUI", "HIGH", "Encryption",
       rules.check_tls_version, _G + "admin-https-ssl-versions",
       "config system global / set admin-https-ssl-versions tlsv1-2 tlsv1-3"),
    _r(10, "p.12 Administrative settings", 1,
       "«admin-host» con redirect HTTPS attivo",
       "«admin-host» with HTTPS redirect on", "MEDIUM", "Hardening",
       rules.check_admin_host, _G + "admin-host",
       "config system global / set admin-host <hostname>"),
    _r(11, "p.12 Administrative settings", 1,
       "Certificato dedicato su GUI e SSL-VPN",
       "Dedicated certificate on GUI and SSL-VPN", "MEDIUM", "Encryption",
       rules.check_factory_certificates,
       _G + "admin-server-cert\nshow vpn ssl settings",
       "config system global / set admin-server-cert <certificato>"),
    _r(12, "p.13 PBKDF2 hashing", 1, "Password amministrative in PBKDF2",
       "Admin passwords in PBKDF2", "MEDIUM", "Hardening",
       rules.check_admin_password_hash, "show system admin   (PB2, not SH2)",
       "config system admin / edit <utente> / set password <nuova>"),
    # --- Logging (p.18) ------------------------------------------------------
    _r(13, "p.18 Logging and reporting", 1, "Log inoltrati fuori dall'apparato",
       "Logs forwarded off the unit", "HIGH", "Logging",
       rules.check_remote_logging,
       "show log fortianalyzer setting\nshow log syslogd setting\n"
       "show log fortiguard setting",
       "config log fortianalyzer setting / set status enable / "
       "set server <ip>"),
    _r(14, "p.18 Logging and reporting", 1, "Syslog cifrato in transito",
       "Syslog encrypted in transit", "MEDIUM", "Logging",
       rules.check_syslog_encrypted,
       "config log syslogd setting\n    show full-configuration | grep enc-algorithm",
       "config log syslogd setting / set enc-algorithm high"),
    # --- Security profiles, HA (p.24, p.38) ----------------------------------
    _r(15, "p.24 Security profiles", 1,
       "Profili di sicurezza sulle policy verso Internet",
       "Security profiles on Internet-bound policies", "HIGH", "Access Rules",
       rules.check_policy_security_profiles, "show firewall policy",
       {"it": "Applicare AV, IPS, web filter e application control alle "
              "policy verso la WAN.",
        "en": "Apply AV, IPS, web filter and application control to "
              "WAN-bound policies."}),
    _r(16, "p.38 High availability", 2, "Cluster HA sull'apparato di bordo",
       "HA cluster on the edge unit", "MEDIUM", "Resilience",
       rules.check_ha_configured, "show system ha",
       "config system ha / set mode a-p / set group-name <nome> / "
       "set monitor <interfacce>"),
    # --- Policies (p.43-44) --------------------------------------------------
    _r(17, "p.43 Policies", 1, "DoS policy", "DoS policy", "MEDIUM",
       "Access Rules", rules.check_dos_policy, "show firewall DoS-policy",
       {"it": "Creare una DoS policy (tcp_syn_flood, tcp_port_scan, "
              "tcp/ip_src/dst_session) in monitor, poi passare a block.",
        "en": "Create a DoS policy (tcp_syn_flood, tcp_port_scan, "
              "tcp/ip_src/dst_session) in monitor, then switch to block."}),
    _r(18, "p.43 Policies", 1, "Local-in policy a protezione dell'apparato",
       "Local-in policies protecting the unit", "MEDIUM", "Access Rules",
       rules.check_local_in_policy, "show firewall local-in-policy",
       "config firewall local-in-policy / edit 0 / set intf <wan> / "
       "set srcaddr <fidati> / set action accept"),
    _r(19, "p.43 Policies", 1, "Policy legate a interfacce specifiche",
       "Policies bound to specific interfaces", "MEDIUM", "Access Rules",
       rules.check_policy_any_interface, "show firewall policy",
       {"it": "Sostituire «any» con le interfacce o zone reali.",
        "en": "Replace «any» with the real interfaces or zones."}),
    _r(20, "p.43 Policies", 1, "Nome univoco per ogni policy",
       "Unique name on every policy", "LOW", "Access Rules",
       rules.check_policy_names, "show firewall policy",
       "config firewall policy / edit <id> / set name <nome univoco>"),
    _r(21, "p.44 Policies", 1, "Nessun oggetto all/any nelle policy",
       "No all/any objects in policies", "CRITICAL", "Access Rules",
       rules.check_any_any_policy, "show firewall policy",
       {"it": "Specificare srcaddr, dstaddr e service espliciti.",
        "en": "Set explicit srcaddr, dstaddr and service."}),
    _r(22, "p.44 Virtual IPs", 1, "Policy deny con match-vip",
       "Deny policies with match-vip", "MEDIUM", "Access Rules",
       rules.check_deny_match_vip, "show firewall policy",
       "config firewall policy / edit <id> / set match-vip enable"),
    # --- Hardening (p.46-51) -------------------------------------------------
    _r(23, "p.46 Physical security", 1,
       "Installazione automatica da USB disabilitata",
       "Automatic install from USB disabled", "MEDIUM", "Hardening",
       rules.check_auto_install, "show system auto-install",
       "config system auto-install / set auto-install-config disable / "
       "set auto-install-image disable"),
    _r(24, "p.47 Encrypted protocols", 1, "Solo SNMPv3", "SNMPv3 only",
       "HIGH", "Management", rules.check_snmp_v3_only,
       "show system snmp community\nshow system snmp user",
       {"it": "Disabilitare le community v1/v2c e configurare utenti SNMPv3.",
        "en": "Disable v1/v2c communities and configure SNMPv3 users."}),
    _r(25, "p.47 Encrypted protocols", 1, "LDAPS e RADSEC",
       "LDAPS and RADSEC", "HIGH", "Encryption",
       rules.check_auth_server_encryption,
       "show user ldap\nshow user radius",
       "config user ldap / edit <server> / set secure ldaps  ·  "
       "config user radius / edit <server> / set transport-protocol tls"),
    _r(26, "p.47 Encrypted protocols", 1, "Autenticazione NTP",
       "NTP authentication", "LOW", "Encryption",
       rules.check_ntp_auth, "show system ntp",
       "config system ntp / config ntpserver / edit <id> / "
       "set authentication enable / set key-id <n> / set key <chiave>"),
    _r(27, "p.47 Encrypted protocols", 1, "Autenticazione MD5 su OSPF",
       "MD5 authentication on OSPF", "MEDIUM", "Encryption",
       rules.check_ospf_auth, "show router ospf",
       "config router ospf / config ospf-interface / edit <nome> / "
       "set authentication message-digest"),
    _r(28, "p.48 Strong ciphers", 1, "Crittografia forte (strong-crypto)",
       "Strong cryptography (strong-crypto)", "HIGH", "Encryption",
       rules.check_strong_crypto, _G + "strong-crypto",
       "config system global / set strong-crypto enable"),
    _r(29, "p.48 Strong ciphers", 1, "Cifrari a chiave statica disabilitati",
       "Static-key ciphers disabled", "MEDIUM", "Encryption",
       rules.check_static_key_ciphers, _G + "ssl-static-key-ciphers",
       "config system global / set ssl-static-key-ciphers disable"),
    _r(30, "p.48 Strong ciphers", 2, "Parametri Diffie-Hellman a 8192 bit",
       "Diffie-Hellman parameters at 8192 bits", "LOW", "Encryption",
       rules.check_dh_params, _G + "dh-params",
       "config system global / set dh-params 8192"),
    _r(31, "p.49 Secure password storage", 1,
       "Cifratura dei dati privati con chiave propria",
       "Private-data encryption with an own key", "HIGH", "Encryption",
       rules.check_private_data_encryption, _G + "private-data-encryption",
       "config system global / set private-data-encryption enable"),
    _r(32, "p.51 Non-standard admin ports", 1, "Porte amministrative non standard",
       "Non-standard admin ports", "LOW", "Hardening",
       rules.check_admin_ports_changed, _G + "admin-s",
       "config system global / set admin-sport <porta> / "
       "set admin-ssh-port <porta>"),
    _r(33, "p.51 Non-standard admin usernames", 1,
       "Account «admin» di default rinominato",
       "Default «admin» account renamed", "HIGH", "Hardening",
       rules.check_vendor_defaults, "show system admin",
       {"it": "Creare un super_admin con nome proprio ed eliminare «admin».",
        "en": "Create a named super_admin and delete «admin»."}),
    # --- Remote access (p.35) ------------------------------------------------
    _r(34, "p.35 SSL VPN and Agentless VPN", 1,
       "SSL-VPN tunnel mode (non supportato da 7.6.3)",
       "SSL-VPN tunnel mode (unsupported from 7.6.3)", "HIGH", "VPN",
       rules.check_sslvpn_tunnel_mode,
       "show vpn ssl settings\nshow vpn ssl web portal",
       {"it": "Migrare gli utenti a IPsec dial-up (FortiClient) o ZTNA, poi "
              "disattivare il tunnel mode.",
        "en": "Move users to IPsec dial-up (FortiClient) or ZTNA, then turn "
              "tunnel mode off."}),
]
