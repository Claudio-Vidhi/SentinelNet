# -*- coding: utf-8 -*-
"""Definizioni dei benchmark: metadati che legano una citazione a una regola.

Regole condivise fra benchmark (es. la versione TLS vale sia per CIS sia per
NIST SC-13) puntano alla STESSA funzione: cambia solo la citazione, il titolo e
il testo di rimedio. Nessuna logica e' duplicata.

Nomenclatura: CIS versiona i benchmark per prodotto (esiste un "CIS Fortinet
FortiGate Benchmark"), non esiste una "CIS Benchmark v4.0" globale.
"""

from typing import Any, Dict, List

from . import rules

BENCHMARKS: Dict[str, List[Dict[str, Any]]] = {
    "cis": [
        {"id": "AUD-CIS-01",
         "title": "Protocolli di gestione non sicuri (Telnet / HTTP)",
         "severity": "CRITICAL", "category": "Hardening",
         "check": rules.check_management_protocols,
         "remediation": "set allowaccess ssh https (rimuovere telnet e http)"},
        {"id": "AUD-CIS-02",
         "title": "Policy permissiva any-to-any",
         "severity": "CRITICAL", "category": "Access Rules",
         "check": rules.check_any_any_policy,
         "remediation": "Specificare srcaddr, dstaddr e service espliciti."},
        {"id": "AUD-CIS-03",
         "title": "Cifrari SSL/TLS legacy (TLS < 1.2)",
         "severity": "HIGH", "category": "Encryption",
         "check": rules.check_tls_version,
         "remediation": "set ssl-min-proto-version TLSv1-2"},
        {"id": "AUD-CIS-04",
         "title": "Timeout di inattivita' della console di gestione",
         "severity": "MEDIUM", "category": "Hardening",
         "check": rules.check_idle_timeout,
         "remediation": "set admintimeout 10"},
        {"id": "AUD-CIS-05",
         "title": "Community SNMP v1/v2c di default",
         "severity": "HIGH", "category": "Management",
         "check": rules.check_snmp_community,
         "remediation": "Disabilitare SNMP v1/v2c e configurare SNMPv3."},
        {"id": "AUD-CIS-06",
         "title": "Cifratura forte non applicata (strong-crypto)",
         "severity": "MEDIUM", "category": "Encryption",
         "check": rules.check_strong_crypto,
         "remediation": "set strong-crypto enable"},
    ],
    "nist": [
        {"id": "AUD-NIST-01",
         "title": "Protezione del perimetro (SC-7)",
         "severity": "CRITICAL", "category": "Access Rules",
         "check": rules.check_boundary_protection,
         "remediation": "Restringere le destinazioni delle policy in ingresso "
                        "da WAN."},
        {"id": "AUD-NIST-02",
         "title": "Restrizione dell'accesso amministrativo remoto (AC-17)",
         "severity": "CRITICAL", "category": "Hardening",
         "check": rules.check_admin_trusthost,
         "remediation": "set trusthost1 <subnet gestione> <netmask>"},
        {"id": "AUD-NIST-03",
         "title": "Protezione crittografica dei dati in transito (SC-13)",
         "severity": "HIGH", "category": "Encryption",
         "check": rules.check_tls_version,
         "remediation": "Imporre TLS 1.2+ e suite AES-256."},
        {"id": "AUD-NIST-04",
         "title": "Audit trail centralizzato (AU-2 / AU-12)",
         "severity": "MEDIUM", "category": "Logging",
         "check": rules.check_syslog,
         "remediation": "set status enable; set server <IP syslog>"},
    ],
    "pci": [
        {"id": "AUD-PCI-01",
         "title": "Req 1.2 — Porte di amministrazione esposte (22, 3389)",
         "severity": "CRITICAL", "category": "Access Rules",
         "check": rules.check_inbound_admin_ports,
         "remediation": "Bloccare SSH/RDP in ingresso da Internet; usare "
                        "VPN o bastion host."},
        {"id": "AUD-PCI-02",
         "title": "Req 1.3 — Traffico diretto fra Internet e CDE",
         "severity": "CRITICAL", "category": "Access Rules",
         "check": rules.check_any_any_policy,
         "remediation": "Isolare la rete cardholder dietro una DMZ."},
        {"id": "AUD-PCI-03",
         "title": "Req 2.2 — Default di fabbrica e policy password",
         "severity": "HIGH", "category": "Hardening",
         "check": rules.check_vendor_defaults,
         "remediation": "Rimuovere l'account 'admin' di default e abilitare "
                        "la password policy."},
        {"id": "AUD-PCI-04",
         "title": "Req 10.2 — Audit trail automatici",
         "severity": "MEDIUM", "category": "Logging",
         "check": rules.check_syslog,
         "remediation": "Configurare l'inoltro syslog verso il collector."},
    ],
}
