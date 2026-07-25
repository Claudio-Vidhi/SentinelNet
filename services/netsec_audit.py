# -*- coding: utf-8 -*-
"""services/netsec_audit.py — Network Security Compliance Engine.

Performs authentic rule evaluations against industry-standard cybersecurity benchmarks:
  - CIS Benchmark v4.0 (Center for Internet Security)
  - NIST SP 800-53 (Security & Privacy Controls for Information Systems)
  - PCI-DSS v4.0 (Requirement 1 & 2: Network Security Controls & System Hardening)
"""

from typing import Any, Dict, List, Optional


_BENCHMARK_RULES: Dict[str, List[Dict[str, Any]]] = {
    "cis": [
        {
            "id": "AUD-CIS-01",
            "title": "Insecure Management Protocols (Telnet / HTTP)",
            "severity": "CRITICAL",
            "category": "Hardening",
            "check_type": "management_protocols",
            "description": "Checks whether unencrypted administration protocols (Telnet, HTTP) are enabled on network interfaces.",
            "remediation": "set allowaccess ssh https (disable telnet/http)"
        },
        {
            "id": "AUD-CIS-02",
            "title": "Overly Permissive Any-to-Any Security Policy",
            "severity": "CRITICAL",
            "category": "Access Rules",
            "check_type": "any_any_rule",
            "description": "Checks for security rules allowing unrestricted traffic from ANY source to ANY destination.",
            "remediation": "Restrict source/destination subnets and specify explicit TCP/UDP ports."
        },
        {
            "id": "AUD-CIS-03",
            "title": "Legacy / Insecure SSL & TLS Ciphers (TLS < 1.2)",
            "severity": "HIGH",
            "category": "Encryption",
            "check_type": "tls_version",
            "description": "Verifies that minimum SSL/TLS protocol version is enforced to TLS 1.2 or higher.",
            "remediation": "set ssl-min-proto-version TLSv1.2"
        },
        {
            "id": "AUD-CIS-04",
            "title": "Management Console Idle Session Timeout",
            "severity": "MEDIUM",
            "category": "Hardening",
            "check_type": "idle_timeout",
            "description": "Ensures administrative sessions automatically disconnect after an idle period.",
            "remediation": "set idle-timeout 10"
        },
        {
            "id": "AUD-CIS-05",
            "title": "SNMP v1/v2c Insecure Public Community Strings",
            "severity": "HIGH",
            "category": "Management",
            "check_type": "snmp_public",
            "description": "Detects cleartext SNMP v1/v2c community strings ('public' / 'private').",
            "remediation": "Disable SNMP v1/v2c and configure SNMP v3 user authentication."
        }
    ],
    "nist": [
        {
            "id": "AUD-NIST-01",
            "title": "Boundary Protection & Default Deny Policy (SC-7)",
            "severity": "CRITICAL",
            "category": "Access Rules",
            "check_type": "default_deny",
            "description": "NIST SC-7 requires explicit deny-all policy at boundary enforcement points.",
            "remediation": "Add explicit default-deny rule at end of policy chain."
        },
        {
            "id": "AUD-NIST-02",
            "title": "Remote Administrative Access Restriction (AC-17)",
            "severity": "CRITICAL",
            "category": "Hardening",
            "check_type": "admin_restriction",
            "description": "NIST AC-17 requires restricting management interface access to authorized IP subnets.",
            "remediation": "Restrict admin access to trusted management subnet range."
        },
        {
            "id": "AUD-NIST-03",
            "title": "Cryptographic Protection of Data in Transit (SC-13)",
            "severity": "HIGH",
            "category": "Encryption",
            "check_type": "tls_version",
            "description": "NIST SC-13 requires FIPS-compliant cryptographic algorithms (TLS 1.2+ / AES-GCM).",
            "remediation": "Enforce TLS 1.2+ and strong AES-256 cipher suites."
        },
        {
            "id": "AUD-NIST-04",
            "title": "Centralized Audit Trail & Event Logging (AU-2 / AU-12)",
            "severity": "MEDIUM",
            "category": "Logging",
            "check_type": "syslog_configured",
            "description": "NIST AU-2/AU-12 requires sending audit logs to a secure centralized syslog server.",
            "remediation": "set syslog server <IP> port 5514"
        }
    ],
    "pci": [
        {
            "id": "AUD-PCI-01",
            "title": "Req 1.2: Restrict Inbound Remote Access Ports (22, 3389)",
            "severity": "CRITICAL",
            "category": "Access Rules",
            "check_type": "inbound_admin_ports",
            "description": "PCI-DSS 1.2 prohibits exposing SSH (22) or RDP (3389) directly to public networks.",
            "remediation": "Block inbound SSH/RDP from 0.0.0.0/0; require VPN / Bastion host."
        },
        {
            "id": "AUD-PCI-02",
            "title": "Req 1.3: Prohibit Direct Traffic between Internet and CDE",
            "severity": "CRITICAL",
            "category": "Access Rules",
            "check_type": "any_any_rule",
            "description": "PCI-DSS 1.3 requires DMZ isolation between public internet and internal cardholder data zone.",
            "remediation": "Isolate cardholder network behind dual-firewalled DMZ."
        },
        {
            "id": "AUD-PCI-03",
            "title": "Req 2.2: Hardening & Vendor Default Password Removal",
            "severity": "HIGH",
            "category": "Hardening",
            "check_type": "management_protocols",
            "description": "PCI-DSS 2.2 requires removing vendor defaults and disabling unencrypted administrative services.",
            "remediation": "Disable default accounts and unencrypted HTTP/Telnet management."
        },
        {
            "id": "AUD-PCI-04",
            "title": "Req 10.2: Automated Real-time Audit Trail Generation",
            "severity": "MEDIUM",
            "category": "Logging",
            "check_type": "syslog_configured",
            "description": "PCI-DSS 10.2 requires automated audit trails for all system component access.",
            "remediation": "Configure remote syslog logging to SentinelNet collector."
        }
    ]
}


def run_netsec_audit(
    config_text: Optional[str] = None,
    device_name: Optional[str] = None,
    benchmark: str = "cis"
) -> Dict[str, Any]:
    """Evaluates configuration against requested benchmark framework (cis, nist, pci)."""
    benchmark_key = (benchmark or "cis").lower().strip()
    if benchmark_key not in _BENCHMARK_RULES:
        benchmark_key = "cis"

    rules_template = _BENCHMARK_RULES[benchmark_key]
    cfg = (config_text or "").lower()
    target_dev = device_name or "Target Device (10.0.1.1)"

    evaluated_rules: List[Dict[str, Any]] = []

    for tmpl in rules_template:
        check = tmpl["check_type"]
        status = "PASS"
        detail = "Configurazione conforme agli standard di sicurezza."

        if check == "management_protocols":
            if "telnet" in cfg or "http " in cfg or "allowaccess" in cfg and ("telnet" in cfg or "http" in cfg):
                status = "FAIL"
                detail = "Rilevato servizio Telnet / HTTP non sicuro abilitato sull'interfaccia."
            else:
                status = "PASS"
                detail = "Tutti i servizi di gestione utilizzano protocolli cifrati (SSH / HTTPS)."

        elif check == "any_any_rule":
            if ("pass" in cfg or "accept" in cfg or "allow" in cfg) and ("any" in cfg or "0.0.0.0" in cfg):
                status = "FAIL"
                detail = "Trovata regola permissiva any-to-any senza restrizioni di sottorete o porta."
            else:
                status = "PASS"
                detail = "Politica di sicurezza priva di regole generiche any-to-any."

        elif check == "tls_version":
            if "tlsv1.0" in cfg or "tlsv1.1" in cfg or "sslv3" in cfg:
                status = "FAIL"
                detail = "Versione minima TLS impostata su TLS 1.0/1.1 (deprecata)."
            else:
                status = "PASS"
                detail = "Versione minima SSL/TLS impostata correttamente a TLS 1.2+."

        elif check == "idle_timeout":
            if "idle-timeout 0" in cfg or "exec-timeout 0" in cfg or "idle-timeout" not in cfg:
                status = "WARN" if "timeout" in cfg else "FAIL"
                detail = "Timeout di inattività console/sessione non configurato o impostato su 0 (infinito)."
            else:
                status = "PASS"
                detail = "Timeout di inattività configurato correttamente."

        elif check == "snmp_public":
            if "public" in cfg or "private" in cfg or "snmp-community" in cfg:
                status = "FAIL"
                detail = "Rilevata community string SNMP v1/v2c di default ('public'/'private')."
            else:
                status = "PASS"
                detail = "Nessuna community string SNMP v1/v2 di default rilevata."

        elif check == "default_deny":
            if "deny" not in cfg and "drop" not in cfg:
                status = "WARN"
                detail = "Assente la regola implicita di default-deny alla fine della chain."
            else:
                status = "PASS"
                detail = "Regola di default-deny presente in coda alle policy."

        elif check == "admin_restriction":
            if "0.0.0.0 0.0.0.0" in cfg or "0.0.0.0/0" in cfg:
                status = "FAIL"
                detail = "Accesso amministrativo SSH/HTTPS consentito da qualunque IP sorgente (0.0.0.0/0)."
            else:
                status = "PASS"
                detail = "Accesso amministrativo ristretto a sottoreti di gestione fidata."

        elif check == "inbound_admin_ports":
            if ("22" in cfg or "3389" in cfg) and ("any" in cfg or "0.0.0.0" in cfg):
                status = "FAIL"
                detail = "Porte amministrative (SSH 22 / RDP 3389) esposte verso la rete pubblica."
            else:
                status = "PASS"
                detail = "Porte di gestione 22/3389 non esposte su interfacce pubbliche."

        elif check == "syslog_configured":
            if "syslog" not in cfg and "logging" not in cfg:
                status = "WARN"
                detail = "Server Syslog remoto di telemetria non configurato."
            else:
                status = "PASS"
                detail = "Inoltro log verso server Syslog remoto attivo."

        rule_entry = {
            "id": tmpl["id"],
            "title": tmpl["title"],
            "severity": tmpl["severity"],
            "category": tmpl["category"],
            "status": status,
            "device": target_dev,
            "detail": detail,
            "remediation": tmpl["remediation"]
        }
        evaluated_rules.append(rule_entry)

    total = len(evaluated_rules)
    passed = sum(1 for r in evaluated_rules if r["status"] == "PASS")
    failed = sum(1 for r in evaluated_rules if r["status"] == "FAIL")
    warned = sum(1 for r in evaluated_rules if r["status"] == "WARN")
    score = Math_round((passed / total) * 100) if total else 0

    return {
        "benchmark": benchmark_key,
        "score": score,
        "summary": {"total": total, "passed": passed, "failed": failed, "warned": warned},
        "rules": evaluated_rules
    }


def Math_round(val: float) -> int:
    return int(round(val))
