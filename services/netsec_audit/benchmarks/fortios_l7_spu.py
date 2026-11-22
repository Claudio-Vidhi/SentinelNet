# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""FortiGate Layer-7 Security, IPS/SSL Tuning & SPU/NPU Optimization (vendor ``fortios``)."""

from typing import Any, Dict, List

from .. import rules
from .vendors import FORTIOS

KEY = "fortios-l7-spu"
TITLE = "FortiGate L7 Security & SPU Optimization"
GROUP = "vendor"


def _r(n, ref, level, title_it, title_en, severity, category, check, audit,
       remediation):
    return {"id": "AUD-FL7-%02d" % n, "vendor": FORTIOS, "ref": ref,
            "level": level, "automated": True,
            "title": {"it": title_it, "en": title_en},
            "severity": severity, "category": category, "check": check,
            "audit": audit, "remediation": remediation}


_VIP_TEMPLATE = (
    "config firewall vip\n"
    '    edit "VIP_WebServer_443"\n'
    "        set extip 203.0.113.10\n"
    '        set mappedip "10.10.20.50"\n'
    '        set extintf "wan1"\n'
    "        set portforward enable\n"
    "        set protocol tcp\n"
    "        set extport 443\n"
    "        set mappedport 443\n"
    "    next\n"
    "end\n"
    "config firewall ssl-ssh-profile\n"
    '    edit "SSL_Protect_WebServer"\n'
    "        config https\n"
    "            set ports 443\n"
    "            set status deep-inspection\n"
    "            set min-allowed-ssl-version tls-1.2\n"
    "            set unsupported-ssl-version block\n"
    "            set expired-server-cert block\n"
    "        end\n"
    "        set server-cert-mode replace\n"
    '        set server-cert "Cert_WebServer_Prod"\n'
    "    next\n"
    "end\n"
    "config ips sensor\n"
    '    edit "IPS_WebServer_Linux"\n'
    "        config entries\n"
    "            edit 1\n"
    "                set location server\n"
    "                set severity high critical\n"
    "                set os Linux\n"
    "                set application Apache Nginx\n"
    "                set status enable\n"
    "                set action block\n"
    "            next\n"
    "        end\n"
    "    next\n"
    "end\n"
    "config firewall policy\n"
    "    edit <id>\n"
    "        set inspection-mode flow\n"
    "        set utm-status enable\n"
    '        set ssl-ssh-profile "SSL_Protect_WebServer"\n'
    '        set ips-sensor "IPS_WebServer_Linux"\n'
    "        set logtraffic all\n"
    "    next\n"
    "end"
)

RULES: List[Dict[str, Any]] = [
    _r(1, "L7-VIP", 1,
       "Policy WAN verso VIP con IPS e Protecting SSL Server",
       "Inbound WAN-to-VIP policies with IPS and Protecting SSL Server",
       "HIGH", "Access Rules", rules.check_inbound_vip_l7_profiles,
       "show firewall vip\nshow firewall policy", _VIP_TEMPLATE),
    _r(2, "L7-DoS", 1,
       "DoS policy attiva sulle interfacce WAN",
       "Active DoS policy covering WAN interfaces",
       "MEDIUM", "Access Rules", rules.check_dos_policy_wan_coverage,
       "show firewall DoS-policy",
       "config firewall DoS-policy / edit 0 / set interface <wan> / "
       "set srcaddr all / set dstaddr all / set service ALL"),
    _r(3, "L7-SSL", 1,
       "Ispezione SSL/SSH attiva, TLS >= 1.2 e certificati dedicati",
       "SSL/SSH inspection enabled, TLS >= 1.2 and dedicated certificates",
       "HIGH", "Encryption", rules.check_ssl_inspection_profile,
       "show firewall ssl-ssh-profile\nshow firewall policy",
       "config firewall policy / edit <id> / set ssl-ssh-profile "
       "certificate-inspection  ·  config firewall ssl-ssh-profile / "
       "set min-allowed-ssl-version tls-1.2"),
    _r(4, "SPU-IPS", 1,
       "Sensori IPS mirati senza packet logging in produzione",
       "Targeted IPS sensors without packet logging in production",
       "MEDIUM", "Threat Prevention", rules.check_ips_sensor_optimization,
       "show ips sensor\nshow firewall policy",
       "config ips sensor / edit <sensore> / config entries / edit 1 / "
       "set log-packet disable / set location server|client / set os <OS>"),
    _r(5, "SPU-NPU", 1,
       "Offload hardware ASIC abilitato sulle policy",
       "Hardware ASIC offload enabled on firewall policies",
       "MEDIUM", "Performance & SPU", rules.check_policy_asic_offload,
       "show full-configuration firewall policy | grep auto-asic-offload",
       "config firewall policy / edit <id> / set auto-asic-offload enable"),
    _r(6, "SPU-FLOW", 1,
       "Ispezione flow-based single-pass preferita (CP9)",
       "Single-pass flow-based inspection preferred (CP9)",
       "MEDIUM", "Performance & SPU", rules.check_policy_inspection_mode,
       "show full-configuration firewall policy | grep inspection-mode",
       "config firewall policy / edit <id> / set inspection-mode flow"),
    _r(7, "SPU-BYP", 1,
       "Policy di bypass NPU limitate a host /32 e porte puntuali",
       "NPU bypass policies scoped to /32 hosts and exact ports",
       "MEDIUM", "Access Rules", rules.check_policy_bypass_scope,
       "show firewall policy",
       "config firewall policy / edit <id> / set srcaddr <host_32> / "
       "set dstaddr <host_32> / set service <porta_specifica>"),
    _r(8, "SPU-ALG", 2,
       "Session-helper SIP verificato (impatto offload NPU/VoIP)",
       "SIP session-helper reviewed (NPU offload/VoIP impact)",
       "LOW", "Performance & SPU", rules.check_sip_session_helper,
       "show system session-helper",
       "config system session-helper / delete <id_sip>"),
    _r(9, "L7-WAN", 1,
       "Profili di sicurezza sulle policy verso Internet",
       "Security profiles on Internet-bound policies",
       "HIGH", "Access Rules", rules.check_policy_security_profiles,
       "show firewall policy",
       {"it": "Applicare AV, IPS, web filter, DNS filter e application control "
              "alle policy verso la WAN.",
        "en": "Apply AV, IPS, web filter, DNS filter and application control "
              "to WAN-bound policies."}),
    _r(10, "L3-ANY", 1,
       "Nessuna policy permissiva any-to-any",
       "No permissive any-to-any policies",
       "CRITICAL", "Access Rules", rules.check_any_any_policy,
       "show firewall policy",
       {"it": "Specificare srcaddr, dstaddr e service espliciti.",
        "en": "Set explicit srcaddr, dstaddr and service."}),
    _r(11, "L7-LOG", 1,
       "Registrazione del traffico sulle policy accept",
       "Traffic logging on accept policies",
       "HIGH", "Logging", rules.check_policy_logging,
       "show firewall policy | grep logtraffic",
       "config firewall policy / edit <id> / set logtraffic all"),
]
