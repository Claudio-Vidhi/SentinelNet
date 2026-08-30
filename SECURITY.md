# Security Policy

## Reporting a Vulnerability

We take the security of SentinelNet seriously. If you believe you have found a security vulnerability in SentinelNet, please follow these guidelines:

**DO NOT file a public GitHub issue.**

### Reporting Process
1. Use [GitHub Security Advisories](https://github.com/Claudio-Vidhi/SentinelNet/security/advisories/new) to submit a confidential report.
2. If Security Advisories are unavailable, contact the project maintainers privately.
3. Provide detailed steps to reproduce the issue, including:
   - Affected version(s) or commit SHA
   - Configuration preconditions (e.g., specific auth mode, tenant topology)
   - Proof of concept (PoC) or minimal reproduction steps
   - Potential impact of the vulnerability

### Response Timeline
- **Initial Acknowledgement**: Within 48 hours of receipt.
- **Triage and Verification**: Within 5 business days.
- **Fix and Disclosure**: Security patches will be prioritized and published alongside a security advisory acknowledging responsible disclosure.

---

## Supported Versions

SentinelNet is pre-1.0 and ships from a single line of development. Only the
latest released minor is supported: fixes land there, not in older tags.

| Version | Supported |
| --- | --- |
| 0.24.x (current) | Yes |
| < 0.24.0 | No — upgrade to the latest release |

---

## Air-Gap & Data Protection Principles

1. **Zero Outbound Telemetry**: SentinelNet makes no outbound tracking, telemetry, or metric reporting calls.
2. **Local Processing**: Network discovery (LLDP, ARP, MAC), SNMP polling, NetFlow/IPFIX collection, and Syslog ingesters operate entirely within the local host/network boundary.
3. **Cryptographic Storage**: Sensitive device passwords, enable secrets, and API tokens are encrypted with AES-GCM via `security/crypto_vault.py` and are never logged or exported in plain text.
