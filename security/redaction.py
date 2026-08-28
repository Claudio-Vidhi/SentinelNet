# -*- coding: utf-8 -*-
"""Secret redaction in contexts destined for external LLMs (finding I-1).

Exposes ``redact(payload)``: a pure, idempotent function that accepts ``str``
or nested ``dict``/``list`` structures and returns the same type with secrets
masked (``***REDACTED***``). Dict keys are preserved; only values are masked.

Should be called as the SINGLE point of passage before any data leaves the
process toward an LLM provider (in-app assistant in ``ai_assistant.chat`` and
MCP tool responses in ``mcp_server.api``).

Known limitations (documented, not handled):
- secrets in proprietary formats not listed among the patterns;
- secrets split across multiple lines (except PEM blocks, which are handled);
- generic binary/base64 values not attributable to a known pattern.

Does NOT mask: interface names, VLANs, hostnames, IP addresses (IPs are a
matter of separate GDPR policy, not of redaction).
"""

import re

MASK = "***REDACTED***"

# Patterns (regex, group-to-mask). Each regex has a 'secret' group
# that identifies only the portion to replace, preserving the rest of the line.
_PATTERNS = [
    # Cisco IOS: enable secret/password (with or without hash type: "enable secret 5 $1$...")
    re.compile(r"(?im)^(\s*enable\s+(?:secret|password)(?:\s+level\s+\d+)?(?:\s+\d)?\s+)(?P<secret>\S+)"),
    # Cisco IOS: username ... password/secret [type]
    re.compile(r"(?im)^(\s*username\s+\S+.*?\s(?:password|secret)(?:\s+\d)?\s+)(?P<secret>\S+)"),
    # SNMP community
    re.compile(r"(?im)^(\s*snmp-server\s+community\s+)(?P<secret>\S+)"),
    # SNMPv3 user: both passphrases sit on one line
    # (snmp-server user U G v3 auth sha <auth> priv aes 128 <priv>)
    re.compile(r"(?im)(\bauth\s+(?:md5|sha)\s+)(?P<secret>\S+)"),
    re.compile(r"(?im)(\bpriv\s+(?:aes(?:\s+\d+)?|des|3des)\s+)(?P<secret>\S+)"),
    # RADIUS/TACACS key (also "key 7 <hash>")
    re.compile(r"(?im)^(\s*(?:key|pac\s+key|shared-secret)(?:\s+\d)?\s+)(?P<secret>\S+)"),
    re.compile(r"(?im)((?:radius|tacacs)(?:-server)?\s+.*?\bkey(?:\s+\d)?\s+)(?P<secret>\S+)"),
    # generic WPA/PSK (Cisco WLC/AireOS, IOS wireless)
    re.compile(r"(?im)^(\s*(?:wpa-psk|psk|pre-shared-key|passphrase)\s+(?:ascii|hex)?\s*(?:\d\s+)?)(?P<secret>\S+)"),
    # FortiOS: set psksecret / passwd / password / private-key / passphrase
    re.compile(r"(?im)^(\s*set\s+(?:psksecret|passwd|password|private-key|passphrase|auth-pwd|key)\s+)(?P<secret>.+?)\s*$"),
    # generic api key / token / bearer in text or commands
    re.compile(r"(?i)((?:api[-_]?key|token|bearer|secret[-_]?key|client[-_]?secret)[\"'\s:=]+)(?P<secret>[A-Za-z0-9_\-\.\+/=]{8,})"),
    # PEM private key blocks (multiline)
    re.compile(
        r"(?s)(?P<secret>-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----)"
    ),
    # Fernet blob (urlsafe base64 starting with gAAAAA)
    re.compile(r"(?P<secret>gAAAAA[A-Za-z0-9_\-]{20,}={0,2})"),
]


def _redact_text(text: str) -> str:
    for pattern in _PATTERNS:
        text = pattern.sub(
            lambda m: m.group(0).replace(m.group("secret"), MASK),
            text,
        )
    return text


def redact(payload):
    """Masks secrets in ``payload`` (str, dict, list, tuple; other types
    returned unchanged). Idempotent: ``redact(redact(x)) == redact(x)``."""
    if isinstance(payload, str):
        return _redact_text(payload)
    if isinstance(payload, dict):
        return {k: redact(v) for k, v in payload.items()}
    if isinstance(payload, (list, tuple)):
        return type(payload)(redact(v) for v in payload)
    return payload
