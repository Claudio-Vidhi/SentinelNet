# -*- coding: utf-8 -*-
"""Redazione segreti nei contesti destinati a LLM esterni (finding I-1).

Espone ``redact(payload)``: funzione pura e idempotente che accetta ``str``
oppure strutture annidate ``dict``/``list`` e ritorna lo stesso tipo con i
segreti mascherati (``***REDACTED***``). Le chiavi dei dict sono preservate;
solo i valori vengono mascherati.

Va chiamata come UNICO punto di passaggio prima che qualunque dato lasci il
processo verso un provider LLM (assistente in-app in ``ai_assistant.chat`` e
risposte dei tool MCP in ``mcp_server.api``).

Limiti noti (documentati, non gestiti):
- segreti in formati proprietari non elencati nei pattern;
- segreti spezzati su più righe (eccetto blocchi PEM, gestiti);
- valori binari/base64 generici non riconducibili a un pattern noto.

NON maschera: nomi interfaccia, VLAN, hostname, indirizzi IP (gli IP sono
materia di policy GDPR separata, non di redazione).
"""

import re

MASK = "***REDACTED***"

# Pattern (regex, gruppo-da-mascherare). Ogni regex ha un gruppo 'secret'
# che identifica la sola porzione da sostituire, preservando il resto della riga.
_PATTERNS = [
    # Cisco IOS: enable secret/password (con o senza tipo hash: "enable secret 5 $1$...")
    re.compile(r"(?im)^(\s*enable\s+(?:secret|password)(?:\s+level\s+\d+)?(?:\s+\d)?\s+)(?P<secret>\S+)"),
    # Cisco IOS: username ... password/secret [tipo]
    re.compile(r"(?im)^(\s*username\s+\S+.*?\s(?:password|secret)(?:\s+\d)?\s+)(?P<secret>\S+)"),
    # SNMP community
    re.compile(r"(?im)^(\s*snmp-server\s+community\s+)(?P<secret>\S+)"),
    # RADIUS/TACACS key (anche "key 7 <hash>")
    re.compile(r"(?im)^(\s*(?:key|pac\s+key|shared-secret)(?:\s+\d)?\s+)(?P<secret>\S+)"),
    re.compile(r"(?im)((?:radius|tacacs)(?:-server)?\s+.*?\bkey(?:\s+\d)?\s+)(?P<secret>\S+)"),
    # WPA/PSK generici (Cisco WLC/AireOS, IOS wireless)
    re.compile(r"(?im)^(\s*(?:wpa-psk|psk|pre-shared-key|passphrase)\s+(?:ascii|hex)?\s*(?:\d\s+)?)(?P<secret>\S+)"),
    # FortiOS: set psksecret / passwd / password / private-key / passphrase
    re.compile(r"(?im)^(\s*set\s+(?:psksecret|passwd|password|private-key|passphrase|auth-pwd|key)\s+)(?P<secret>.+?)\s*$"),
    # generici api key / token / bearer in testo o comandi
    re.compile(r"(?i)((?:api[-_]?key|token|bearer|secret[-_]?key|client[-_]?secret)[\"'\s:=]+)(?P<secret>[A-Za-z0-9_\-\.\+/=]{8,})"),
    # blocchi PEM di chiave privata (multiriga)
    re.compile(
        r"(?s)(?P<secret>-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----)"
    ),
    # blob Fernet (base64 urlsafe che inizia con gAAAAA)
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
    """Maschera i segreti in ``payload`` (str, dict, list, tuple; altri tipi
    ritornati invariati). Idempotente: ``redact(redact(x)) == redact(x)``."""
    if isinstance(payload, str):
        return _redact_text(payload)
    if isinstance(payload, dict):
        return {k: redact(v) for k, v in payload.items()}
    if isinstance(payload, (list, tuple)):
        return type(payload)(redact(v) for v in payload)
    return payload
