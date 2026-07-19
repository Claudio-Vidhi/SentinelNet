# -*- coding: utf-8 -*-
"""Test per redaction.py (finding I-1): mascheramento segreti multivendor,
idempotenza, sopravvivenza dei dati non sensibili e verifica che i choke-point
LLM (ai_assistant.chat) applichino la redazione."""

import unittest
from unittest.mock import patch, MagicMock

from ai import ai_assistant
from security.redaction import redact, MASK

PEM_BLOCK = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA7yn3bRHQ8xKf\nQIDAQABAoIBAQCwg8mJx\n"
    "-----END RSA PRIVATE KEY-----"
)

GOLDEN_CONFIG = f"""
hostname CORE-SW-01
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
enable password 7 0822455D0A16
username admin privilege 15 secret 5 $1$abcd$XyZ123456789
username backup password 0 SuperSegreta123
snmp-server community C0mmun1tyRW rw
radius-server host 10.1.1.5 key 7 104D000A0618
tacacs-server key SharedTacacsKey99
interface GigabitEthernet1/0/1
 description uplink verso DIST-01
 switchport access vlan 42
config system interface
    set psksecret ENC_XXXsecretvalueXXX
    set password FortiPass123!
end
wpa-psk ascii 0 MyWifiPassphrase2024
api_key = sk-abc123def456ghi789
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig
{PEM_BLOCK}
fernet: gAAAAABkX1234567890abcdefghijklmnopqrstuv==
"""

SECRETS = [
    "$1$mERr$hx5rVt7rPNoS4wqbXKX7m0",
    "0822455D0A16",
    "$1$abcd$XyZ123456789",
    "SuperSegreta123",
    "C0mmun1tyRW",
    "104D000A0618",
    "SharedTacacsKey99",
    "ENC_XXXsecretvalueXXX",
    "FortiPass123!",
    "MyWifiPassphrase2024",
    "sk-abc123def456ghi789",
    "eyJhbGciOiJIUzI1NiJ9.payload.sig",
    "MIIEpAIBAAKCAQEA7yn3bRHQ8xKf",
    "gAAAAABkX1234567890abcdefghijklmnopqrstuv==",
]

SURVIVORS = [
    "hostname CORE-SW-01",
    "GigabitEthernet1/0/1",
    "vlan 42",
    "10.1.1.5",
    "uplink verso DIST-01",
]


class TestRedaction(unittest.TestCase):
    def test_golden_fixture_no_secret_survives(self):
        out = redact(GOLDEN_CONFIG)
        for secret in SECRETS:
            self.assertNotIn(secret, out, f"segreto non mascherato: {secret}")
        self.assertIn(MASK, out)

    def test_non_secrets_survive(self):
        out = redact(GOLDEN_CONFIG)
        for keep in SURVIVORS:
            self.assertIn(keep, out, f"dato legittimo perso: {keep}")

    def test_idempotent(self):
        once = redact(GOLDEN_CONFIG)
        self.assertEqual(once, redact(once))

    def test_nested_structures(self):
        payload = {
            "config": GOLDEN_CONFIG,
            "devices": [{"ip": "10.0.0.1", "snmp": "snmp-server community S3gr3ta ro"}],
            "count": 3,
        }
        out = redact(payload)
        self.assertNotIn("S3gr3ta", str(out))
        self.assertEqual(out["count"], 3)
        self.assertEqual(out["devices"][0]["ip"], "10.0.0.1")

    def test_non_string_passthrough(self):
        self.assertEqual(redact(42), 42)
        self.assertIsNone(redact(None))


class TestChatChokePoint(unittest.TestCase):
    @patch("ai.ai_assistant.requests.post")
    def test_chat_redacts_before_send(self, mock_post):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"content": [{"type": "text", "text": "ok"}]}
        mock_post.return_value = resp

        ai_assistant.chat(
            [{"role": "user", "content": "config:\nenable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0"}],
            provider="anthropic", api_key="k", rate_limit_rpm=0,
        )
        sent = mock_post.call_args.kwargs["json"]
        self.assertNotIn("$1$mERr$hx5rVt7rPNoS4wqbXKX7m0", str(sent))
        self.assertIn(MASK, str(sent))


if __name__ == "__main__":
    unittest.main()
