# -*- coding: utf-8 -*-
"""OIDC single sign-on.

These tests exist because an unverified id_token is an admin account for
anyone who can reach the callback. Each one signs a token with a locally
generated key and asserts that a wrong signature, a wrong issuer, a wrong
audience, an expired token, a replayed nonce or an unsigned "alg: none" token
are all refused — and that a correct one still works.
"""
import os
import shutil
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_sso_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR
os.environ["SENTINELNET_BASE_URL"] = "https://sentinelnet.example.com"

import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from security import sso  # noqa: E402

ISSUER = "https://idp.example.com"
CLIENT_ID = "sentinelnet"
NONCE = "the-nonce-of-this-login"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

_DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": ISSUER + "/authorize",
    "token_endpoint": ISSUER + "/token",
    "jwks_uri": ISSUER + "/jwks",
}


class _FakeSigningKey:
    def __init__(self, key):
        self.key = key


def _config(**overrides):
    cfg = {
        "enabled": True,
        "provider_name": "Corporate SSO",
        "client_id": CLIENT_ID,
        "client_secret_enc": "",
        "issuer_url": ISSUER,
        "default_role": "viewer",
        "admin_group": "net-admins",
        "operator_group": "net-operators",
        "auto_provision": False,
        "sync_roles": False,
    }
    cfg.update(overrides)
    return cfg


def _token(key=_KEY, **overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "0123-4567",
        "iat": now,
        "exp": now + 300,
        "nonce": NONCE,
        "preferred_username": "mario.rossi",
        "email": "mario.rossi@example.com",
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256")


class TestIdTokenVerification(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def setUp(self):
        sso.clear()
        # No network: discovery and the JWKS lookup are answered locally.
        self._real_discover = sso.discover
        self._real_jwk = jwt.PyJWKClient
        sso.discover = lambda _issuer: _DISCOVERY
        jwt.PyJWKClient = lambda _uri: type(
            "C", (), {"get_signing_key_from_jwt":
                      staticmethod(lambda _t: _FakeSigningKey(_KEY.public_key()))})()

    def tearDown(self):
        sso.discover = self._real_discover
        jwt.PyJWKClient = self._real_jwk

    def test_a_valid_token_is_accepted(self):
        claims = sso.verify_id_token(_config(), _token(), NONCE)
        self.assertEqual(claims["preferred_username"], "mario.rossi")

    def test_a_token_signed_by_another_key_is_refused(self):
        with self.assertRaises(sso.SSOError):
            sso.verify_id_token(_config(), _token(key=_OTHER_KEY), NONCE)

    def test_an_unsigned_token_is_refused(self):
        """alg: none is the oldest JWT forgery there is."""
        now = int(time.time())
        forged = jwt.encode({"iss": ISSUER, "aud": CLIENT_ID, "sub": "x",
                             "iat": now, "exp": now + 300, "nonce": NONCE,
                             "preferred_username": "root"},
                            key="", algorithm="none")
        with self.assertRaises(sso.SSOError):
            sso.verify_id_token(_config(), forged, NONCE)

    def test_a_token_for_another_audience_is_refused(self):
        with self.assertRaises(sso.SSOError):
            sso.verify_id_token(_config(), _token(aud="another-app"), NONCE)

    def test_a_token_from_another_issuer_is_refused(self):
        with self.assertRaises(sso.SSOError):
            sso.verify_id_token(_config(), _token(iss="https://evil.example"), NONCE)

    def test_an_expired_token_is_refused(self):
        past = int(time.time()) - 3600
        with self.assertRaises(sso.SSOError):
            sso.verify_id_token(_config(), _token(iat=past, exp=past + 300), NONCE)

    def test_a_replayed_nonce_is_refused(self):
        with self.assertRaises(sso.SSOError):
            sso.verify_id_token(_config(), _token(nonce="a-different-login"), NONCE)

    def test_a_token_without_a_subject_is_refused(self):
        with self.assertRaises(sso.SSOError):
            sso.verify_id_token(_config(), _token(sub=None), NONCE)

    def test_hmac_and_none_are_not_accepted_algorithms(self):
        self.assertTrue(all(not a.startswith("HS") for a in sso.ALLOWED_ALGORITHMS))
        self.assertNotIn("none", sso.ALLOWED_ALGORITHMS)


class TestLoginState(unittest.TestCase):
    def setUp(self):
        sso.clear()
        self._real_discover = sso.discover
        sso.discover = lambda _issuer: _DISCOVERY

    def tearDown(self):
        sso.discover = self._real_discover

    def test_auth_url_carries_pkce_and_state(self):
        url = sso.start_login(_config(), "https://sentinelnet.example.com/cb")
        self.assertIn("code_challenge=", url)
        self.assertIn("code_challenge_method=S256", url)
        self.assertIn("response_type=code", url)
        self.assertIn("state=", url)
        self.assertIn("nonce=", url)

    def test_state_is_single_use(self):
        url = sso.start_login(_config(), "https://sentinelnet.example.com/cb")
        state = url.split("state=")[1].split("&")[0]
        self.assertIsNotNone(sso.consume_state(state))
        self.assertIsNone(sso.consume_state(state))

    def test_an_unknown_state_is_refused(self):
        self.assertIsNone(sso.consume_state("never-issued"))

    def test_an_expired_state_is_refused(self):
        url = sso.start_login(_config(), "https://sentinelnet.example.com/cb")
        state = url.split("state=")[1].split("&")[0]
        digest = sso._digest(state)
        nonce, verifier, _exp = sso._states[digest]
        sso._states[digest] = (nonce, verifier, time.time() - 1)
        self.assertIsNone(sso.consume_state(state))


class TestRoleMapping(unittest.TestCase):
    def test_admin_group_wins(self):
        claims = {"groups": ["net-operators", "net-admins"]}
        self.assertEqual(sso.resolve_role(_config(), claims), "admin")

    def test_operator_group_maps(self):
        self.assertEqual(sso.resolve_role(_config(), {"groups": ["net-operators"]}),
                         "operator")

    def test_unknown_groups_fall_back_to_the_default_role(self):
        self.assertEqual(sso.resolve_role(_config(), {"groups": ["sales"]}), "viewer")

    def test_group_match_is_case_insensitive_and_reads_roles_too(self):
        self.assertEqual(sso.resolve_role(_config(), {"roles": ["NET-ADMINS"]}), "admin")

    def test_a_blank_mapping_never_matches(self):
        cfg = _config(admin_group="", operator_group="")
        self.assertEqual(sso.resolve_role(cfg, {"groups": ["", "sales"]}), "viewer")

    def test_username_prefers_preferred_username_then_email_then_sub(self):
        self.assertEqual(sso.resolve_username({"preferred_username": "a",
                                               "email": "b@example.com",
                                               "sub": "d"}), "a")
        self.assertEqual(sso.resolve_username({"email": "b@example.com", "sub": "d"}),
                         "b@example.com")
        self.assertEqual(sso.resolve_username({"sub": "d"}), "d")
        with self.assertRaises(sso.SSOError):
            sso.resolve_username({})


if __name__ == "__main__":
    unittest.main()
