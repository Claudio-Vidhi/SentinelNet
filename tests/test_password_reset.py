# -*- coding: utf-8 -*-
"""Password recovery by email.

Two properties carry the security of this flow and both are asserted here:
the link is mailed only to the address stored on the account (never to a
fallback such as the SMTP sender), and its URL comes from configuration rather
than from the request's Host header, which the caller controls.
"""
import os
import shutil
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_reset_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR
os.environ["SENTINELNET_BASE_URL"] = "https://sentinelnet.example.com"

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from core import app_settings  # noqa: E402
from security import password_reset, security_manager, user_manager  # noqa: E402
from services import mailer  # noqa: E402

USER, PASS = "reset-user", "PasswordSicura1!"
EMAIL = "operator@example.com"
NEW_PASS = "NuovaPasswordSicura2!"


class _Sent(list):
    """Collects what the mailer was asked to deliver."""

    def __call__(self, to, subject, body):
        self.append({"to": to, "subject": subject, "body": body})


class TestPasswordReset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        user_manager.create_user(USER, PASS, role="operator", email=EMAIL)
        cls.client = TestClient(app_server.app)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def setUp(self):
        password_reset.clear()
        security_manager._failed_attempts.clear()
        self.sent = _Sent()
        self._real_send = mailer.send_email
        mailer.send_email = self.sent

    def tearDown(self):
        mailer.send_email = self._real_send
        # Leave the account on its known password for the next test.
        user_manager.reset_password_break_glass(USER, PASS)

    def _request_reset(self, username=USER, **kwargs):
        return self.client.post("/api/auth/forgot-password",
                                json={"username": username}, **kwargs)

    def _token_from_mail(self):
        self.assertEqual(len(self.sent), 1)
        body = self.sent[0]["body"]
        return body.split("reset_token=")[1].split()[0]

    # --- delivery ---

    def test_link_goes_only_to_the_stored_address(self):
        r = self._request_reset()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.sent[0]["to"], EMAIL)

    def test_link_uses_configured_base_url_not_the_host_header(self):
        """A poisoned Host header must not end up in the mailed link."""
        r = self._request_reset(headers={"Host": "attacker.example"})
        self.assertEqual(r.status_code, 200)
        body = self.sent[0]["body"]
        self.assertIn("https://sentinelnet.example.com/?reset_token=", body)
        self.assertNotIn("attacker.example", body)

    def test_account_without_an_email_gets_no_mail(self):
        user_manager.create_user("no-address", PASS, role="viewer")
        try:
            r = self._request_reset("no-address")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(self.sent, [])
        finally:
            user_manager.delete_user("no-address")

    def test_disabled_account_gets_no_mail(self):
        user_manager.set_disabled(USER, True)
        try:
            self._request_reset()
            self.assertEqual(self.sent, [])
        finally:
            user_manager.set_disabled(USER, False)

    # --- enumeration ---

    def test_unknown_and_known_users_are_indistinguishable(self):
        known = self._request_reset()
        password_reset.clear()
        security_manager._failed_attempts.clear()
        unknown = self._request_reset("nobody-at-all")
        self.assertEqual(known.status_code, unknown.status_code)
        self.assertEqual(known.json(), unknown.json())

    def test_a_failing_mailer_does_not_change_the_answer(self):
        def boom(*_a, **_kw):
            raise mailer.MailerError("SMTP disabilitato")

        mailer.send_email = boom
        r = self._request_reset()
        self.assertEqual(r.status_code, 200)
        self.assertIn("Se l'account esiste", r.json()["message"])

    # --- redemption ---

    def test_token_sets_the_new_password_once(self):
        self._request_reset()
        token = self._token_from_mail()

        r = self.client.post("/api/auth/reset-password",
                             json={"token": token, "new_password": NEW_PASS})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(user_manager.verify_user(USER, NEW_PASS))

        # Single use: the same link must not work a second time.
        again = self.client.post("/api/auth/reset-password",
                                 json={"token": token, "new_password": "AltraPassword3!"})
        self.assertEqual(again.status_code, 400)
        self.assertTrue(user_manager.verify_user(USER, NEW_PASS))

    def test_expired_token_is_refused(self):
        token = password_reset.issue(USER)
        # Reach into the store rather than sleeping 15 minutes.
        digest = password_reset._digest(token)
        username, _exp = password_reset._tokens[digest]
        password_reset._tokens[digest] = (username, time.time() - 1)

        r = self.client.post("/api/auth/reset-password",
                             json={"token": token, "new_password": NEW_PASS})
        self.assertEqual(r.status_code, 400)
        self.assertTrue(user_manager.verify_user(USER, PASS))

    def test_forged_token_is_refused(self):
        r = self.client.post("/api/auth/reset-password",
                             json={"token": "not-a-real-token", "new_password": NEW_PASS})
        self.assertEqual(r.status_code, 400)
        self.assertTrue(user_manager.verify_user(USER, PASS))

    def test_weak_password_is_refused_and_token_survives(self):
        self._request_reset()
        token = self._token_from_mail()

        weak = self.client.post("/api/auth/reset-password",
                                json={"token": token, "new_password": "short"})
        self.assertEqual(weak.status_code, 400)
        # The policy check runs before the token is burned, so the user can
        # retry with a valid password instead of asking for a new link.
        ok = self.client.post("/api/auth/reset-password",
                              json={"token": token, "new_password": NEW_PASS})
        self.assertEqual(ok.status_code, 200)

    def test_reset_forces_a_change_at_next_login(self):
        self._request_reset()
        token = self._token_from_mail()
        self.client.post("/api/auth/reset-password",
                         json={"token": token, "new_password": NEW_PASS})
        self.assertTrue(user_manager.must_change_password(USER))

    # --- rate limit ---

    def test_repeated_requests_are_throttled(self):
        limit = security_manager.MAX_ATTEMPTS
        for _ in range(limit):
            self.assertEqual(self._request_reset().status_code, 200)
        self.assertEqual(self._request_reset().status_code, 429)


class TestBaseUrl(unittest.TestCase):
    def tearDown(self):
        os.environ["SENTINELNET_BASE_URL"] = "https://sentinelnet.example.com"

    def test_env_wins(self):
        os.environ["SENTINELNET_BASE_URL"] = "https://other.example.com/"
        self.assertEqual(app_settings.resolve_base_url(), "https://other.example.com")

    def test_wildcard_bind_refuses_to_guess(self):
        os.environ.pop("SENTINELNET_BASE_URL", None)
        os.environ["SENTINELNET_HOST"] = "0.0.0.0"
        try:
            with self.assertRaises(app_settings.BaseUrlError):
                app_settings.resolve_base_url()
        finally:
            os.environ.pop("SENTINELNET_HOST", None)

    def test_configured_host_builds_the_url(self):
        os.environ.pop("SENTINELNET_BASE_URL", None)
        os.environ["SENTINELNET_HOST"] = "192.0.2.10"
        try:
            self.assertTrue(
                app_settings.resolve_base_url().startswith("http://192.0.2.10:"))
        finally:
            os.environ.pop("SENTINELNET_HOST", None)


if __name__ == "__main__":
    unittest.main()
