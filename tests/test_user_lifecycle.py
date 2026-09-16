# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Account lifecycle after creation: approval of invited accounts, recovery by
address, admin-initiated reset, last login, the user's own profile and
"sign out everywhere".

The property that matters most: an invitation mailed to the wrong address
must not open the dashboard. Accepting it creates an account that cannot sign
in until an administrator approves it.
"""
import os
import shutil
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_lifecycle_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR
os.environ["SENTINELNET_BASE_URL"] = "https://sentinelnet.example.com"

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from routers.deps import CSRF_HEADER  # noqa: E402
from security import (email_verify, password_reset, security_manager,  # noqa: E402
                      user_invite, user_manager)
from services import mailer  # noqa: E402

ADMIN, PASS = "life-admin", "PasswordSicura1!"
USER, USER_EMAIL = "life-user", "Life.User@example.com"
INVITED = "invitee@example.com"
H = {CSRF_HEADER: "1"}


class _Sent(list):
    def __call__(self, to, subject, body):
        self.append({"to": to, "subject": subject, "body": body})

    def token(self, name):
        return self[-1]["body"].split(f"{name}=")[1].split()[0]


def _login(username, password):
    client = TestClient(app_server.app)
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    return client, r


class TestUserLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        user_manager.create_user(ADMIN, PASS, role="admin")
        cls.admin, r = _login(ADMIN, PASS)
        assert r.status_code == 200, r.text

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def setUp(self):
        user_invite.clear()
        password_reset.clear()
        email_verify.clear()
        security_manager._failed_attempts.clear()
        user_manager.create_user(USER, PASS, role="viewer", email=USER_EMAIL)
        self.sent = _Sent()
        self._real_send = mailer.send_email
        mailer.send_email = self.sent

    def tearDown(self):
        mailer.send_email = self._real_send
        user_manager.delete_user(USER)
        user_manager.delete_user(INVITED)

    def _accept_invite(self, role="viewer"):
        r = self.admin.post("/api/users/invite", json={"email": INVITED, "role": role}, headers=H)
        self.assertEqual(r.status_code, 200, r.text)
        return TestClient(app_server.app).post(
            "/api/auth/accept-invite",
            json={"token": self.sent.token("invite_token"), "password": PASS})

    # --- approval of invited accounts ---

    def test_accepted_invitation_waits_for_approval(self):
        r = self._accept_invite()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["pending_approval"])
        _c, login = _login(INVITED, PASS)
        self.assertEqual(login.status_code, 403)
        self.assertNotIn("access_token", login.json())

    def test_pending_account_gets_no_recovery_mail(self):
        self._accept_invite()
        self.sent.clear()
        TestClient(app_server.app).post("/api/auth/forgot-password", json={"username": INVITED})
        self.assertEqual(self.sent, [])

    def test_admin_approval_opens_the_account(self):
        self._accept_invite()
        listed = {u["username"]: u for u in self.admin.get("/api/users").json()}
        self.assertTrue(listed[INVITED]["pending_approval"])

        r = self.admin.post("/api/users/approve", json={"username": INVITED}, headers=H)
        self.assertEqual(r.status_code, 200)
        _c, login = _login(INVITED, PASS)
        self.assertEqual(login.status_code, 200)

    def test_non_admin_cannot_approve(self):
        self._accept_invite()
        viewer, _r = _login(USER, PASS)
        r = viewer.post("/api/users/approve", json={"username": INVITED}, headers=H)
        self.assertEqual(r.status_code, 403)
        self.assertTrue(user_manager.is_pending(INVITED))

    def test_pending_admin_is_not_an_active_admin(self):
        before = user_manager.count_active_admins()
        self._accept_invite(role="admin")
        self.assertEqual(user_manager.count_active_admins(), before)
        self.assertFalse(user_manager.is_last_active_admin(INVITED))

    # --- recovery by address ---

    def test_recovery_accepts_the_email_address(self):
        r = TestClient(app_server.app).post("/api/auth/forgot-password",
                                            json={"username": "life.user@EXAMPLE.com"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual([m["to"] for m in self.sent], [USER_EMAIL])
        token = self.sent.token("reset_token")
        self.assertEqual(password_reset.consume(token), USER)

    def test_one_mail_per_account_sharing_an_address(self):
        user_manager.create_user("life-user-2", PASS, role="viewer", email=USER_EMAIL)
        try:
            TestClient(app_server.app).post("/api/auth/forgot-password",
                                            json={"username": USER_EMAIL})
            self.assertEqual(len(self.sent), 2)
            owners = {password_reset.consume(m["body"].split("reset_token=")[1].split()[0])
                      for m in self.sent}
            self.assertEqual(owners, {USER, "life-user-2"})
        finally:
            user_manager.delete_user("life-user-2")

    # --- admin-initiated reset ---

    def test_admin_sends_reset_link_to_stored_address(self):
        r = self.admin.post("/api/users/send-reset", json={"username": USER}, headers=H)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.sent[0]["to"], USER_EMAIL)
        self.assertEqual(password_reset.consume(self.sent.token("reset_token")), USER)

    def test_admin_reset_without_address_is_refused(self):
        user_manager.set_email(USER, "")
        r = self.admin.post("/api/users/send-reset", json={"username": USER}, headers=H)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.sent, [])

    def test_admin_reset_failure_is_reported(self):
        def boom(*_a, **_kw):
            raise mailer.MailerError("SMTP disabilitato")
        mailer.send_email = boom
        r = self.admin.post("/api/users/send-reset", json={"username": USER}, headers=H)
        self.assertEqual(r.status_code, 400)
        self.assertIn("SMTP", r.json()["detail"])

    # --- new user without a password: setup link ---

    def _create(self, **fields):
        body = {"username": "life-new", "password": "", "role": "viewer", "email": "new.hire@example.com"}
        body.update(fields)
        return self.admin.post("/api/users", json=body, headers=H)

    def test_new_user_with_email_and_no_password_gets_a_setup_link(self):
        try:
            r = self._create()
            self.assertEqual(r.status_code, 200, r.text)
            self.assertTrue(r.json()["setup_link_sent"])
            self.assertEqual(self.sent[0]["to"], "new.hire@example.com")
            token = self.sent.token("reset_token")

            ok = TestClient(app_server.app).post("/api/auth/reset-password",
                                                 json={"token": token, "new_password": PASS})
            self.assertEqual(ok.status_code, 200)
            # The user chose this password: nothing left to force at first login.
            self.assertFalse(user_manager.must_change_password("life-new"))
            _c, login = _login("life-new", PASS)
            self.assertEqual(login.status_code, 200)
        finally:
            user_manager.delete_user("life-new")

    def test_setup_link_lasts_a_day(self):
        try:
            self._create()
            digest = password_reset._digest(self.sent.token("reset_token"))
            _user, expires = password_reset._tokens[digest]
            import time
            self.assertGreater(expires - time.time(), 23 * 3600)
        finally:
            user_manager.delete_user("life-new")

    def test_new_user_without_password_needs_an_email(self):
        r = self._create(email="")
        self.assertEqual(r.status_code, 400)
        self.assertIsNone(user_manager.get_role("life-new"))

    def test_failed_setup_mail_leaves_no_account(self):
        def boom(*_a, **_kw):
            raise mailer.MailerError("SMTP disabilitato")
        mailer.send_email = boom
        r = self._create()
        self.assertEqual(r.status_code, 400)
        self.assertIsNone(user_manager.get_role("life-new"))

    def test_new_user_with_password_gets_no_mail(self):
        try:
            r = self._create(password=PASS)
            self.assertEqual(r.status_code, 200)
            self.assertFalse(r.json()["setup_link_sent"])
            self.assertEqual(self.sent, [])
            self.assertTrue(user_manager.must_change_password("life-new"))
        finally:
            user_manager.delete_user("life-new")

    # --- last login ---

    def test_last_login_is_recorded(self):
        before = {u["username"]: u for u in self.admin.get("/api/users").json()}
        self.assertFalse(before[USER]["last_login"])
        _login(USER, PASS)
        after = {u["username"]: u for u in self.admin.get("/api/users").json()}
        self.assertTrue(after[USER]["last_login"])

    # --- own profile ---

    def test_profile_shows_own_data_only(self):
        viewer, _r = _login(USER, PASS)
        p = viewer.get("/api/profile").json()
        self.assertEqual(p["username"], USER)
        self.assertEqual(p["email"], USER_EMAIL)
        self.assertEqual(p["role"], "viewer")
        for key in ("groups", "allowed_tabs", "last_login"):
            self.assertIn(key, p)
        self.assertNotIn("hashed_password", p)

    def test_email_change_needs_the_current_password(self):
        viewer, _r = _login(USER, PASS)
        r = viewer.post("/api/profile/email",
                        json={"email": "new@example.com", "current_password": "wrong-one"},
                        headers=H)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.sent, [])

    def test_email_change_takes_effect_only_after_verification(self):
        viewer, _r = _login(USER, PASS)
        r = viewer.post("/api/profile/email",
                        json={"email": "new@example.com", "current_password": PASS},
                        headers=H)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.sent[0]["to"], "new@example.com")
        self.assertEqual(user_manager.get_email(USER), USER_EMAIL)

        token = self.sent.token("verify_email_token")
        anon = TestClient(app_server.app)
        self.assertEqual(anon.post("/api/auth/verify-email", json={"token": token}).status_code, 200)
        self.assertEqual(user_manager.get_email(USER), "new@example.com")
        self.assertEqual(anon.post("/api/auth/verify-email", json={"token": token}).status_code, 400)

    def test_clearing_the_email_needs_no_verification(self):
        viewer, _r = _login(USER, PASS)
        r = viewer.post("/api/profile/email",
                        json={"email": "", "current_password": PASS}, headers=H)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(user_manager.get_email(USER), "")
        self.assertEqual(self.sent, [])

    # --- sign out everywhere ---

    def test_logout_all_invalidates_every_session(self):
        first, _r = _login(USER, PASS)
        second, _r = _login(USER, PASS)
        self.assertEqual(second.get("/api/profile").status_code, 200)

        r = first.post("/api/auth/logout-all", headers=H)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(second.get("/api/profile").status_code, 401)

        third, login = _login(USER, PASS)
        self.assertEqual(login.status_code, 200)
        self.assertEqual(third.get("/api/profile").status_code, 200)


if __name__ == "__main__":
    unittest.main()
