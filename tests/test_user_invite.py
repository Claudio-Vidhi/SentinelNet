# -*- coding: utf-8 -*-
"""User invitations by email.

The property under test: username and role come from the invitation the
administrator issued, never from the request that redeems it. An invitee who
edits the accept call must not be able to name a different account or claim a
role they were not offered.
"""
import os
import shutil
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_invite_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR
os.environ["SENTINELNET_BASE_URL"] = "https://sentinelnet.example.com"

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from routers.deps import CSRF_HEADER  # noqa: E402
from security import user_invite, user_manager  # noqa: E402
from services import mailer  # noqa: E402

ADMIN, ADMIN_PASS = "invite-admin", "PasswordSicura1!"
INVITED = "nuovo.collega@example.com"
CHOSEN_PASS = "PasswordScelta2!"


class _Sent(list):
    def __call__(self, to, subject, body):
        self.append({"to": to, "subject": subject, "body": body})


class TestUserInvite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        user_manager.create_user(ADMIN, ADMIN_PASS, role="admin")
        cls.client = TestClient(app_server.app)
        r = cls.client.post("/api/auth/login",
                            json={"username": ADMIN, "password": ADMIN_PASS})
        assert r.status_code == 200, r.text
        cls.headers = {CSRF_HEADER: "1"}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def setUp(self):
        user_invite.clear()
        self.sent = _Sent()
        self._real_send = mailer.send_email
        mailer.send_email = self.sent

    def tearDown(self):
        mailer.send_email = self._real_send
        user_manager.delete_user(INVITED)

    def _invite(self, email=INVITED, role="viewer"):
        return self.client.post("/api/users/invite",
                                json={"email": email, "role": role},
                                headers=self.headers)

    def _token_from_mail(self):
        self.assertEqual(len(self.sent), 1)
        return self.sent[0]["body"].split("invite_token=")[1].split()[0]

    # --- issuing ---

    def test_invitation_creates_no_account_until_accepted(self):
        r = self._invite()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.sent[0]["to"], INVITED)
        self.assertIsNone(user_manager.get_role(INVITED))

    def test_link_uses_the_configured_base_url(self):
        self._invite()
        self.assertIn("https://sentinelnet.example.com/?invite_token=",
                      self.sent[0]["body"])

    def test_existing_account_is_refused_up_front(self):
        user_manager.create_user(INVITED, CHOSEN_PASS, role="viewer")
        r = self._invite()
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.sent, [])

    def test_malformed_address_and_bad_role_are_refused(self):
        self.assertEqual(self._invite(email="not-an-address").status_code, 400)
        self.assertEqual(self._invite(role="superuser").status_code, 400)
        self.assertEqual(self.sent, [])

    def test_non_admin_cannot_invite(self):
        user_manager.create_user("invite-viewer", ADMIN_PASS, role="viewer")
        try:
            with TestClient(app_server.app) as viewer:
                viewer.post("/api/auth/login",
                            json={"username": "invite-viewer", "password": ADMIN_PASS})
                r = viewer.post("/api/users/invite",
                                json={"email": INVITED, "role": "admin"},
                                headers={CSRF_HEADER: "1"})
                self.assertIn(r.status_code, (401, 403))
        finally:
            user_manager.delete_user("invite-viewer")

    # --- redeeming ---

    def test_accepting_creates_the_account_with_the_invited_role(self):
        self._invite(role="operator")
        token = self._token_from_mail()

        r = self.client.post("/api/auth/accept-invite",
                             json={"token": token, "password": CHOSEN_PASS})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["username"], INVITED)
        self.assertEqual(user_manager.get_role(INVITED), "operator")
        self.assertEqual(user_manager.get_email(INVITED), INVITED)
        self.assertTrue(user_manager.verify_user(INVITED, CHOSEN_PASS))
        # The invitee chose the password, so there is nothing to force.
        self.assertFalse(user_manager.must_change_password(INVITED))

    def test_the_request_cannot_choose_username_or_role(self):
        """Extra fields in the accept call are ignored: both come from the
        invitation, so a redeemer cannot promote themselves."""
        self._invite(role="viewer")
        token = self._token_from_mail()

        r = self.client.post("/api/auth/accept-invite",
                             json={"token": token, "password": CHOSEN_PASS,
                                   "username": "root", "role": "admin"})
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(user_manager.get_role("root"))
        self.assertEqual(user_manager.get_role(INVITED), "viewer")

    def test_invitation_is_single_use(self):
        self._invite()
        token = self._token_from_mail()
        self.assertEqual(
            self.client.post("/api/auth/accept-invite",
                             json={"token": token, "password": CHOSEN_PASS}).status_code, 200)
        user_manager.delete_user(INVITED)
        again = self.client.post("/api/auth/accept-invite",
                                 json={"token": token, "password": CHOSEN_PASS})
        self.assertEqual(again.status_code, 400)
        self.assertIsNone(user_manager.get_role(INVITED))

    def test_expired_invitation_is_refused(self):
        token = user_invite.issue(INVITED, "viewer")
        digest = user_invite._digest(token)
        payload, _exp = user_invite._invites[digest]
        user_invite._invites[digest] = (payload, time.time() - 1)

        r = self.client.post("/api/auth/accept-invite",
                             json={"token": token, "password": CHOSEN_PASS})
        self.assertEqual(r.status_code, 400)
        self.assertIsNone(user_manager.get_role(INVITED))

    def test_forged_token_is_refused(self):
        r = self.client.post("/api/auth/accept-invite",
                             json={"token": "made-up", "password": CHOSEN_PASS})
        self.assertEqual(r.status_code, 400)

    def test_weak_password_is_refused_and_invitation_survives(self):
        self._invite()
        token = self._token_from_mail()

        weak = self.client.post("/api/auth/accept-invite",
                                json={"token": token, "password": "short"})
        self.assertEqual(weak.status_code, 400)
        self.assertIsNone(user_manager.get_role(INVITED))
        # Policy is checked before the token is burned: the invitee retries.
        ok = self.client.post("/api/auth/accept-invite",
                              json={"token": token, "password": CHOSEN_PASS})
        self.assertEqual(ok.status_code, 200)


if __name__ == "__main__":
    unittest.main()
