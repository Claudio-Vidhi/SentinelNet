# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The browser session slides while the operator is working, and the
administrator decides how long an idle session and a session in total last.

The cookie token used to live exactly 60 minutes from login, and the dashboard
logs out on the first 401: someone busy in the console was thrown back to the
login screen one hour in, mid-task, with no warning. A request that declares
recent user activity now gets a fresh cookie (at most once a minute), so the
session ends after `idle_minutes` without input; an idle tab (background
polling only) still expires, and so does a session older than `max_hours`."""

import os
import shutil
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_renew_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

import jwt  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from core.app_settings import save_app_settings  # noqa: E402
from routers import auth  # noqa: E402
from security import security_manager, user_manager  # noqa: E402

USER, PASS = "renewadmin", "PasswordSicura1!"
VIEWER, VPASS = "renewviewer", "PasswordSicura1!"
ACTIVE = {auth.ACTIVITY_HEADER: "1"}
CSRF = {"X-Requested-With": "SentinelNet"}


def _token(seconds_left, auth_age_s=0, sep=0):
    now = time.time()
    return jwt.encode({"sub": USER, "role": "admin", "sep": sep, "jti": os.urandom(8).hex(),
                       "exp": int(now + seconds_left), "auth_time": int(now - auth_age_s)},
                      security_manager.JWT_SECRET_KEY, algorithm=security_manager.JWT_ALGORITHM)


def _cookie_payload(resp):
    for header in resp.headers.get_list("set-cookie"):
        if header.startswith("net_session="):
            tok = header.split(";", 1)[0].split("=", 1)[1]
            if not tok or tok == '""':
                return None
            return jwt.decode(tok, security_manager.JWT_SECRET_KEY,
                              algorithms=[security_manager.JWT_ALGORITHM])
    return None


class TestSessionRenewal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        user_manager.create_user(USER, PASS, role="admin")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def setUp(self):
        save_app_settings({"session": {"idle_minutes": 60, "max_hours": 12}})

    def _get(self, token, headers=None):
        client = TestClient(app_server.app)
        client.cookies.set("net_session", token)
        return client.get("/api/auth/me", headers=headers or {})

    def test_active_request_gets_a_fresh_cookie(self):
        r = self._get(_token(seconds_left=20 * 60), ACTIVE)
        self.assertEqual(r.status_code, 200)
        renewed = _cookie_payload(r)
        self.assertIsNotNone(renewed, "an active session must be renewed")
        self.assertAlmostEqual(renewed["exp"], time.time() + 60 * 60, delta=5)

    def test_renewal_uses_the_configured_idle_time(self):
        save_app_settings({"session": {"idle_minutes": 15, "max_hours": 12}})
        renewed = _cookie_payload(self._get(_token(seconds_left=5 * 60), ACTIVE))
        self.assertIsNotNone(renewed)
        self.assertAlmostEqual(renewed["exp"], time.time() + 15 * 60, delta=5)

    def test_auth_time_survives_renewal(self):
        # The absolute cap counts from the original sign-in, not the renewal.
        renewed = _cookie_payload(self._get(_token(seconds_left=600, auth_age_s=3600), ACTIVE))
        self.assertIsNotNone(renewed)
        self.assertAlmostEqual(renewed["auth_time"], time.time() - 3600, delta=5)

    def test_token_renewed_less_than_a_minute_ago_is_not_reissued(self):
        self.assertIsNone(_cookie_payload(self._get(_token(seconds_left=60 * 60 - 20), ACTIVE)))

    def test_background_polling_does_not_keep_an_idle_session_alive(self):
        self.assertIsNone(_cookie_payload(self._get(_token(seconds_left=600))))

    def test_absolute_cap_stops_renewal(self):
        save_app_settings({"session": {"idle_minutes": 60, "max_hours": 2}})
        old = 2 * 3600 + 60
        self.assertIsNone(_cookie_payload(self._get(_token(seconds_left=600, auth_age_s=old), ACTIVE)))

    def test_renewal_never_outlives_the_absolute_cap(self):
        # 1 h cap, signed in 50 min ago: the fresh token ends at the cap, not 60 min later.
        save_app_settings({"session": {"idle_minutes": 60, "max_hours": 1}})
        renewed = _cookie_payload(self._get(_token(seconds_left=600, auth_age_s=50 * 60), ACTIVE))
        self.assertIsNotNone(renewed)
        self.assertAlmostEqual(renewed["exp"], time.time() + 10 * 60, delta=5)

    def test_ended_session_is_never_renewed(self):
        # "Sign out everywhere" bumped the epoch: the token is dead, no new cookie.
        r = self._get(_token(seconds_left=600, sep=99), ACTIVE)
        self.assertEqual(r.status_code, 401)
        self.assertIsNone(_cookie_payload(r))

    def test_logout_does_not_hand_back_a_cookie(self):
        client = TestClient(app_server.app)
        client.cookies.set("net_session", _token(seconds_left=600))
        r = client.post("/api/auth/logout", headers={**CSRF, **ACTIVE})
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(_cookie_payload(r))

    def test_new_tokens_follow_the_configured_idle_time(self):
        save_app_settings({"session": {"idle_minutes": 20, "max_hours": 12}})
        payload = security_manager.verify_access_token(
            security_manager.create_access_token({"sub": USER}))
        self.assertAlmostEqual(payload["auth_time"], time.time(), delta=5)
        self.assertAlmostEqual(payload["exp"], time.time() + 20 * 60, delta=5)

    def test_corrupt_or_out_of_range_settings_fall_back_to_safe_values(self):
        save_app_settings({"session": {"idle_minutes": "x", "max_hours": 99999}})
        cfg = security_manager.session_settings()
        self.assertEqual(cfg["idle_minutes"], security_manager.SESSION_IDLE_DEFAULT)
        self.assertEqual(cfg["max_hours"], security_manager.SESSION_MAX_HOURS_LIMIT)


class TestSessionSettingsApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        user_manager.create_user(USER, PASS, role="admin")
        user_manager.create_user(VIEWER, VPASS, role="viewer")

    def setUp(self):
        save_app_settings({"session": {}})

    def _client(self, user, pw):
        c = TestClient(app_server.app)
        self.assertEqual(c.post("/api/auth/login", json={"username": user, "password": pw}).status_code, 200)
        return c

    def test_admin_reads_defaults_and_saves(self):
        c = self._client(USER, PASS)
        r = c.get("/api/settings/session")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["idle_minutes"], security_manager.SESSION_IDLE_DEFAULT)
        r = c.post("/api/settings/session", headers=CSRF, json={"idle_minutes": 30, "max_hours": 8})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(security_manager.session_settings(), {"idle_minutes": 30, "max_hours": 8})

    def test_out_of_range_values_rejected(self):
        c = self._client(USER, PASS)
        for body in ({"idle_minutes": 1, "max_hours": 8}, {"idle_minutes": 30, "max_hours": 0},
                     {"idle_minutes": 5000, "max_hours": 8}):
            self.assertEqual(c.post("/api/settings/session", headers=CSRF, json=body).status_code, 422, body)

    def test_idle_time_cannot_exceed_the_total_cap(self):
        c = self._client(USER, PASS)
        r = c.post("/api/settings/session", headers=CSRF, json={"idle_minutes": 180, "max_hours": 2})
        self.assertEqual(r.status_code, 400)

    def test_non_admin_cannot_change_it(self):
        c = self._client(VIEWER, VPASS)
        self.assertEqual(c.get("/api/settings/session").status_code, 403)
        r = c.post("/api/settings/session", headers=CSRF, json={"idle_minutes": 1440, "max_hours": 720})
        self.assertEqual(r.status_code, 403)


if __name__ == "__main__":
    unittest.main()
