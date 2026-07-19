# -*- coding: utf-8 -*-
"""Test di integrazione per l'autenticazione a cookie HttpOnly (finding L-1):
login imposta il cookie, cookie + header anti-CSRF autenticano le scritture,
cookie senza header anti-CSRF -> 403, Bearer resta valido per i client
programmatici, logout cancella il cookie."""

import os
import shutil
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_auth_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from security import user_manager  # noqa: E402

USER, PASS = "testadmin", "PasswordSicura1!"


class TestCookieAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        user_manager.create_user(USER, PASS, role="admin")
        cls.client = TestClient(app_server.app)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def _login(self, client):
        r = client.post("/api/auth/login", json={"username": USER, "password": PASS})
        self.assertEqual(r.status_code, 200)
        return r

    def test_login_sets_httponly_cookie(self):
        with TestClient(app_server.app) as client:
            r = self._login(client)
            set_cookie = r.headers.get("set-cookie", "")
            self.assertIn("net_session=", set_cookie)
            self.assertIn("HttpOnly", set_cookie)
            self.assertIn("SameSite=strict", set_cookie.replace("samesite", "SameSite"))

    def test_cookie_authenticates_get(self):
        with TestClient(app_server.app) as client:
            self._login(client)
            r = client.get("/api/auth/me")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["username"], USER)

    def test_cookie_post_without_csrf_header_rejected(self):
        with TestClient(app_server.app) as client:
            self._login(client)
            r = client.post("/api/auth/logout")
            self.assertEqual(r.status_code, 403)

    def test_cookie_post_with_csrf_header_ok(self):
        with TestClient(app_server.app) as client:
            self._login(client)
            r = client.post("/api/auth/logout",
                            headers={"X-Requested-With": "SentinelNet"})
            self.assertEqual(r.status_code, 200)

    def test_bearer_still_works_without_csrf_header(self):
        with TestClient(app_server.app) as client:
            token = self._login(client).json()["access_token"]
            bare = TestClient(app_server.app)
            r = bare.post("/api/auth/logout",
                          headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(r.status_code, 200)

    def test_logout_clears_cookie(self):
        with TestClient(app_server.app) as client:
            self._login(client)
            client.post("/api/auth/logout",
                        headers={"X-Requested-With": "SentinelNet"})
            r = client.get("/api/auth/me")
            self.assertEqual(r.status_code, 401)

    def test_no_auth_rejected(self):
        with TestClient(app_server.app) as client:
            r = client.get("/api/auth/me")
            self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main()
