# -*- coding: utf-8 -*-
"""Lockout persistente con chiave sorgente+account e rate limit sulle rotte
costose (WP6, docs/app-review-fix-plan.md)."""

import os
import shutil
import tempfile
import unittest
from collections import defaultdict

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_lockout_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from security import security_manager, user_manager  # noqa: E402

USER_A, PASS_A = "lockadmin", "PasswordSicura1!"
USER_B, PASS_B = "secondo", "PasswordSicura2!"


class TestLockoutPersistent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_users = user_manager.USERS_JSON
        user_manager.USERS_JSON = os.path.join(_TMP_DATA_DIR, "users.json")
        user_manager.create_user(USER_A, PASS_A, role="admin")
        user_manager.create_user(USER_B, PASS_B, role="operator")
        cls.client = TestClient(app_server.app)

    @classmethod
    def tearDownClass(cls):
        user_manager.USERS_JSON = cls._orig_users
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def setUp(self):
        # stato lockout isolato per ogni caso
        self._orig_attempts_file = security_manager.ATTEMPTS_FILE
        self._tmp = tempfile.mkdtemp(prefix="attempts_case_")
        security_manager.ATTEMPTS_FILE = os.path.join(self._tmp, "login_attempts.json")
        security_manager._failed_attempts = defaultdict(list)
        security_manager._attempts_loaded = False

    def tearDown(self):
        security_manager.ATTEMPTS_FILE = self._orig_attempts_file
        security_manager._failed_attempts = defaultdict(list)
        security_manager._attempts_loaded = False
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _fail_login(self, username, password="password-sbagliata"):
        return self.client.post("/api/auth/login",
                                json={"username": username, "password": password})

    def test_lockout_after_max_failures(self):
        for _ in range(security_manager.MAX_ATTEMPTS):
            self.assertEqual(self._fail_login(USER_A).status_code, 401)
        self.assertEqual(self._fail_login(USER_A).status_code, 429)
        # lockout blocca anche le credenziali corrette
        self.assertEqual(self._fail_login(USER_A, PASS_A).status_code, 429)

    def test_lockout_is_per_source_and_account(self):
        for _ in range(security_manager.MAX_ATTEMPTS):
            self._fail_login(USER_A)
        # un altro account dalla stessa sorgente NON e' bloccato
        self.assertEqual(self._fail_login(USER_B, PASS_B).status_code, 200)

    def test_lockout_survives_restart(self):
        for _ in range(security_manager.MAX_ATTEMPTS):
            self._fail_login(USER_A)
        # simula il restart: memoria azzerata, stato riletto da disco
        security_manager._failed_attempts = defaultdict(list)
        security_manager._attempts_loaded = False
        self.assertEqual(self._fail_login(USER_A, PASS_A).status_code, 429)

    def test_successful_login_resets_the_key(self):
        self._fail_login(USER_A)
        self._fail_login(USER_A)
        self.assertEqual(self._fail_login(USER_A, PASS_A).status_code, 200)
        # dopo il successo il contatore riparte da zero
        self.assertEqual(self._fail_login(USER_A).status_code, 401)

    def test_recovery_clears_every_source_for_the_account(self):
        security_manager.record_failed_attempt(f"login:10.0.0.1:{USER_A}")
        security_manager.record_failed_attempt(f"login:10.0.0.2:{USER_A}")
        security_manager.record_failed_attempt(f"login:10.0.0.1:{USER_B}")
        security_manager.clear_account_lockouts(USER_A)
        self.assertFalse(security_manager.is_locked_out(f"login:10.0.0.1:{USER_A}"))
        self.assertFalse(security_manager.is_locked_out(f"login:10.0.0.2:{USER_A}"))
        # gli altri account restano intatti (stato conservato, non cancellato)
        self.assertIn(f"login:10.0.0.1:{USER_B}", security_manager._failed_attempts)


class TestRateLimitMiddleware(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app_server.app)

    def setUp(self):
        self._orig_max = app_server._RATE_LIMIT_MAX
        app_server._RATE_LIMIT_MAX = 3
        app_server._rate_hits.clear()

    def tearDown(self):
        app_server._RATE_LIMIT_MAX = self._orig_max
        app_server._rate_hits.clear()

    def test_expensive_endpoint_throttled(self):
        # /api/ws-token esiste ed e' nella lista: le prime richieste passano
        # (401: senza autenticazione), la quarta viene limitata (429).
        for _ in range(3):
            r = self.client.post("/api/ws-token")
            self.assertEqual(r.status_code, 401)
        r = self.client.post("/api/ws-token")
        self.assertEqual(r.status_code, 429)

    def test_non_listened_routes_not_throttled(self):
        for _ in range(5):
            r = self.client.post("/api/auth/login",
                                 json={"username": "nessuno", "password": "x"})
            self.assertNotEqual(r.status_code, 429)


if __name__ == "__main__":
    unittest.main()
