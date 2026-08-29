# -*- coding: utf-8 -*-
"""Integrità dell'archivio utenti (WP1, docs/app-review-fix-plan.md).

Un users.json corrotto o vuoto non deve mai essere letto come "nessun
utente": la registrazione iniziale resta chiusa, il login è sospeso con una
spiegazione, e ogni read-modify-write è serializzato dal lock del modulo."""

import os
import shutil
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_userstore_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from security import user_manager  # noqa: E402


class TestUserStoreIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app_server.app)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def setUp(self):
        self._orig = user_manager.USERS_JSON
        self._tmp = tempfile.mkdtemp(prefix="userstore_case_")
        user_manager.USERS_JSON = os.path.join(self._tmp, "users.json")

    def tearDown(self):
        user_manager.USERS_JSON = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _corrupt(self, content="{ questa non e' json"):
        with open(user_manager.USERS_JSON, "w", encoding="utf-8") as f:
            f.write(content)

    # --- comportamento del modulo ---

    def test_missing_store_is_true_first_start(self):
        self.assertFalse(user_manager.has_any_user())
        self.assertIsNone(user_manager.store_integrity_error())
        self.assertEqual(user_manager.get_users(), {})

    def test_corrupt_store_raises_and_counts_as_occupied(self):
        self._corrupt()
        with self.assertRaises(user_manager.UsersStoreError):
            user_manager.get_users()
        self.assertTrue(user_manager.has_any_user())
        self.assertIsNotNone(user_manager.store_integrity_error())

    def test_empty_file_is_corrupt_not_first_start(self):
        self._corrupt("")
        self.assertTrue(user_manager.has_any_user())
        self.assertIsNotNone(user_manager.store_integrity_error())

    def test_non_dict_root_is_corrupt(self):
        self._corrupt("[1, 2, 3]")
        self.assertTrue(user_manager.has_any_user())

    def test_role_lookup_fails_closed_on_corrupt_store(self):
        self.assertTrue(user_manager.create_user("alice", "passwordsicura1", role="admin"))
        self._corrupt()
        with self.assertRaises(user_manager.UsersStoreError):
            user_manager.get_role("alice")

    def test_full_roundtrip_through_the_lock(self):
        # create/verify/change/delete passano tutti dallo stesso RLock:
        # il giro completo non deve deadlockare ne' perdere dati.
        self.assertTrue(user_manager.create_user("bob", "passwordsicura1", role="viewer"))
        self.assertTrue(user_manager.verify_user("bob", "passwordsicura1"))
        self.assertTrue(user_manager.change_password("bob", "passwordsicura1", "nuovapassword1"))
        self.assertTrue(user_manager.verify_user("bob", "nuovapassword1"))
        self.assertTrue(user_manager.set_groups("bob", ["g1"]))
        self.assertTrue(user_manager.set_email("bob", "bob@example.test"))
        self.assertTrue(user_manager.delete_user("bob"))
        self.assertFalse(user_manager.has_any_user())

    # --- endpoint ---

    def test_register_refused_on_corrupt_store(self):
        self._corrupt()
        r = self.client.post("/api/auth/register",
                             json={"username": "intruso", "password": "PasswordSicura1!"})
        self.assertEqual(r.status_code, 500)
        # l'archivio resta corrotto: nessun account creato sopra
        with self.assertRaises(user_manager.UsersStoreError):
            user_manager.get_users()

    def test_register_still_works_on_true_first_start(self):
        r = self.client.post("/api/auth/register",
                             json={"username": "primoadmin", "password": "PasswordSicura1!"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(user_manager.get_role("primoadmin"), "admin")

    def test_register_refused_when_users_exist(self):
        self.assertTrue(user_manager.create_user("esistente", "passwordsicura1", role="admin"))
        r = self.client.post("/api/auth/register",
                             json={"username": "secondo", "password": "PasswordSicura1!"})
        self.assertEqual(r.status_code, 403)

    def test_login_suspended_on_corrupt_store(self):
        self.assertTrue(user_manager.create_user("carol", "passwordsicura1", role="admin"))
        self._corrupt()
        r = self.client.post("/api/auth/login",
                             json={"username": "carol", "password": "passwordsicura1"})
        self.assertEqual(r.status_code, 503)


if __name__ == "__main__":
    unittest.main()
