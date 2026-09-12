# -*- coding: utf-8 -*-
"""S1 — revoca dei token JWT.

Il buco: ``logout`` cancellava solo il cookie. Un Bearer copiato prima del
logout restava valido fino alla scadenza (fino a 60 minuti), e il docstring
della rotta lo diceva pure. Gli account disabilitati o eliminati erano invece
GIA' coperti da ``get_current_user`` (routers/deps.py): quello non era il
buco, e non va "risistemato" una seconda volta.

La denylist e' limitata per costruzione: una voce vale fino a ``exp`` del suo
token, oltre il quale il token e' invalido comunque, quindi la potatura la
tiene piccola senza bisogno di uno spazzino.
"""

import os
import shutil
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_revoke_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from security import security_manager, user_manager  # noqa: E402

USER, PASS = "revoke_admin", "PasswordSicura1!"
CSRF = {"X-Requested-With": "XMLHttpRequest"}


class TestTokenRevocation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        user_manager.create_user(USER, PASS, role="admin")
        cls.client = TestClient(app_server.app)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def _bearer(self):
        r = self.client.post("/api/auth/login",
                             json={"username": USER, "password": PASS})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["access_token"]

    def test_every_token_carries_an_identifier(self):
        payload = security_manager.verify_access_token(self._bearer())
        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertTrue(payload.get("jti"))

    def test_two_logins_get_two_different_identifiers(self):
        a = security_manager.verify_access_token(self._bearer())
        b = security_manager.verify_access_token(self._bearer())
        assert a is not None and b is not None
        self.assertNotEqual(a["jti"], b["jti"])

    def test_a_bearer_stops_working_after_its_own_logout(self):
        token = self._bearer()
        h = {"Authorization": "Bearer " + token}
        self.assertEqual(self.client.get("/api/auth/me", headers=h).status_code, 200)
        r = self.client.post("/api/auth/logout", headers={**h, **CSRF})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.client.get("/api/auth/me", headers=h).status_code, 401)

    def test_logging_out_one_session_leaves_the_other_alone(self):
        """Il logout revoca IL token con cui viene chiamato, non l'utente: un
        taglio per utente ucciderebbe anche la sessione MCP o l'altro
        browser."""
        keep = self._bearer()
        drop = self._bearer()
        self.client.post("/api/auth/logout",
                         headers={"Authorization": "Bearer " + drop, **CSRF})
        r = self.client.get("/api/auth/me",
                            headers={"Authorization": "Bearer " + keep})
        self.assertEqual(r.status_code, 200, r.text)

    def test_the_denylist_survives_a_reload_of_the_store(self):
        token = self._bearer()
        self.client.post("/api/auth/logout",
                         headers={"Authorization": "Bearer " + token, **CSRF})
        security_manager._revoked_loaded = False
        security_manager._revoked = {}
        self.assertIsNone(security_manager.verify_access_token(token))

    def test_an_entry_is_pruned_once_its_token_could_no_longer_be_valid(self):
        import time
        security_manager.revoke_token({"jti": "stale", "exp": time.time() - 10})
        security_manager.revoke_token({"jti": "live", "exp": time.time() + 3600})
        self.assertNotIn("stale", security_manager._revoked)
        self.assertIn("live", security_manager._revoked)

    def test_a_token_without_an_identifier_is_not_revocable_but_still_verifies(self):
        """Un token emesso prima di questa modifica non ha jti. Rifiutarlo
        sarebbe un logout forzato di tutti; accettarlo e' il comportamento di
        prima, che scade da se' entro l'ora."""
        from datetime import timedelta
        legacy = security_manager.create_access_token(
            {"sub": USER, "role": "admin"}, expires_delta=timedelta(minutes=5))
        import jwt
        decoded = jwt.decode(legacy, security_manager.JWT_SECRET_KEY,
                             algorithms=[security_manager.JWT_ALGORITHM],
                             options={"verify_signature": True})
        decoded.pop("jti", None)
        stripped = jwt.encode(decoded, security_manager.JWT_SECRET_KEY,
                              algorithm=security_manager.JWT_ALGORITHM)
        self.assertIsNotNone(security_manager.verify_access_token(stripped))

    def test_a_corrupt_store_never_blocks_authentication(self):
        with open(security_manager.REVOKED_FILE, "w", encoding="utf-8") as f:
            f.write("{not json")
        security_manager._revoked_loaded = False
        security_manager._revoked = {}
        self.assertIsNotNone(security_manager.verify_access_token(self._bearer()))


if __name__ == "__main__":
    unittest.main()
