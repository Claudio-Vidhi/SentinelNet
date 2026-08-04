# -*- coding: utf-8 -*-
"""Deve sempre restare un amministratore UTILIZZABILE.

Un amministratore disabilitato non puo' autenticarsi (``routers/deps.py``
rifiuta il token), quindi contarlo nel quorum equivale a non avere nessuno:
l'applicazione resta chiusa e si riapre solo modificando ``users.json`` a mano.

Le tre rotte che possono ridurre il numero di amministratori utilizzabili -
cancellazione, cambio ruolo, disabilitazione - devono quindi applicare LA
STESSA regola, sul numero di amministratori ATTIVI.
"""
import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR",
                      tempfile.mkdtemp(prefix="sentinelnet_quorum_"))
os.environ.setdefault("SENTINELNET_JWT_SECRET", "test-secret-admin-quorum")

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from security import user_manager  # noqa: E402

CSRF = {"X-Requested-With": "SentinelNet"}


class TestAdminQuorum(unittest.TestCase):
    """Serve un archivio utenti PRIVATO: qui si azzera l'elenco a ogni test e le
    asserzioni contano gli amministratori dell'installazione intera. Sul file
    condiviso dalla suite cancellerebbe gli utenti degli altri moduli."""

    @classmethod
    def setUpClass(cls):
        cls._orig_users_json = user_manager.USERS_JSON
        user_manager.USERS_JSON = os.path.join(
            tempfile.mkdtemp(prefix="quorum_users_"), "users.json")

    @classmethod
    def tearDownClass(cls):
        user_manager.USERS_JSON = cls._orig_users_json

    def setUp(self):
        # Ogni test riparte da un solo amministratore attivo.
        for u in user_manager.list_users():
            user_manager.delete_user(u["username"])
        user_manager.create_user("alice", "alicepass123", role="admin")
        self.client = TestClient(app_server.app)
        r = self.client.post("/api/auth/login",
                             json={"username": "alice", "password": "alicepass123"})
        self.assertEqual(r.status_code, 200, r.text)

    def _usable_admins(self):
        return sorted(u["username"] for u in user_manager.list_users()
                      if u["role"] == "admin" and not u["disabled"])

    def _add_admin(self, name, disabled=False):
        user_manager.create_user(name, "adminpass1234", role="admin")
        if disabled:
            user_manager.set_disabled(name, True)

    # --- il buco vero: un admin disabilitato non tiene su il quorum ---

    def test_self_demotion_blocked_when_the_only_other_admin_is_disabled(self):
        self._add_admin("carol", disabled=True)
        r = self.client.post("/api/users/role", headers=CSRF,
                             json={"username": "alice", "role": "viewer"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("amministratore", r.json()["detail"])
        self.assertEqual(self._usable_admins(), ["alice"])

    def test_the_rule_itself(self):
        # La cancellazione non puo' esercitare il quorum passando dalla rotta:
        # per cancellare un amministratore bisogna essere un amministratore
        # DIVERSO e attivo, quindi ce ne sono sempre almeno due e la guardia non
        # scatterebbe mai. Era il difetto della versione precedente, che sulla
        # DELETE metteva codice irraggiungibile e lasciava scoperto il cambio
        # ruolo. La regola si fissa quindi qui, dove vive.
        self._add_admin("carol", disabled=True)
        self.assertTrue(user_manager.is_last_active_admin("alice"),
                        "un admin disabilitato non tiene su il quorum")
        self.assertFalse(user_manager.is_last_active_admin("carol"),
                         "un admin gia' disabilitato non e' mai l'ultimo")

        self._add_admin("dave")
        self.assertFalse(user_manager.is_last_active_admin("alice"),
                         "con due admin attivi nessuno dei due e' l'ultimo")

        user_manager.set_role("dave", "viewer")
        self.assertFalse(user_manager.is_last_active_admin("dave"),
                         "chi non e' amministratore non e' mai l'ultimo")
        self.assertFalse(user_manager.is_last_active_admin("nessuno"),
                         "un utente inesistente non e' mai l'ultimo")

    def test_disable_blocked_for_the_last_active_admin(self):
        self._add_admin("carol", disabled=True)
        self._add_admin("dave")
        r = self.client.post("/api/users/disable", headers=CSRF,
                             json={"username": "dave", "disabled": True})
        self.assertEqual(r.status_code, 200, r.text)
        # Ora alice e' l'ultima attiva: non puo' declassarsi.
        r = self.client.post("/api/users/role", headers=CSRF,
                             json={"username": "alice", "role": "operator"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertEqual(self._usable_admins(), ["alice"])

    # --- il rovescio: un admin disabilitato non deve essere intoccabile ---

    def test_a_disabled_admin_can_still_be_deleted_and_demoted(self):
        self._add_admin("carol", disabled=True)
        r = self.client.post("/api/users/role", headers=CSRF,
                             json={"username": "carol", "role": "viewer"})
        self.assertEqual(r.status_code, 200, r.text)
        self._add_admin("erin", disabled=True)
        r = self.client.post("/api/users/delete", headers=CSRF,
                             json={"username": "erin"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self._usable_admins(), ["alice"])

    # --- cancellazione del proprio account ---

    def test_a_user_can_delete_their_own_account(self):
        self._add_admin("bob")
        r = self.client.post("/api/auth/login",
                             json={"username": "bob", "password": "adminpass1234"})
        self.assertEqual(r.status_code, 200, r.text)
        r = self.client.post("/api/users/delete", headers=CSRF,
                             json={"username": "bob"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self._usable_admins(), ["alice"])

    def test_a_non_admin_can_delete_their_own_account_but_not_others(self):
        user_manager.create_user("vic", "vicpass12345", role="viewer")
        r = self.client.post("/api/auth/login",
                             json={"username": "vic", "password": "vicpass12345"})
        self.assertEqual(r.status_code, 200, r.text)
        # Un viewer non puo' cancellare un altro account...
        r = self.client.post("/api/users/delete", headers=CSRF,
                             json={"username": "alice"})
        self.assertEqual(r.status_code, 403, r.text)
        # ...ma puo' cancellare il proprio.
        r = self.client.post("/api/users/delete", headers=CSRF,
                             json={"username": "vic"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertNotIn("vic", [u["username"] for u in user_manager.list_users()])

    def test_the_last_active_admin_cannot_delete_themselves(self):
        # E' la ragione per cui la guardia sul quorum smette di essere codice
        # morto: ora la cancellazione di se stessi la puo' raggiungere.
        self._add_admin("carol", disabled=True)
        r = self.client.post("/api/users/delete", headers=CSRF,
                             json={"username": "alice"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertEqual(self._usable_admins(), ["alice"])

    def test_an_admin_can_delete_the_admin_who_created_them(self):
        # Cio' che l'utente aveva chiesto: nessun account e' intoccabile solo
        # perche' ha creato gli altri.
        self._add_admin("bob")
        r = self.client.post("/api/auth/login",
                             json={"username": "bob", "password": "adminpass1234"})
        self.assertEqual(r.status_code, 200, r.text)
        r = self.client.post("/api/users/delete", headers=CSRF,
                             json={"username": "alice"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self._usable_admins(), ["bob"])


if __name__ == "__main__":
    unittest.main()
