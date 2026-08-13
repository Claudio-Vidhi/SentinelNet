# -*- coding: utf-8 -*-
"""Conversazioni salvate dell'assistente AI.

Il punto delicato non è il CRUD, è la proprietà: una conversazione contiene
quello che l'utente ha allegato alla chat (inventario, config di apparati) e
non deve essere leggibile, modificabile o cancellabile da un altro account.
Ogni query filtra per username; qui si verifica che il filtro ci sia davvero.
"""

import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR",
                      tempfile.mkdtemp(prefix="sentinelnet_aiconv_"))
os.environ.setdefault("SENTINELNET_JWT_SECRET", "test-secret-ai-conversations")

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from core import db  # noqa: E402
from security import user_manager  # noqa: E402

PASS = "PasswordSicura1!"


class TestAiConversations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.migrate()
        for user in ("alice", "bob"):
            try:
                user_manager.create_user(user, PASS, role="operator")
            except Exception:
                pass

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200, r.text
        # Bearer esplicito: sul cookie i metodi che modificano stato esigono
        # anche l'header anti-CSRF (routers/deps.py).
        c.headers.update({"Authorization": "Bearer " + r.json()["access_token"]})
        return c

    def test_roundtrip_and_auto_title(self):
        c = self._client("alice")
        msgs = [{"role": "user", "content": "Perché la Gi1/0/7 è down?"},
                {"role": "assistant", "content": "Link fisico assente."}]
        r = c.post("/api/ai/conversations", json={"messages": msgs})
        self.assertEqual(200, r.status_code, r.text)
        conv_id = r.json()["id"]
        # Senza titolo esplicito si usa l'inizio del primo messaggio utente:
        # una lista di "Nuova conversazione" non fa ritrovare niente.
        self.assertEqual("Perché la Gi1/0/7 è down?", r.json()["title"])

        r = c.get(f"/api/ai/conversations/{conv_id}")
        self.assertEqual(msgs, r.json()["messages"])

        listed = c.get("/api/ai/conversations").json()["conversations"]
        row = next(x for x in listed if x["id"] == conv_id)
        self.assertEqual(2, row["message_count"])

    def test_new_conversation_button_creates_it_immediately(self):
        """Il pulsante '+' crea una conversazione VUOTA: deve comparire subito
        in elenco, non solo dopo la prima risposta dell'AI — era il difetto
        segnalato. Titolo vuoto finché non c'è un messaggio da cui ricavarlo."""
        c = self._client("alice")
        r = c.post("/api/ai/conversations", json={"messages": []})
        self.assertEqual(200, r.status_code, r.text)
        conv_id = r.json()["id"]
        self.assertEqual("", r.json()["title"])

        row = next(x for x in c.get("/api/ai/conversations").json()["conversations"]
                   if x["id"] == conv_id)
        self.assertEqual(0, row["message_count"])

        # Il primo messaggio dà il titolo alla conversazione già esistente.
        c.put(f"/api/ai/conversations/{conv_id}", json={
            "messages": [{"role": "user", "content": "quali vlan sul core?"}]})
        row = next(x for x in c.get("/api/ai/conversations").json()["conversations"]
                   if x["id"] == conv_id)
        self.assertEqual("quali vlan sul core?", row["title"])

    def test_manual_title_survives_later_messages(self):
        """Chi rinomina una conversazione non deve vedersela ribattezzare dal
        messaggio successivo."""
        c = self._client("alice")
        conv_id = c.post("/api/ai/conversations", json={"messages": []}).json()["id"]
        c.put(f"/api/ai/conversations/{conv_id}", json={"title": "VLAN core Milano"})
        c.put(f"/api/ai/conversations/{conv_id}", json={
            "messages": [{"role": "user", "content": "e i trunk?"}]})
        got = c.get(f"/api/ai/conversations/{conv_id}").json()
        self.assertEqual("VLAN core Milano", got["title"])
        self.assertEqual(1, len(got["messages"]))

    def test_rename_does_not_touch_messages(self):
        c = self._client("alice")
        msgs = [{"role": "user", "content": "elenco vlan"}]
        conv_id = c.post("/api/ai/conversations", json={"messages": msgs}).json()["id"]
        r = c.put(f"/api/ai/conversations/{conv_id}", json={"title": "VLAN sede Milano"})
        self.assertEqual(200, r.status_code, r.text)
        got = c.get(f"/api/ai/conversations/{conv_id}").json()
        self.assertEqual("VLAN sede Milano", got["title"])
        self.assertEqual(msgs, got["messages"])

    def test_another_user_cannot_read_update_or_delete(self):
        alice = self._client("alice")
        conv_id = alice.post("/api/ai/conversations", json={
            "messages": [{"role": "user", "content": "config del core switch"}]}).json()["id"]

        bob = self._client("bob")
        self.assertEqual(404, bob.get(f"/api/ai/conversations/{conv_id}").status_code)
        self.assertEqual(404, bob.put(f"/api/ai/conversations/{conv_id}",
                                      json={"title": "mio"}).status_code)
        self.assertEqual(404, bob.delete(f"/api/ai/conversations/{conv_id}").status_code)
        self.assertNotIn(conv_id, [x["id"] for x in
                                   bob.get("/api/ai/conversations").json()["conversations"]])
        # E deve essere ancora lì, intatta, per la proprietaria.
        self.assertEqual(200, alice.get(f"/api/ai/conversations/{conv_id}").status_code)

    def test_delete_removes_it_from_the_list(self):
        c = self._client("alice")
        conv_id = c.post("/api/ai/conversations", json={
            "messages": [{"role": "user", "content": "da buttare"}]}).json()["id"]
        self.assertEqual(200, c.delete(f"/api/ai/conversations/{conv_id}").status_code)
        self.assertNotIn(conv_id, [x["id"] for x in
                                   c.get("/api/ai/conversations").json()["conversations"]])
        self.assertEqual(404, c.delete(f"/api/ai/conversations/{conv_id}").status_code)

    def test_anonymous_is_rejected(self):
        self.assertEqual(401, TestClient(app_server.app)
                         .get("/api/ai/conversations").status_code)

    def test_ai_generate_config_profile_selection(self):
        c = self._client("alice")
        # Invalid profile_id returns 400
        r = c.post("/api/ai/generate-config", json={
            "tenant": "Generale",
            "hostname": "SW-TEST",
            "profile_id": "nonexistent_profile_id_123"
        })
        self.assertEqual(400, r.status_code)
        self.assertIn("Profilo AI specificato non trovato", r.json()["detail"])


if __name__ == "__main__":
    unittest.main()
