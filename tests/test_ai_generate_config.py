# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""AI config generator (Provisioner panel), and the routes of the in-app chat
that was removed in 0.65.0: the chat must stay gone, the generator must stay."""

import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR",
                      tempfile.mkdtemp(prefix="sentinelnet_aigen_"))
os.environ.setdefault("SENTINELNET_JWT_SECRET", "test-secret-ai-generate-config")

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from core import db  # noqa: E402
from security import user_manager  # noqa: E402

PASS = "PasswordSicura1!"


class TestAiGenerateConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.migrate()
        try:
            user_manager.create_user("alice", PASS, role="operator")
        except Exception:
            pass
        cls.client = TestClient(app_server.app)
        r = cls.client.post("/api/auth/login", json={"username": "alice", "password": PASS})
        assert r.status_code == 200, r.text
        cls.client.headers.update({"Authorization": "Bearer " + r.json()["access_token"]})

    def test_unknown_profile_id_is_400(self):
        r = self.client.post("/api/ai/generate-config", json={
            "tenant": "Generale",
            "hostname": "SW-TEST",
            "profile_id": "nonexistent_profile_id_123"
        })
        self.assertEqual(400, r.status_code)
        self.assertIn("Profilo AI specificato non trovato", r.json()["detail"])

    def test_chat_and_conversation_routes_are_gone(self):
        self.assertEqual(404, self.client.post("/api/ai/chat", json={"messages": []}).status_code)
        self.assertEqual(404, self.client.get("/api/ai/conversations").status_code)


if __name__ == "__main__":
    unittest.main()
