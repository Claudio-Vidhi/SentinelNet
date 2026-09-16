# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Audit checklist routes had no auth dependency at all (9 handlers reachable
unauthenticated). This locks in: unauthenticated -> 401 on every route, viewer
-> 403 on every write, operator -> auth passes (404/422 from the handler is
fine, it proves auth ran) on at least one read and one write."""
import os
import tempfile
import unittest

from fastapi.testclient import TestClient

import app_server
from core import db
from routers.deps import CSRF_HEADER
from security import security_manager, user_invite, user_manager
from services import mailer

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"

READS = [
    ("get", "/api/audit-checklist/templates"),
    ("get", "/api/audit-checklist/templates/1"),
    ("get", "/api/audit-checklist/engagements"),
    ("get", "/api/audit-checklist/engagements/1"),
    ("get", "/api/audit-checklist/engagements/1/report"),
]

WRITES = [
    ("post", "/api/audit-checklist/engagements", {"customer_name": "Acme"}),
    ("patch", "/api/audit-checklist/engagements/1", {"status": "in_progress"}),
    ("put", "/api/audit-checklist/engagements/1/items/1.1", {"status": "pass"}),
    ("post", "/api/audit-checklist/engagements/1/evidence",
     {"item_ref": "1.1", "kind": "note"}),
]

class _PrivateUsers(unittest.TestCase):
    """Private users store: setUp wipes it, the suite's shared file is never touched."""

    @classmethod
    def setUpClass(cls):
        cls._orig = user_manager.USERS_JSON
        user_manager.USERS_JSON = os.path.join(
            tempfile.mkdtemp(prefix="audit_checklist_users_"), "users.json")
        db.migrate()  # ensure audit_templates/audit_engagements exist (no lifespan under TestClient)

    @classmethod
    def tearDownClass(cls):
        user_manager.USERS_JSON = cls._orig

    def setUp(self):
        for u in user_manager.list_users():
            user_manager.delete_user(u["username"])
        security_manager._failed_attempts.clear()
        user_invite.clear()
        self._real_send = mailer.send_email
        mailer.send_email = lambda *a, **k: None
        user_manager.create_user("viewer1", PW, role="viewer", email="viewer1@example.com")
        user_manager.create_user("op1", PW, role="operator", email="op1@example.com")

    def tearDown(self):
        mailer.send_email = self._real_send

    def _as(self, name):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": name, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        return c


class TestAuditChecklistAuth(_PrivateUsers):

    def test_unauthenticated_gets_401_on_every_route(self):
        c = TestClient(app_server.app)
        for method, path in READS:
            with self.subTest(method=method, path=path):
                r = getattr(c, method)(path, headers=H)
                self.assertEqual(r.status_code, 401, f"{method} {path}: {r.text}")
        for method, path, body in WRITES:
            with self.subTest(method=method, path=path):
                r = getattr(c, method)(path, json=body, headers=H)
                self.assertEqual(r.status_code, 401, f"{method} {path}: {r.text}")

    def test_viewer_gets_403_on_every_write(self):
        viewer = self._as("viewer1")
        for method, path, body in WRITES:
            with self.subTest(method=method, path=path):
                r = getattr(viewer, method)(path, json=body, headers=H)
                self.assertEqual(r.status_code, 403, f"{method} {path}: {r.text}")

    def test_operator_passes_auth_on_read_and_write(self):
        op = self._as("op1")
        r = op.get("/api/audit-checklist/templates")
        self.assertIn(r.status_code, (200, 404), r.text)
        r = op.post("/api/audit-checklist/engagements", json={"customer_name": "Acme"}, headers=H)
        self.assertIn(r.status_code, (201, 400, 422), r.text)


if __name__ == "__main__":
    unittest.main()
