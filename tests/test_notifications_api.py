# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Test degli endpoint API /api/notifications/*:
- Autenticazione e RBAC (admin vs operator/viewer)
- Scoping multi-tenant sui gruppi nelle preferenze
- Validazione Pydantic degli schemi
- CRUD regole admin e test invio
- Isolamento dello storico invii (admin vede tutto, utente vede solo il proprio)
"""

import os
import tempfile
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from core import data_config, db
from routers.deps import CSRF_HEADER
from security import security_manager, user_manager
from services import mailer

H = {CSRF_HEADER: "SentinelNet"}
PASS = "PasswordSicura1!"


class TestNotificationsApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_users = user_manager.USERS_JSON
        cls._orig_data_dir = data_config.DATA_DIR
        cls._tmp_dir = tempfile.mkdtemp(prefix="sentinelnet_test_notifapi_")
        data_config.DATA_DIR = cls._tmp_dir
        user_manager.USERS_JSON = os.path.join(cls._tmp_dir, "users.json")

        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()

    @classmethod
    def tearDownClass(cls):
        user_manager.USERS_JSON = cls._orig_users
        data_config.DATA_DIR = cls._orig_data_dir

    def setUp(self):
        for u in user_manager.list_users():
            try:
                user_manager.delete_user(u["username"])
            except Exception:
                pass
        security_manager._failed_attempts.clear()

        user_manager.create_user("admin_user", PASS, role="admin", email="admin@example.com")
        user_manager.create_user("op_scoped", PASS, role="operator", groups=["sede-a"], email="op@example.com")
        user_manager.create_user("op_no_email", PASS, role="operator", groups=["sede-a"])

        conn = db.get_observability_connection()
        try:
            conn.execute("DELETE FROM notify_outbox")
            conn.execute("DELETE FROM notify_log")
            conn.execute("DELETE FROM notify_rules")
            conn.execute("DELETE FROM notify_prefs")
            conn.execute("DELETE FROM notify_cursors")
            conn.commit()
        finally:
            conn.close()

    def _client(self, username: str = None):
        c = TestClient(app_server.app)
        if username:
            r = c.post("/api/auth/login", json={"username": username, "password": PASS})
            self.assertEqual(r.status_code, 200, r.text)
        return c

    # --- Autenticazione e RBAC ---

    def test_unauthenticated_rejected(self):
        c = self._client()
        for method, path in [
            ("get", "/api/notifications/prefs"),
            ("put", "/api/notifications/prefs"),
            ("get", "/api/notifications/rules"),
            ("post", "/api/notifications/rules"),
            ("get", "/api/notifications/log"),
        ]:
            r = getattr(c, method)(path, headers=H)
            self.assertEqual(r.status_code, 401, f"{method} {path} should return 401")

    def test_non_admin_cannot_access_rules(self):
        op = self._client("op_scoped")
        self.assertEqual(op.get("/api/notifications/rules").status_code, 403)
        self.assertEqual(
            op.post("/api/notifications/rules", headers=H, json={
                "name": "Test",
                "recipients": ["ops@example.com"],
            }).status_code,
            403,
        )
        self.assertEqual(
            op.put("/api/notifications/rules/1", headers=H, json={
                "name": "Test",
                "recipients": ["ops@example.com"],
            }).status_code,
            403,
        )
        self.assertEqual(op.delete("/api/notifications/rules/1", headers=H).status_code, 403)
        self.assertEqual(op.post("/api/notifications/rules/1/test", headers=H).status_code, 403)

    # --- Preferenze personali ---

    def test_get_and_update_personal_prefs(self):
        c = self._client("op_scoped")
        r = c.get("/api/notifications/prefs")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data["has_email"])
        self.assertEqual(data["email"], "op@example.com")
        self.assertIn("prefs", data)

        # Salva nuove preferenze valide entro lo scope
        r_put = c.put(
            "/api/notifications/prefs",
            headers=H,
            json={
                "enabled": True,
                "kinds": ["device.down", "incident.opened"],
                "min_severity": "high",
                "groups": ["sede-a"],
                "mode": "immediate",
                "digest_every_min": 60,
                "quiet_start": "22:00",
                "quiet_end": "07:00",
                "quiet_bypass_critical": True,
            },
        )
        self.assertEqual(r_put.status_code, 200, r_put.text)

        # Verifica persistenza
        r2 = c.get("/api/notifications/prefs")
        self.assertEqual(r2.json()["prefs"]["min_severity"], "high")
        self.assertEqual(r2.json()["prefs"]["groups"], ["sede-a"])
        self.assertEqual(r2.json()["prefs"]["quiet_start"], "22:00")

    def test_personal_prefs_scope_violation_rejected(self):
        c = self._client("op_scoped")
        # Utente scoped su "sede-a" prova a configurare "sede-b"
        r = c.put(
            "/api/notifications/prefs",
            headers=H,
            json={
                "enabled": True,
                "kinds": ["device.down"],
                "min_severity": "low",
                "groups": ["sede-b"],
                "mode": "immediate",
                "digest_every_min": 60,
            },
        )
        self.assertEqual(r.status_code, 403)

    def test_personal_prefs_validation_errors(self):
        c = self._client("op_scoped")

        # Invalid kind
        r1 = c.put("/api/notifications/prefs", headers=H, json={
            "enabled": True,
            "kinds": ["not.a.kind"],
            "groups": ["sede-a"],
        })
        self.assertEqual(r1.status_code, 422)

        # Invalid severity
        r2 = c.put("/api/notifications/prefs", headers=H, json={
            "enabled": True,
            "min_severity": "ultra-critical",
            "groups": ["sede-a"],
        })
        self.assertEqual(r2.status_code, 422)

        # Invalid digest interval
        r3 = c.put("/api/notifications/prefs", headers=H, json={
            "enabled": True,
            "digest_every_min": 999,
            "groups": ["sede-a"],
        })
        self.assertEqual(r3.status_code, 422)

        # Invalid quiet hours time format
        r4 = c.put("/api/notifications/prefs", headers=H, json={
            "enabled": True,
            "quiet_start": "25:70",
            "groups": ["sede-a"],
        })
        self.assertEqual(r4.status_code, 422)

    def test_personal_test_email(self):
        c_no_mail = self._client("op_no_email")
        r_fail = c_no_mail.post("/api/notifications/prefs/test", headers=H)
        self.assertEqual(r_fail.status_code, 400)

        c_ok = self._client("op_scoped")
        with patch.object(mailer, "send_email", return_value=None) as mock_send:
            r_ok = c_ok.post("/api/notifications/prefs/test", headers=H)
            self.assertEqual(r_ok.status_code, 200)
            mock_send.assert_called_once()
            self.assertEqual(mock_send.call_args[0][0], "op@example.com")

    # --- Regole Admin CRUD e Test ---

    def test_admin_rules_crud_and_test(self):
        adm = self._client("admin_user")

        # Create
        create_payload = {
            "name": "NOC Escalation",
            "enabled": True,
            "recipients": ["noc@example.com", "oncall@example.com"],
            "kinds": ["device.down", "incident.opened"],
            "min_severity": "high",
            "groups": ["sede-a"],
            "mode": "immediate",
            "digest_every_min": 60,
            "quiet_start": "23:00",
            "quiet_end": "06:00",
            "quiet_bypass_critical": True,
        }
        r_create = adm.post("/api/notifications/rules", headers=H, json=create_payload)
        self.assertEqual(r_create.status_code, 200)
        rule_id = r_create.json()["id"]
        self.assertIsInstance(rule_id, int)

        # List
        r_list = adm.get("/api/notifications/rules")
        self.assertEqual(r_list.status_code, 200)
        rules = r_list.json()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["name"], "NOC Escalation")
        self.assertEqual(rules[0]["recipients"], ["noc@example.com", "oncall@example.com"])

        # Update
        update_payload = dict(create_payload)
        update_payload["name"] = "NOC Escalation Updated"
        update_payload["min_severity"] = "critical"
        r_update = adm.put(f"/api/notifications/rules/{rule_id}", headers=H, json=update_payload)
        self.assertEqual(r_update.status_code, 200)

        r_list2 = adm.get("/api/notifications/rules")
        self.assertEqual(r_list2.json()[0]["name"], "NOC Escalation Updated")
        self.assertEqual(r_list2.json()[0]["min_severity"], "critical")

        # Test rule
        with patch.object(mailer, "send_email", return_value=None) as mock_send:
            r_test = adm.post(f"/api/notifications/rules/{rule_id}/test", headers=H)
            self.assertEqual(r_test.status_code, 200)
            self.assertEqual(mock_send.call_count, 2)

        # Delete
        r_del = adm.delete(f"/api/notifications/rules/{rule_id}", headers=H)
        self.assertEqual(r_del.status_code, 200)

        # Verify deletion
        r_list3 = adm.get("/api/notifications/rules")
        self.assertEqual(len(r_list3.json()), 0)

        # 404 on non-existent
        self.assertEqual(adm.put(f"/api/notifications/rules/{rule_id}", headers=H, json=update_payload).status_code, 404)
        self.assertEqual(adm.delete(f"/api/notifications/rules/{rule_id}", headers=H).status_code, 404)
        self.assertEqual(adm.post(f"/api/notifications/rules/{rule_id}/test", headers=H).status_code, 404)

    def test_rule_validation_errors(self):
        adm = self._client("admin_user")
        # Empty recipients
        r1 = adm.post("/api/notifications/rules", headers=H, json={
            "name": "Bad Rule",
            "recipients": [],
        })
        self.assertEqual(r1.status_code, 422)

        # Invalid recipient email
        r2 = adm.post("/api/notifications/rules", headers=H, json={
            "name": "Bad Rule",
            "recipients": ["notanemail"],
        })
        self.assertEqual(r2.status_code, 422)

    # --- Storico invii e isolamento ---

    def test_log_visibility_scoped_to_user(self):
        conn = db.get_observability_connection()
        now = int(time.time())
        try:
            conn.execute(
                """INSERT INTO notify_log (ts, target, recipient, kind, title, status, item_count)
                   VALUES (?, 'user:op_scoped', 'op@example.com', 'device.down', 'Subject Op', 'sent', 1)""",
                (now - 10,),
            )
            conn.execute(
                """INSERT INTO notify_log (ts, target, recipient, kind, title, status, item_count)
                   VALUES (?, 'user:other_user', 'other@example.com', 'device.down', 'Subject Other', 'sent', 1)""",
                (now - 20,),
            )
            conn.execute(
                """INSERT INTO notify_log (ts, target, recipient, kind, title, status, item_count)
                   VALUES (?, 'rule:1', 'team@example.com', 'incident.opened', 'Subject Rule', 'sent', 1)""",
                (now - 30,),
            )
            conn.commit()
        finally:
            conn.close()

        # Admin vede tutti e 3
        adm = self._client("admin_user")
        r_adm = adm.get("/api/notifications/log")
        self.assertEqual(r_adm.status_code, 200)
        self.assertEqual(len(r_adm.json()), 3)

        # Utente operatore vede solo user:op_scoped
        op = self._client("op_scoped")
        r_op = op.get("/api/notifications/log")
        self.assertEqual(r_op.status_code, 200)
        logs = r_op.json()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["target"], "user:op_scoped")
        self.assertEqual(logs[0]["recipient"], "op@example.com")
