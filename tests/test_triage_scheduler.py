# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Test unitari e di integrazione per Triage Automatico Programmato (v13)."""

import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Setup data dir isolato per test
os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_triage_sched_"))

from core import db
from services import triage_scheduler
from services import inventory_manager
from starlette.testclient import TestClient
import app_server


class TestTriageScheduler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.migrate()
        cls.client = TestClient(app_server.app)

    def setUp(self):
        # Ripulisce tabelle prima di ogni test
        conn = db.get_observability_connection()
        try:
            conn.execute("DELETE FROM scheduled_triage_log")
            conn.execute("DELETE FROM scheduled_triage")
            conn.commit()
        finally:
            conn.close()

    def test_create_and_get_schedule(self):
        user = {"username": "admin1", "sub": "admin1", "role": "admin"}
        data = {
            "name": "Triage Notturno Sede 1",
            "tenant": "Sede-1",
            "devices": None,
            "interval_minutes": 360,
            "enabled": True,
        }
        res = triage_scheduler.create_schedule(data, user)
        self.assertIsNotNone(res.get("id"))
        self.assertEqual(res["name"], "Triage Notturno Sede 1")
        self.assertEqual(res["tenant"], "Sede-1")
        self.assertEqual(res["interval_minutes"], 360)
        self.assertTrue(res["enabled"])
        self.assertEqual(res["created_by"], "admin1")

        schedules = triage_scheduler.get_schedules(user)
        self.assertEqual(len(schedules), 1)
        self.assertEqual(schedules[0]["id"], res["id"])

    @patch("security.user_manager.get_user_groups", return_value=["Sede-1"])
    def test_tenant_scope_enforcement(self, mock_groups):
        # Operatore con accesso solo a Sede-1
        operator = {"username": "op1", "sub": "op1", "role": "operator"}

        # 1. Creazione per Sede-2 deve fallire con PermissionError
        with self.assertRaises(PermissionError):
            triage_scheduler.create_schedule({
                "name": "Triage Non Autorizzato",
                "tenant": "Sede-2",
                "interval_minutes": 60,
            }, operator)

        # 2. Creazione per 'all' deve fallire per operatore limitato
        with self.assertRaises(PermissionError):
            triage_scheduler.create_schedule({
                "name": "Triage Tutte le Sedi",
                "tenant": "all",
                "interval_minutes": 60,
            }, operator)

        # 3. Creazione per Sede-1 consentita
        res = triage_scheduler.create_schedule({
            "name": "Triage Sede 1",
            "tenant": "Sede-1",
            "interval_minutes": 60,
        }, operator)
        self.assertEqual(res["tenant"], "Sede-1")

    def test_device_list_validation(self):
        user = {"username": "admin1", "sub": "admin1", "role": "admin"}
        mock_devices = [
            {"IP": "192.0.2.1", "Hostname": "sw1", "Group": "Sede-1"},
            {"IP": "192.0.2.2", "Hostname": "sw2", "Group": "Sede-2"},
        ]
        with patch.object(inventory_manager, "get_all_devices", return_value=mock_devices):
            # IP non in inventario
            with self.assertRaises(ValueError):
                triage_scheduler.create_schedule({
                    "name": "Test Inesistente",
                    "tenant": "Sede-1",
                    "devices": ["192.0.2.99"],
                }, user)

            # IP appartiene a Sede-2 ma tenant è Sede-1
            with self.assertRaises(ValueError):
                triage_scheduler.create_schedule({
                    "name": "Test Gruppo Discordante",
                    "tenant": "Sede-1",
                    "devices": ["192.0.2.2"],
                }, user)

            # IP valido in Sede-1
            sched = triage_scheduler.create_schedule({
                "name": "Test Valido",
                "tenant": "Sede-1",
                "devices": ["192.0.2.1"],
            }, user)
            self.assertEqual(sched["devices"], ["192.0.2.1"])

    def test_update_and_delete_schedule(self):
        user = {"username": "admin1", "sub": "admin1", "role": "admin"}
        sched = triage_scheduler.create_schedule({
            "name": "Originale",
            "tenant": "Sede-1",
            "interval_minutes": 60,
        }, user)

        updated = triage_scheduler.update_schedule(sched["id"], {
            "name": "Modificato",
            "interval_minutes": 120,
            "enabled": False,
        }, user)
        self.assertIsNotNone(updated)
        self.assertEqual(updated["name"], "Modificato")
        self.assertEqual(updated["interval_minutes"], 120)
        self.assertFalse(updated["enabled"])

        ok = triage_scheduler.delete_schedule(sched["id"], user)
        self.assertTrue(ok)
        self.assertIsNone(triage_scheduler.get_schedule(sched["id"]))

    def test_history_logging(self):
        user = {"username": "admin1", "sub": "admin1", "role": "admin"}
        sched = triage_scheduler.create_schedule({
            "name": "Per Storico",
            "tenant": "Sede-1",
            "interval_minutes": 60,
        }, user)

        triage_scheduler._log_schedule_result(
            sched["id"], "Sede-1", total=5, successes=5, errors=0,
            status="success", summary="5/5 apparati ok"
        )

        history = triage_scheduler.get_schedule_history(sched["id"])
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["device_count"], 5)
        self.assertEqual(history[0]["status"], "success")

        reloaded = triage_scheduler.get_schedule(sched["id"])
        self.assertEqual(reloaded["last_status"], "success")
        self.assertEqual(reloaded["last_summary"], "5/5 apparati ok")

    def test_triage_disabled_tenant_is_skipped(self):
        user = {"username": "admin1", "sub": "admin1", "role": "admin"}
        sched = triage_scheduler.create_schedule({
            "name": "Telemetria spenta", "tenant": "Sede-1", "interval_minutes": 60,
        }, user)
        devs = [{"IP": "192.0.2.10", "Group": "Sede-1", "Site": "central"}]
        with patch.object(inventory_manager, "get_all_devices", return_value=devs),              patch("services.tenant_telemetry.get_app_settings",
                   return_value={"tenant_telemetry": {"Sede-1": {"triage_enabled": False}}}):
            res = triage_scheduler.execute_schedule_job(sched["id"])
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["queued"], 0)

    def test_api_endpoints_permissions(self):
        from routers.deps import require_operator, get_current_user

        # 1. Non autenticato -> 401
        res = self.client.get("/api/triage/schedules")
        self.assertEqual(res.status_code, 401)

        # 2. Con token operatore limitato a Sede-1
        user = {"username": "op1", "sub": "op1", "role": "operator"}
        app_server.app.dependency_overrides[get_current_user] = lambda: user
        app_server.app.dependency_overrides[require_operator] = lambda: user
        try:
            with patch("security.user_manager.get_user_groups", return_value=["Sede-1"]):
                # Creazione su gruppo non autorizzato -> 403
                res = self.client.post("/api/triage/schedules", json={
                    "name": "Op Triage",
                    "tenant": "Sede-2",
                    "interval_minutes": 60,
                })
                self.assertEqual(res.status_code, 403)

                # Creazione su gruppo autorizzato -> 200
                res = self.client.post("/api/triage/schedules", json={
                    "name": "Op Triage Sede 1",
                    "tenant": "Sede-1",
                    "interval_minutes": 60,
                })
                self.assertEqual(res.status_code, 200)
                created_id = res.json()["id"]

                # Lista pianificazioni
                res = self.client.get("/api/triage/schedules")
                self.assertEqual(res.status_code, 200)
                self.assertTrue(any(s["id"] == created_id for s in res.json()))

                # Storico
                res = self.client.get(f"/api/triage/schedules/{created_id}/history")
                self.assertEqual(res.status_code, 200)

                # Eliminazione
                res = self.client.delete(f"/api/triage/schedules/{created_id}")
                self.assertEqual(res.status_code, 200)
        finally:
            app_server.app.dependency_overrides.pop(get_current_user, None)
            app_server.app.dependency_overrides.pop(require_operator, None)


if __name__ == "__main__":
    unittest.main()
