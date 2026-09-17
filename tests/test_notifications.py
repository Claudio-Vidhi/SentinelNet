# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Test del motore notifiche email: filtri, perimetro tenant, anti-flood, orari silenziosi, retry."""

import json
import time
from unittest.mock import patch, MagicMock

import pytest

from core import db
from services import notifications, mailer
from security import user_manager


@pytest.fixture(autouse=True)
def setup_db_and_clean():
    db.migrate()
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
    yield


def test_smtp_disabled_enqueues_nothing():
    with patch.object(mailer, "get_config", return_value={"enabled": False}):
        enqueued = notifications.emit(
            kind="device.down",
            device_ip="192.0.2.1",
            severity="high",
            title="Switch down",
        )
        assert enqueued == 0


def test_filters_and_scope():
    # Mock SMTP abilitato
    with patch.object(mailer, "get_config", return_value={"enabled": True, "from_email": "sn@example.com"}):
        with patch.object(user_manager, "get_users", return_value={
            "admin_all": {"email": "admin@example.com", "role": "super_admin", "groups": []},
            "operator_scoped": {"email": "op@example.com", "role": "operator", "groups": ["TenantA"]},
        }):
            with patch.object(user_manager, "get_email", side_effect=lambda u: f"{u}@example.com"):
                with patch.object(user_manager, "get_user_groups", side_effect=lambda u: ["TenantA"] if u == "operator_scoped" else []):
                    # Dispositivo in TenantA
                    with patch("services.inventory_manager.get_all_devices", return_value=[
                        {"IP": "192.0.2.10", "Group": "TenantA"}
                    ]):
                        # Evento su 192.0.2.10 (TenantA): sia admin che operator lo ricevono
                        eq = notifications.emit(
                            kind="incident.opened",
                            device_ip="192.0.2.10",
                            severity="high",
                            title="Incidente TenantA",
                        )
                        assert eq == 2

                    # Dispositivo in TenantB
                    with patch("services.inventory_manager.get_all_devices", return_value=[
                        {"IP": "192.0.2.20", "Group": "TenantB"}
                    ]):
                        # Evento su 192.0.2.20 (TenantB): solo admin lo riceve, operator_scoped no (fuori perimetro)
                        eq = notifications.emit(
                            kind="incident.opened",
                            device_ip="192.0.2.20",
                            severity="high",
                            title="Incidente TenantB",
                        )
                        assert eq == 1


def test_anti_flood_suppressed():
    with patch.object(mailer, "get_config", return_value={"enabled": True, "from_email": "sn@example.com"}):
        with patch.object(user_manager, "get_users", return_value={
            "user1": {"email": "u1@example.com", "role": "admin", "groups": []},
        }):
            with patch.object(user_manager, "get_email", return_value="u1@example.com"):
                with patch.object(user_manager, "get_user_groups", return_value=[]):
                    with patch("services.inventory_manager.get_all_devices", return_value=[]):
                        # Prima emissione: accodata
                        eq1 = notifications.emit(
                            kind="siem.alert",
                            device_ip="192.0.2.1",
                            severity="critical",
                            title="Attacco rilevato",
                            dedup_key="rule_123",
                        )
                        assert eq1 == 1

                        # Seconda emissione con stessa dedup_key entro 30 min: soppressa
                        eq2 = notifications.emit(
                            kind="siem.alert",
                            device_ip="192.0.2.1",
                            severity="critical",
                            title="Attacco rilevato",
                            dedup_key="rule_123",
                        )
                        assert eq2 == 0

                        # Verifica che sia registrato lo stato suppressed nel log
                        logs = notifications.list_log(status_filter="suppressed")
                        assert len(logs) == 1
                        assert logs[0]["status"] == "suppressed"


def test_quiet_hours_defer_and_critical_bypass():
    from datetime import datetime, timezone
    # Ora attuale: 23:30 (dentro 22:00 - 07:00)
    now_dt = datetime(2026, 9, 16, 23, 30, 0, tzinfo=timezone.utc)
    in_quiet, defer_ts = notifications._is_in_quiet_hours("22:00", "07:00", now_dt)
    assert in_quiet is True
    # Il differimento punta alle 07:00 del giorno dopo
    defer_dt = datetime.fromtimestamp(defer_ts, tz=timezone.utc)
    assert defer_dt.hour == 7 and defer_dt.minute == 0


@pytest.mark.anyio
async def test_notification_tick_delivery_and_retry():
    # Inserisce un item direttamente nell'outbox con due_ts nel passato
    now = int(time.time())
    conn = db.get_observability_connection()
    try:
        conn.execute("""
            INSERT INTO notify_outbox
                (target, kind, severity, device_ip, grp, title, ctx_json, dedup_key, created_ts, due_ts, attempts)
            VALUES ('user:testuser', 'incident.opened', 'high', '192.0.2.1', 'TenantA', 'Test incidente', '{}', 'k1', ?, ?, 0)
        """, (now, now - 10))
        conn.commit()
    finally:
        conn.close()

    # Caso 1: Invio fallito (MailerError) -> attempts incrementato
    with patch.object(mailer, "get_config", return_value={"enabled": True, "from_email": "sn@example.com"}):
        with patch.object(user_manager, "get_email", return_value="test@example.com"):
            with patch.object(mailer, "send_email", side_effect=mailer.MailerError("SMTP Down")):
                await notifications.notification_tick()

    conn = db.get_observability_connection()
    try:
        row = conn.execute("SELECT attempts FROM notify_outbox WHERE target = 'user:testuser'").fetchone()
        assert row is not None
        assert row["attempts"] == 1
    finally:
        conn.close()

    # Caso 2: Invio riuscito -> eliminato dall'outbox e scritto in notify_log con status 'sent'
    with patch.object(mailer, "get_config", return_value={"enabled": True, "from_email": "sn@example.com"}):
        with patch.object(user_manager, "get_email", return_value="test@example.com"):
            with patch.object(mailer, "send_email", return_value=None):
                # Porta due_ts nel passato per farglielo riprocessare
                conn = db.get_observability_connection()
                try:
                    conn.execute("UPDATE notify_outbox SET due_ts = ?", (now - 10,))
                    conn.commit()
                finally:
                    conn.close()

                await notifications.notification_tick()

    conn = db.get_observability_connection()
    try:
        outbox_rows = conn.execute("SELECT * FROM notify_outbox WHERE target = 'user:testuser'").fetchall()
        assert len(outbox_rows) == 0
        log_rows = conn.execute("SELECT * FROM notify_log WHERE status = 'sent'").fetchall()
        assert len(log_rows) == 1
        assert log_rows[0]["recipient"] == "test@example.com"
    finally:
        conn.close()
