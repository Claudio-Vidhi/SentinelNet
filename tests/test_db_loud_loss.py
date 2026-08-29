# -*- coding: utf-8 -*-
"""Perdite della pipeline dichiarate, mai silenziose (WP7,
docs/app-review-fix-plan.md): lo scarto per coda piena viene contato E
loggato (rate-limited), la morte definitiva del writer diventa uno stato
leggibile dall'endpoint health."""

import logging
import os
import queue
import shutil
import tempfile
import threading
import time

import pytest

from core import db
from observability.ingesters import udp_server


@pytest.fixture
def db_metrics():
    """Salva/ripristina i contatori globali del writer."""
    saved = dict(db.metrics)
    yield db.metrics
    db.metrics.clear()
    db.metrics.update(saved)


@pytest.fixture
def drop_throttle():
    saved = db._drop_last_log_ts
    db._drop_last_log_ts = 0.0
    yield
    db._drop_last_log_ts = saved


def test_queue_full_drop_counts_and_announces(db_metrics, drop_throttle,
                                             monkeypatch, caplog):
    monkeypatch.setattr(db, "_write_queue", queue.Queue(maxsize=1))
    db.metrics["writes_dropped_queue_full"] = 0

    assert db.enqueue_write("INSERT INTO x VALUES (?)", (1,)) is True
    with caplog.at_level(logging.WARNING, logger="sentinelnet.db"):
        assert db.enqueue_write("INSERT INTO x VALUES (?)", (2,)) is False

    assert db.metrics["writes_dropped_queue_full"] == 1
    assert any("Coda scritture observability piena" in r.message
               for r in caplog.records)


def test_queue_full_log_is_rate_limited(db_metrics, drop_throttle):
    db.metrics["writes_dropped_queue_full"] = 1
    assert db._log_queue_full_drops(1) is True
    # subito dopo: stessa finestra, niente bis
    assert db._log_queue_full_drops(2) is False
    # oltre l'intervallo: torna a parlare
    db._drop_last_log_ts = time.monotonic() - db.DROP_LOG_INTERVAL_S - 1
    assert db._log_queue_full_drops(3) is True


def test_writer_dead_flag_after_restart_budget(db_metrics, monkeypatch):
    def always_crash():
        raise RuntimeError("writer failure")

    monkeypatch.setattr(db, "_writer_loop", always_crash)
    monkeypatch.setattr(db, "_stop_event", threading.Event())
    monkeypatch.setattr(db.time, "sleep", lambda s: None)
    db.metrics["writer_dead"] = 0
    db.metrics["writer_restarts"] = 0

    db._writer_supervisor()

    assert db.metrics["writer_dead"] == 1
    assert db.metrics["writer_restarts"] == db.MAX_WRITER_RESTARTS + 1


def test_health_state_reports_degradation(db_metrics):
    db.metrics["writes_dropped_queue_full"] = 0
    db.metrics["writer_dead"] = 0
    state = db.health_state()
    assert state["degraded"] is False
    assert state["writer_dead"] is False
    assert isinstance(state["queue_depth"], int)

    db.metrics["writes_dropped_queue_full"] = 3
    assert db.health_state()["degraded"] is True

    db.metrics["writes_dropped_queue_full"] = 0
    db.metrics["writer_dead"] = 1
    state = db.health_state()
    assert state["degraded"] is True
    assert state["writer_dead"] is True


def test_ingest_drop_log_is_rate_limited_per_listener():
    udp_server._ingest_drop_last.clear()
    assert udp_server._log_ingest_drop("netflow") is True
    assert udp_server._log_ingest_drop("netflow") is False
    # un altro listener ha la propria finestra
    assert udp_server._log_ingest_drop("syslog") is True
    udp_server._ingest_drop_last.clear()


# --- endpoint health ---------------------------------------------------------

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_loudloss_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from security import user_manager  # noqa: E402


@pytest.fixture(scope="module")
def admin_client():
    orig = user_manager.USERS_JSON
    user_manager.USERS_JSON = os.path.join(_TMP_DATA_DIR, "users.json")
    user_manager.create_user("healthadmin", "PasswordSicura1!", role="admin")
    with TestClient(app_server.app) as client:
        yield client
    user_manager.USERS_JSON = orig
    shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)


def test_health_endpoint_exposes_db_health(admin_client):
    r = admin_client.post("/api/auth/login",
                          json={"username": "healthadmin",
                                "password": "PasswordSicura1!"})
    assert r.status_code == 200
    token = r.json()["access_token"]

    r = admin_client.get("/api/observability/health",
                         headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert "db_health" in body
    dbh = body["db_health"]
    for key in ("writer_dead", "writes_dropped_queue_full",
                "writes_dropped_error", "writer_restarts",
                "queue_depth", "degraded"):
        assert key in dbh
    assert isinstance(dbh["degraded"], bool)
