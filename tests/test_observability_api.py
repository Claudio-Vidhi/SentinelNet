# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Observability API: /syslog (multi-tenant scope, hostile parameters), the
interface routes moved out of the removed incidents router, the incidents
routes being gone, old incident settings ignored, and the MCP observability
tools being off by default."""

import json
import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_obsapi_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
from core import db  # noqa: E402
from security import user_manager  # noqa: E402

PASS = "PasswordSicura1!"
NOW = int(time.time())


def _seed_syslog(conn, tenant, message, ts=None, action="deny", severity=3):
    cur = conn.execute(
        "INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, "
        "message) VALUES (?, ?, '10.0.0.254', ?, ?, ?)",
        (ts or NOW, tenant, severity, action, message))
    return cur.lastrowid


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()
        for user, role, groups in (("adm", "admin", None),
                                   ("op_a", "operator", ["sede-a"]),
                                   ("op_ab", "operator", ["sede-a", "sede-b"])):
            try:
                user_manager.create_user(user, PASS, role=role, groups=groups)
            except Exception:
                pass

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200
        return c


class TestSyslogEndpoint(_Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        conn = db.get_observability_connection()
        _seed_syslog(conn, "sede-a", "link down su Gi1/0/7")
        _seed_syslog(conn, "sede-b", "admin login failed")
        conn.commit()
        conn.close()

    def test_hostile_params_rejected(self):
        c = self._client("adm")
        for url in ("/api/observability/syslog?window=15m;DROP TABLE x",
                    "/api/observability/syslog?window=999999d"):
            r = c.get(url)
            self.assertIn(r.status_code, (400, 422), url)

    def test_anonymous_401(self):
        r = TestClient(app_server.app).get("/api/observability/syslog")
        self.assertEqual(r.status_code, 401)

    def test_top_talkers_route_is_gone(self):
        # Removed with the flow collectors: no route, not an empty answer.
        r = self._client("adm").get("/api/observability/top?window=1h")
        self.assertEqual(r.status_code, 404)

    def test_syslog_endpoint_scoped(self):
        r = self._client("op_a").get("/api/observability/syslog?window=1h")
        self.assertEqual(r.status_code, 200)
        events = r.json()["events"]
        self.assertEqual({e["tenant"] for e in events}, {"sede-a"})
        r = self._client("adm").get("/api/observability/syslog?window=1h")
        self.assertEqual({e["tenant"] for e in r.json()["events"]},
                         {"sede-a", "sede-b"})


class TestMcpDefaultOff(_Base):
    def test_obs_tools_disabled_by_default(self):
        settings_path = data_config.get_path("app_settings.json")
        settings = {}
        if os.path.exists(settings_path):
            settings = json.load(open(settings_path, encoding="utf-8"))
        settings.pop("mcp", None)
        json.dump(settings, open(settings_path, "w", encoding="utf-8"))
        r = self._client("adm").get("/api/mcp/tool-config")
        self.assertEqual(r.status_code, 200)
        disabled = r.json()["disabled_tools"]
        self.assertEqual(disabled, ["linux_health"])

    def test_explicit_admin_choice_wins(self):
        c = self._client("adm")
        r = c.post("/api/mcp/settings", json={"disabled_tools": []},
                   headers={"X-Requested-With": "SentinelNet"})
        self.assertEqual(r.status_code, 200)
        disabled = c.get("/api/mcp/tool-config").json()["disabled_tools"]
        self.assertEqual(disabled, [])

    def test_obs_tools_registered(self):
        from ai import mcp_server
        for gone in ("get_top_talkers", "get_anomalies", "list_incidents",
                     "get_incident"):
            self.assertNotIn(gone, mcp_server.TOOLS)
        self.assertIn("linux_health", mcp_server.TOOLS)


class TestIncidentsRemoved(_Base):
    """The incidents engine is gone: its routes answer 404, the two interface
    routes the Interfaces tab needs live under /api/observability."""

    H = {"X-Requested-With": "SentinelNet"}

    def test_old_incident_routes_are_404(self):
        c = self._client("adm")
        for url in ("/api/incidents", "/api/incidents/1", "/api/incidents/rules",
                    "/api/incidents/interfaces", "/api/observability/anomalies"):
            self.assertEqual(c.get(url).status_code, 404, url)
        for url in ("/api/incidents/1/status", "/api/incidents/1/explain",
                    "/api/incidents/interfaces/expected",
                    "/api/incidents/rules/X/parameters",
                    "/api/observability/anomalies/1/status"):
            self.assertEqual(c.post(url, json={}, headers=self.H).status_code,
                             404, url)

    def test_moved_interface_routes_run(self):
        self.assertEqual(TestClient(app_server.app).get(
            "/api/observability/interfaces").status_code, 401)
        c = self._client("adm")
        r = c.get("/api/observability/interfaces")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["min_transitions"], 4)
        # Missing tenant/device_ip: the handler ran and refused it.
        r = c.post("/api/observability/interfaces/expected", json={},
                   headers=self.H)
        self.assertEqual(r.status_code, 400, r.text)


class TestLegacyIncidentSettings(_Base):
    """An install upgraded from a release with the incidents engine still has
    correlation_rules and old MCP tool names saved: startup and the surviving
    routes ignore them."""

    def setUp(self):
        from core.app_settings import save_app_settings
        save_app_settings({
            "correlation_rules": {"IFACE_FLAPPING_001": {"min_transitions": 50},
                                  "BLOCKED_TRAFFIC_001": {"min_observations": 9}},
            "mcp": {"disabled_tools": ["get_anomalies", "list_incidents",
                                       "linux_health"]}})
        self.addCleanup(save_app_settings, {"correlation_rules": None, "mcp": None,
                                            "observability": {}})

    def test_startup_and_routes_ignore_them(self):
        import asyncio
        from core.app_settings import save_app_settings
        from observability import listener_manager

        save_app_settings({"observability": {"enabled": True,
                                             "syslog_enabled": False,
                                             "api_poll_s": 0}})

        async def _boot():
            await listener_manager.apply_obs_config(data_config.obs_config())
            await listener_manager.shutdown()

        db.migrate()
        asyncio.run(_boot())

        c = self._client("adm")
        self.assertEqual(c.get("/api/mcp/tool-config").json()["disabled_tools"],
                         ["linux_health"])
        r = c.get("/api/observability/interfaces")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["min_transitions"], 4)


@classmethod
def _tearDownModule():
    shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()


class TestApiContextTenantScope(_Base):
    """The "latest snapshot per kind" subquery must be tenant-scoped too.

    Two customers may each own 192.0.2.10. With an unscoped subquery, MAX(id)
    picks whichever tenant wrote last; the outer tenant filter then drops that
    row and the scoped user sees nothing instead of their own snapshot.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        conn = db.get_observability_connection()
        for tenant, payload in (("sede-a", {"cpu": 11}), ("sede-b", {"cpu": 99})):
            conn.execute(
                "INSERT INTO api_observations (ts, tenant, device_ip, kind, "
                "summary_json) VALUES (?, ?, '192.0.2.10', 'system', ?)",
                (NOW, tenant, json.dumps(payload)))
        conn.commit()

    def test_scoped_user_sees_their_own_latest_snapshot(self):
        c = self._client("op_a")
        r = c.get("/api/observability/api-context", params={"device_ip": "192.0.2.10"})
        self.assertEqual(r.status_code, 200)
        obs = r.json()["observations"]
        self.assertEqual(len(obs), 1, "sede-b's newer row hid sede-a's own snapshot")
        self.assertEqual(obs[0]["tenant"], "sede-a")

    def test_unscoped_admin_still_sees_one_row_per_tenant_kind(self):
        c = self._client("adm")
        r = c.get("/api/observability/api-context", params={"device_ip": "192.0.2.10"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()["observations"]), 1)


class TestObsBindValidation(unittest.TestCase):
    """Security review 2026-10-12, L3: 'bind' was stored as given."""

    def test_a_non_address_bind_is_refused_before_saving(self):
        import asyncio
        from fastapi import HTTPException
        from routers import observability as obs_router
        admin = {"sub": "adm", "role": "super_admin"}
        for bad in (123, "not-an-ip", "0.0.0.0; rm"):
            with self.subTest(bind=bad), \
                 patch.object(obs_router, "save_app_settings") as save:
                with self.assertRaises(HTTPException) as ctx:
                    asyncio.run(obs_router.obs_set_config({"bind": bad}, current_user=admin))
                self.assertEqual(ctx.exception.status_code, 400)
                save.assert_not_called()


class TestObsConfigLegacyFlowKeys(_Base):
    """A tab running JS cached from before the flow removal still posts
    ipfix_* / sflow_* / netflow_* keys: they are dropped, not a 400."""

    def setUp(self):
        from unittest.mock import AsyncMock
        from observability import listener_manager
        p = patch.object(listener_manager, "apply_obs_config", new=AsyncMock())
        p.start()
        self.addCleanup(p.stop)
        # Other modules in the same worker read obs_config() defaults.
        from core.app_settings import save_app_settings
        self.addCleanup(save_app_settings, {"observability": {}})

    def _post(self, body):
        return self._client("adm").post("/api/observability/config", json=body,
                                        headers={"X-Requested-With": "SentinelNet"})

    def _saved(self):
        from core.app_settings import get_app_settings
        return get_app_settings().get("observability", {})

    def test_legacy_keys_are_dropped_and_the_rest_saved(self):
        from core.app_settings import save_app_settings
        # A key left behind in the file by an older release is cleaned too.
        save_app_settings({"observability": {"sflow_port": 6343}})
        r = self._post({
            "enabled": False, "syslog_enabled": True, "syslog_port": 5515,
            "ipfix_enabled": True, "ipfix_port": 4739,
            "sflow_enabled": False, "netflow_port": 2055})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(sorted(r.json()["ignored"]),
                         ["ipfix_enabled", "ipfix_port", "netflow_port", "sflow_enabled"])
        saved = self._saved()
        self.assertEqual(saved["syslog_port"], 5515)
        self.assertTrue(saved["syslog_enabled"])
        self.assertFalse([k for k in saved if k.startswith(("ipfix_", "sflow_", "netflow_"))])

    def test_no_legacy_keys_gives_empty_ignored(self):
        r = self._post({"enabled": False})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["ignored"], [])

    def test_unknown_non_legacy_key_still_400(self):
        r = self._post({"enabled": False, "bogus_port": 1})
        self.assertEqual(r.status_code, 400)
        self.assertIn("bogus_port", r.json()["detail"])

    def test_get_reports_platform_default_port(self):
        for platform, port in (("win32", 514), ("linux", 5514)):
            with patch.object(data_config.sys, "platform", platform):
                r = self._client("adm").get("/api/observability/config")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["syslog"]["default_port"], port)
