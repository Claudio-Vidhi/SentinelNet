# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Demo mode (docs/demo.md): data directory redirection, the synthetic seed,
the start/stop routes and the guard that keeps every packet on loopback."""
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from core import data_config, demo_guard
from routers.deps import CSRF_HEADER
from security import security_manager, user_manager
from services import self_update

ROOT = pathlib.Path(__file__).resolve().parent.parent
PW = "PasswordSicura1!"


def _python(real_dir: str, code: str) -> str:
    """Run ``code`` in a fresh interpreter: data_config decides at import, and
    conftest has already pinned this process's data directory."""
    env = dict(os.environ, SENTINELNET_DATA_DIR=real_dir, PYTHONPATH=str(ROOT))
    out = subprocess.run([sys.executable, "-c", code], cwd=real_dir, env=env,
                         capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr[-3000:]
    return out.stdout.strip().splitlines()[-1]


class TestDataDirRedirection(unittest.TestCase):
    CODE = ("from core import data_config as d; import json, os; "
            "print(json.dumps([d.DATA_DIR, d.DEMO_MODE, os.environ['SENTINELNET_DATA_DIR']]))")

    def test_without_marker_the_real_dir(self):
        real = tempfile.mkdtemp(prefix="demo_real_")
        self.assertEqual(json.loads(_python(real, self.CODE)), [real, False, real])

    def test_with_marker_the_demo_dir(self):
        real = tempfile.mkdtemp(prefix="demo_real_")
        open(os.path.join(real, "demo-mode"), "w").close()
        demo = os.path.join(real, "demo")
        self.assertEqual(json.loads(_python(real, self.CODE)), [demo, True, demo])


class TestSeed(unittest.TestCase):
    CODE = """
import json, os
from core import data_config, db
from collectors import mac_history
from services import demo_seed, inventory_manager, segment_manager, cve_intel
from services.config_drift import history
seeded = demo_seed.seed()
devs = inventory_manager.get_all_devices()
per_tenant = {}
for d in devs:
    per_tenant[d["Group"]] = per_tenant.get(d["Group"], 0) + 1
conn = db.get_observability_connection()
policy = conn.execute("SELECT COUNT(*) FROM policy_hit_snapshots").fetchone()[0]
audits = conn.execute("SELECT COUNT(*) FROM netsec_audit_runs").fetchone()[0]
conn.close()
print(json.dumps({
    "seeded": seeded, "dir": data_config.DATA_DIR,
    "orgs": sorted(inventory_manager.get_all_groups()),
    "per_tenant": per_tenant,
    "max_versions": max(len(history.list_versions(d)) for d in devs),
    "segments": sum(len(segment_manager.list_segments(o)["segments"]) for o in per_tenant),
    "arp": len(mac_history.search_arp(limit=500)),
    "macs": len(mac_history.positions_for_mac("aa:bb:cc:10:00:01")),
    "cve": sum(1 for d in devs if (cve_intel.load(d) or {}).get("cves")),
    "policy": policy, "audits": audits,
}))
"""

    def test_populates_every_area_once(self):
        real = tempfile.mkdtemp(prefix="demo_seed_")
        open(os.path.join(real, "demo-mode"), "w").close()
        first = json.loads(_python(real, self.CODE))
        self.assertTrue(first["seeded"])
        self.assertEqual(first["dir"], os.path.join(real, "demo"))
        self.assertEqual(first["orgs"], ["acme-hq", "plant-demo", "plant-legacy"])
        for tenant in first["orgs"]:
            self.assertGreaterEqual(first["per_tenant"].get(tenant, 0), 2, tenant)
        self.assertGreaterEqual(first["max_versions"], 2)
        for key in ("segments", "arp", "macs", "cve", "policy", "audits"):
            self.assertGreater(first[key], 0, key)
        self.assertTrue(os.path.isfile(os.path.join(real, "demo", "DEMO-CREDENTIALS.txt")))
        # Nothing but the marker and the demo workspace in the real directory.
        self.assertEqual(sorted(os.listdir(real)), ["demo", "demo-mode"])

        second = json.loads(_python(real, self.CODE))
        self.assertFalse(second["seeded"])
        self.assertEqual({k: v for k, v in second.items() if k != "seeded"},
                         {k: v for k, v in first.items() if k != "seeded"})

    def test_refuses_outside_demo_mode(self):
        from services import demo_seed
        with self.assertRaises(RuntimeError):
            demo_seed.seed()


class TestRoutes(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="demo_api_")
        self.marker = os.path.join(tmp, "demo-mode")
        for p in (patch.object(data_config, "DEMO_MARKER", self.marker),
                  patch.object(data_config, "DEMO_DIR", os.path.join(tmp, "demo")),
                  patch.object(user_manager, "USERS_JSON", os.path.join(tmp, "users.json"))):
            p.start()
            self.addCleanup(p.stop)
        security_manager._failed_attempts.clear()

    def _as(self, name, role):
        user_manager.create_user(name, PW, role=role)
        c = TestClient(app_server.app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", json={"username": name, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        c.headers.update({CSRF_HEADER: "1"})
        return c

    def _supervised(self):
        return (patch.object(self_update, "supervisor", return_value="systemd"),
                patch.object(self_update, "restart", return_value="systemd"))

    def test_status_reports_demo_flag(self):
        r = TestClient(app_server.app).get("/api/auth/status")
        self.assertIs(r.json()["demo"], False)

    def test_start_without_auth_is_refused_once_users_exist(self):
        user_manager.create_user("someone", PW, role="viewer")
        sup, rst = self._supervised()
        with sup, rst as restart:
            r = TestClient(app_server.app).post("/api/demo/start")
        self.assertIn(r.status_code, (401, 403), r.text)
        restart.assert_not_called()
        self.assertFalse(os.path.exists(self.marker))

    def test_start_without_auth_on_a_fresh_install(self):
        sup, rst = self._supervised()
        with sup, rst as restart:
            r = TestClient(app_server.app).post("/api/demo/start")
        self.assertEqual(r.status_code, 200, r.text)
        restart.assert_called_once()
        self.assertTrue(os.path.exists(self.marker))
        self.assertEqual(r.json()["username"], "admin")
        self.assertGreaterEqual(len(r.json()["password"]), 16)

    def test_admin_below_super_admin_is_refused(self):
        c = self._as("adm", "admin")
        sup, rst = self._supervised()
        with sup, rst:
            self.assertEqual(c.post("/api/demo/start").status_code, 403)
        self.assertFalse(os.path.exists(self.marker))

    def test_super_admin_start_returns_credentials_and_marks(self):
        c = self._as("root", "super_admin")
        sup, rst = self._supervised()
        with sup, rst as restart:
            r = c.post("/api/demo/start")
        self.assertEqual(r.status_code, 200, r.text)
        restart.assert_called_once()
        self.assertTrue(os.path.exists(self.marker))
        # Same credentials as the file the seed will read at boot.
        from services import demo_seed
        self.assertEqual((r.json()["username"], r.json()["password"]), demo_seed.credentials())

    def test_no_supervisor_points_to_the_dev_launcher(self):
        c = self._as("root", "super_admin")
        with patch.object(self_update, "supervisor", return_value=""):
            r = c.post("/api/demo/start")
        self.assertEqual(r.status_code, 409)
        self.assertIn("scripts/dev/run_demo.py", r.json()["detail"])
        self.assertFalse(os.path.exists(self.marker))

    def test_stop_outside_demo_is_409(self):
        c = self._as("root", "super_admin")
        self.assertEqual(c.post("/api/demo/stop").status_code, 409)

    def test_stop_in_demo_removes_marker(self):
        c = self._as("root", "super_admin")
        open(self.marker, "w").close()
        sup, rst = self._supervised()
        with sup, rst as restart, patch.object(data_config, "DEMO_MODE", True):
            r = c.post("/api/demo/stop")
        self.assertEqual(r.status_code, 200, r.text)
        restart.assert_called_once()
        self.assertFalse(os.path.exists(self.marker))


class TestGuard(unittest.TestCase):
    def setUp(self):
        p = patch.object(data_config, "DEMO_MODE", True)
        p.start()
        self.addCleanup(p.stop)
        demo_guard.install()

    def test_active_routes_answer_409(self):
        c = TestClient(app_server.app, raise_server_exceptions=False)
        for path, body in (("/api/scan-subnet", {"network": "192.0.2.0/24", "ports": [22]}),
                           ("/api/send-command", {}), ("/api/run-triage", {}),
                           ("/api/provisioner/push-ssh", {})):
            with self.subTest(path=path):
                r = c.post(path, json=body)
                self.assertEqual(r.status_code, 409, r.text)
                self.assertIn("Demo mode", r.json()["detail"])

    def test_outbound_sockets_are_refused_loopback_is_not(self):
        with self.assertRaises(demo_guard.DemoModeError):
            socket.create_connection(("192.0.2.1", 22), timeout=1)
        with self.assertRaises(demo_guard.DemoModeError):
            socket.getaddrinfo("example.com", 443)
        with self.assertRaises(demo_guard.DemoModeError):
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("192.0.2.1", 161))
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        try:
            socket.create_connection(srv.getsockname(), timeout=1).close()
        finally:
            srv.close()

    def test_icmp_is_refused(self):
        from collectors import network_scanner
        with patch.object(subprocess, "run") as run, self.assertRaises(demo_guard.DemoModeError):
            network_scanner._ping("192.0.2.1")
        run.assert_not_called()

    def test_off_outside_demo(self):
        with patch.object(data_config, "DEMO_MODE", False):
            self.assertFalse(demo_guard.blocked("POST", "/api/scan-subnet"))
            demo_guard.refuse()


if __name__ == "__main__":
    unittest.main()
