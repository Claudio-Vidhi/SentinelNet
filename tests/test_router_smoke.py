"""
Smoke tests that actually execute handler bodies for every router.
"""
import importlib
import pkgutil
import unittest
from unittest import mock
from fastapi.testclient import TestClient

import routers
import app_server
from security import user_manager

ROUTER_MODULES = [
    f"routers.{m.name}"
    for m in pkgutil.iter_modules(routers.__path__)
    if not m.name.startswith("_")
]

SMOKE_ENDPOINTS = [
    ("post", "/api/analyzer/config", {"device": "does-not-exist"}),
    ("get", "/api/arp/search?q=aa:bb", None),
    ("get", "/api/arp/stats", None),
    ("post", "/api/topology/reset", None),
    ("get", "/api/mac/uplink-ports?device=nope", None),
    ("post", "/api/scan/subnet", {"subnet": "10.0.0.0/30"}),
    ("delete", "/api/catalog/group/nope", None),
    ("get", "/api/ai/profiles", None),
    ("get", "/api/settings/app", None),
    ("get", "/api/settings/ui-variant", None),
    ("post", "/api/settings/ui-variant", {"ui_variant": "design-1"}),
    ("get", "/api/redundancy/groups", None),
    ("post", "/api/policy-test/192.0.2.1/trace", {"src_ip": "1.1.1.1", "dst_ip": "203.0.113.2"}),
    ("get", "/api/policy-test/192.0.2.1/examples", None),
    ("get", "/api/policy-test/192.0.2.1/findings", None),
    ("get", "/api/cloud-backup/settings", None),
    ("get", "/api/cloud-backup/status", None),
    ("post", "/api/cloud-backup/run", None),
]

class TestRouterSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app_server.app, raise_server_exceptions=True)
        try:
            user_manager.create_user("smokeadmin", "Pass123!", role="admin")
        except Exception:
            pass # already exists
        r = cls.client.post("/api/auth/login", json={"username": "smokeadmin", "password": "Pass123!"})
        if r.status_code == 200:
            token = r.json().get("access_token")
            if token:
                cls.client.headers.update({"Authorization": f"Bearer {token}", "X-Requested-With": "SentinelNet"})

    def test_router_module_imports(self):
        for modname in ROUTER_MODULES:
            with self.subTest(modname=modname):
                importlib.import_module(modname)

    def test_app_builds_and_has_routes(self):
        routes = [r.path for r in self.client.app.routes]
        self.assertTrue(routes, "app registered no routes")

    def test_endpoints_execute_without_server_error(self):
        # /api/cloud-backup/run would perform a real SFTP upload if ambient
        # app_settings.json had the mirror enabled: never let a smoke test
        # depend on that. Mock is harmless for every other endpoint here.
        with mock.patch("services.cloud_backup.run_mirror",
                        return_value={"ok": False, "error": "smoke test", "uploaded": 0,
                                      "skipped": 0, "failed": 0, "verified": 0, "files": {}}):
            for method, path, body in SMOKE_ENDPOINTS:
                with self.subTest(method=method, path=path):
                    fn = getattr(self.client, method)
                    resp = fn(path, json=body) if body is not None else fn(path)
                    self.assertNotEqual(resp.status_code, 500, f"{method.upper()} {path} raised a server error: {resp.text}")

    def test_ws_terminal_rejects_bad_token(self):
        with self.assertRaises(Exception):
            with self.client.websocket_connect("/ws/terminal?token=bogus"):
                pass

    def test_banner_error_is_translated_into_a_diagnosis(self):
        # "Error reading SSH protocol banner" da solo manda a cercare un guasto
        # di rete: il TCP si apre, e' il dispositivo che chiude senza
        # presentarsi perche' sta rifiutando le sessioni dopo login falliti.
        import paramiko
        from routers.commands import _ssh_failure_hint

        hint = _ssh_failure_hint(paramiko.SSHException("Error reading SSH protocol banner"))
        self.assertIn("Error reading SSH protocol banner", hint)
        self.assertIn("login falliti", hint)
        self.assertIn("admin-lockout-threshold", hint)

    def test_other_ssh_errors_are_passed_through_untouched(self):
        # Solo l'errore illeggibile viene spiegato: annotare anche gli altri
        # sposterebbe rumore davanti a messaggi gia' chiari.
        import paramiko
        from routers.commands import _ssh_failure_hint

        self.assertEqual(_ssh_failure_hint(paramiko.AuthenticationException("Authentication failed.")),
                         "Authentication failed.")
        self.assertEqual(_ssh_failure_hint(OSError("No route to host")), "No route to host")

if __name__ == '__main__':
    unittest.main()
