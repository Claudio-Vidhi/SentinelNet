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
from tests.routes import route_paths  # noqa: E402

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
        routes = sorted(route_paths(self.client.app))
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


class RouteWalkerSurvivesNesting(unittest.TestCase):
    """The whole point of tests/routes.py: it must find a route that
    include_router did NOT copy into the parent.

    Without this, the walker is indistinguishable from the flat loop it
    replaced on the pinned fastapi, and the day the pin is lifted nobody
    would know whether it works — the contract suites would just go quiet.
    """

    def test_it_finds_routes_a_parent_only_mounts(self):
        from fastapi import APIRouter, FastAPI
        from tests.routes import iter_routes, route_paths

        child = APIRouter()

        @child.get("/api/deep")
        def _deep():  # pragma: no cover - never called, only registered
            return {}

        parent = FastAPI()
        # Mounted, not copied: this is the shape fastapi 0.141 produces for
        # every include_router, and the shape a flat app.routes loop misses.
        parent.mount("/", child)

        self.assertNotIn("/api/deep", {getattr(r, "path", "") for r in parent.routes},
                         "premessa del test caduta: il mount ha copiato le rotte")
        self.assertIn("/api/deep", route_paths(parent))
        self.assertTrue(any(getattr(r, "path", "") == "/api/deep"
                            for r in iter_routes(parent)))

    def test_a_cycle_does_not_hang_the_walk(self):
        from tests.routes import iter_routes

        class Loop:
            path = "/loop"

        node = Loop()
        node.routes = [node]

        class App:
            routes = [node]

        self.assertEqual([r.path for r in iter_routes(App())], ["/loop"])


if __name__ == '__main__':
    unittest.main()
