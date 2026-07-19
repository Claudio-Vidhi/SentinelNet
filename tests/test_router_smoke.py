"""
Smoke tests that actually execute handler bodies for every router.
"""
import importlib
import pkgutil
import unittest
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
        for method, path, body in SMOKE_ENDPOINTS:
            with self.subTest(method=method, path=path):
                fn = getattr(self.client, method)
                resp = fn(path, json=body) if body is not None else fn(path)
                self.assertNotEqual(resp.status_code, 500, f"{method.upper()} {path} raised a server error: {resp.text}")

    def test_ws_terminal_rejects_bad_token(self):
        with self.assertRaises(Exception):
            with self.client.websocket_connect("/ws/terminal?token=bogus"):
                pass

if __name__ == '__main__':
    unittest.main()
