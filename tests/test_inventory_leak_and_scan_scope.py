# -*- coding: utf-8 -*-
"""Due buchi trovati dalla review FastAPI.

1. GET /api/local-devices restituiva l'intera riga di inventario, comprese
   'Password' ed 'Enable Secret' cifrate, a QUALSIASI utente autenticato —
   mentre due righe piu' sotto la community SNMP veniva tolta apposta.
2. POST /api/scan-subnet accettava un group arbitrario: assert_group_allowed
   era importato e mai chiamato, quindi con auto_add un operatore di una sede
   piantava apparati nell'inventario di un'altra.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_leak_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

INVENTORY = [{
    "IP": "192.0.2.10", "Hostname": "switch-01", "Vendor": "cisco",
    "Group": "sede-b", "Username": "operatore",
    "Password": "<ciphertext>", "Enable Secret": "<ciphertext>",
    "SNMP Community": "<ciphertext>",
}]


class TestLocalDevicesHidesCredentials(unittest.TestCase):

    def test_credentials_never_reach_the_client(self):
        from fastapi.testclient import TestClient
        import app_server
        from routers.deps import get_current_user

        app_server.app.dependency_overrides[get_current_user] = \
            lambda: {"sub": "tester", "role": "viewer"}
        try:
            with patch("services.inventory_manager.get_all_devices",
                       return_value=INVENTORY), \
                 patch("services.inventory_manager.get_detected_versions",
                       return_value={}), \
                 patch("services.inventory_manager.get_all_groups",
                       return_value={"sede-b": {}}), \
                 patch("routers.deps.user_manager.get_user_groups",
                       return_value=["sede-b"]):
                r = TestClient(app_server.app).get("/api/local-devices")
        finally:
            app_server.app.dependency_overrides.pop(get_current_user, None)

        self.assertEqual(r.status_code, 200)
        devices = r.json()["devices"]
        self.assertEqual(len(devices), 1)

        # Sul VALORE, non sui nomi dei campi: se qualcuno rinomina la colonna o
        # ne aggiunge una nuova col segreto dentro, un controllo per chiave
        # passerebbe mentre il dato esce lo stesso.
        self.assertNotIn("<ciphertext>", r.text,
                         "un segreto cifrato e' finito nella risposta")

        for secret in ("Password", "Enable Secret", "SNMP Community"):
            self.assertNotIn(secret, devices[0],
                             f"'{secret}' non deve uscire dalla rotta")
        # Il resto della riga continua ad arrivare.
        self.assertEqual(devices[0]["IP"], "192.0.2.10")


class TestScanSubnetGroupScope(unittest.TestCase):

    def _scan(self, group, groups):
        from fastapi.testclient import TestClient
        import app_server
        from routers.deps import get_current_user

        app_server.app.dependency_overrides[get_current_user] = \
            lambda: {"sub": "tester", "role": "operator"}
        try:
            with patch("routers.deps.user_manager.get_user_groups",
                       return_value=groups), \
                 patch("routers.scan._run_scan_job"):
                return TestClient(app_server.app).post(
                    "/api/scan-subnet",
                    json={"network": "192.0.2.0/29", "vendor": "linux",
                          "group": group, "auto_add": True})
        finally:
            app_server.app.dependency_overrides.pop(get_current_user, None)

    def test_group_outside_scope_is_denied(self):
        self.assertEqual(self._scan("sede-b", ["sede-a"]).status_code, 403)

    def test_own_group_is_allowed(self):
        self.assertEqual(self._scan("sede-a", ["sede-a"]).status_code, 200)


class TestProvisionerPushIsAdminOnly(unittest.TestCase):
    """Le push di provisioning accettano host e credenziali dal chiamante e
    scrivono una config day-0 su un apparato che NON e' in inventario: nessun
    assert_device_allowed puo' coprirle, quindi con require_operator un
    operatore di sede aveva raggio d'azione su tutta la rete. Test strutturale
    sulle dipendenze della rotta: nessun payload da inventare."""

    PATHS = ("/api/provisioner/push-ssh", "/api/provisioner/push-serial",
             "/api/provisioner/fgt/push-ssh", "/api/provisioner/fgt/push-serial")

    def test_push_endpoints_require_admin(self):
        import app_server
        from routers.deps import require_admin

        for path in self.PATHS:
            route = next((r for r in app_server.app.routes
                          if getattr(r, "path", None) == path), None)
            self.assertIsNotNone(route, f"rotta {path} non trovata")
            calls = {d.call for d in route.dependant.dependencies}
            self.assertIn(require_admin, calls,
                          f"{path} deve dipendere da require_admin")


if __name__ == "__main__":
    unittest.main()
