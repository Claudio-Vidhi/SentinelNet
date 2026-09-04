# -*- coding: utf-8 -*-
"""Due buchi trovati dalla review FastAPI.

1. GET /api/local-devices restituiva l'intera riga di inventario, comprese
   'Password' ed 'Enable Secret' cifrate, a QUALSIASI utente autenticato —
   mentre due righe piu' sotto la community SNMP veniva tolta apposta.
2. POST /api/scan-subnet accettava un group arbitrario: assert_group_allowed
   era importato e mai chiamato, quindi con auto_add un operatore di una sede
   piantava apparati nell'inventario di un'altra. Risolto alla radice: la
   scansione e' solo scoperta (ping + porte TCP) e non scrive piu' nulla
   nell'inventario; l'unica via d'ingresso resta /api/add-device, che ha il
   suo controllo di sede.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_leak_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
from tests.routes import iter_routes  # noqa: E402
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


class TestScanWritesNothingToInventory(unittest.TestCase):
    """Il buco 2 era group + auto_add: ora la scansione e' solo scoperta e non
    scrive nell'inventario, quindi non c'e' piu' un group da difendere qui.
    Il controllo di sede vive su /api/add-device (test_rbac_scope)."""

    def _scan(self, body):
        from fastapi.testclient import TestClient
        import app_server
        from routers.deps import get_current_user

        app_server.app.dependency_overrides[get_current_user] = \
            lambda: {"sub": "tester", "role": "operator"}
        try:
            with patch("routers.deps.user_manager.get_user_groups",
                       return_value=["sede-a"]), \
                 patch("routers.scan._run_scan_job"):
                return TestClient(app_server.app).post("/api/scan-subnet", json=body)
        finally:
            app_server.app.dependency_overrides.pop(get_current_user, None)

    def test_legacy_keys_are_accepted_and_ignored(self):
        # Chiavi vecchie nel payload non devono ne' errorare ne' risuscitare
        # la scrittura in inventario: pydantic le ignora.
        r = self._scan({"network": "192.0.2.0/29", "vendor": "linux",
                        "group": "sede-b", "auto_add": True})
        self.assertEqual(r.status_code, 200)

    def test_router_has_no_inventory_access(self):
        # Strutturale: se il modulo non nomina inventory_manager non esiste
        # payload che faccia scrivere la scansione nell'inventario.
        import inspect
        from routers import scan
        self.assertNotIn("inventory_manager", inspect.getsource(scan))


class TestProvisionerPushIsAdminOnly(unittest.TestCase):
    """Le push di provisioning accettano host e credenziali dal chiamante e
    scrivono una config day-0 su un apparato che NON e' in inventario: nessun
    assert_device_allowed puo' coprirle, quindi con require_operator un
    operatore di sede aveva raggio d'azione su tutta la rete. Test strutturale
    sulle dipendenze della rotta: nessun payload da inventare."""

    PATHS = ("/api/provisioner/push-ssh", "/api/provisioner/push-serial")

    def test_push_endpoints_require_admin(self):
        import app_server
        from routers.deps import require_admin

        for path in self.PATHS:
            route = next((r for r in iter_routes(app_server.app)
                          if getattr(r, "path", None) == path), None)
            self.assertIsNotNone(route, f"rotta {path} non trovata")
            calls = {d.call for d in route.dependant.dependencies}
            self.assertIn(require_admin, calls,
                          f"{path} deve dipendere da require_admin")


if __name__ == "__main__":
    unittest.main()
