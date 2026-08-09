# -*- coding: utf-8 -*-
"""Fallimenti silenziosi: se lo stato non viene persistito, deve restare
una traccia.

Il ping risponde all'utente con l'esito vero anche quando la scrittura su
``detected_versions.json`` fallisce: la risposta HTTP e' corretta, ma
l'inventario resta indietro e nessuno se ne accorge. Il ``pass`` nudo
rendeva questa divergenza invisibile pure nei log.
"""

import os
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_silentfail_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR


class TestPingPersistenceIsLogged(unittest.TestCase):

    def test_scrittura_stato_fallita_lascia_un_warning(self):
        from fastapi.testclient import TestClient
        from unittest.mock import patch
        import app_server
        from routers.deps import get_current_user

        app_server.app.dependency_overrides[get_current_user] = \
            lambda: {"sub": "tester", "role": "admin"}
        try:
            with patch("services.inventory_manager.get_all_devices",
                       return_value=[{"IP": "192.0.2.10", "Group": "Generale"}]), \
                 patch("collectors.network_scanner._ping", return_value=True), \
                 patch("services.inventory_manager.get_detected_versions",
                       side_effect=OSError("disco pieno")), \
                 patch("routers.triage.log_audit"):
                client = TestClient(app_server.app)
                with self.assertLogs("root", level="WARNING") as captured:
                    res = client.get("/api/ping/192.0.2.10",
                                     headers={"X-Requested-With": "x"})
        finally:
            app_server.app.dependency_overrides.pop(get_current_user, None)

        # L'utente vede comunque l'esito reale del ping...
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["reachable"])
        # ...ma la mancata persistenza non e' piu' muta.
        self.assertTrue(any("192.0.2.10" in m and "non persistito" in m
                            for m in captured.output), captured.output)


if __name__ == "__main__":
    unittest.main()
