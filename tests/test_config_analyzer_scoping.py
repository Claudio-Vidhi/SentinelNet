# -*- coding: utf-8 -*-
"""Scoping of GET /api/config-analyzer/{ip}.

Three routes serve the SAME artifact — the stored backup, addressed by IP — and
gave three different answers to "IP not in inventory":

    download_backup (backup.py)        -> 403, explicit
    config_analyzer_convert (through
      _load_backup_text)               -> 404, the device does not exist
    config_analyzer_device             -> served it

The third tested ``device is not None and scope is not None``, so an IP with no
inventory row never entered the branch, and analyze_device() reads the freshest
backup off disk for that IP regardless of inventory. A backup outlives the
device row it belonged to, so the absent IP is not a lab-only case. The route
runs on get_current_user — the lowest role — while the download asks operator.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_cascope_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

# One device in inventory, in sede-b: the user under test sees sede-a.
INVENTORY = [{"IP": "192.0.2.10", "Hostname": "switch-01",
              "Vendor": "cisco", "Group": "sede-b"}]

ANALYSIS = {"ip": "192.0.2.99", "findings": ["placeholder"]}


class TestConfigAnalyzerDeviceScoping(unittest.TestCase):

    def _get(self, ip, groups):
        """GET the route as a non-admin user scoped to ``groups``."""
        from fastapi.testclient import TestClient
        import app_server
        from routers.deps import get_current_user

        # Depends() captures the function at decoration time, so patching the
        # name in the module lands too late — the override is the only hook.
        app_server.app.dependency_overrides[get_current_user] = \
            lambda: {"sub": "tester", "role": "viewer"}
        try:
            with patch("services.inventory_manager.get_all_devices",
                       return_value=INVENTORY), \
                 patch("routers.deps.user_manager.get_user_groups",
                       return_value=groups), \
                 patch("ai.config_analyzer.analyze_device",
                       return_value=ANALYSIS):
                return TestClient(app_server.app).get(f"/api/config-analyzer/{ip}")
        finally:
            app_server.app.dependency_overrides.pop(get_current_user, None)

    def test_ip_absent_from_inventory_is_denied(self):
        """An IP with no inventory row is out of scope, not unscoped.

        It used to serve the backup analysis of a device the user cannot even
        see listed.
        """
        r = self._get("192.0.2.99", ["sede-a"])
        self.assertEqual(r.status_code, 403)

    def test_ip_of_another_site_stays_403(self):
        r = self._get("192.0.2.10", ["sede-a"])
        self.assertEqual(r.status_code, 403)

    def test_ip_of_own_site_passes(self):
        r = self._get("192.0.2.10", ["sede-b"])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), ANALYSIS)

    def test_admin_sees_everything(self):
        """scope None = no restriction, including an IP not in inventory."""
        from fastapi.testclient import TestClient
        import app_server
        from routers.deps import get_current_user

        app_server.app.dependency_overrides[get_current_user] = \
            lambda: {"sub": "root", "role": "admin"}
        try:
            with patch("services.inventory_manager.get_all_devices",
                       return_value=INVENTORY), \
                 patch("ai.config_analyzer.analyze_device",
                       return_value=ANALYSIS):
                r = TestClient(app_server.app).get("/api/config-analyzer/192.0.2.99")
        finally:
            app_server.app.dependency_overrides.pop(get_current_user, None)
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()
