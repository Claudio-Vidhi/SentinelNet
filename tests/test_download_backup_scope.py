# -*- coding: utf-8 -*-
"""``download_backup`` must scope on the SAME IP it resolves the file with.

It derived the IP twice from the caller-supplied name, two different ways: the
scope check took the FIRST IP the name contains (regex), the file lookup took
the LAST token after splitting on '-' / '_'. A scoped user could therefore put
their own IP first and somebody else's last -- the check passed on theirs, the
walk returned the other tenant's backup.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_dlscope_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

MINE = "192.0.2.10"      # sede-a, the caller's own device
THEIRS = "198.51.100.7"  # sede-b, another customer
SECRET = "enable secret 0 hunter2\n"

INVENTORY = [
    {"IP": MINE, "Hostname": "switch-01", "Vendor": "cisco", "Group": "sede-a"},
    {"IP": THEIRS, "Hostname": "switch-02", "Vendor": "cisco", "Group": "sede-b"},
]


class TestDownloadBackupScope(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="sentinelnet_backups_")
        other = os.path.join(cls._tmp.name, "sede-b")
        os.makedirs(other, exist_ok=True)
        with open(os.path.join(other, f"cisco-{THEIRS}.txt"), "w", encoding="utf-8") as fh:
            fh.write(SECRET)
        mine = os.path.join(cls._tmp.name, "sede-a")
        os.makedirs(mine, exist_ok=True)
        with open(os.path.join(mine, f"cisco-{MINE}.txt"), "w", encoding="utf-8") as fh:
            fh.write("hostname switch-01\n")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _get(self, name, groups=("sede-a",)):
        from fastapi.testclient import TestClient
        import app_server
        from routers.deps import require_operator

        app_server.app.dependency_overrides[require_operator] = \
            lambda: {"sub": "tester", "role": "operator"}
        try:
            with patch("services.inventory_manager.get_all_devices",
                       return_value=INVENTORY), \
                 patch("routers.deps.user_manager.get_user_groups",
                       return_value=list(groups)), \
                 patch("routers.backup.core_engine.BACKUP_FOLDER", self._tmp.name):
                return TestClient(app_server.app).get(f"/api/download-backup/{name}")
        finally:
            app_server.app.dependency_overrides.pop(require_operator, None)

    def test_own_backup_is_served(self):
        r = self._get(MINE)
        self.assertEqual(r.status_code, 200)
        self.assertIn("switch-01", r.text)

    def test_other_tenant_backup_is_refused(self):
        self.assertEqual(self._get(THEIRS).status_code, 403)

    def test_own_ip_first_does_not_unlock_another_tenants_ip(self):
        r = self._get(f"{MINE}-{THEIRS}.txt")
        self.assertNotEqual(r.status_code, 200,
                            "served a backup the caller's scope does not cover")
        self.assertNotIn("hunter2", r.text)

    def test_traversal_is_still_blocked(self):
        r = self._get("..%2f..%2fusers.json")
        self.assertNotEqual(r.status_code, 200)

    def test_admin_is_unscoped(self):
        r = self._get(THEIRS, groups=())
        self.assertEqual(r.status_code, 200)
        self.assertIn("hunter2", r.text)


if __name__ == "__main__":
    unittest.main()
