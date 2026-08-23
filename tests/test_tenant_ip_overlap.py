# -*- coding: utf-8 -*-
"""Two tenants may own the same IP.

Overlapping RFC 1918 space across customers is the normal state of the world,
not an anomaly. Adding tenant B's device used to delete tenant A's row with the
same address — credentials, site and all, with no warning.
"""
import os
import shutil
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_test_tenant_ip_"))

from services import inventory_manager  # noqa: E402


class SameIpInTwoTenantsCoexist(unittest.TestCase):
    def setUp(self):
        inventory_manager.add_group("ACME", "ACME Corp")
        inventory_manager.add_group("BETA", "Beta LLC")
        # Clear hosts csv
        hosts_csv = inventory_manager.get_hosts_csv()
        if os.path.exists(hosts_csv):
            os.remove(hosts_csv)
        inventory_manager.invalidate_device_ip_cache()

    def test_adding_the_second_tenant_keeps_the_first(self):
        inventory_manager.add_or_update_device(
            ip="192.0.2.10", vendor="cisco", profile="custom",
            username="admin", password="pwd", enable_secret="sec",
            group="ACME"
        )
        inventory_manager.add_or_update_device(
            ip="192.0.2.10", vendor="cisco", profile="custom",
            username="admin", password="pwd", enable_secret="sec",
            group="BETA"
        )

        rows = [d for d in inventory_manager.get_all_devices() if d["IP"] == "192.0.2.10"]
        self.assertEqual(2, len(rows))
        self.assertEqual({"ACME", "BETA"}, {r["Group"] for r in rows})

    def test_updating_one_tenant_does_not_touch_the_other(self):
        inventory_manager.add_or_update_device(
            ip="192.0.2.10", vendor="cisco", profile="custom",
            username="admin_a", password="pwd", enable_secret="sec",
            group="ACME"
        )
        inventory_manager.update_device_hostname("192.0.2.10", "switch-01", group="ACME")

        inventory_manager.add_or_update_device(
            ip="192.0.2.10", vendor="cisco", profile="custom",
            username="admin_b", password="pwd", enable_secret="sec",
            group="BETA"
        )
        inventory_manager.update_device_hostname("192.0.2.10", "switch-99", group="BETA")

        # Update ACME's username
        inventory_manager.add_or_update_device(
            ip="192.0.2.10", vendor="cisco", profile="custom",
            username="admin_a_updated", password="pwd", enable_secret="sec",
            group="ACME"
        )

        rows = {r["Group"]: r for r in inventory_manager.get_all_devices()
                if r["IP"] == "192.0.2.10"}
        self.assertEqual("admin_a_updated", rows["ACME"]["Username"])
        self.assertEqual("admin_b", rows["BETA"]["Username"])
        self.assertEqual("switch-01", rows["ACME"]["Hostname"])
        self.assertEqual("switch-99", rows["BETA"]["Hostname"])


class ResolveDeviceAllowedScopeAware(unittest.TestCase):
    def setUp(self):
        from security import user_manager
        from routers import deps
        inventory_manager.add_group("ACME", "ACME Corp")
        inventory_manager.add_group("BETA", "Beta LLC")
        hosts_csv = inventory_manager.get_hosts_csv()
        if os.path.exists(hosts_csv):
            os.remove(hosts_csv)
        inventory_manager.invalidate_device_ip_cache()

        # Create devices with same IP in ACME and BETA
        inventory_manager.add_or_update_device(
            ip="192.0.2.10", vendor="cisco", profile="custom",
            username="admin_a", password="pwd", enable_secret="sec",
            group="ACME"
        )
        inventory_manager.update_device_hostname("192.0.2.10", "switch-01", group="ACME")

        inventory_manager.add_or_update_device(
            ip="192.0.2.10", vendor="cisco", profile="custom",
            username="admin_b", password="pwd", enable_secret="sec",
            group="BETA"
        )
        inventory_manager.update_device_hostname("192.0.2.10", "switch-99", group="BETA")

    def test_scoped_user_resolves_their_own_tenant_device(self):
        from fastapi import HTTPException
        from routers.deps import assert_device_allowed
        user_acme = {"sub": "user_acme", "role": "operator"}
        user_beta = {"sub": "user_beta", "role": "operator"}

        with unittest.mock.patch("routers.deps.user_group_scope") as mock_scope:
            mock_scope.side_effect = lambda u: {"ACME"} if u["sub"] == "user_acme" else {"BETA"}
            dev_a = assert_device_allowed(user_acme, "192.0.2.10")
            self.assertIsNotNone(dev_a)
            self.assertEqual("ACME", dev_a["Group"])
            self.assertEqual("switch-01", dev_a["Hostname"])

            dev_b = assert_device_allowed(user_beta, "192.0.2.10")
            self.assertIsNotNone(dev_b)
            self.assertEqual("BETA", dev_b["Group"])
            self.assertEqual("switch-99", dev_b["Hostname"])

    def test_unscoped_admin_without_tenant_gets_409_on_ambiguity(self):
        from fastapi import HTTPException
        from routers.deps import assert_device_allowed
        admin = {"sub": "admin", "role": "admin"}

        with unittest.mock.patch("routers.deps.user_group_scope", return_value=None):
            with self.assertRaises(HTTPException) as ctx:
                assert_device_allowed(admin, "192.0.2.10")
            self.assertEqual(409, ctx.exception.status_code)
            self.assertIn("192.0.2.10", ctx.exception.detail)
            self.assertIn("ACME", ctx.exception.detail)
            self.assertIn("BETA", ctx.exception.detail)

    def test_unscoped_admin_with_tenant_resolves_specified_device(self):
        from routers.deps import assert_device_allowed
        admin = {"sub": "admin", "role": "admin"}

        with unittest.mock.patch("routers.deps.user_group_scope", return_value=None):
            dev = assert_device_allowed(admin, "192.0.2.10", tenant="BETA")
            self.assertIsNotNone(dev)
            self.assertEqual("BETA", dev["Group"])
            self.assertEqual("switch-99", dev["Hostname"])


if __name__ == "__main__":
    unittest.main()
