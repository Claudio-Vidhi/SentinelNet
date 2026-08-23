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


class BackupTreeDoesNotCrossTenants(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch("core.core_engine.BACKUP_FOLDER", self._tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_saving_backup_in_one_tenant_does_not_touch_or_move_other_tenant(self):
        from core import core_engine
        from services.config_drift import history

        dev_beta = {"IP": "192.0.2.10", "Group": "BETA", "Vendor": "cisco", "Hostname": "switch-99"}
        dev_acme = {"IP": "192.0.2.10", "Group": "ACME", "Vendor": "cisco", "Hostname": "switch-01"}

        # Seed BETA current backup and 2 history versions
        core_engine.save_backup(dev_beta, "switch-99", "hostname switch-99\n! beta v0\n")
        history.record_version(dev_beta, "hostname switch-99\n! beta v1\n")
        history.record_version(dev_beta, "hostname switch-99\n! beta v2\n")

        self.assertEqual(2, len(history.list_versions(dev_beta)))
        beta_backup_file = os.path.join(core_engine.group_backup_dir("BETA", "cisco"), "switch-99-192.0.2.10.txt")
        self.assertTrue(os.path.exists(beta_backup_file))

        # Now save backup for ACME with the same IP
        core_engine.save_backup(dev_acme, "switch-01", "hostname switch-01\n! acme v0\n")
        history.record_version(dev_acme, "hostname switch-01\n! acme v1\n")

        # BETA must still have its backup and both history versions intact
        self.assertTrue(os.path.exists(beta_backup_file), "BETA current backup was moved or deleted!")
        self.assertEqual(2, len(history.list_versions(dev_beta)), "BETA history was moved or truncated!")

        # ACME must have its own backup and history
        acme_backup_file = os.path.join(core_engine.group_backup_dir("ACME", "cisco"), "switch-01-192.0.2.10.txt")
        self.assertTrue(os.path.exists(acme_backup_file))
        self.assertEqual(1, len(history.list_versions(dev_acme)))


class GetDeviceByIpTenantAware(unittest.TestCase):
    def setUp(self):
        inventory_manager.add_group("ACME", "ACME Corp")
        inventory_manager.add_group("BETA", "Beta LLC")
        hosts_csv = inventory_manager.get_hosts_csv()
        if os.path.exists(hosts_csv):
            os.remove(hosts_csv)
        inventory_manager.invalidate_device_ip_cache()

        # Seed same IP in ACME and BETA
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

    def test_calling_with_tenant_resolves_the_correct_device(self):
        dev_acme = inventory_manager.get_device_by_ip("192.0.2.10", tenant="ACME")
        self.assertIsNotNone(dev_acme)
        self.assertEqual("192.0.2.10", dev_acme["ip"])
        self.assertEqual("ACME", dev_acme["tenant"])
        self.assertEqual("switch-01", dev_acme["hostname"])

        dev_beta = inventory_manager.get_device_by_ip("192.0.2.10", tenant="BETA")
        self.assertIsNotNone(dev_beta)
        self.assertEqual("192.0.2.10", dev_beta["ip"])
        self.assertEqual("BETA", dev_beta["tenant"])
        self.assertEqual("switch-99", dev_beta["hostname"])

    def test_calling_without_tenant_returns_collision_sentinel_on_duplicate(self):
        res = inventory_manager.get_device_by_ip("192.0.2.10")
        self.assertEqual({"collision": True}, res)

    def test_nonexistent_device_returns_none(self):
        self.assertIsNone(inventory_manager.get_device_by_ip("198.51.100.1", tenant="ACME"))
        self.assertIsNone(inventory_manager.get_device_by_ip("198.51.100.1"))


if __name__ == "__main__":
    unittest.main()
