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


if __name__ == "__main__":
    unittest.main()
