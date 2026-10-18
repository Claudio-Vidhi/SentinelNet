"""Two tenants may own the same IP: every reader of a device's backup must
stay inside the tenant of the device it resolved, or the newer backup of the
other customer wins."""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from ai import config_analyzer
from core import core_engine

IP = "192.0.2.10"


class BackupTenantScope(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="sentinelnet_scope_")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        for tenant, host in (("sede-a", "mine"), ("sede-b", "theirs")):
            d = os.path.join(self.root, tenant, "cisco")
            os.makedirs(d)
            with open(os.path.join(d, f"{host}-{IP}.txt"), "w", encoding="utf-8") as fh:
                fh.write(f"hostname {host}\n")
        # The other customer's copy is the fresher one.
        os.utime(os.path.join(self.root, "sede-a", "cisco", f"mine-{IP}.txt"), (1, 1))
        p = mock.patch.object(core_engine, "BACKUP_FOLDER", self.root)
        p.start()
        self.addCleanup(p.stop)
        config_analyzer._analyze_device_at.cache_clear()
        self.addCleanup(config_analyzer._analyze_device_at.cache_clear)

    def test_router_reads_the_backup_of_the_resolved_tenant(self):
        from routers import analyzer
        with mock.patch.object(analyzer, "assert_device_allowed",
                               return_value={"IP": IP, "Group": "sede-a"}):
            text = analyzer._load_backup_text(IP, current_user=None)
        self.assertIn("hostname mine", text)
        self.assertNotIn("theirs", text)

    def test_cached_analysis_is_keyed_by_tenant(self):
        seen = []
        with mock.patch.object(config_analyzer, "analyze_device",
                               side_effect=lambda ip, tenant=None: seen.append(tenant) or {}):
            config_analyzer.analyze_device_cached(IP, "sede-a")
            config_analyzer.analyze_device_cached(IP, "sede-b")
        self.assertEqual(seen, ["sede-a", "sede-b"])


if __name__ == "__main__":
    unittest.main()
