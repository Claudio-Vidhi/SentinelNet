# -*- coding: utf-8 -*-
"""hosts.csv is read and written concurrently, and on Windows that raced.

A triage runs up to 10 devices in parallel and each one writes the inventory
back through safe_write_hosts_csv, while the dashboard polls
/api/local-devices, which reads it. Both the os.replace and its in-place
Windows fallback leave the file briefly unopenable or truncated, so a reader
landing in that window got a PermissionError (a 500 on /api/local-devices) or
silently read zero rows (an inventory that blinks empty).

Redirects get_hosts_csv to a temp file rather than setting
SENTINELNET_DATA_DIR: the whole suite runs in one process and shares that
env var, so pointing it somewhere else here -- let alone cleaning that
directory up afterwards -- breaks whichever module resolved its paths from it.
"""
import shutil
import tempfile
import threading
import unittest
import unittest.mock as mock

from services import inventory_manager


class HostsCsvSurvivesConcurrentAccess(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sentinelnet_hostscsv_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        patcher = mock.patch.object(inventory_manager, "get_hosts_csv",
                                    return_value=f"{self.tmp}/network_hosts.csv")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.devices = [
            {"IP": f"192.0.2.{n}", "Vendor": "cisco", "Profile": "default",
             "Group": "Generale", "Site": "central", "Hostname": f"switch-{n:02d}"}
            for n in range(1, 21)
        ]
        inventory_manager.safe_write_hosts_csv(self.devices)

    def test_readers_never_see_the_file_mid_write(self):
        errors = []

        def write():
            for _ in range(40):
                try:
                    inventory_manager.safe_write_hosts_csv(self.devices)
                except Exception as e:  # noqa: BLE001 - the failure is the finding
                    errors.append(f"write: {e!r}")

        def read():
            for _ in range(120):
                try:
                    rows = inventory_manager.get_all_devices()
                except Exception as e:  # noqa: BLE001
                    errors.append(f"read: {e!r}")
                    continue
                # A half-written file is as bad as an unreadable one.
                if len(rows) != len(self.devices):
                    errors.append(f"read: {len(rows)} rows, expected {len(self.devices)}")

        threads = [threading.Thread(target=write)]
        threads += [threading.Thread(target=read) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors[:5], [], f"{len(errors)} failures, first 5 shown")


if __name__ == "__main__":
    unittest.main()
