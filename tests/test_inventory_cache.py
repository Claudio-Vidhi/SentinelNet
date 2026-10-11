# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""get_all_devices() caches parsed rows without ever serving stale ones.

The cache exists because 64 call sites re-read the same inventory, some inside
loops and one on every device-scoped route. The risk it brings is the only
thing worth testing: an inventory answering with what it said a moment ago is
worse than a slow one.
"""
import os
import tempfile
import unittest
from unittest import mock

from services import inventory_manager  # noqa: E402
from tests.conftest import seed_inventory  # noqa: E402

# Own directory with get_hosts_csv() redirected for the test, not our own
# SENTINELNET_DATA_DIR: conftest.py already chose the suite's, and writing the
# inventory there would change it under other modules on the same xdist worker.
_TMP = tempfile.mkdtemp(prefix="sentinelnet_test_invcache_")



def _row(ip):
    return {"IP": ip, "Hostname": "switch-01", "Group": "Generale", "Vendor": "cisco",
            "SSH Port": "22"}


def _write(*ips):
    seed_inventory(hosts=[_row(ip) for ip in ips])


class InventoryCache(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=_TMP)
        patcher = mock.patch.object(inventory_manager, "get_hosts_csv",
                                    return_value=os.path.join(self.dir, "network_hosts.csv"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_rewrite_of_the_same_size_is_still_seen(self):
        """Riscrittura immediata, stessa dimensione: va vista comunque."""
        inventory_manager.write_devices([_row("192.0.2.1")])
        self.assertEqual([d["IP"] for d in inventory_manager.get_all_devices()],
                         ["192.0.2.1"])
        inventory_manager.write_devices([_row("192.0.2.9")])  # same size, right after
        self.assertEqual([d["IP"] for d in inventory_manager.get_all_devices()],
                         ["192.0.2.9"])

    def test_another_inventory_directory_is_not_served_from_the_cache(self):
        """The cache is keyed by database path: pointing get_hosts_csv() at
        another directory (an agent's data dir, another test) must not hand
        back the rows cached for the first one."""
        _write("192.0.2.1")
        self.assertEqual([d["IP"] for d in inventory_manager.get_all_devices()],
                         ["192.0.2.1"])
        other = tempfile.mkdtemp(dir=_TMP)
        with mock.patch.object(inventory_manager, "get_hosts_csv",
                               return_value=os.path.join(other, "network_hosts.csv")):
            _write("192.0.2.9")
            self.assertEqual([d["IP"] for d in inventory_manager.get_all_devices()],
                             ["192.0.2.9"],
                             "la cache ha servito righe di un altro inventario")
        self.assertEqual([d["IP"] for d in inventory_manager.get_all_devices()],
                         ["192.0.2.1"])

    def test_the_rows_handed_out_are_not_the_cached_ones(self):
        """I chiamanti modificano cio' che ricevono prima di riscriverlo
        (routers/inventory.py): una riga condivisa avvelenerebbe la cache."""
        _write("192.0.2.1")
        first = inventory_manager.get_all_devices()
        first[0]["Hostname"] = "avvelenato"
        second = inventory_manager.get_all_devices()
        self.assertEqual(second[0]["Hostname"], "switch-01")

    def test_a_missing_file_is_an_empty_inventory_not_an_error(self):
        self.assertEqual(inventory_manager.get_all_devices(), [])

    def test_legacy_columns_still_get_their_defaults(self):
        seed_inventory(hosts=[{"IP": "192.0.2.1", "Hostname": "switch-01", "Group": "Generale"}])
        device = inventory_manager.get_all_devices()[0]
        self.assertEqual(device["Probe"], "central")
        self.assertEqual(device["SSH Port"], "22")


if __name__ == "__main__":
    unittest.main()
