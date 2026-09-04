# -*- coding: utf-8 -*-
"""get_all_devices() caches parsed rows without ever serving stale ones.

The cache exists because 64 call sites re-read and re-parsed the same CSV,
some inside loops and one on every device-scoped route. The risk it brings is
the only thing worth testing: an inventory answering with what the file said a
moment ago is worse than a slow one.
"""
import os
import tempfile
import unittest
from unittest import mock

from services import inventory_manager  # noqa: E402

# Directory propria e get_hosts_csv() ridiretto per il tempo del test, non un
# SENTINELNET_DATA_DIR nostro: conftest.py ha gia' scelto quella della suite e
# scriverci il network_hosts.csv significherebbe farlo trovare cambiato agli
# altri moduli sullo stesso worker xdist.
_TMP = tempfile.mkdtemp(prefix="sentinelnet_test_invcache_")

HEADER = "IP,Hostname,Group,Site,Vendor,SSH Port\n"


def _write(path, *ips):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(HEADER)
        for ip in ips:
            f.write(f"{ip},switch-01,Generale,central,cisco,22\n")


class InventoryCache(unittest.TestCase):
    def setUp(self):
        self.csv = os.path.join(_TMP, f"network_hosts_{id(self)}.csv")
        patcher = mock.patch.object(inventory_manager, "get_hosts_csv",
                                    return_value=self.csv)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(inventory_manager._invalidate_rows_cache)
        inventory_manager._invalidate_rows_cache()

    def test_a_rewrite_of_the_same_size_is_still_seen(self):
        """Riscrittura immediata, stessa dimensione: va vista comunque."""
        _write(self.csv, "192.0.2.1")
        self.assertEqual([d["IP"] for d in inventory_manager.get_all_devices()],
                         ["192.0.2.1"])
        _write(self.csv, "192.0.2.9")  # stessa lunghezza, subito dopo
        self.assertEqual([d["IP"] for d in inventory_manager.get_all_devices()],
                         ["192.0.2.9"])

    def test_a_filesystem_with_one_second_timestamps_does_not_pin_the_cache(self):
        """Il caso che rompe una cache basata sulla sola firma (mtime, size).

        NTFS qui data i file al 100ns e le due scritture si distinguono da
        sole, quindi il test sopra passerebbe anche senza guardia. ext3 e FAT
        datano al secondo: due scritture di pari dimensione dentro lo stesso
        secondo hanno firma IDENTICA, e senza la soglia di freschezza la
        seconda non si vedrebbe mai piu' -- non per un secondo, mai. Qui il
        secondo intero e' simulato, perche' il filesystem su cui gira la suite
        non e' quello su cui gira il prodotto."""
        real_stat = os.stat

        class _CoarseStat:
            def __init__(self, st):
                self.st_mtime_ns = (st.st_mtime_ns // 1_000_000_000) * 1_000_000_000
                self.st_size = st.st_size

        with mock.patch.object(inventory_manager.os, "stat",
                               lambda p, *a, **k: _CoarseStat(real_stat(p))):
            _write(self.csv, "192.0.2.1")
            self.assertEqual([d["IP"] for d in inventory_manager.get_all_devices()],
                             ["192.0.2.1"])
            _write(self.csv, "192.0.2.9")
            self.assertEqual([d["IP"] for d in inventory_manager.get_all_devices()],
                             ["192.0.2.9"],
                             "la cache ha servito righe vecchie: la firma non "
                             "puo' essere l'unico criterio")

    def test_the_rows_handed_out_are_not_the_cached_ones(self):
        """I chiamanti modificano cio' che ricevono prima di riscriverlo
        (routers/inventory.py): una riga condivisa avvelenerebbe la cache."""
        _write(self.csv, "192.0.2.1")
        first = inventory_manager.get_all_devices()
        first[0]["Hostname"] = "avvelenato"
        second = inventory_manager.get_all_devices()
        self.assertEqual(second[0]["Hostname"], "switch-01")

    def test_a_missing_file_is_an_empty_inventory_not_an_error(self):
        try:
            os.remove(self.csv)
        except OSError:
            pass
        self.assertEqual(inventory_manager.get_all_devices(), [])

    def test_legacy_columns_still_get_their_defaults(self):
        with open(self.csv, "w", encoding="utf-8", newline="") as f:
            f.write("IP,Hostname,Group\n192.0.2.1,switch-01,Generale\n")
        device = inventory_manager.get_all_devices()[0]
        self.assertEqual(device["Site"], "central")
        self.assertEqual(device["SSH Port"], "22")


if __name__ == "__main__":
    unittest.main()
