# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import os
import tempfile
import unittest
from unittest.mock import patch

from services import inventory_manager as im
from tests.conftest import make_location


class TestBatch(unittest.TestCase):
    def setUp(self):
        p = patch.object(im, "HOSTS_CSV", os.path.join(tempfile.mkdtemp(), "network_hosts.csv"))
        p.start()
        self.addCleanup(p.stop)
        im.add_group("acme")
        self.loc = make_location("acme", "Roma")

    def _e(self, ip, **kw):
        return dict(ip=ip, vendor="cisco", profile="custom", username="u", password="p",
                    enable_secret="", group="acme", location=self.loc, **kw)

    def test_one_write_for_many_devices(self):
        with patch.object(im, "write_devices", wraps=im.write_devices) as w:
            im.upsert_devices([self._e(f"192.0.2.{i}") for i in range(1, 201)])
        self.assertEqual(w.call_count, 1)
        self.assertEqual(len(im.get_all_devices()), 200)

    def test_one_bad_entry_writes_nothing(self):
        with self.assertRaises(ValueError):
            im.upsert_devices([self._e("192.0.2.1"), self._e("999.0.2.1")])
        self.assertEqual(im.get_all_devices(), [])

    def test_hostname_in_entry(self):
        im.upsert_devices([self._e("192.0.2.1", hostname="rm-fw-01")])
        self.assertEqual(im.get_all_devices()[0]["Hostname"], "rm-fw-01")

    def test_single_add_still_works(self):
        im.add_or_update_device("192.0.2.1", "cisco", "custom", "u", "p", "", "acme", location=self.loc)
        self.assertEqual(len(im.get_all_devices()), 1)

    def test_csv_columns_and_org_alias(self):
        cols = im._csv_columns("indirizzo;organizzazione;note\n192.0.2.1;acme;x\n")
        self.assertEqual(cols, [("indirizzo", "IP"), ("organizzazione", "Group"), ("note", None)])


if __name__ == "__main__":
    unittest.main()
