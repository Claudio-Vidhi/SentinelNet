# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Decommissioned devices live in their own file (spec 2026-10-09
device-decommission): every reader of the inventory stops seeing them, and
no inventory write can lose them."""
import os
import tempfile
import unittest
from unittest.mock import patch

from security import crypto_vault
from services import device_history, inventory_manager

A1 = ("tenant-a", "192.0.2.1")
A2 = ("tenant-a", "192.0.2.2")
B1 = ("tenant-b", "192.0.2.1")


def _row(ip, group="tenant-a", **kw):
    r = {"IP": ip, "Vendor": "cisco", "Profile": "ios", "Group": group, "Probe": "central",
         "Username": "admin", "Password": crypto_vault.encrypt_password("pw1")}
    r.update(kw)
    return r


class _Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="decom_")
        self.csv = os.path.join(tmp, "network_hosts.csv")
        self.log = os.path.join(tmp, "device_history.jsonl")
        groups = os.path.join(tmp, "groups.json")
        for p in (patch.object(inventory_manager, "get_hosts_csv", lambda: self.csv),
                  patch.object(inventory_manager, "get_groups_json", lambda: groups),
                  patch.object(device_history, "_path", lambda: self.log),
                  patch.object(device_history, "_audit_lines", lambda: [])):
            p.start()
            self.addCleanup(p.stop)
        inventory_manager.save_groups({"tenant-a": {"description": ""},
                                       "tenant-b": {"description": ""}})
        inventory_manager.safe_write_hosts_csv(
            [_row("192.0.2.1"), _row("192.0.2.2"), _row("192.0.2.1", group="tenant-b")])

    def active(self):
        return sorted(inventory_manager.device_pair(d) for d in inventory_manager.get_all_devices())

    def decom(self):
        return sorted(inventory_manager.device_pair(d)
                      for d in inventory_manager.get_decommissioned_devices())

    def row(self, pair):
        return next(d for d in inventory_manager.get_all_devices()
                    if inventory_manager.device_pair(d) == pair)


class TestMoves(_Base):
    def test_decommission_moves_only_the_named_pair(self):
        self.assertEqual(inventory_manager.decommission([A1], "op"), 1)
        self.assertEqual(self.active(), [A2, B1])
        self.assertEqual(self.decom(), [A1])
        (d,) = inventory_manager.get_decommissioned_devices()
        self.assertEqual(d["Decommissioned By"], "op")
        self.assertRegex(d["Decommissioned"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_file_sits_next_to_the_inventory(self):
        self.assertEqual(os.path.dirname(inventory_manager.get_decommissioned_csv()),
                         os.path.dirname(self.csv))

    def test_reactivate_restores_the_identical_row(self):
        before = self.row(A1)
        inventory_manager.decommission([A1], "op")
        self.assertEqual(inventory_manager.reactivate([A1]), 1)
        self.assertEqual(self.row(A1), before)
        self.assertNotIn("Decommissioned", self.row(A1))
        self.assertEqual(self.decom(), [])

    def test_delete_from_both_files(self):
        inventory_manager.decommission([A1], "op")
        self.assertEqual(inventory_manager.delete_devices([A1, A2]), 2)
        self.assertEqual(self.active(), [B1])
        self.assertEqual(self.decom(), [])

    def test_unknown_pairs_are_a_noop(self):
        self.assertEqual(inventory_manager.decommission([("tenant-a", "192.0.2.99")], "op"), 0)
        self.assertEqual(inventory_manager.reactivate([A1]), 0)
        self.assertEqual(self.active(), [A1, A2, B1])


class TestGuard(_Base):
    def test_adding_a_decommissioned_pair_is_refused(self):
        inventory_manager.decommission([A1], "op")
        with self.assertRaisesRegex(ValueError, "192.0.2.1"):
            inventory_manager.add_or_update_device("192.0.2.1", "cisco", "ios", "u", "p", "",
                                                   "tenant-a")
        self.assertEqual(self.decom(), [A1])
        self.assertNotIn(A1, self.active())

    def test_unrelated_write_keeps_the_decommissioned_file(self):
        inventory_manager.decommission([A1], "op")
        with open(inventory_manager.get_decommissioned_csv(), encoding="utf-8") as f:
            before = f.read()
        inventory_manager.update_device_hostname("192.0.2.2", "sw-02", "tenant-a")
        with open(inventory_manager.get_decommissioned_csv(), encoding="utf-8") as f:
            self.assertEqual(f.read(), before)

    def test_late_triage_write_does_not_bring_it_back(self):
        inventory_manager.decommission([A1], "op")
        inventory_manager.update_device_hostname("192.0.2.1", "sw-01", "tenant-a")
        self.assertNotIn(A1, self.active())

    def test_interrupted_decommission_blocks_nothing_and_completes(self):
        # Crash after the first write: the row is in both files.
        inventory_manager._write_decommissioned(
            [dict(self.row(A1), **{"Decommissioned": "2026-10-09T12:00:00Z",
                                   "Decommissioned By": "op"})])
        inventory_manager.update_device_hostname("192.0.2.2", "sw-02", "tenant-a")
        inventory_manager.decommission([A1], "op")
        self.assertEqual(self.active(), [A2, B1])
        self.assertEqual(self.decom(), [A1])

    def test_interrupted_reactivate_completes(self):
        inventory_manager.decommission([A1], "op")
        row = {k: v for k, v in inventory_manager.get_decommissioned_devices()[0].items()
               if k not in ("Decommissioned", "Decommissioned By")}
        inventory_manager.safe_write_hosts_csv(inventory_manager.get_all_devices() + [row],
                                               exempt={A1})
        self.assertEqual(inventory_manager.reactivate([A1]), 1)
        self.assertEqual(self.active(), [A1, A2, B1])
        self.assertEqual(self.decom(), [])


class TestHistory(_Base):
    def test_lifecycle_events(self):
        inventory_manager.decommission([A1], "op")
        inventory_manager.reactivate([A1])
        inventory_manager.decommission([A1], "op")
        inventory_manager.delete_devices([A1])
        kinds = [e["event"] for e in device_history.events({"tenant-a"}, ip="192.0.2.1")]
        self.assertEqual(kinds, ["removed", "decommissioned", "reactivated",
                                 "decommissioned", "added"])

    def test_relabel_only_touches_named_kinds(self):
        device_history.record([_row("192.0.2.5")], [_row("192.0.2.6")],
                              relabel={"removed": "decommissioned"})
        kinds = {e["event"] for e in device_history.events({"tenant-a"})}
        self.assertIn("decommissioned", kinds)
        self.assertIn("added", kinds)


if __name__ == "__main__":
    unittest.main()
