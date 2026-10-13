# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Two inventoried switches with the same hostname in two locations are two
devices: a CDP/LLDP neighbour is matched to the right one by its announced IP
or by the MACs learned on the local port, not to whichever was read first."""

import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_test_samename_"))

from core.core_engine import _pick_same_name  # noqa: E402

DEVICES = {
    "192.0.2.10": {"Location": "loc-a", "Group": "t"},   # announcer
    "192.0.2.1": {"Location": "loc-a", "Group": "t"},    # SW01 in site A
    "198.51.100.1": {"Location": "loc-b", "Group": "t"},  # SW01 in site B
}
CANDS = ["198.51.100.1", "192.0.2.1"]
MAC_A, MAC_B = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"
OWN = {"192.0.2.1": {MAC_A}, "198.51.100.1": {MAC_B}}


def pick(port_seen=(), neigh_ip=None, own=OWN):
    return _pick_same_name(CANDS, "192.0.2.10", ["Gi1/0/1"], neigh_ip, DEVICES,
                           lambda sw, port: set(port_seen), lambda ip: own.get(ip, set()))


class TestPickSameName(unittest.TestCase):
    def test_announced_ip_wins(self):
        self.assertEqual(pick(neigh_ip="198.51.100.1"), "198.51.100.1")

    def test_mac_on_the_local_port_decides(self):
        self.assertEqual(pick(port_seen=[MAC_B]), "198.51.100.1")

    def test_no_known_mac_on_the_port_means_a_third_device(self):
        self.assertIsNone(pick(port_seen=["aa:bb:cc:00:00:99"]))

    def test_without_mac_data_the_same_location_wins(self):
        self.assertEqual(pick(), "192.0.2.1")

    def test_a_candidate_with_unknown_macs_is_not_ruled_out(self):
        own = {"192.0.2.1": {MAC_A}}
        self.assertEqual(pick(port_seen=["aa:bb:cc:00:00:99"], own=own), "192.0.2.1")


class TestNameTwins(unittest.TestCase):
    def test_managed_devices_sharing_a_hostname(self):
        from routers.catalog import _name_twins
        nodes = [{"id": "192.0.2.1", "label": "SW01", "discovered": False},
                 {"id": "198.51.100.1", "label": "sw01.lan", "discovered": False},
                 {"id": "192.0.2.2", "label": "SW02", "discovered": False},
                 {"id": "discovered_AP", "label": "AP", "discovered": True},
                 {"id": "discovered_AP~2", "label": "AP", "discovered": True}]
        self.assertEqual(_name_twins(nodes), {"192.0.2.1": ["198.51.100.1"], "198.51.100.1": ["192.0.2.1"],
                                              "discovered_AP": ["discovered_AP~2"], "discovered_AP~2": ["discovered_AP"]})


class TestSameDiscovered(unittest.TestCase):
    """One unmanaged name announced from two places: one device or two."""

    def seen(self, loc, chassis="", port="Gi1/0/1"):
        return {"loc": loc, "chassis": chassis, "seen": ("192.0.2.10", port)}

    def same(self, a, b, macs=None):
        from core.core_engine import _same_discovered
        macs = macs or {}
        return _same_discovered(a, b, lambda sw, port: set(macs.get(port, ())))

    def test_chassis_mac_decides(self):
        self.assertTrue(self.same(self.seen("a", "aabb.cc00.0001"), self.seen("b", "AA:BB:CC:00:00:01")))
        self.assertFalse(self.same(self.seen("a", "aabb.cc00.0001"), self.seen("a", "aabb.cc00.0002")))

    def test_a_chassis_that_is_a_name_is_not_a_mac(self):
        # Some devices put their own name in the chassis id: it proves nothing.
        self.assertFalse(self.same(self.seen("a", "box"), self.seen("b", "box")))

    def test_port_macs_decide_when_there_is_no_chassis_mac(self):
        macs = {"Gi1/0/1": {"m1"}, "Gi1/0/2": {"m1"}}
        self.assertTrue(self.same(self.seen("a"), self.seen("b", port="Gi1/0/2"), macs))
        macs = {"Gi1/0/1": {"m1"}, "Gi1/0/2": {"m2"}}
        self.assertFalse(self.same(self.seen("a"), self.seen("a", port="Gi1/0/2"), macs))

    def test_without_macs_the_location_decides(self):
        self.assertTrue(self.same(self.seen("a"), self.seen("a")))
        self.assertFalse(self.same(self.seen("a"), self.seen("b")))


if __name__ == "__main__":
    unittest.main()
