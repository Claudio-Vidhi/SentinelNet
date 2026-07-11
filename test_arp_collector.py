# -*- coding: utf-8 -*-
"""Test unitari di arp_collector (parser) e del layer MAC<->IP di mac_history."""
import os
import tempfile
import unittest
from unittest import mock

import arp_collector as ac

CISCO_ARP = """\
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.0.10.1               -   aabb.cc00.0100  ARPA   Vlan10
Internet  10.0.10.55              5   aabb.cc00.0155  ARPA   Vlan10
Internet  10.0.20.7              12   aabb.cc00.0207  ARPA   Vlan20
Internet  10.0.10.99              0   Incomplete      ARPA
"""

FORTI_ARP = """\
Address           Age(min)   Hardware Addr      Interface
192.168.1.100     3          aa:bb:cc:dd:ee:01  internal
192.168.1.101     11         aa:bb:cc:dd:ee:02  internal
"""


class ParserTest(unittest.TestCase):
    def test_cisco_show_ip_arp(self):
        rows = ac.parse_arp_output(CISCO_ARP)
        self.assertEqual(len(rows), 3)          # Incomplete scartata
        self.assertEqual(rows[0]["ip"], "10.0.10.1")
        self.assertEqual(rows[0]["mac"], "aabb.cc00.0100")
        self.assertEqual(rows[0]["vlan"], "10")
        self.assertEqual(rows[0]["interface"], "Vlan10")
        self.assertEqual(rows[2]["vlan"], "20")

    def test_fortios_get_system_arp(self):
        rows = ac.parse_arp_output(FORTI_ARP)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["ip"], "192.168.1.100")
        self.assertEqual(rows[0]["interface"], "internal")

    def test_api_arp_normalization(self):
        data = [{"ip": "10.1.1.5", "mac": "aa:bb:cc:dd:ee:ff", "interface": "lan"},
                {"ip": "", "mac": "aa:bb:cc:dd:ee:00"}, "spazzatura"]
        rows = ac._normalize_api_arp(data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "10.1.1.5")

    def test_empty_output(self):
        self.assertEqual(ac.parse_arp_output(""), [])
        self.assertEqual(ac.parse_arp_output(None), [])


class DbTest(unittest.TestCase):
    def setUp(self):
        import mac_history
        self.mh = mac_history
        # ignore_cleanup_errors: su Windows il WAL di SQLite tiene un handle
        # aperto e la rimozione della tempdir fallirebbe.
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._orig_db = mac_history.DB_PATH
        mac_history.DB_PATH = os.path.join(self._tmp.name, "test.db")
        mac_history._init_done = False

    def tearDown(self):
        self.mh.DB_PATH = self._orig_db
        self.mh._init_done = False
        self._tmp.cleanup()

    def test_record_and_search_arp(self):
        counts = self.mh.record_arp_entries(
            [{"mac": "AABB.CC00.0155", "ip": "10.0.10.55", "vlan": "10",
              "interface": "Vlan10"}],
            source_ip="10.0.0.1", source_name="core-sw", source_type="switch",
            tenant="Generale")
        self.assertEqual(counts["new"], 1)
        # upsert sulla stessa tripla (mac, ip, source)
        counts = self.mh.record_arp_entries(
            [{"mac": "aa:bb:cc:00:01:55", "ip": "10.0.10.55"}],
            source_ip="10.0.0.1", source_type="switch")
        self.assertEqual(counts["updated"], 1)

        res = self.mh.search_arp(mac="aabbcc000155")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["ip"], "10.0.10.55")
        self.assertEqual(res[0]["seen_count"], 2)
        # ricerca per prefisso IP
        self.assertEqual(len(self.mh.search_arp(ip="10.0.10.")), 1)
        self.assertEqual(len(self.mh.search_arp(ip="192.168.")), 0)

    def test_client_map_joins_access_port(self):
        self.mh.record_arp_entries(
            [{"mac": "aa:bb:cc:00:01:55", "ip": "10.0.10.55", "vlan": "10"}],
            source_ip="10.0.0.254", source_type="firewall")
        self.mh.record_sightings(
            [{"mac": "aa:bb:cc:00:01:55", "vlan": "10",
              "interface": "GigabitEthernet1/0/5"},
             {"mac": "aa:bb:cc:00:01:55", "vlan": "10",
              "interface": "TenGigabitEthernet1/1/1", "is_uplink": True}],
            switch_ip="10.0.0.10", switch_name="acc-sw-01")
        rows = self.mh.client_map(ip="10.0.10.55")
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["source_type"], "firewall")   # chi ruota la VLAN
        self.assertEqual(r["switch_ip"], "10.0.0.10")    # dove è attaccato
        self.assertEqual(r["switch_port"], "GigabitEthernet1/0/5")  # uplink escluso

    def test_tenant_scoping(self):
        self.mh.record_arp_entries(
            [{"mac": "aa:bb:cc:00:02:07", "ip": "10.0.20.7"}],
            source_ip="10.0.0.1", tenant="TenantA")
        self.assertEqual(len(self.mh.search_arp(tenants=["TenantA"])), 1)
        self.assertEqual(len(self.mh.search_arp(tenants=["TenantB"])), 0)
        self.assertEqual(len(self.mh.search_arp(tenants=[])), 0)


class CollectTest(unittest.TestCase):
    def test_collect_all_mixed(self):
        import mac_history
        devices = [
            {"IP": "10.0.0.1", "Vendor": "cisco", "Hostname": "core", "Group": "Generale"},
            {"IP": "10.0.0.2", "Vendor": "cisco", "Hostname": "acc", "Group": "Generale"},
            {"IP": "10.0.0.3", "Vendor": "cisco", "Hostname": "down", "Group": "Generale"},
        ]
        def fake_collect(device):
            if device["IP"] == "10.0.0.1":
                return {"status": "success", "source_type": "switch",
                        "entries": [{"mac": "aa:bb:cc:00:01:55", "ip": "10.0.10.55"}]}
            if device["IP"] == "10.0.0.2":
                return {"status": "success", "source_type": "switch", "entries": []}
            return {"status": "error", "source_type": "switch", "message": "timeout"}
        with mock.patch.object(ac, "collect_from_device", side_effect=fake_collect), \
             mock.patch.object(mac_history, "record_arp_entries",
                               return_value={"new": 1, "updated": 0, "skipped": 0}) as rec:
            summary = ac.collect_all(devices)
        self.assertEqual(summary["devices"]["10.0.0.1"]["status"], "success")
        self.assertEqual(summary["devices"]["10.0.0.2"]["status"], "empty")
        self.assertEqual(summary["devices"]["10.0.0.3"]["status"], "error")
        self.assertEqual(summary["total_new"], 1)
        rec.assert_called_once()


if __name__ == "__main__":
    unittest.main()
