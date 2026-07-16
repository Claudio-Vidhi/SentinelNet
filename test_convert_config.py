# -*- coding: utf-8 -*-
"""Test per config_analyzer.convert_config (Config Converter deterministico).
Esecuzione: python test_convert_config.py"""

import unittest

import config_analyzer

FORTI_SAMPLE = """#config-version=FGT60F-7.0.5
config system global
    set hostname FW-TEST
end
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.252
        set allowaccess ping https
        set description "Uplink ISP"
    next
    edit "lan"
        set ip 192.168.1.1 255.255.255.0
        set status down
    next
end
config firewall address
    edit "SRV-WEB"
        set subnet 192.168.1.10 255.255.255.255
    next
end
config router static
    edit 1
        set gateway 203.0.113.1
        set device "wan1"
    next
end
config firewall policy
    edit 1
        set name "LAN-to-WAN"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set schedule "always"
    next
end
"""

IOS_SAMPLE = """hostname SW-TEST
!
interface GigabitEthernet0/1
 description Uplink core
 ip address 10.0.0.1 255.255.255.252
!
interface GigabitEthernet0/2
 shutdown
!
ip route 0.0.0.0 0.0.0.0 10.0.0.2
!
access-list 10 permit 192.168.1.0 0.0.0.255
!
end
"""


class TestFortiosToIos(unittest.TestCase):
    def setUp(self):
        self.result = config_analyzer.convert_config(FORTI_SAMPLE, 'fortios', 'ios')

    def test_interfaces_mapped(self):
        targets = [m["target"] for m in self.result["mapped"]]
        wan = next((t for t in targets if t.startswith('interface wan1')), None)
        self.assertIsNotNone(wan)
        self.assertIn('ip address 203.0.113.2 255.255.255.252', wan)
        self.assertIn('description Uplink ISP', wan)
        lan = next((t for t in targets if t.startswith('interface lan')), None)
        self.assertIsNotNone(lan)
        self.assertIn('shutdown', lan)

    def test_static_route_mapped(self):
        targets = [m["target"] for m in self.result["mapped"]]
        self.assertTrue(any(t.startswith('ip route 0.0.0.0 0.0.0.0 203.0.113.1')
                            for t in targets))

    def test_address_mapped_as_host(self):
        targets = [m["target"] for m in self.result["mapped"]]
        obj = next((t for t in targets if 'object network SRV-WEB' in t), None)
        self.assertIsNotNone(obj)
        self.assertIn('host 192.168.1.10', obj)

    def test_policy_unmapped(self):
        unmapped = '\n'.join(self.result["unmapped"])
        self.assertIn('firewall policy', unmapped)
        self.assertIn('LAN-to-WAN', unmapped)
        # Le policy NON devono comparire tra i mappati
        self.assertFalse(any('LAN-to-WAN' in m["target"] for m in self.result["mapped"]))

    def test_preview_text(self):
        self.assertIn('! Anteprima conversione fortios -> ios', self.result["preview_text"])
        self.assertIn('interface wan1', self.result["preview_text"])


class TestIosToFortios(unittest.TestCase):
    def setUp(self):
        self.result = config_analyzer.convert_config(IOS_SAMPLE, 'ios', 'fortios')

    def test_interface_mapped(self):
        targets = [m["target"] for m in self.result["mapped"]]
        gi1 = next((t for t in targets if 'edit "GigabitEthernet0/1"' in t), None)
        self.assertIsNotNone(gi1)
        self.assertIn('set ip 10.0.0.1 255.255.255.252', gi1)
        self.assertIn('set description "Uplink core"', gi1)
        gi2 = next((t for t in targets if 'edit "GigabitEthernet0/2"' in t), None)
        self.assertIsNotNone(gi2)
        self.assertIn('set status down', gi2)

    def test_static_route_mapped(self):
        targets = [m["target"] for m in self.result["mapped"]]
        route = next((t for t in targets if 'config router static' in t), None)
        self.assertIsNotNone(route)
        self.assertIn('set dst 0.0.0.0 0.0.0.0', route)
        self.assertIn('set gateway 10.0.0.2', route)

    def test_acl_unmapped(self):
        self.assertTrue(any('access-list 10' in u for u in self.result["unmapped"]))


class TestValidation(unittest.TestCase):
    def test_unknown_vendor_raises(self):
        with self.assertRaises(ValueError):
            config_analyzer.convert_config('x', 'juniper', 'ios')
        with self.assertRaises(ValueError):
            config_analyzer.convert_config('x', 'ios', 'nxos')

    def test_same_vendor_raises(self):
        with self.assertRaises(ValueError):
            config_analyzer.convert_config('x', 'ios', 'ios')


if __name__ == '__main__':
    unittest.main(verbosity=2)
