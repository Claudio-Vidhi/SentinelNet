# -*- coding: utf-8 -*-
"""Test per config_analyzer.convert_config (Config Converter deterministico,
solo vendor firewall: FortiOS <-> PAN-OS). Esecuzione: python test_convert_config.py"""

import unittest

from ai import config_analyzer

FORTI_SAMPLE = """#config-version=FGT60F-7.0.5
config system global
    set hostname FW-TEST
end
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.252
        set allowaccess ping https
    next
    edit "lan"
        set ip 192.168.1.1 255.255.255.0
    next
end
config firewall address
    edit "SRV-WEB"
        set subnet 192.168.1.10 255.255.255.255
    next
end
config firewall service custom
    edit "SVC-HTTP"
        set tcp-portrange 80
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
        set nat enable
        set schedule "always"
    next
end
"""

PANOS_SAMPLE = """set network interface ethernet ethernet1/1 layer3 ip 203.0.113.2/30
set network interface ethernet ethernet1/2 layer3 ip 192.168.1.1/24
set address SRV-WEB ip-netmask 192.168.1.10/32
set service SVC-HTTP protocol tcp port 80
set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0
set network virtual-router default routing-table ip static-route default nexthop ip-address 203.0.113.1
set rulebase security rules LAN-to-WAN from LAN
set rulebase security rules LAN-to-WAN to WAN
set rulebase security rules LAN-to-WAN source any
set rulebase security rules LAN-to-WAN destination any
set rulebase security rules LAN-to-WAN service any
set rulebase security rules LAN-to-WAN action allow
set rulebase nat rules LAN-to-WAN from LAN
set rulebase nat rules LAN-to-WAN to WAN
"""


class TestValidation(unittest.TestCase):
    def test_ios_as_source_rejected(self):
        with self.assertRaises(ValueError):
            config_analyzer.convert_config('x', 'ios', 'fortios')

    def test_ios_as_target_rejected(self):
        with self.assertRaises(ValueError):
            config_analyzer.convert_config('x', 'fortios', 'ios')

    def test_unknown_vendor_raises(self):
        with self.assertRaises(ValueError):
            config_analyzer.convert_config('x', 'juniper', 'panos')
        with self.assertRaises(ValueError):
            config_analyzer.convert_config('x', 'panos', 'nxos')

    def test_same_vendor_raises(self):
        with self.assertRaises(ValueError):
            config_analyzer.convert_config('x', 'panos', 'panos')
        with self.assertRaises(ValueError):
            config_analyzer.convert_config('x', 'fortios', 'fortios')


class TestFortiosToPanos(unittest.TestCase):
    def setUp(self):
        self.result = config_analyzer.convert_config(FORTI_SAMPLE, 'fortios', 'panos')

    def test_interfaces_mapped(self):
        targets = [m["target"] for m in self.result["mapped"]]
        wan = next((t for t in targets
                    if 'network interface ethernet wan1 layer3 ip 203.0.113.2/30' in t), None)
        self.assertIsNotNone(wan)
        lan = next((t for t in targets
                    if 'network interface ethernet lan layer3 ip 192.168.1.1/24' in t), None)
        self.assertIsNotNone(lan)

    def test_address_mapped(self):
        targets = [m["target"] for m in self.result["mapped"]]
        obj = next((t for t in targets if 'set address SRV-WEB ip-netmask' in t), None)
        self.assertIsNotNone(obj)
        self.assertIn('192.168.1.10/32', obj)

    def test_service_mapped(self):
        targets = [m["target"] for m in self.result["mapped"]]
        svc = next((t for t in targets if 'set service SVC-HTTP' in t), None)
        self.assertIsNotNone(svc)
        self.assertIn('protocol tcp port 80', svc)

    def test_static_route_mapped(self):
        targets = [m["target"] for m in self.result["mapped"]]
        route = next((t for t in targets if 'static-route' in t and 'destination' in t), None)
        self.assertIsNotNone(route)
        self.assertIn('destination 0.0.0.0/0', route)
        nh = next((t for t in targets if 'nexthop ip-address 203.0.113.1' in t), None)
        self.assertIsNotNone(nh)

    def test_policy_mapped_with_nat_note(self):
        entry = next((m for m in self.result["mapped"]
                      if 'rulebase security rules "LAN-to-WAN"' in m["target"]), None)
        self.assertIsNotNone(entry)
        self.assertIn('from lan', entry["target"])
        self.assertIn('to wan1', entry["target"])
        self.assertIn('action allow', entry["target"])
        self.assertIn('rulebase nat rules "LAN-to-WAN"', entry["target"])
        self.assertIn('NAT', entry["note"])

    def test_preview_text(self):
        self.assertIn('Anteprima conversione fortios -> panos', self.result["preview_text"])


class TestPanosToFortios(unittest.TestCase):
    def setUp(self):
        self.result = config_analyzer.convert_config(PANOS_SAMPLE, 'panos', 'fortios')

    def test_interfaces_mapped(self):
        targets = [m["target"] for m in self.result["mapped"]]
        wan = next((t for t in targets if 'edit "ethernet1/1"' in t), None)
        self.assertIsNotNone(wan)
        self.assertIn('set ip 203.0.113.2 255.255.255.252', wan)

    def test_address_mapped(self):
        targets = [m["target"] for m in self.result["mapped"]]
        obj = next((t for t in targets if 'firewall address' in t and 'SRV-WEB' in t), None)
        self.assertIsNotNone(obj)
        self.assertIn('set subnet 192.168.1.10 255.255.255.255', obj)

    def test_service_mapped(self):
        targets = [m["target"] for m in self.result["mapped"]]
        svc = next((t for t in targets if 'SVC-HTTP' in t), None)
        self.assertIsNotNone(svc)
        self.assertIn('set tcp-portrange 80', svc)

    def test_static_route_mapped(self):
        targets = [m["target"] for m in self.result["mapped"]]
        route = next((t for t in targets if 'router static' in t), None)
        self.assertIsNotNone(route)
        self.assertIn('set dst 0.0.0.0 0.0.0.0', route)
        self.assertIn('set gateway 203.0.113.1', route)

    def test_policy_mapped_with_nat(self):
        entry = next((m for m in self.result["mapped"]
                      if 'firewall policy' in m["target"] and 'LAN-to-WAN' in m["target"]), None)
        self.assertIsNotNone(entry)
        self.assertIn('set action accept', entry["target"])
        self.assertIn('set nat enable', entry["target"])
        self.assertIn('NAT', entry["note"])

    def test_preview_text(self):
        self.assertIn('Anteprima conversione panos -> fortios', self.result["preview_text"])


if __name__ == '__main__':
    unittest.main(verbosity=2)
