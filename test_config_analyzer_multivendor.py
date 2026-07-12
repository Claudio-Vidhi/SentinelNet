# -*- coding: utf-8 -*-
"""Test unitari di config_analyzer multi-vendor (FortiOS / Cisco WLC AireOS).
Eseguibile direttamente: python test_config_analyzer_multivendor.py"""
import unittest

import config_analyzer as ca

FORTIOS = '''#config-version=FGT60F-7.4.1-FW-build2463-230830:opmode=0:vdom=0
config system global
    set hostname FG-TEST
end
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.252
        set allowaccess ping https ssh http
        set role wan
    next
    edit "lan"
        set ip 10.1.1.1 255.255.255.0
        set allowaccess ping https ssh telnet
        set role lan
        set description "LAN interna"
    next
    edit "vlan10"
        set ip 10.1.10.1 255.255.255.0
        set interface "lan"
        set vlanid 10
    next
end
config system admin
    edit "admin"
        set trusthost1 10.1.1.0 255.255.255.0
    next
    edit "backdoor"
        set accprofile "super_admin"
    next
end
config firewall address
    edit "SRV-WEB"
        set subnet 10.1.10.5 255.255.255.255
    next
    edit "OBSOLETO"
        set subnet 10.9.9.9 255.255.255.255
    next
end
config firewall addrgrp
    edit "GRP-SERVER"
        set member "SRV-WEB"
    next
end
config firewall service custom
    edit "TCP-8080"
        set tcp-portrange 8080
    next
    edit "SVC-MAI-USATO"
        set tcp-portrange 9999
    next
end
config firewall vip
    edit "VIP-WEB"
        set extip 203.0.113.10
        set mappedip "10.1.10.5"
        set extintf "wan1"
    next
end
config router static
    edit 1
        set gateway 203.0.113.1
        set device "wan1"
    next
end
config vpn ipsec phase1-interface
    edit "VPN-SEDE2"
        set interface "wan1"
    next
end
config vpn ipsec phase2-interface
    edit "VPN-SEDE2-P2"
        set phase1name "VPN-SEDE2"
    next
end
config firewall policy
    edit 1
        set name "any-any"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
    next
    edit 2
        set name "web-in"
        set srcintf "wan1"
        set dstintf "lan"
        set srcaddr "all"
        set dstaddr "VIP-WEB"
        set action accept
        set schedule "always"
        set service "TCP-8080"
        set logtraffic disable
    next
    edit 3
        set name "vecchia"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "GRP-SERVER"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set status disable
    next
end
'''

FORTIOS_LOGGED = FORTIOS + '''
config log memory setting
    set status enable
end
'''

AIREOS = '''config sysname WLC-TEST
config network webmode enable
config mobility group domain CAMPUS
config radius auth add 1 10.1.1.50 1812 ascii segreto
config interface create vlan20 20
config interface address dynamic-interface vlan20 10.1.20.5 255.255.255.0 10.1.20.1
config interface vlan vlan20 20
config wlan create 1 CORP corp-ssid
config wlan interface 1 vlan20
config wlan security wpa enable 1
config wlan security wpa wpa2 enable 1
config wlan enable 1
config wlan create 2 GUEST guest-open
config wlan security wpa disable 2
config wlan broadcast-ssid disable 2
config wlan enable 2
config wlan create 3 LEGACY legacy-ssid
config wlan security wpa enable 3
config wlan security wpa wpa1 enable 3
config wlan security wpa wpa1 ciphers tkip enable 3
config wlan disable 3
'''

IOS = '''hostname SW-TEST
!
interface GigabitEthernet1/0/1
 switchport access vlan 10
!
'''


class DetectTest(unittest.TestCase):
    def test_sniff_fortios(self):
        self.assertEqual(ca.detect_config_type(FORTIOS), 'fortios')

    def test_sniff_aireos(self):
        self.assertEqual(ca.detect_config_type(AIREOS), 'wlc-aireos')

    def test_sniff_ios_default(self):
        self.assertEqual(ca.detect_config_type(IOS), 'ios')
        self.assertEqual(ca.detect_config_type(''), 'ios')
        self.assertEqual(ca.detect_config_type(None), 'ios')

    def test_vendor_overrides_sniff(self):
        self.assertEqual(ca.detect_config_type(IOS, {"Vendor": "fortinet"}),
                         'fortios')
        self.assertEqual(ca.detect_config_type(IOS, {"Vendor": "cisco_wlc"}),
                         'wlc-aireos')
        self.assertEqual(ca.detect_config_type(FORTIOS, {"Vendor": "cisco"}),
                         'ios')


class FortiosTest(unittest.TestCase):
    def setUp(self):
        self.r = ca.analyze_fortios_config(FORTIOS)

    def test_hostname(self):
        self.assertEqual(self.r["hostname"], "FG-TEST")

    def test_interfaces(self):
        names = {i["name"]: i for i in self.r["interfaces"]}
        self.assertEqual(names["wan1"]["ip"], "203.0.113.2/30")
        self.assertEqual(names["lan"]["description"], "LAN interna")
        self.assertIn("https", names["wan1"]["allowaccess"])

    def test_vlans(self):
        self.assertEqual(self.r["vlans"],
                         [{"id": "10", "name": "vlan10", "parent": "lan",
                           "ip": "10.1.10.1/24"}])

    def test_policies(self):
        pols = {p["id"]: p for p in self.r["policies"]}
        self.assertEqual(len(pols), 3)
        self.assertEqual(pols["1"]["srcaddr"], ["all"])
        self.assertEqual(pols["1"]["nat"], "enable")
        self.assertEqual(pols["2"]["dstaddr"], ["VIP-WEB"])
        self.assertEqual(pols["3"]["status"], "disable")

    def test_objects(self):
        self.assertEqual({a["name"] for a in self.r["addresses"]},
                         {"SRV-WEB", "OBSOLETO"})
        self.assertEqual(self.r["addr_groups"][0]["member"], ["SRV-WEB"])
        self.assertEqual(self.r["vips"][0]["extip"], "203.0.113.10")

    def test_routes_vpn(self):
        self.assertEqual(self.r["routing"]["static"][0]["next_hop"],
                         "203.0.113.1")
        self.assertEqual(self.r["vpn"]["phase1"], ["VPN-SEDE2"])
        self.assertEqual(self.r["vpn"]["phase2"], ["VPN-SEDE2-P2"])

    def test_validation(self):
        v = self.r["validation"]
        self.assertEqual(v["any_any_policies"], ["1 (any-any)"])
        self.assertEqual(v["disabled_policies"], ["3 (vecchia)"])
        self.assertEqual(v["unlogged_policies"], ["2 (web-in)"])
        self.assertEqual(v["unused_addresses"], ["OBSOLETO"])
        self.assertEqual(v["unused_services"], ["SVC-MAI-USATO"])
        # lan ha telnet: management insicuro (wan1 ha http)
        insec = {i["name"]: i["allowaccess"]
                 for i in v["insecure_mgmt_interfaces"]}
        self.assertEqual(insec["lan"], ["telnet"])
        self.assertEqual(insec["wan1"], ["http"])
        self.assertEqual(v["admins_without_trusthost"], ["backdoor"])
        self.assertTrue(v["logging_disabled"])

    def test_logging_enabled(self):
        v = ca.analyze_fortios_config(FORTIOS_LOGGED)["validation"]
        self.assertFalse(v["logging_disabled"])

    def test_tolerant_on_garbage(self):
        # Non deve mai sollevare eccezioni
        for bad in ("", None, "config firewall policy\nedit 1\nset",
                    "end\nend\nnext\nconfig x"):
            r = ca.analyze_fortios_config(bad)
            self.assertIn("validation", r)


class AireosTest(unittest.TestCase):
    def setUp(self):
        self.r = ca.analyze_wlc_config(AIREOS)

    def test_meta(self):
        self.assertEqual(self.r["hostname"], "WLC-TEST")
        self.assertEqual(self.r["platform"], "aireos")
        self.assertEqual(self.r["mobility_group"], "CAMPUS")

    def test_wlans(self):
        w = {x["id"]: x for x in self.r["wlans"]}
        self.assertEqual(w["1"]["ssid"], "corp-ssid")
        self.assertEqual(w["1"]["security"], "WPA2")
        self.assertEqual(w["1"]["interface"], "vlan20")
        self.assertTrue(w["1"]["enabled"])
        self.assertEqual(w["2"]["security"], "open")
        self.assertFalse(w["2"]["broadcast_ssid"])
        self.assertEqual(w["3"]["security"], "WPA")
        self.assertTrue(w["3"]["tkip"])
        self.assertFalse(w["3"]["enabled"])

    def test_dynamic_interfaces(self):
        d = self.r["dynamic_interfaces"][0]
        self.assertEqual(d["name"], "vlan20")
        self.assertEqual(d["vlan"], "20")
        self.assertEqual(d["ip"], "10.1.20.5/24")

    def test_radius(self):
        self.assertEqual(self.r["radius_servers"],
                         [{"kind": "auth", "index": "1", "ip": "10.1.1.50",
                           "port": "1812"}])

    def test_validation(self):
        v = self.r["validation"]
        self.assertEqual(v["open_wlans"], ["2 (guest-open)"])
        self.assertEqual(v["legacy_tkip_wlans"], ["3 (legacy-ssid)"])
        self.assertEqual(v["disabled_wlans"], ["3 (legacy-ssid)"])
        self.assertEqual(v["broadcast_ssid_off"], ["2 (guest-open)"])
        self.assertTrue(v["management_http"])

    def test_iosxe_wlan_blocks(self):
        cfg = ("hostname C9800\n!\nwlan CORP 1 corp-ssid\n"
               " security wpa wpa2\n no shutdown\n!\n"
               "wlan OPEN 2 open-ssid\n no security wpa\n shutdown\n!\n")
        r = ca.analyze_wlc_config(cfg)
        self.assertEqual(r["platform"], "iosxe")
        self.assertEqual(r["hostname"], "C9800")
        w = {x["id"]: x for x in r["wlans"]}
        self.assertEqual(w["1"]["security"], "WPA2")
        self.assertEqual(w["2"]["security"], "open")
        self.assertIn("2 (open-ssid)", r["validation"]["open_wlans"])
        self.assertIn("2 (open-ssid)", r["validation"]["disabled_wlans"])
        self.assertIn("ios_base", r)

    def test_tolerant_on_garbage(self):
        for bad in ("", None, "config wlan create\nconfig wlan security"):
            r = ca.analyze_wlc_config(bad)
            self.assertIn("validation", r)


class IosRegressionTest(unittest.TestCase):
    def test_ios_contract_unchanged(self):
        r = ca.analyze_config(IOS)
        for key in ("vlans", "interfaces", "routing", "acls", "vpn",
                    "validation"):
            self.assertIn(key, r)
        self.assertEqual(r["interfaces"][0]["access_vlan"], "10")


if __name__ == "__main__":
    unittest.main()
