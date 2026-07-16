"""
Unit tests for config_analyzer.parse_fortigate_config.

Covers the Firewall sub-tab backend parser: policies, interfaces/zones,
VIP/NAT, and address/service objects extracted from a raw FortiOS config
(section-based `config <path>` / `edit <name>` / `set k v...` / `next` / `end`).
"""
import unittest

from config_analyzer import parse_fortigate_config

SAMPLE_CONFIG = '''
#config-version=FGVM64-7.2.5-FW-build1517:opmode=0:vdom=0
config system interface
    edit "port1"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
        set allowaccess ping https ssh
    next
    edit "port2"
        set vdom "root"
        set ip 192.168.1.1 255.255.255.0
        set allowaccess ping
    next
end
config system zone
    edit "lan"
        set interface "port2"
    next
end
config firewall policy
    edit 1
        set name "outbound"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "lan-net"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS"
        set nat enable
    next
    edit 2
        set name "block-telnet"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "TELNET"
    next
end
config firewall vip
    edit "web-vip"
        set extip 203.0.113.10
        set mappedip "10.0.0.20"
        set extintf "port1"
        set extport 443
        set mappedport 443
    next
end
config firewall address
    edit "lan-net"
        set subnet 192.168.1.0 255.255.255.0
    next
end
config firewall service custom
    edit "HTTPS-8443"
        set tcp-portrange 8443
    next
end
'''


class TestParseFortigateConfig(unittest.TestCase):

    def setUp(self):
        self.result = parse_fortigate_config(SAMPLE_CONFIG)

    def test_returns_expected_top_level_keys(self):
        self.assertEqual(
            set(self.result.keys()),
            {"policies", "interfaces_zones", "vips_nat", "addresses_services"},
        )

    def test_two_policies_parsed_with_expected_fields(self):
        policies = self.result["policies"]
        self.assertEqual(len(policies), 2)
        p1 = next(p for p in policies if p["id"] == "1")
        self.assertEqual(p1["name"], "outbound")
        self.assertEqual(p1["srcintf"], ["port2"])
        self.assertEqual(p1["dstintf"], ["port1"])
        self.assertEqual(p1["srcaddr"], ["lan-net"])
        self.assertEqual(p1["dstaddr"], ["all"])
        self.assertEqual(p1["service"], ["HTTPS"])
        self.assertEqual(p1["action"], "accept")
        self.assertEqual(p1["nat"], "enable")

        p2 = next(p for p in policies if p["id"] == "2")
        self.assertEqual(p2["action"], "deny")
        self.assertEqual(p2["nat"], "disable")

    def test_two_interfaces_with_ip_vdom_and_zone(self):
        ifaces = {i["name"]: i for i in self.result["interfaces_zones"]}
        self.assertEqual(set(ifaces.keys()), {"port1", "port2"})
        self.assertEqual(ifaces["port1"]["ip"], "10.0.0.1/24")
        self.assertEqual(ifaces["port1"]["vdom"], "root")
        self.assertEqual(ifaces["port1"]["zone"], "")
        self.assertEqual(ifaces["port2"]["ip"], "192.168.1.1/24")
        self.assertEqual(ifaces["port2"]["zone"], "lan")

    def test_one_vip(self):
        vips = self.result["vips_nat"]
        self.assertEqual(len(vips), 1)
        vip = vips[0]
        self.assertEqual(vip["name"], "web-vip")
        self.assertEqual(vip["extip"], "203.0.113.10")
        self.assertEqual(vip["mappedip"], "10.0.0.20")
        self.assertEqual(vip["extport"], "443")

    def test_one_address_and_one_service_object(self):
        objs = self.result["addresses_services"]
        kinds = {(o["kind"], o["name"]) for o in objs}
        self.assertIn(("address", "lan-net"), kinds)
        self.assertIn(("service", "HTTPS-8443"), kinds)
        addr = next(o for o in objs if o["name"] == "lan-net")
        self.assertEqual(addr["subnet"], "192.168.1.0/24")
        svc = next(o for o in objs if o["name"] == "HTTPS-8443")
        self.assertEqual(svc["tcp_portrange"], "8443")

    def test_tolerant_of_empty_or_garbage_input(self):
        self.assertEqual(
            parse_fortigate_config(""),
            {"policies": [], "interfaces_zones": [], "vips_nat": [], "addresses_services": []},
        )
        # non deve mai sollevare eccezioni
        parse_fortigate_config("not a fortios config at all\n\t***")


if __name__ == "__main__":
    unittest.main()
