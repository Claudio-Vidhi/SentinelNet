# -*- coding: utf-8 -*-
"""Unit tests for services.policy_test.model."""

import unittest
from services.policy_test.model import (
    Cube, FieldSet, Flow, Finding, PortSet, Route, RouteTable, Rule, RuleSet, Step, Trace,
    int_to_ip, ip_to_int, mask_to_prefix_len, proto_from_name,
)


class TestCubePrimitives(unittest.TestCase):

    def test_ip_to_int_and_back(self):
        self.assertEqual(ip_to_int("192.0.2.1"), 0xC0000201)
        self.assertEqual(int_to_ip(0xC0000201), "192.0.2.1")
        self.assertEqual(ip_to_int("0.0.0.0"), 0)
        self.assertEqual(ip_to_int("255.255.255.255"), 0xFFFFFFFF)

    def test_mask_to_prefix_len(self):
        self.assertEqual(mask_to_prefix_len(0xFFFFFFFF), 32)
        self.assertEqual(mask_to_prefix_len(0xFFFFFF00), 24)
        self.assertEqual(mask_to_prefix_len(0xFFFF0000), 16)
        self.assertEqual(mask_to_prefix_len(0xFF000000), 8)
        self.assertEqual(mask_to_prefix_len(0), 0)
        # Non-contiguous wildcard mask e.g. 255.0.255.0
        self.assertIsNone(mask_to_prefix_len(0xFF00FF00))

    def test_cube_exact_and_any(self):
        c_exact = Cube.from_ip("192.0.2.10")
        self.assertTrue(c_exact.is_exact())
        self.assertFalse(c_exact.is_any())
        self.assertTrue(c_exact.contains_ip(ip_to_int("192.0.2.10")))
        self.assertFalse(c_exact.contains_ip(ip_to_int("192.0.2.11")))

        c_any = Cube.any()
        self.assertTrue(c_any.is_any())
        self.assertTrue(c_any.contains_ip(ip_to_int("192.0.2.10")))
        self.assertTrue(c_any.contains_ip(ip_to_int("198.51.100.1")))

    def test_cube_cidr_containment(self):
        c_24 = Cube.from_cidr("192.0.2.0", 24)
        c_28 = Cube.from_cidr("192.0.2.16", 28)
        c_host = Cube.from_ip("192.0.2.20")
        c_other = Cube.from_cidr("198.51.100.0", 24)

        self.assertTrue(c_24.contains_cube(c_28))
        self.assertTrue(c_24.contains_cube(c_host))
        self.assertTrue(c_28.contains_cube(c_host))
        self.assertFalse(c_28.contains_cube(c_24))
        self.assertFalse(c_24.contains_cube(c_other))

    def test_non_contiguous_wildcard_cube(self):
        # Cisco IOS wildcard: 0.0.255.0 means 2nd byte fixed, 3rd byte don't care, 4th byte fixed
        # e.g. 192.0.255.10 with wildcard 0.0.255.0 matches 192.0.X.10  # check-private-data: ok
        c_wild = Cube.from_wildcard("192.0.0.10", "0.0.255.0")
        self.assertTrue(c_wild.contains_ip(ip_to_int("192.0.1.10")))  # check-private-data: ok
        self.assertTrue(c_wild.contains_ip(ip_to_int("192.0.200.10")))  # check-private-data: ok
        self.assertFalse(c_wild.contains_ip(ip_to_int("192.0.1.11")))  # check-private-data: ok
        self.assertFalse(c_wild.contains_ip(ip_to_int("192.1.1.10")))  # check-private-data: ok

    def test_cube_intersection(self):
        c_24 = Cube.from_cidr("192.0.2.0", 24)
        c_28 = Cube.from_cidr("192.0.2.16", 28)
        c_other = Cube.from_cidr("198.51.100.0", 24)

        self.assertTrue(c_24.intersects(c_28))
        self.assertFalse(c_24.intersects(c_other))


class TestPortSetPrimitives(unittest.TestCase):

    def test_portset_normalization(self):
        ps = PortSet.from_list([(80, 80), (81, 85), (443, 443), (1, 10)])
        self.assertEqual(ps.intervals, ((1, 10), (80, 85), (443, 443)))

    def test_portset_from_ops(self):
        eq80 = PortSet.from_op("eq", 80)
        self.assertEqual(eq80.intervals, ((80, 80),))
        self.assertTrue(eq80.contains_port(80))
        self.assertFalse(eq80.contains_port(81))

        gt1024 = PortSet.from_op("gt", 1024)
        self.assertEqual(gt1024.intervals, ((1025, 65535),))
        self.assertTrue(gt1024.contains_port(5000))
        self.assertFalse(gt1024.contains_port(1024))

        lt100 = PortSet.from_op("lt", 100)
        self.assertEqual(lt100.intervals, ((1, 99),))
        self.assertTrue(lt100.contains_port(50))
        self.assertFalse(lt100.contains_port(100))

        range_http = PortSet.from_op("range", 80, 88)
        self.assertEqual(range_http.intervals, ((80, 88),))

        neq443 = PortSet.from_op("neq", 443)
        self.assertEqual(neq443.intervals, ((1, 442), (444, 65535)))
        self.assertFalse(neq443.contains_port(443))
        self.assertTrue(neq443.contains_port(80))

    def test_portset_containment_and_intersection(self):
        wide = PortSet.from_list([(1, 1024)])
        narrow = PortSet.from_list([(80, 80), (443, 443)])
        high = PortSet.from_list([(8080, 8080)])

        self.assertTrue(wide.contains_portset(narrow))
        self.assertFalse(narrow.contains_portset(wide))
        self.assertTrue(wide.intersects(narrow))
        self.assertFalse(wide.intersects(high))


class TestFieldSetAndMatching(unittest.TestCase):

    def test_field_set_containment(self):
        broad = FieldSet(
            src_ips=[Cube.from_cidr("192.0.2.0", 24)],
            dst_ips=[Cube.any()],
            dst_ports=PortSet.from_list([(1, 1024)]),
            protos={6},
        )
        narrow = FieldSet(
            src_ips=[Cube.from_ip("192.0.2.50")],
            dst_ips=[Cube.from_ip("198.51.100.1")],
            dst_ports=PortSet.from_op("eq", 443),
            protos={6},
        )
        other_proto = FieldSet(
            src_ips=[Cube.from_ip("192.0.2.50")],
            dst_ips=[Cube.from_ip("198.51.100.1")],
            dst_ports=PortSet.from_op("eq", 443),
            protos={17},
        )

        self.assertTrue(broad.contains(narrow))
        self.assertFalse(narrow.contains(broad))
        self.assertFalse(broad.contains(other_proto))

    def test_field_set_flow_matching(self):
        fs = FieldSet(
            src_ips=[Cube.from_cidr("192.0.2.0", 24)],
            dst_ips=[Cube.from_cidr("198.51.100.0", 24)],
            dst_ports=PortSet.from_op("eq", 443),
            protos={6},
        )
        f_match = Flow(src_ip="192.0.2.10", dst_ip="198.51.100.20", proto="tcp", dport=443)
        f_bad_port = Flow(src_ip="192.0.2.10", dst_ip="198.51.100.20", proto="tcp", dport=80)
        f_bad_src = Flow(src_ip="10.0.0.1", dst_ip="198.51.100.20", proto="tcp", dport=443)
        f_bad_proto = Flow(src_ip="192.0.2.10", dst_ip="198.51.100.20", proto="udp", dport=443)

        self.assertTrue(fs.matches(f_match))
        self.assertFalse(fs.matches(f_bad_port))
        self.assertFalse(fs.matches(f_bad_src))
        self.assertFalse(fs.matches(f_bad_proto))

    def test_proto_from_name(self):
        self.assertEqual(proto_from_name("tcp"), 6)
        self.assertEqual(proto_from_name("UDP"), 17)
        self.assertEqual(proto_from_name("icmp"), 1)
        self.assertEqual(proto_from_name("ip"), None)
        self.assertEqual(proto_from_name("any"), None)
        self.assertEqual(proto_from_name(6), 6)


class TestRouteTable(unittest.TestCase):

    def test_longest_prefix_match(self):
        rt = RouteTable(routes=[
            Route(prefix="0.0.0.0/0", prefix_cube=Cube.any(), next_hop="192.0.2.1", interface="Vlan1", source="static"),
            Route(prefix="198.51.100.0/24", prefix_cube=Cube.from_cidr("198.51.100.0", 24), next_hop="192.0.2.254", interface="Vlan10", source="static"),
            Route(prefix="198.51.100.128/25", prefix_cube=Cube.from_cidr("198.51.100.128", 25), next_hop=None, interface="Vlan20", source="connected"),
        ])

        # Match /25
        r1 = rt.lookup("198.51.100.200")
        self.assertIsNotNone(r1)
        self.assertEqual(r1.interface, "Vlan20")
        self.assertEqual(r1.prefix, "198.51.100.128/25")

        # Match /24
        r2 = rt.lookup("198.51.100.10")
        self.assertIsNotNone(r2)
        self.assertEqual(r2.interface, "Vlan10")
        self.assertEqual(r2.prefix, "198.51.100.0/24")

        # Match default route 0.0.0.0/0
        r3 = rt.lookup("203.0.113.5")
        self.assertIsNotNone(r3)
        self.assertEqual(r3.interface, "Vlan1")
        self.assertEqual(r3.prefix, "0.0.0.0/0")


if __name__ == "__main__":
    unittest.main()
