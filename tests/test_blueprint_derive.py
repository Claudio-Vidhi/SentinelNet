# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""«Ricava dalle configurazioni»: draft operations from config backups (pure)."""
import unittest

from ai import config_analyzer as ca
from services.blueprint_derive import derive

IOS = """hostname switch-01
!
interface Vlan10
 ip address 10.10.1.1 255.255.255.0
!
interface Vlan20
 ip address 10.10.2.1 255.255.255.0
 shutdown
!
interface Vlan30
 ip address 10.10.3.1 255.255.255.0
!
interface Loopback0
 ip address 10.255.0.1 255.255.255.255
!
interface Loopback1
 ip address 10.10.4.1 255.255.255.0
!
interface GigabitEthernet0/1
 ip address 203.0.113.6 255.255.255.252
!
interface GigabitEthernet0/2
 ip address 10.10.9.0 255.255.255.254
!
interface GigabitEthernet0/3
 ip address 192.0.2.1 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 203.0.113.5
ip route vrf Mgmt-vrf 0.0.0.0 0.0.0.0 10.10.0.254
"""

FGT = """config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.252
    next
    edit "internal"
        set ip 10.20.1.1 255.255.255.0
    next
    edit "dmz"
        set ip 10.20.2.1 255.255.255.0
        set status down
    next
end
config router static
    edit 1
        set gateway 203.0.113.9
        set device "wan1"
    next
end
config vpn ipsec phase1-interface
    edit "to-milano"
        set interface "wan1"
        set remote-gw 203.0.113.6
    next
    edit "to-partner"
        set interface "wan1"
        set remote-gw 198.51.100.77
    next
end
"""


def loc(name, role="branch", subnets=(), gateway=""):
    return {"org": "acme", "name": name, "role": role, "subnets": list(subnets), "probe": "central", "gateway": gateway}


LOCS = {"milano": loc("Milano", "hq", ["10.10.1.0/24"]), "roma": loc("Roma"), "torino": loc("Torino")}
VIEW = {"locations": LOCS, "links": {}}


def dev(ip, location):
    return {"IP": ip, "Group": "acme", "Location": location}


def an(ifaces=(), default=False, peers=()):
    return {"interfaces": [{"name": n, "ip": ip} for n, ip in ifaces],
            "routing": {"static": [{"prefix": "0.0.0.0/0", "vrf": ""}] if default else []},
            "vpn": {"phase1": [n for n, _ in peers], "phase2": [],
                    "peers": [{"name": n, "remote_gw": gw} for n, gw in peers]}}


class TestFromRealParsers(unittest.TestCase):
    def test_ios_switch_and_fortigate(self):
        devices = [dev("10.20.0.1", "roma"), dev("10.10.0.1", "milano")]
        analyses = {"10.10.0.1": ca.analyze_config(IOS), "10.20.0.1": ca.analyze_fortios_config(FGT)}
        ops, notes = derive(VIEW, devices, analyses)
        self.assertEqual(ops, [
            # Vlan10 covered, Vlan20 shut, loopbacks, /31, public 203.0.113.x and 192.0.2.x skipped
            {"op": "add_subnet", "id": "milano", "subnet": "10.10.3.0/24"},
            {"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"},          # dmz is down
            {"op": "set_gateway", "id": "milano", "ip": "10.10.0.1"},            # the VRF default does not count
            {"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"},
            # remote-gw 203.0.113.6 is the switch's Gi0/1 address
            {"op": "add_link", "a": "roma", "b": "milano", "kind": "vpn", "note": "to-milano"},
        ])
        self.assertEqual(notes, ["1 peer IPsec verso indirizzi che non sono apparati di questa organizzazione."])


class TestSubnets(unittest.TestCase):
    def test_covered_networks_are_not_proposed_again(self):
        # The preview already holds 10.20.0.0/16 (e.g. from the open draft).
        view = {"locations": dict(LOCS, roma=loc("Roma", subnets=["10.20.0.0/16"])), "links": {}}
        ops, _ = derive(view, [dev("10.20.0.1", "roma")], {"10.20.0.1": an([("internal", "10.20.1.1/24")])})
        self.assertEqual(ops, [])

    def test_same_network_in_two_locations_goes_to_the_first(self):
        same = an([("lan", "10.40.0.1/24")])
        ops, _ = derive(VIEW, [dev("10.30.0.1", "torino"), dev("10.20.0.1", "roma")],
                        {"10.30.0.1": same, "10.20.0.1": same})
        self.assertEqual(ops, [{"op": "add_subnet", "id": "roma", "subnet": "10.40.0.0/24"}])

    def test_unparsable_interface_addresses_are_ignored(self):
        ops, _ = derive(VIEW, [dev("10.20.0.1", "roma")],
                        {"10.20.0.1": an([("a", ""), ("b", "10.20.0.1 255.0.0.0"), ("c", "fe80::1/64")])})
        self.assertEqual(ops, [])


class TestGateways(unittest.TestCase):
    def test_exactly_one_candidate(self):
        two = derive(VIEW, [dev("10.20.0.1", "roma"), dev("10.20.0.2", "roma")],
                     {"10.20.0.1": an(default=True), "10.20.0.2": an(default=True)})
        self.assertEqual(two, ([], ["Roma: 2 apparati con rotta di default, gateway da scegliere a mano."]))

    def test_location_with_a_gateway_or_only_a_vrf_default(self):
        has_gw = {"locations": dict(LOCS, roma=loc("Roma", gateway="10.20.0.9")), "links": {}}
        self.assertEqual(derive(has_gw, [dev("10.20.0.1", "roma")], {"10.20.0.1": an(default=True)}), ([], []))
        vrf_only = {"interfaces": [], "routing": {"static": [{"prefix": "0.0.0.0/0", "vrf": "Mgmt-vrf"}]}, "vpn": []}
        self.assertEqual(derive(VIEW, [dev("10.20.0.1", "roma")], {"10.20.0.1": vrf_only}), ([], []))


class TestVpnLinks(unittest.TestCase):
    DEVICES = [dev("10.10.0.1", "milano"), dev("10.20.0.1", "roma"), dev("10.20.0.2", "roma")]
    ANALYSES = {"10.10.0.1": an(peers=[("to-roma", "10.20.0.1"), ("to-self", "10.10.0.1")]),
                "10.20.0.1": an(peers=[("to-milano", "10.10.0.1")]),
                "10.20.0.2": an(peers=[("to-roma-2", "10.20.0.1")])}

    def test_a_long_peer_name_is_cut(self):
        # Security review 2026-10-12: config text reaches the LLM rename pass.
        analyses = {"10.10.0.1": an(peers=[("x" * 500, "10.20.0.1")])}
        ops, _ = derive(VIEW, self.DEVICES[:2], analyses)
        self.assertEqual(len(ops[0]["note"]), 64)

    def test_one_link_per_pair_by_management_ip(self):
        ops, notes = derive(VIEW, self.DEVICES, self.ANALYSES)
        self.assertEqual(ops, [{"op": "add_link", "a": "milano", "b": "roma", "kind": "vpn", "note": "to-roma"}])
        self.assertEqual(notes, [])

    def test_existing_vpn_link_is_not_proposed(self):
        linked = {"locations": LOCS, "links": {"milano--roma--vpn": {
            "org": "acme", "a": "milano", "b": "roma", "kind": "vpn", "note": ""}}}
        self.assertEqual(derive(linked, self.DEVICES, self.ANALYSES)[0], [])


class TestOwnerMap(unittest.TestCase):
    def test_management_ip_beats_an_interface_address_of_an_earlier_device(self):
        devices = [dev("10.10.0.1", "milano"), dev("10.20.0.1", "roma"), dev("10.30.0.1", "torino")]
        analyses = {"10.10.0.1": an([("x", "10.20.0.1/24")]), "10.20.0.1": an(),
                    "10.30.0.1": an(peers=[("to-roma", "10.20.0.1")])}
        ops, _ = derive(VIEW, devices, analyses)
        self.assertIn({"op": "add_link", "a": "torino", "b": "roma", "kind": "vpn", "note": "to-roma"}, ops)


class TestSkippedDevices(unittest.TestCase):
    def test_counted_in_the_notes(self):
        devices = [dev("10.30.0.1", ""), dev("10.30.0.2", "nowhere"), dev("10.20.0.1", "roma"), dev("10.20.0.2", "roma")]
        ops, notes = derive(VIEW, devices, {"10.20.0.1": None, "10.20.0.2": {}})
        self.assertEqual(ops, [])
        self.assertEqual(notes, ["2 apparati senza sede: ignorati.",
                                 "1 apparati senza backup della configurazione.",
                                 "1 backup non leggibili."])
