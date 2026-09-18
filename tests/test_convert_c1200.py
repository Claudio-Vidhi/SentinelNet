# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Config Converter: Cisco IOS (2960/9200) -> Catalyst 1200."""

import unittest

from ai import config_analyzer

IOS_SAMPLE = """switch-01#show running-config
Building configuration...

Current configuration : 4242 bytes
!
version 17.9
hostname switch_01
!
username admin privilege 15 secret 9 $9$abcdefghijkl$mnopqrstuvwxyz
username ops password 0 Example123
!
vlan 10
 name USERS
!
vlan 20,30-32
 name RANGE
!
spanning-tree mode rapid-pvst
port-channel load-balance src-dst-ip
lacp system-priority 200
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-vrf
 ip address 192.0.2.250 255.255.255.0
!
interface GigabitEthernet1/0/1
 description PC Ufficio
 switchport access vlan 10
 switchport mode access
 switchport voice vlan 20
 spanning-tree portfast edge
 spanning-tree bpduguard enable
 storm-control broadcast level 5.00
!
interface GigabitEthernet1/0/23
 switchport mode trunk
 channel-group 1 mode passive
 lacp rate fast
 lacp port-priority 100
!
interface GigabitEthernet1/0/24
 description UPLINK
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20,30-32
 switchport mode trunk
 channel-group 1 mode active
!
interface FastEthernet0/5
 switchport mode access
 switchport access vlan 10
 shutdown
!
interface GigabitEthernet0/5
 switchport access vlan 20
!
interface TenGigabitEthernet1/1/1
 switchport mode trunk
!
interface GigabitEthernet2/0/1
 switchport access vlan 10
!
interface Port-channel1
 description LAG verso core
 switchport trunk allowed vlan 10,20
 switchport mode trunk
!
interface Vlan1
 ip address 192.0.2.10 255.255.255.0
!
ip default-gateway 192.0.2.1
ip ssh version 2
ip access-list extended BLOCK
 deny ip any any
snmp-server community public RO 10
snmp-server location Server-Room
line vty 0 4
 transport input ssh
!
end
"""


class TestIosToC1200(unittest.TestCase):
    def setUp(self):
        self.r = config_analyzer.convert_config(IOS_SAMPLE, 'ios', 'c1200')
        self.by_src = {m["source"].splitlines()[0]: m for m in self.r["mapped"] if m["source"]}
        self.targets = [m["target"] for m in self.r["mapped"]]
        self.unmapped_heads = [u.splitlines()[0] for u in self.r["unmapped"]]

    def test_hostname_normalized(self):
        m = self.by_src["hostname switch_01"]
        self.assertEqual(m["target"], "hostname switch-01")
        self.assertTrue(m["note"])

    def test_vlans_created_and_named(self):
        self.assertEqual(self.by_src["vlan 10"]["target"],
                         "vlan database\nvlan 10\nexit\ninterface vlan 10\nname USERS\nexit")
        self.assertEqual(self.by_src["vlan 20,30-32"]["target"], "vlan database\nvlan 20,30-32\nexit")

    def test_access_port(self):
        m = self.by_src["interface GigabitEthernet1/0/1"]
        self.assertEqual(m["target"].splitlines(), [
            "interface GigabitEthernet1", 'description "PC Ufficio"',
            "switchport access vlan 10", "spanning-tree portfast", "exit"])
        self.assertIn("BPDU", m["note"])
        self.assertIn("storm-control", m["note"])
        self.assertIn("voice vlan id 20", self.targets)

    def test_lag_member_active(self):
        m = self.by_src["interface GigabitEthernet1/0/24"]
        # L2 settings belong to po1 on the C1200, not to the member.
        self.assertEqual(m["target"].splitlines(), [
            "interface GigabitEthernet24", "description UPLINK",
            "channel-group 1 mode auto", "exit"])
        self.assertIn("po1", m["note"])

    def test_lag_member_passive_with_lacp_tuning(self):
        m = self.by_src["interface GigabitEthernet1/0/23"]
        self.assertEqual(m["target"].splitlines(), [
            "interface GigabitEthernet23", "channel-group 1 mode auto",
            "lacp timeout short", "lacp port-priority 100", "exit"])
        self.assertIn("passive", m["note"])

    def test_lag_globals(self):
        m = self.by_src["port-channel load-balance src-dst-ip"]
        self.assertEqual(m["target"], "port-channel load-balance src-dst-mac-ip")
        self.assertTrue(m["note"])
        self.assertIn("lacp system-priority 200", self.targets)

    def test_2960_port_flat_numbering(self):
        m = self.by_src["interface FastEthernet0/5"]
        self.assertTrue(m["target"].startswith("interface GigabitEthernet5\n"))
        self.assertTrue(m["target"].endswith("shutdown\nexit"))

    def test_2960_collision_unmapped(self):
        # Fa0/5 already took GigabitEthernet5.
        self.assertTrue(any(u.startswith("interface GigabitEthernet0/5") and "collisione" in u
                            for u in self.r["unmapped"]))

    def test_uplink_stack_and_mgmt_unmapped(self):
        self.assertIn("interface TenGigabitEthernet1/1/1", self.unmapped_heads)
        self.assertIn("interface GigabitEthernet2/0/1", self.unmapped_heads)
        self.assertIn("interface GigabitEthernet0/0", self.unmapped_heads)

    def test_port_channel_and_svi(self):
        self.assertEqual(self.by_src["interface Port-channel1"]["target"].splitlines(), [
            "interface po1", 'description "LAG verso core"', "switchport mode trunk",
            "switchport trunk allowed vlan add 10,20", "exit"])
        self.assertEqual(self.by_src["interface Vlan1"]["target"],
                         "interface vlan 1\nip address 192.0.2.10 255.255.255.0\nno ip address dhcp\nexit")

    def test_users(self):
        self.assertEqual(self.by_src["username admin privilege 15 secret 9 $9$abcdefghijkl$mnopqrstuvwxyz"]["target"],
                         "username admin password <PASSWORD> privilege 15")
        self.assertEqual(self.by_src["username ops password 0 Example123"]["target"],
                         "username ops password Example123 privilege 1")

    def test_snmp_ssh_gateway(self):
        self.assertEqual(self.by_src["snmp-server community public RO 10"]["target"],
                         "snmp-server community public ro")
        self.assertIn("snmp-server server", self.targets)
        self.assertIn("snmp-server location Server-Room", self.targets)
        self.assertIn("ip default-gateway 192.0.2.1", self.targets)
        self.assertIn("ip ssh server", self.targets)
        self.assertIn("spanning-tree mode rapid-pvst", self.targets)

    def test_unmapped_rest(self):
        self.assertIn("ip access-list extended BLOCK", self.unmapped_heads)
        self.assertIn("line vty 0 4", self.unmapped_heads)
        self.assertNotIn("ip ssh version 2", self.unmapped_heads)

    def test_show_run_framing_ignored(self):
        for noise in ("switch-01#show running-config", "Building configuration...",
                      "Current configuration : 4242 bytes", "version 17.9", "end"):
            self.assertNotIn(noise, self.unmapped_heads)

    def test_reverse_pair_rejected(self):
        with self.assertRaises(ValueError):
            config_analyzer.convert_config('x', 'c1200', 'ios')


if __name__ == '__main__':
    unittest.main()
