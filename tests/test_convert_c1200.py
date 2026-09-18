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


VTP_CLIENT = """sw-02#show running-config
hostname sw-02
vtp mode client
!
interface GigabitEthernet1/0/1
 switchport access vlan 31
!
interface GigabitEthernet1/0/2
 switchport access vlan 241
 switchport voice vlan 242
!
interface GigabitEthernet1/0/24
 switchport mode trunk
 switchport trunk allowed vlan 1-4094
!
end
sw-02#show vlan brief

VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/3
3    CAMERAS                          active
31   SERVIZI                          active    Gi1/0/1
241  VOIP                             active    Gi1/0/2
242  VLAN0242                         active
1002 fddi-default                     act/unsup
"""


class TestVtpClientVlans(unittest.TestCase):
    def vtp_entry(self, text):
        r = config_analyzer.convert_config(text, 'ios', 'c1200')
        return r, next(m for m in r["mapped"] if "VTP" in m["note"])

    def test_vlans_from_ports_and_show_vlan(self):
        r, m = self.vtp_entry(VTP_CLIENT)
        # 3 is in the VLAN database but on no port: still created. 1 and 1002
        # are built in; 242 keeps no name (IOS default 'VLAN0242').
        self.assertEqual(m["target"].splitlines(), [
            "vlan database", "vlan 3,31,241-242", "exit",
            "interface vlan 3", "name CAMERAS", "exit",
            "interface vlan 31", "name SERVIZI", "exit",
            "interface vlan 241", "name VOIP", "exit"])
        self.assertEqual(r["mapped"][0], m)  # created before the ports use them
        # The show-vlan table is input, not configuration left unmapped.
        self.assertEqual(r["unmapped"], ["vtp mode client"])

    def test_without_show_vlan_asks_for_it(self):
        _r, m = self.vtp_entry(VTP_CLIENT.split("sw-02#show vlan brief")[0])
        self.assertIn("vlan 31,241-242", m["target"])
        self.assertIn("show vlan brief", m["note"])

    def test_backup_show_vlan_section(self):
        text = ("hostname sw-02\ninterface GigabitEthernet1/0/1\n switchport access vlan 31\n"
                "\n--- SHOW VLAN ---\n31   SERVIZI   active   Gi1/0/1\n")
        _r, m = self.vtp_entry(text)
        self.assertIn("name SERVIZI", m["target"])


class TestShippedSamples(unittest.TestCase):
    """static/samples/ is what the converter UI offers to read and download."""

    def read(self, name):
        from pathlib import Path
        return (Path(__file__).resolve().parents[1] / "static" / "samples" / name).read_text(encoding="utf-8")

    def test_ui_points_at_existing_files(self):
        js = self.read("../js/config-analyzer.js")
        for name in ("ios-2960-9200-sample.txt", "c1200-sample.txt"):
            self.assertIn(name, js)
            self.assertTrue(self.read(name).strip())

    def test_ios_sample_converts_to_the_c1200_sample(self):
        r = config_analyzer.convert_config(self.read("ios-2960-9200-sample.txt"), 'ios', 'c1200')
        # Only what the C1200 genuinely lacks is left over.
        self.assertEqual(sorted(u.splitlines()[0] for u in r["unmapped"]),
                         ["line vty 0 4", "vtp mode transparent"])
        c1200 = self.read("c1200-sample.txt")
        for m in r["mapped"]:
            for line in m["target"].splitlines():
                if line != "exit":
                    self.assertIn(line.strip(), c1200)


class TestBackupKeepsShowVlan(unittest.TestCase):
    """The converter's {ip} path must keep the backup's SHOW VLAN section;
    every other caller (netsec audit) still gets the bare running-config."""

    def load(self, **kw):
        import os
        import tempfile
        from unittest.mock import patch
        from routers import analyzer
        backup = ("hostname sw-02\n!\n--- SHOW VLAN ---\n31   SERVIZI   active\n"
                  "--- SHOW VTP STATUS ---\nVTP Operating Mode : Client\n")
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(backup)
        self.addCleanup(os.remove, path)
        with patch("routers.analyzer.assert_device_allowed", return_value={"IP": "192.0.2.5"}), \
             patch("ai.config_analyzer._find_freshest_backup", return_value=(path, "t")):
            return analyzer._load_backup_text("192.0.2.5", None, **kw)

    def test_default_is_running_config_only(self):
        self.assertNotIn("SHOW VLAN", self.load())

    def test_with_show_vlan(self):
        text = self.load(with_show_vlan=True)
        self.assertIn("31   SERVIZI   active", text)
        self.assertNotIn("VTP STATUS", text)


if __name__ == '__main__':
    unittest.main()
