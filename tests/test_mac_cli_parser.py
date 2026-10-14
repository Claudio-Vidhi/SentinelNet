# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI MAC-table parser: IOS and CBS layouts."""
import unittest

from collectors import arp_collector, mac_collector

IOS = """\
          Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 All    0100.0ccc.cccc    STATIC      CPU
  10    aabb.cc00.0105    DYNAMIC     Gi1/0/5
"""

# CBS/SG: port before type, colon MACs. Parsed to zero rows before the fix
# while the scan reported success.
CBS = """\
Flags: I - Internal usage VLAN
Aging time is 300 sec

    Vlan          Mac Address         Port       Type
------------ --------------------- ---------- ----------
     1         aa:bb:cc:00:01:01    gi1/0/48   dynamic
     1         aa:bb:cc:00:01:02       0         self
    103        aa:bb:cc:00:01:03    gi1/0/12   dynamic
"""

CBS_ARP = """\
  VLAN    Interface     IP address          HW address         status
--------------------- --------------- ------------------- ---------------
vlan 103   gi1/0/48   192.0.2.10      aa:bb:cc:00:01:03   dynamic
"""


class CliMacTableTest(unittest.TestCase):
    def test_ios(self):
        rows = mac_collector.parse_cli_mac_table(IOS)
        self.assertEqual([(r["vlan"], r["interface"]) for r in rows],
                         [("10", "GigabitEthernet1/0/5")])

    def test_cbs(self):
        rows = mac_collector.parse_cli_mac_table(CBS)
        self.assertEqual([(r["mac"], r["vlan"], r["interface"], r["type"]) for r in rows],
                         [("aa:bb:cc:00:01:01", "1", "GigabitEthernet1/0/48", "dynamic"),
                          ("aa:bb:cc:00:01:03", "103", "GigabitEthernet1/0/12", "dynamic")])

    def test_cbs_arp_status_is_not_the_interface(self):
        rows = arp_collector.parse_arp_output(CBS_ARP)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["vlan"], "103")
        self.assertEqual(rows[0]["interface"], "")


if __name__ == "__main__":
    unittest.main()
