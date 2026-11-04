# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""core/port_media: medium and speed from 'show interfaces status', port mode
from the running-config. Synthetic sample in the IOS layout."""
import unittest

from core import port_media

BACKUP = """hostname switch-01
!
interface GigabitEthernet1/0/1
 description uplink core
 switchport mode access
 switchport access vlan 2
!
interface GigabitEthernet1/0/2
 switchport mode trunk
!
interface TenGigabitEthernet1/1/1
 switchport trunk allowed vlan 10,20
!
end
--- SHOW INTERFACES STATUS ---
Port         Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1      uplink core        connected    2          a-full a-1000 10/100/1000BaseTX
Gi1/0/2                         connected    trunk      a-full  a-100 10/100/1000BaseTX
Gi1/1/1                         connected    trunk        full   1000 1000BaseSX SFP
Gi1/1/2                         connected    trunk        full   1000 1000BaseLX SFP
Te1/1/1                         connected    trunk        full    10G SFP-10GBase-SR
Te1/1/2                         connected    trunk        full    10G SFP-10GBase-LR
Te1/1/3                         connected    trunk        full    10G SFP-H10GB-CU1M
Te1/1/4                         notconnect   1            full    10G Not Present
--- SHOW CDP NEIGHBORS ---
"""


class TestClassify(unittest.TestCase):

    def test_types(self):
        cases = {
            ("10/100/1000BaseTX", "a-1000"): ("copper", "1G"),
            ("10/100/1000BaseTX", "a-100"): ("copper", "100M"),
            ("1000BaseSX SFP", "1000"): ("mm", "1G"),
            ("1000BaseLX SFP", "1000"): ("sm", "1G"),
            ("1000BaseT SFP", "1000"): ("copper", "1G"),
            ("SFP-10GBase-SR", "10G"): ("mm", "10G"),
            ("SFP-10GBase-LR", "10G"): ("sm", "10G"),
            ("SFP-10GBase-LRM", "10G"): ("mm", "10G"),
            ("SFP-H10GB-CU1M", "10G"): ("dac", "10G"),
            ("SFP-10GBase-CX1", "10G"): ("dac", "10G"),
            ("SFP-25G-SR-S", "25G"): ("mm", "25G"),
            ("QSFP-40G-SR4", "40G"): ("mm", "40G"),
            ("QSFP-100G-LR4-S", "100G"): ("sm", "100G"),
            ("10GBase-T", "a-10G"): ("copper", "10G"),
            ("Not Present", "10G"): (None, "10G"),
        }
        for (t, sp), want in cases.items():
            self.assertEqual(port_media.classify(t, sp), want, t)

    def test_speed_from_port_name_last(self):
        self.assertEqual(port_media.classify("", "auto", "Te1/1/1"), (None, "10G"))
        self.assertEqual(port_media.classify("", "", "Fa0/1"), (None, "100M"))


class TestFacts(unittest.TestCase):

    def test_status_rows_with_spaces_in_name(self):
        rows = port_media.parse_interfaces_status(BACKUP)
        self.assertEqual(rows["gi1/0/1"], {"speed": "a-1000", "type": "10/100/1000BaseTX"})
        self.assertEqual(rows["te1/1/4"]["type"], "Not Present")
        self.assertEqual(len(rows), 8)

    def test_port_facts(self):
        f = port_media.port_facts(BACKUP)
        self.assertEqual(f["gi1/0/1"], {"mode": "access", "medium": "copper", "speed": "1G"})
        self.assertEqual(f["gi1/0/2"]["mode"], "trunk")
        self.assertEqual(f["te1/1/1"], {"mode": "trunk", "medium": "mm", "speed": "10G"})
        self.assertEqual(f["te1/1/3"]["medium"], "dac")
        self.assertNotIn("medium", f["te1/1/4"])

    def test_no_status_section(self):
        f = port_media.port_facts(BACKUP.split("--- SHOW INTERFACES STATUS ---")[0])
        self.assertEqual(f["gi1/0/1"], {"mode": "access"})


if __name__ == "__main__":
    unittest.main()
