# -*- coding: utf-8 -*-
"""Cisco wireless controller HA (SSO) detection.

The redundancy tab only ever knew two things: StackWise (CLI parser, vendor
key 'cisco') and FortiGate FGCP (REST). A controller in HA showed up nowhere,
even though the DB schema has had 'sso' as a valid group_type all along --
nothing wrote it, because nothing collected 'show redundancy summary' /
'show chassis' and no parser read them.

Fixtures follow the output shapes in Cisco's documentation, with RFC 5737
addresses.
"""
import unittest

from redundancy.models import GroupType
from redundancy.parsers.cisco_wlc import (
    parse_aireos_sso,
    parse_iosxe_sso,
    parse_wlc_sso,
)


def _backup(*sections: tuple[str, str]) -> str:
    """A backup body with the '--- TAG ---' sections the triage appends."""
    out = "=== NEIGHBOR DISCOVERY ===\n"
    for tag, body in sections:
        out += f"\n--- {tag} ---\n{body}\n"
    return out


AIREOS_PAIR = """\
             Redundancy Mode = SSO ENABLED
                 Local State = ACTIVE
                  Peer State = STANDBY HOT
                        Unit = Primary
             Redundancy Port = UP
             BulkSync Status = Complete
"""

AIREOS_STANDALONE = """\
             Redundancy Mode = SSO DISABLED
                 Local State = ACTIVE
                  Peer State = N/A
"""

AIREOS_PEER_GONE = """\
             Redundancy Mode = SSO ENABLED
                 Local State = ACTIVE
                  Peer State = N/A
             Redundancy Port = DOWN
"""

CHASSIS_PAIR = """\
Chassis/Stack Mac Address : aabb.ccdd.eeff - Local Mac Address
Mac persistency wait time: Indefinite
                                             H/W   Current
Chassis#   Role        Mac Address     Priority Version  State            IP
--------------------------------------------------------------------------------
*1         Active      aabb.ccdd.eeff     1      V02      Ready            192.0.2.1
 2         Standby     aabb.ccdd.ee00     2      V02      Ready            192.0.2.2
"""

CHASSIS_SINGLE = """\
Chassis/Stack Mac Address : aabb.ccdd.eeff - Local Mac Address
Chassis#   Role        Mac Address     Priority Version  State            IP
--------------------------------------------------------------------------------
*1         Active      aabb.ccdd.eeff     1      V02      Ready            192.0.2.1
"""

REDUNDANCY_PAIR = """\
Redundant System Information :
------------------------------
Switchovers system experienced = 0
                 Hardware Mode = Duplex
    Configured Redundancy Mode = sso
     Operating Redundancy Mode = sso
                Communications = Up

Current Processor Information :
-------------------------------
               Active Location = slot 1
        Current Software state = ACTIVE

Peer Processor Information :
----------------------------
              Standby Location = slot 2
        Current Software state = STANDBY HOT
"""

REDUNDANCY_NON_REDUNDANT = """\
Redundant System Information :
------------------------------
                 Hardware Mode = Simplex
     Operating Redundancy Mode = Non-redundant

Current Processor Information :
-------------------------------
        Current Software state = ACTIVE
"""


class AireOsRedundancy(unittest.TestCase):
    def test_an_sso_pair_yields_an_active_and_a_standby(self):
        members = parse_aireos_sso(
            _backup(("SHOW REDUNDANCY SUMMARY", AIREOS_PAIR)))
        self.assertEqual([m["role"] for m in members], ["active", "standby"])
        self.assertEqual([m["state"] for m in members], ["ready", "standby_hot"])

    def test_sso_disabled_is_not_a_group(self):
        self.assertIsNone(parse_aireos_sso(
            _backup(("SHOW REDUNDANCY SUMMARY", AIREOS_STANDALONE))))

    def test_a_missing_peer_leaves_one_member_so_health_reads_degraded(self):
        # The whole point of surfacing these: an HA pair that lost its peer
        # must not look the same as a healthy one.
        from redundancy.models import GroupInfo, GroupHealth, MemberInfo, MemberRole, MemberState
        members = parse_aireos_sso(
            _backup(("SHOW REDUNDANCY SUMMARY", AIREOS_PEER_GONE)))
        self.assertEqual(len(members), 1)
        info = GroupInfo(
            group_type=GroupType.SSO, name="wlc-01",
            members=[MemberInfo(role=MemberRole(m["role"]),
                                state=MemberState(m["state"]))
                     for m in members])
        self.assertEqual(info.compute_health(), GroupHealth.DEGRADED)

    def test_a_backup_without_the_section_is_not_a_group(self):
        self.assertIsNone(parse_aireos_sso(_backup(("SHOW INVENTORY", "NAME: x"))))


class Catalyst9800Redundancy(unittest.TestCase):
    def test_show_chassis_names_both_members_with_their_addresses(self):
        members = parse_iosxe_sso(_backup(("SHOW CHASSIS", CHASSIS_PAIR)))
        self.assertEqual([m["member_index"] for m in members], [1, 2])
        self.assertEqual([m["role"] for m in members], ["active", "standby"])
        self.assertEqual(members[0]["details"]["mgmt_ip"], "192.0.2.1")
        self.assertEqual(members[1]["details"]["mac"], "aabb.ccdd.ee00")

    def test_a_single_chassis_falls_through_rather_than_inventing_a_pair(self):
        self.assertIsNone(parse_iosxe_sso(_backup(("SHOW CHASSIS", CHASSIS_SINGLE))))

    def test_show_redundancy_is_the_fallback_when_show_chassis_is_absent(self):
        members = parse_iosxe_sso(_backup(("SHOW REDUNDANCY", REDUNDANCY_PAIR)))
        self.assertEqual([m["role"] for m in members], ["active", "standby"])
        self.assertEqual(members[1]["state"], "standby_hot")

    def test_show_chassis_wins_when_both_sections_are_present(self):
        members = parse_iosxe_sso(_backup(("SHOW CHASSIS", CHASSIS_PAIR),
                                          ("SHOW REDUNDANCY", REDUNDANCY_PAIR)))
        self.assertEqual(members[0]["details"]["mgmt_ip"], "192.0.2.1")

    def test_a_non_redundant_controller_is_not_a_group(self):
        self.assertIsNone(parse_iosxe_sso(
            _backup(("SHOW REDUNDANCY", REDUNDANCY_NON_REDUNDANT))))


class VendorDispatch(unittest.TestCase):
    def test_each_controller_family_gets_its_own_parser(self):
        aireos = _backup(("SHOW REDUNDANCY SUMMARY", AIREOS_PAIR))
        iosxe = _backup(("SHOW CHASSIS", CHASSIS_PAIR))
        self.assertEqual(len(parse_wlc_sso(aireos, "cisco_wlc")), 2)
        self.assertEqual(len(parse_wlc_sso(iosxe, "cisco_9800")), 2)
        # Crossed over, neither finds its section.
        self.assertIsNone(parse_wlc_sso(iosxe, "cisco_wlc"))
        self.assertIsNone(parse_wlc_sso(aireos, "cisco_9800"))

    def test_a_switch_is_not_a_controller(self):
        self.assertIsNone(parse_wlc_sso(
            _backup(("SHOW REDUNDANCY SUMMARY", AIREOS_PAIR)), "cisco"))


class TriageDispatch(unittest.TestCase):
    """One device is a stack or an HA pair, never both: the triage must run a
    single upsert, or the second would dissolve the group the first wrote."""

    def test_a_controller_is_detected_as_sso(self):
        from core import core_engine
        gt, members = core_engine.parse_device_redundancy(
            _backup(("SHOW REDUNDANCY SUMMARY", AIREOS_PAIR)), "cisco_wlc")
        self.assertEqual(gt, GroupType.SSO)
        self.assertEqual(len(members), 2)

    def test_a_switch_still_takes_the_stack_path(self):
        from core import core_engine
        stack = """\
*1       Active   aabb.ccdd.eeff     15     V02     Ready
 2       Standby  aabb.ccdd.ee00     10     V02     Ready
"""
        gt, members = core_engine.parse_device_redundancy(
            _backup(("SHOW SWITCH", stack)), "cisco")
        self.assertEqual(gt, GroupType.STACK)
        self.assertEqual(len(members), 2)

    def test_a_standalone_controller_reports_no_members_so_its_group_dissolves(self):
        from core import core_engine
        gt, members = core_engine.parse_device_redundancy(
            _backup(("SHOW REDUNDANCY SUMMARY", AIREOS_STANDALONE)), "cisco_wlc")
        self.assertEqual(gt, GroupType.SSO)
        self.assertIsNone(members)


if __name__ == "__main__":
    unittest.main()
