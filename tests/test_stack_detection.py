import tempfile
import unittest

from core.core_engine import parse_switch_stack

# Output reale (ridotto) di uno stack StackWise a 2 unità.
STACK_2X_3850 = """
hostname SW-CORE-01
!
=== NEIGHBOR DISCOVERY ===

--- SHOW SWITCH ---
Switch/Stack Mac Address : 0c6e.e200.1111 - Local Mac Address
Mac persistency wait time: Indefinite
                                             H/W   Current
Switch#   Role    Mac Address     Priority Version  State
------------------------------------------------------------
*1       Active   0c6e.e200.1111     15     V02     Ready
 2       Standby  0c6e.e200.2222     10     V02     Ready

--- SHOW INVENTORY ---
NAME: "c38xx Stack", DESCR: "Cisco Catalyst 3850 Stackable Ethernet Switch"
PID: WS-C3850-24XS-S   , VID: V02  , SN: FOC2035STCK

NAME: "Switch 1", DESCR: "Cisco Catalyst 3850 Stackable Ethernet Switch"
PID: WS-C3850-24XS-S   , VID: V02  , SN: FOC2035X0AB

NAME: "Switch 1 - Power Supply A", DESCR: "Cisco Catalyst 3850 350WAC Power Supply"
PID: PWR-C1-350WAC     , VID: V01  , SN: LIT2033PSU1

NAME: "Switch 2", DESCR: "Cisco Catalyst 3850 Stackable Ethernet Switch"
PID: WS-C3850-24XS-S   , VID: V02  , SN: FOC2035X0CD

NAME: "Switch 2 - Power Supply A", DESCR: "Cisco Catalyst 3850 350WAC Power Supply"
PID: PWR-C1-350WAC     , VID: V01  , SN: LIT2033PSU2
"""

# Stack a 3 unità, modello diverso, una unità con versione disallineata.
STACK_3X_9300 = """
--- SHOW SWITCH ---
                                             H/W   Current
Switch#   Role    Mac Address     Priority Version  State
------------------------------------------------------------
 1       Member   aabb.cc00.0001     5      V01     Ready
*2       Active   aabb.cc00.0002     15     V01     Ready
 3       Member   aabb.cc00.0003     1      V01     V-Mismatch

--- SHOW INVENTORY ---
NAME: "Switch 1", DESCR: "C9300-48P"
PID: C9300-48P         , VID: V02  , SN: FCW2214A001

NAME: "Switch 2", DESCR: "C9300-48P"
PID: C9300-48P         , VID: V02  , SN: FCW2214A002

NAME: "Switch 3", DESCR: "C9300-48P"
PID: C9300-48P         , VID: V02  , SN: FCW2214A003
"""

STANDALONE = """
--- SHOW SWITCH ---
                                             H/W   Current
Switch#   Role    Mac Address     Priority Version  State
------------------------------------------------------------
*1       Active   0c6e.e200.9999     1      V01     Ready

--- SHOW INVENTORY ---
NAME: "Switch 1", DESCR: "WS-C2960X-48FPD-L"
PID: WS-C2960X-48FPD-L , VID: V03  , SN: FOC1949SOLO
"""


class TestParseSwitchStack(unittest.TestCase):
    def test_two_unit_stack(self):
        members = parse_switch_stack(STACK_2X_3850, "cisco")
        self.assertIsNotNone(members)
        assert members is not None
        self.assertEqual(len(members), 2)
        self.assertEqual([m["member_index"] for m in members], [1, 2])
        self.assertEqual([m["role"] for m in members], ["master", "member"])
        # Il serial dello chassis "c38xx Stack" non deve rubare il posto
        # a quello delle singole unità, né gli alimentatori.
        self.assertEqual([m["serial"] for m in members], ["FOC2035X0AB", "FOC2035X0CD"])
        self.assertEqual({m["model"] for m in members}, {"WS-C3850-24XS-S"})
        self.assertEqual({m["state"] for m in members}, {"ready"})

    def test_three_unit_stack_other_model_and_mismatch(self):
        """Conteggio e modello vengono dai dati, non da valori fissi."""
        members = parse_switch_stack(STACK_3X_9300, "cisco")
        assert members is not None
        self.assertEqual(len(members), 3)
        self.assertEqual({m["model"] for m in members}, {"C9300-48P"})
        self.assertEqual([m["role"] for m in members], ["member", "master", "member"])
        self.assertEqual(members[2]["state"], "version_mismatch")

    def test_standalone_is_not_a_stack(self):
        self.assertIsNone(parse_switch_stack(STANDALONE, "cisco"))

    def test_unsupported_vendor(self):
        self.assertIsNone(parse_switch_stack(STACK_2X_3850, "hpe"))
        self.assertIsNone(parse_switch_stack(STACK_2X_3850, ""))


class TestStackHealth(unittest.TestCase):
    def test_version_mismatch_degrades_group(self):
        from redundancy.models import GroupHealth, GroupInfo, GroupType, MemberInfo, MemberRole, MemberState

        g = GroupInfo(
            group_type=GroupType.STACK,
            name="SW-CORE-01",
            members=[
                MemberInfo(role=MemberRole.MASTER, state=MemberState.READY),
                MemberInfo(role=MemberRole.MEMBER, state=MemberState.VERSION_MISMATCH),
            ],
        )
        self.assertEqual(g.compute_health(), GroupHealth.DEGRADED)


class TestStackUpsert(unittest.TestCase):
    """Giro completo parser -> gruppo STACK -> badge esposto alla mappa."""

    def setUp(self):
        from redundancy import store

        # ignore_cleanup_errors: su Windows i file WAL restano agganciati alle
        # connessioni sqlite che lo store non chiude esplicitamente.
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        store.set_db_path(f"{self._tmp.name}/redundancy.db")
        self.addCleanup(store.set_db_path, None)
        self.addCleanup(self._tmp.cleanup)

    def test_detect_badge_manual_override_and_dissolve(self):
        from redundancy import service

        members = parse_switch_stack(STACK_2X_3850, "cisco")
        gid = service.upsert_stack_from_cli("Sede1", "10.0.0.1", "SW-CORE-01", members)
        self.assertIsNotNone(gid)

        badge = service.device_redundancy_badge("10.0.0.1")
        assert badge is not None
        self.assertEqual(badge["type"], "stack")
        self.assertEqual(badge["member_count"], 2)
        self.assertEqual(badge["model"], "WS-C3850-24XS-S")
        self.assertEqual(len(badge["members"]), 2)

        # Un gruppo modificato a mano non viene sovrascritto dal rilevamento CLI.
        service.save_manual_group({
            "id": gid, "group_name": "Sede1", "group_type": "stack",
            "name": "SW-CORE-01", "logical_device_ip": "10.0.0.1",
            "members": [{"role": "master", "serial": "OVERRIDE1"},
                        {"role": "member", "serial": "OVERRIDE2"},
                        {"role": "member", "serial": "OVERRIDE3"}],
        })
        service.upsert_stack_from_cli("Sede1", "10.0.0.1", "SW-CORE-01", members)
        badge = service.device_redundancy_badge("10.0.0.1")
        assert badge is not None
        self.assertEqual(badge["member_count"], 3)
        self.assertEqual(badge["members"][0]["serial"], "OVERRIDE1")

    def test_standalone_dissolves_detected_group(self):
        from redundancy import service

        service.upsert_stack_from_cli("Sede1", "10.0.0.2", "SW-2",
                                      parse_switch_stack(STACK_3X_9300, "cisco"))
        self.assertIsNotNone(service.device_redundancy_badge("10.0.0.2"))
        # Lo stack è stato smontato: il triage successivo scioglie il gruppo.
        service.upsert_stack_from_cli("Sede1", "10.0.0.2", "SW-2",
                                      parse_switch_stack(STANDALONE, "cisco"))
        self.assertIsNone(service.device_redundancy_badge("10.0.0.2"))


if __name__ == "__main__":
    unittest.main()
