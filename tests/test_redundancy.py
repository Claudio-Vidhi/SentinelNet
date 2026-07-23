import json
import pathlib
import unittest

from redundancy.models import (
    DetectionSource,
    GroupHealth,
    GroupType,
    MemberRole,
    MemberState,
    classify_virtual_mac,
    normalize_mac,
    normalize_serial,
)
from redundancy.parsers.fortios import parse_ha_status

FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures" / "redundancy"


def load_fixture(filename: str) -> dict:
    with open(FIXTURE_DIR / filename, "r", encoding="utf-8") as f:
        return json.load(f)


class TestRedundancyModelsAndParser(unittest.TestCase):
    def test_normalize_helpers(self):
        self.assertEqual(normalize_serial(" fgt-60f 123 "), "FGT60F123")
        self.assertIsNone(normalize_serial(None))
        self.assertEqual(normalize_mac("00:09:0F:09:00:01"), "00090f090001")
        self.assertIsNone(normalize_mac(""))

    def test_classify_virtual_mac(self):
        self.assertEqual(classify_virtual_mac("00090f090001"), "fortigate_fgcp")
        self.assertEqual(classify_virtual_mac("00005e00010a"), "vrrp")
        self.assertEqual(classify_virtual_mac("00000c07ac01"), "hsrp")
        self.assertIsNone(classify_virtual_mac("001122334455"))

    def test_parse_ha_status_maps_roles_and_matching_checksums(self):
        group = parse_ha_status(
            load_fixture("fortios_ha_status.json"),
            load_fixture("fortios_ha_checksums.json"),
        )
        self.assertEqual(group.group_type, GroupType.HA_PAIR)
        self.assertEqual(
            [member.role for member in group.members],
            [MemberRole.ACTIVE, MemberRole.STANDBY],
        )
        self.assertEqual(group.health, GroupHealth.OK)

    def test_checksum_mismatch_sets_out_of_sync(self):
        group = parse_ha_status(
            load_fixture("fortios_ha_status.json"),
            load_fixture("fortios_ha_checksums_mismatch.json"),
        )
        self.assertEqual(group.health, GroupHealth.OUT_OF_SYNC)

    def test_two_active_members_override_checksum_health(self):
        group = parse_ha_status(
            {
                "results": {
                    "group_name": "fgcp",
                    "member": [
                        {"serial_no": "FGT-A", "is_root_master": True},
                        {"serial_no": "FGT-B", "is_root_master": True},
                    ],
                }
            },
            {"results": [{"checksum": "same"}, {"checksum": "same"}]},
        )
        self.assertEqual(group.health, GroupHealth.SPLIT_BRAIN)


class TestRedundancyStoreAndService(unittest.TestCase):
    def setUp(self):
        import tempfile
        import redundancy.store as store
        import redundancy.service as service
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        store.set_db_path(self.temp_db.name)
        store.init_db()
        self.store = store
        self.service = service

    def tearDown(self):
        import os
        try:
            os.unlink(self.temp_db.name)
        except OSError:
            pass

    def test_manual_ha_pair_without_virtual_ip_is_rejected(self):
        with self.assertRaises(ValueError):
            self.service.save_manual_group({"group_type": "ha_pair", "group_name": "Roma", "name": "FGCP"})

    def test_logical_stack_device_cannot_belong_to_two_groups(self):
        stack_payload = {
            "group_type": "stack",
            "group_name": "Roma",
            "name": "Stack-1",
            "logical_device_ip": "10.0.0.1",
            "members": [{"role": "master", "device_ip": "10.0.0.1"}]
        }
        self.service.save_manual_group(stack_payload)
        with self.assertRaises(self.service.ConflictError):
            self.service.save_manual_group({**stack_payload, "name": "Stack-2"})

    def test_fgcp_upsert_matches_member_by_normalized_serial(self):
        parsed_fgcp = parse_ha_status(
            load_fixture("fortios_ha_status.json"),
            load_fixture("fortios_ha_checksums.json"),
        )
        group_id = self.service.upsert_fgcp("Roma", parsed_fgcp, managed_devices=[
            {"IP": "10.0.0.2", "Group": "Roma", "Serial": "FGT60E1234567890"},
        ])
        group = self.store.get_group(group_id)
        self.assertEqual(group["members"][0]["device_ip"], "10.0.0.2")


if __name__ == "__main__":
    unittest.main()

