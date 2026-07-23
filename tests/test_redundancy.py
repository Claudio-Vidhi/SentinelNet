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
        group = self.store.get_group(group_id)
        self.assertEqual(group["members"][0]["device_ip"], "10.0.0.2")


class TestRedundancyApiAndTopology(unittest.TestCase):
    def setUp(self):
        import tempfile
        from fastapi.testclient import TestClient
        import app_server
        import redundancy.store as store
        import redundancy.service as service
        from security.security_manager import create_access_token
        from security import user_manager

        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        store.set_db_path(self.temp_db.name)
        store.init_db()

        self.client = TestClient(app_server.app)

        try:
            user_manager.create_user("user_roma", "Pass123!", role="operator", groups=["Roma"])
        except Exception:
            pass

        token_admin = create_access_token({"sub": "admin", "role": "admin"})
        token_roma = create_access_token({"sub": "user_roma", "role": "operator"})

        self.headers_admin = {"Authorization": f"Bearer {token_admin}", "X-Requested-With": "SentinelNet"}
        self.headers_roma = {"Authorization": f"Bearer {token_roma}", "X-Requested-With": "SentinelNet"}

        self.g1_id = service.save_manual_group({
            "group_type": "ha_pair", "group_name": "Roma", "name": "HA-Roma", "virtual_ip": "10.1.1.1",
            "members": [
                {"role": "active", "device_ip": "10.1.1.2", "serial": "SN1"},
                {"role": "standby", "device_ip": "10.1.1.3", "serial": "SN2"},
            ]
        })["id"]

        self.g2_id = service.save_manual_group({
            "group_type": "ha_pair", "group_name": "Milano", "name": "HA-Milano", "virtual_ip": "10.2.2.1",
            "members": [
                {"role": "active", "device_ip": "10.2.2.2", "serial": "SN3"},
                {"role": "standby", "device_ip": "10.2.2.3", "serial": "SN4"},
            ]
        })["id"]

    def tearDown(self):
        import os
        try:
            os.unlink(self.temp_db.name)
        except OSError:
            pass

    def test_scoped_user_cannot_read_other_group(self):
        response = self.client.get(f"/api/redundancy/groups/{self.g2_id}", headers=self.headers_roma)
        self.assertEqual(response.status_code, 403)

    def test_scoped_user_list_filters_by_group(self):
        response = self.client.get("/api/redundancy/groups", headers=self.headers_roma)
        self.assertEqual(response.status_code, 200)
        group_names = [g["group_name"] for g in response.json()["results"]]
        self.assertIn("Roma", group_names)
        self.assertNotIn("Milano", group_names)

    def test_network_map_marks_members_and_adds_ha_edge(self):
        from unittest import mock
        mock_nodes = [
            {"id": "10.1.1.2", "label": "Device A", "group": "Roma"},
            {"id": "10.1.1.3", "label": "Device B", "group": "Roma"},
        ]
        with mock.patch("core.core_engine._generate_network_map", return_value={"nodes": mock_nodes, "links": []}):
            response = self.client.get("/api/network-map", headers=self.headers_admin)
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertIsNotNone(data["nodes"][0]["redundancy"])
            self.assertEqual(data["nodes"][0]["redundancy"]["type"], "ha_pair")
            self.assertEqual([link["kind"] for link in data["links"]].count("redundancy_heartbeat"), 1)


if __name__ == "__main__":
    unittest.main()


