# -*- coding: utf-8 -*-
"""Test per assegnazione massiva identità a più dispositivi.

Copre: bulk_assign_profile (service), endpoint POST /api/identities/{id}/assign
con scoping per sede, identity non trovata, mismatch body/path, default.
"""
import os
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_bulkassign_"))

from services import inventory_manager  # noqa: E402
from routers import provisioner as provisioner_router  # noqa: E402
from fastapi import HTTPException  # noqa: E402

ADMIN = {"sub": "tester", "role": "admin"}
OPERATOR_T1 = {"sub": "op1", "role": "operator"}


class TestBulkAssignProfileService(unittest.TestCase):
    def setUp(self):
        fd, self.csv_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        os.remove(self.csv_path)
        self._orig = inventory_manager.HOSTS_CSV
        inventory_manager.HOSTS_CSV = self.csv_path
        inventory_manager.invalidate_device_ip_cache()

    def tearDown(self):
        inventory_manager.HOSTS_CSV = self._orig
        if os.path.exists(self.csv_path):
            os.remove(self.csv_path)

    def _seed(self, ips):
        for ip in ips:
            inventory_manager.add_or_update_device(
                ip, "cisco", "default", "u", "p", "s", "Generale")

    def test_assign_multiple(self):
        self._seed(["192.0.2.1", "192.0.2.2", "192.0.2.3"])
        assigned, not_found = inventory_manager.bulk_assign_profile(
            ["192.0.2.1", "192.0.2.3"], "identity:abc")
        self.assertEqual(sorted(assigned), ["192.0.2.1", "192.0.2.3"])
        self.assertEqual(not_found, [])
        devs = {d["IP"]: d for d in inventory_manager.get_all_devices()}
        self.assertEqual(devs["192.0.2.1"]["Profile"], "identity:abc")
        self.assertEqual(devs["192.0.2.2"]["Profile"], "default")
        self.assertEqual(devs["192.0.2.3"]["Profile"], "identity:abc")

    def test_not_found_reported(self):
        self._seed(["192.0.2.10"])
        assigned, not_found = inventory_manager.bulk_assign_profile(
            ["192.0.2.10", "192.0.2.99"], "identity:x")
        self.assertEqual(assigned, ["192.0.2.10"])
        self.assertEqual(not_found, ["192.0.2.99"])

    def test_empty_list(self):
        self._seed(["192.0.2.20"])
        assigned, not_found = inventory_manager.bulk_assign_profile([], "identity:y")
        self.assertEqual(assigned, [])
        self.assertEqual(not_found, [])


class TestBulkAssignEndpoint(unittest.TestCase):
    def setUp(self):
        fd, self.csv_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        os.remove(self.csv_path)
        fd2, self.groups_path = tempfile.mkstemp(suffix=".json")
        os.close(fd2)
        os.remove(self.groups_path)
        self._orig_csv = inventory_manager.HOSTS_CSV
        self._orig_groups = inventory_manager.GROUPS_JSON
        inventory_manager.HOSTS_CSV = self.csv_path
        inventory_manager.GROUPS_JSON = self.groups_path
        inventory_manager.invalidate_device_ip_cache()
        # Patch identity_manager usato dal router
        self._orig_get_creds = provisioner_router.identity_manager.get_identity_credentials
        self.audits = []
        self._orig_log = provisioner_router.log_audit
        provisioner_router.log_audit = lambda msg: self.audits.append(msg)

    def tearDown(self):
        inventory_manager.HOSTS_CSV = self._orig_csv
        inventory_manager.GROUPS_JSON = self._orig_groups
        provisioner_router.identity_manager.get_identity_credentials = self._orig_get_creds
        provisioner_router.log_audit = self._orig_log
        for p in (self.csv_path, self.groups_path):
            if os.path.exists(p):
                os.remove(p)

    def _seed(self, ip, group="Generale"):
        inventory_manager.add_or_update_device(
            ip, "cisco", "default", "u", "p", "s", group)

    def test_assign_success(self):
        self._seed("192.0.2.50")
        self._seed("192.0.2.51")
        provisioner_router.identity_manager.get_identity_credentials = lambda iid: ("u", "p", "s")
        payload = provisioner_router.BulkAssignIdentitySchema(
            identity_id="id1", ips=["192.0.2.50", "192.0.2.51"])
        res = provisioner_router.identities_bulk_assign("id1", payload, current_user=ADMIN)
        self.assertEqual(res["status"], "success")
        self.assertEqual(sorted(res["assigned"]), ["192.0.2.50", "192.0.2.51"])
        self.assertEqual(res["skipped"], [])
        devs = {d["IP"]: d for d in inventory_manager.get_all_devices()}
        self.assertEqual(devs["192.0.2.50"]["Profile"], "identity:id1")
        self.assertTrue(any("massiva" in a for a in self.audits))

    def test_identity_not_found(self):
        self._seed("192.0.2.60")
        provisioner_router.identity_manager.get_identity_credentials = lambda iid: None
        payload = provisioner_router.BulkAssignIdentitySchema(
            identity_id="missing", ips=["192.0.2.60"])
        with self.assertRaises(HTTPException) as ctx:
            provisioner_router.identities_bulk_assign("missing", payload, current_user=ADMIN)
        self.assertEqual(ctx.exception.status_code, 404)

    def test_mismatch_body_path(self):
        payload = provisioner_router.BulkAssignIdentitySchema(
            identity_id="other", ips=["192.0.2.1"])
        with self.assertRaises(HTTPException) as ctx:
            provisioner_router.identities_bulk_assign("id1", payload, current_user=ADMIN)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_default_profile(self):
        self._seed("192.0.2.70")
        # Prima assegna identità, poi ripristina default
        inventory_manager.bulk_assign_profile(["192.0.2.70"], "identity:old")
        payload = provisioner_router.BulkAssignIdentitySchema(
            identity_id="default", ips=["192.0.2.70"])
        res = provisioner_router.identities_bulk_assign("default", payload, current_user=ADMIN)
        self.assertEqual(res["assigned"], ["192.0.2.70"])
        dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "192.0.2.70")
        self.assertEqual(dev["Profile"], "default")

    def test_scope_skips_forbidden_group(self):
        inventory_manager.add_group("Sede_A")
        inventory_manager.add_group("Sede_B")
        self._seed("192.0.2.80", group="Sede_A")
        self._seed("192.0.2.81", group="Sede_B")
        provisioner_router.identity_manager.get_identity_credentials = lambda iid: ("u", "p", "s")
        # Operatore limitato a Sede_A (import locale nel router → patch su deps)
        with mock.patch("routers.deps.user_group_scope", return_value={"Sede_A"}):
            payload = provisioner_router.BulkAssignIdentitySchema(
                identity_id="id2", ips=["192.0.2.80", "192.0.2.81"])
            res = provisioner_router.identities_bulk_assign("id2", payload, current_user=OPERATOR_T1)
        self.assertEqual(res["assigned"], ["192.0.2.80"])
        skipped_ips = [s["ip"] for s in res["skipped"]]
        self.assertIn("192.0.2.81", skipped_ips)
        reasons = {s["ip"]: s["reason"] for s in res["skipped"]}
        self.assertEqual(reasons["192.0.2.81"], "forbidden")

    def test_unknown_ip_skipped_not_found(self):
        self._seed("192.0.2.90")
        provisioner_router.identity_manager.get_identity_credentials = lambda iid: ("u", "p", "s")
        payload = provisioner_router.BulkAssignIdentitySchema(
            identity_id="id3", ips=["192.0.2.90", "192.0.2.200"])
        res = provisioner_router.identities_bulk_assign("id3", payload, current_user=ADMIN)
        self.assertEqual(res["assigned"], ["192.0.2.90"])
        reasons = {s["ip"]: s["reason"] for s in res["skipped"]}
        self.assertEqual(reasons.get("192.0.2.200"), "not_found")


if __name__ == "__main__":
    unittest.main()