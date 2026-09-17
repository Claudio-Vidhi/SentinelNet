# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant scope on three routes the security review found open: device
attribute assignment, bulk command job status, MAC override listing."""
import time
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from routers import catalog, commands, mac

DEVICES = [
    {"IP": "192.0.2.10", "Group": "tenant-a"},
    {"IP": "198.51.100.10", "Group": "tenant-b"},
]
OP_A = {"sub": "op-a", "role": "operator"}
OP_B = {"sub": "op-b", "role": "operator"}


def _groups(user):
    return {"op-a": ["tenant-a"], "op-b": ["tenant-b"]}.get(user, [])


class ScopeFixes(unittest.TestCase):
    def setUp(self):
        for p in (patch("routers.deps.user_manager.get_user_groups", side_effect=_groups),
                  patch("routers.deps.inventory_manager.get_all_devices", return_value=DEVICES),
                  patch("routers.mac.inventory_manager.get_all_devices", return_value=DEVICES)):
            p.start()
            self.addCleanup(p.stop)

    def test_assign_category_other_tenant_is_forbidden(self):
        with patch("routers.catalog.inventory_manager.set_device_meta") as setm:
            with self.assertRaises(HTTPException) as cm:
                catalog.assign_device_category(
                    catalog.DeviceCategorySchema(node_id="198.51.100.10", name="x"), OP_A)
            self.assertEqual(cm.exception.status_code, 403)
            setm.assert_not_called()

    def test_assign_category_own_tenant_writes_with_tenant(self):
        with patch("routers.catalog.inventory_manager.set_device_meta", return_value=True) as setm, \
             patch("routers.catalog.log_audit"):
            catalog.assign_device_category(
                catalog.DeviceCategorySchema(node_id="192.0.2.10", name="x"), OP_A)
        setm.assert_called_once_with("192.0.2.10", tenant="tenant-a", name="x")

    def test_bulk_job_hidden_from_other_user(self):
        commands._bulk_jobs["j1"] = {"status": "running", "results": ["secret"],
                                     "started_at": time.time(), "owner": "op-a"}
        self.addCleanup(commands._bulk_jobs.pop, "j1", None)
        self.assertEqual(commands.get_bulk_command_status("j1", OP_A)["results"], ["secret"])
        with self.assertRaises(HTTPException) as cm:
            commands.get_bulk_command_status("j1", OP_B)
        self.assertEqual(cm.exception.status_code, 404)

    def test_mac_overrides_filtered_to_scope(self):
        rows = [{"switch_ip": "192.0.2.10", "command": "a", "fmt": "cisco"},
                {"switch_ip": "198.51.100.10", "command": "b", "fmt": "cisco"}]
        with patch("routers.mac.mac_history.list_overrides", return_value=rows):
            got = mac.mac_list_overrides(OP_A)["overrides"]
        self.assertEqual([r["switch_ip"] for r in got], ["192.0.2.10"])


if __name__ == "__main__":
    unittest.main()
