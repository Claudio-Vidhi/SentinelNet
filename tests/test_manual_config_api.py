# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Manual config API: the router runs end to end into a temporary data dir."""
import os
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="sentinelnet_manualapi_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from routers.deps import get_current_user  # noqa: E402
from services.config_drift.normalize import TRIAGE_MARKER  # noqa: E402

IOS_LOG = (
    "switch-01#show running-config\n"
    "hostname switch-01\n"
    "interface Vlan10\n"
    " ip address 192.0.2.10 255.255.255.0\n"
    "end\n"
    "switch-01#show version\n"
    "Cisco IOS Software, C2960X Software, Version 15.2(7)E2, RELEASE SOFTWARE\n"
    "switch-01#show cdp neighbors detail\n"
    "Device ID: switch-02\n"
    "switch-01#\n"
)


class ManualConfigApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Same isolation as tests/test_remote_site.py: DATA_DIR is a global
        # another module on this xdist worker may have moved.
        from core import data_config
        from services import inventory_manager
        prev = data_config.DATA_DIR
        data_config.DATA_DIR = _TMP
        cls.addClassCleanup(setattr, data_config, "DATA_DIR", prev)
        for name, filename in (("get_hosts_csv", "network_hosts.csv"),
                               ("get_groups_json", "groups.json")):
            p = mock.patch.object(inventory_manager, name,
                                  return_value=os.path.join(_TMP, filename))
            p.start()
            cls.addClassCleanup(p.stop)
        inventory_manager.add_group("tenant-a")
        inventory_manager.add_group("tenant-b")
        cls.client = TestClient(app_server.app)

    def _as(self, role, groups=()):
        app_server.app.dependency_overrides[get_current_user] = \
            lambda: {"sub": "tester", "role": role}
        self.addCleanup(app_server.app.dependency_overrides.pop, get_current_user, None)
        for target, value in (("routers.deps.user_manager.get_user_groups", list(groups)),
                              ("routers.deps.user_manager.effective_tabs", None)):
            p = mock.patch(target, return_value=value)
            p.start()
            self.addCleanup(p.stop)

    def _import(self, **overrides):
        body = {"text": IOS_LOG, "ip": "192.0.2.10", "vendor": "cisco",
                "group": "tenant-a", "site": "central"}
        body.update(overrides)
        return self.client.post("/api/manual-config/import", json=body)

    def test_viewer_is_refused(self):
        self._as("viewer")
        self.assertEqual(self._import().status_code, 403)

    def test_bad_body_is_422(self):
        self._as("operator")
        self.assertEqual(self.client.post("/api/manual-config/import", json={}).status_code, 422)

    def test_empty_config_is_400(self):
        self._as("operator")
        self.assertEqual(self._import(text="  \n").status_code, 400)

    def test_tenant_out_of_scope_is_403(self):
        self._as("operator", ["tenant-b"])
        self.assertEqual(self._import(ip="192.0.2.11").status_code, 403)

    def test_import_lands_where_every_analysis_reads(self):
        self._as("operator")
        r = self._import()
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        with open(body["file"], encoding="utf-8") as f:
            saved = f.read()
        self.assertIn("hostname switch-01", saved)
        self.assertIn(TRIAGE_MARKER, saved)
        self.assertIn("--- SHOW CDP NEIGHBORS DETAIL ---", saved)

        from ai import config_analyzer
        from services import inventory_manager
        from services.config_drift import history
        path, _tenant = config_analyzer._find_freshest_backup("192.0.2.10", "tenant-a")
        self.assertEqual(os.path.normcase(path), os.path.normcase(body["file"]))
        device = next(d for d in inventory_manager.get_all_devices()
                      if d["IP"] == "192.0.2.10" and d["Group"] == "tenant-a")
        self.assertTrue(inventory_manager.is_manual(device))
        self.assertEqual(device.get("Hostname"), "switch-01")
        entry = inventory_manager.get_detected_versions()["192.0.2.10"]
        self.assertEqual((entry["status"], entry["version"]), ("manual", "15.2(7)E2"))
        self.assertTrue(history.list_versions(device))
        self.assertIn("cve", body["analyses"])

    def test_reupload_adds_a_version(self):
        self._as("operator")
        self.assertEqual(self._import(ip="192.0.2.12").status_code, 200)
        changed = IOS_LOG.replace("interface Vlan10", "interface Vlan11")
        self.assertEqual(self._import(ip="192.0.2.12", text=changed).status_code, 200)
        from services import inventory_manager
        from services.config_drift import history
        device = next(d for d in inventory_manager.get_all_devices()
                      if d["IP"] == "192.0.2.12" and d["Group"] == "tenant-a")
        self.assertEqual(len(history.list_versions(device)), 2)

    def test_reachable_device_is_409(self):
        from services import inventory_manager
        inventory_manager.add_or_update_device("192.0.2.20", "cisco", "", "admin", "x", "",
                                               "tenant-a")
        self._as("operator")
        self.assertEqual(self._import(ip="192.0.2.20").status_code, 409)

    def test_same_ip_reachable_in_another_tenant_is_not_a_conflict(self):
        """Review focus 5: identity is (tenant, IP)."""
        from services import inventory_manager
        inventory_manager.add_or_update_device("192.0.2.21", "cisco", "", "admin", "x", "",
                                               "tenant-b")
        self._as("operator")
        self.assertEqual(self._import(ip="192.0.2.21").status_code, 200)

    def test_scoped_user_cannot_overwrite_another_tenants_ip(self):
        """update_version_inventory is keyed by IP only: a tenant-b operator must
        not reach tenant-a's device through the same address."""
        from services import inventory_manager
        inventory_manager.add_or_update_device("192.0.2.22", "cisco", "", "admin", "x", "",
                                               "tenant-a")
        inventory_manager.update_version_inventory("192.0.2.22", "cisco", "1.0", "online")
        self._as("operator", ["tenant-b"])
        self.assertEqual(self._import(ip="192.0.2.22", group="tenant-b").status_code, 403)
        entry = inventory_manager.get_detected_versions()["192.0.2.22"]
        self.assertEqual((entry["version"], entry["status"]), ("1.0", "online"))
        self.assertFalse(any(d["IP"] == "192.0.2.22" and d["Group"] == "tenant-b"
                             for d in inventory_manager.get_all_devices()))

    def test_preview_and_guide(self):
        self._as("operator")
        p = self.client.post("/api/manual-config/preview", json={"text": IOS_LOG})
        self.assertEqual(p.status_code, 200, p.text)
        self.assertEqual(p.json()["hostname"], "switch-01")
        self.assertEqual(p.json()["ip_candidates"], ["192.0.2.10"])
        self.assertEqual(p.json()["sniffed_vendor"], "")  # IOS is a fallback, not a match
        self.assertEqual(p.json()["vendor"], "cisco")
        g = self.client.get("/api/manual-config/guide")
        self.assertEqual(g.status_code, 200, g.text)
        self.assertIn("central", [s["id"] for s in g.json()["sites"]])
        self.assertIn("switch", g.json()["categories"])
        self.assertIn("cisco", [v["vendor"] for v in g.json()["vendors"]])


if __name__ == "__main__":
    unittest.main()
