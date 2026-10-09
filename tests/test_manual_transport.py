# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The 'manual' transport: a device SentinelNet never connects to."""
import os
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="sentinelnet_manualtx_")
os.environ.setdefault("SENTINELNET_DATA_DIR", _TMP)

from services import inventory_manager as im  # noqa: E402


class ValidateManual(unittest.TestCase):
    def test_manual_alone_is_valid_and_portless(self):
        self.assertEqual(im._validate_transports({"manual": 22}), {"manual": None})

    def test_manual_with_another_transport_is_refused(self):
        with self.assertRaises(ValueError):
            im._validate_transports({"manual": None, "ssh": 22})

    def test_is_manual(self):
        self.assertTrue(im.is_manual({"Transports": '{"manual":null}'}))
        self.assertFalse(im.is_manual({"Transports": '{"ssh":22}'}))
        self.assertFalse(im.is_manual({"SSH Port": "22"}))  # legacy row


class ManualSurvivesOtherWrites(unittest.TestCase):
    """Review focus 4: a later write without transports keeps the device manual."""

    def setUp(self):
        self.hosts = os.path.join(tempfile.mkdtemp(prefix="sentinelnet_manualtx_"), "network_hosts.csv")
        p = mock.patch.object(im, "get_hosts_csv", return_value=self.hosts)
        p.start()
        self.addCleanup(p.stop)

    def test_update_without_transports_keeps_manual(self):
        im.add_or_update_device("192.0.2.30", "cisco", "", "", "", "", "Generale",
                                transports={"manual": None})
        im.add_or_update_device("192.0.2.30", "cisco", "", "", "", "", "Generale",
                                probe="central")
        row = next(d for d in im.get_all_devices() if d["IP"] == "192.0.2.30")
        self.assertTrue(im.is_manual(row))


class LocalDevicesFlag(unittest.TestCase):
    def test_local_devices_marks_manual_rows(self):
        from fastapi.testclient import TestClient
        import app_server
        from routers.deps import get_current_user
        rows = [{"IP": "192.0.2.31", "Vendor": "cisco", "Group": "Generale",
                 "Probe": "central", "Transports": '{"manual":null}'},
                {"IP": "192.0.2.32", "Vendor": "cisco", "Group": "Generale",
                 "Probe": "central", "Transports": '{"ssh":22}'}]
        app_server.app.dependency_overrides[get_current_user] = \
            lambda: {"sub": "root", "role": "super_admin"}
        self.addCleanup(app_server.app.dependency_overrides.pop, get_current_user, None)
        with mock.patch("services.inventory_manager.get_all_devices", return_value=rows), \
             mock.patch("redundancy.service.redundancy_badges_by_ip", return_value={}), \
             mock.patch("collectors.mac_history.device_positions", return_value={}):
            r = TestClient(app_server.app).get("/api/local-devices")
        self.assertEqual(r.status_code, 200, r.text)
        flags = {d["IP"]: d["manual"] for d in r.json()["devices"]}
        self.assertEqual(flags, {"192.0.2.31": True, "192.0.2.32": False})


if __name__ == "__main__":
    unittest.main()
