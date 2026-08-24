# -*- coding: utf-8 -*-
"""Customizable inventory export.

The CSV export used to be a fixed six-column dump of the whole (scoped)
inventory. It now takes filters (tenant, site, vendor, redundancy type) and an
explicit column list, and it can put one row per physical unit so that the
serial of every switch in a stack -- or of every node in an HA pair -- lands in
its own row instead of being concatenated into one unfilterable cell.

What is checked here: the filters actually narrow the set, the tenant scope
still wins over a hand-written filter, the column registry is the single
source of truth, and the anti-formula neutralisation survived the rewrite.
"""

import csv
import io
import os
import tempfile
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_export_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

DEVICES = [
    {"IP": "192.0.2.10", "Hostname": "switch-01", "Vendor": "cisco",
     "Group": "sede-a", "Site": "central", "Profile": "default", "SSH Port": "22"},
    {"IP": "192.0.2.11", "Hostname": "switch-02", "Vendor": "cisco",
     "Group": "sede-b", "Site": "branch", "Profile": "default", "SSH Port": "22"},
    {"IP": "192.0.2.12", "Hostname": "fw-01", "Vendor": "fortinet",
     "Group": "sede-a", "Site": "branch", "Profile": "default", "SSH Port": "22"},
]

VERSIONS = {
    "192.0.2.10": {"version": "17.9.4", "status": "online", "model": "C9200-24P",
                   "serial": "AAA0000A0AA"},
    "192.0.2.11": {"version": "17.9.4", "status": "online"},
    "192.0.2.12": {"version": "7.4.12", "status": "online", "serial": "BBB0000B0BB"},
}

# switch-01 is a two-unit stack, fw-01 an HA pair; switch-02 is standalone.
BADGES = {
    "192.0.2.10": {
        "type": "stack", "role": "master", "health": "ok", "name": "stack-a",
        "member_count": 2,
        "members": [
            {"index": 1, "role": "master", "serial": "AAA0000A0AA",
             "model": "C9200-24P", "state": "ready"},
            {"index": 2, "role": "member", "serial": "AAA0000A0AB",
             "model": "C9200-24P", "state": "ready"},
        ],
    },
    "192.0.2.12": {
        "type": "ha_pair", "role": "active", "health": "ok", "name": "ha-fw",
        "member_count": 2,
        "members": [
            {"index": 1, "role": "active", "serial": "BBB0000B0BB",
             "model": "FortiGate-60F", "state": "ready"},
            {"index": 2, "role": "standby", "serial": "BBB0000B0BC",
             "model": "FortiGate-60F", "state": "ready"},
        ],
    },
}


def _export(query="", user=None, devices=None, versions=None, badges=None):
    from fastapi.testclient import TestClient
    import app_server
    from routers.deps import get_current_user

    app_server.app.dependency_overrides[get_current_user] = \
        lambda: user or {"sub": "tester", "role": "admin"}
    try:
        with patch("services.inventory_manager.get_all_devices",
                   return_value=devices if devices is not None else DEVICES), \
             patch("services.inventory_manager.get_detected_versions",
                   return_value=versions if versions is not None else VERSIONS), \
             patch("redundancy.service.redundancy_badges_by_ip",
                   return_value=(badges if badges is not None else BADGES)), \
             patch("routers.inventory.log_audit"):
            client = TestClient(app_server.app)
            return client.get("/api/export/devices" + query,
                              headers={"X-Requested-With": "x"})
    finally:
        app_server.app.dependency_overrides.pop(get_current_user, None)


def _preview(query="", user=None, devices=None, versions=None, badges=None):
    from fastapi.testclient import TestClient
    import app_server
    from routers.deps import get_current_user

    app_server.app.dependency_overrides[get_current_user] = \
        lambda: user or {"sub": "tester", "role": "admin"}
    try:
        with patch("services.inventory_manager.get_all_devices",
                   return_value=devices if devices is not None else DEVICES), \
             patch("services.inventory_manager.get_detected_versions",
                   return_value=versions if versions is not None else VERSIONS), \
             patch("redundancy.service.redundancy_badges_by_ip",
                   return_value=(badges if badges is not None else BADGES)), \
             patch("routers.inventory.log_audit"):
            client = TestClient(app_server.app)
            return client.get("/api/export/devices/preview" + query,
                              headers={"X-Requested-With": "x"})
    finally:
        app_server.app.dependency_overrides.pop(get_current_user, None)


def _rows(res):
    return list(csv.reader(io.StringIO(res.text)))


class TestDeviceExportPreview(unittest.TestCase):
    def test_preview_returns_correct_shape(self):
        res = _preview("?columns=hostname,ip&limit=2")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["headers"], ["Hostname", "IP"])
        self.assertEqual(data["total_rows"], 3)
        self.assertEqual(len(data["rows"]), 2)
        self.assertEqual(data["rows"][0], ["switch-01", "192.0.2.10"])


class TestColumnRegistry(unittest.TestCase):
    def test_the_ui_can_read_the_registry_from_the_api(self):
        # The frontend must not keep its own copy of the column list: it would
        # drift, and a stale key would only fail at download time.
        from fastapi.testclient import TestClient
        import app_server
        from routers.deps import get_current_user
        app_server.app.dependency_overrides[get_current_user] = \
            lambda: {"sub": "tester", "role": "admin"}
        try:
            res = TestClient(app_server.app).get(
                "/api/export/devices/columns", headers={"X-Requested-With": "x"})
        finally:
            app_server.app.dependency_overrides.pop(get_current_user, None)
        self.assertEqual(res.status_code, 200)
        body = res.json()
        keys = {c["key"] for c in body["columns"]}
        self.assertLessEqual({"serial", "member_serial", "redundancy_type"}, keys)
        self.assertLessEqual(set(body["default"]), keys)
        per_member = {c["key"] for c in body["columns"] if c["per_member"]}
        self.assertIn("member_serial", per_member)
        self.assertNotIn("serial", per_member)

    def test_an_unknown_column_is_refused(self):
        res = _export("?columns=hostname,Password")
        self.assertEqual(res.status_code, 400)

    def test_the_frontend_does_not_hardcode_the_column_list(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base, "static/js/devices.js"), encoding="utf-8") as f:
            body = f.read()
        self.assertIn("/api/export/devices/columns", body)


class TestColumnSelection(unittest.TestCase):
    def test_no_columns_asked_keeps_the_historic_export(self):
        rows = _rows(_export())
        self.assertEqual(rows[0],
                         ["Hostname", "IP", "Vendor", "Tenant", "Version", "Status"])
        self.assertEqual(len(rows) - 1, len(DEVICES))

    def test_columns_come_out_in_the_order_they_were_asked(self):
        rows = _rows(_export("?columns=ip,serial,hostname"))
        self.assertEqual(rows[0], ["IP", "Serial", "Hostname"])
        self.assertEqual(rows[1], ["192.0.2.10", "AAA0000A0AA", "switch-01"])

    def test_a_device_never_scanned_exports_an_empty_serial(self):
        rows = _rows(_export("?columns=ip,serial"))
        self.assertIn(["192.0.2.11", ""], rows)


class TestFilters(unittest.TestCase):
    def test_tenant_filter(self):
        rows = _rows(_export("?groups=sede-a&columns=ip"))
        self.assertEqual({r[0] for r in rows[1:]}, {"192.0.2.10", "192.0.2.12"})

    def test_site_filter(self):
        rows = _rows(_export("?sites=branch&columns=ip"))
        self.assertEqual({r[0] for r in rows[1:]}, {"192.0.2.11", "192.0.2.12"})

    def test_vendor_filter_ignores_case(self):
        rows = _rows(_export("?vendors=Fortinet&columns=ip"))
        self.assertEqual({r[0] for r in rows[1:]}, {"192.0.2.12"})

    def test_filters_combine(self):
        rows = _rows(_export("?groups=sede-a&sites=branch&columns=ip"))
        self.assertEqual({r[0] for r in rows[1:]}, {"192.0.2.12"})

    def test_redundancy_filter_including_standalone(self):
        rows = _rows(_export("?redundancy=standalone&columns=ip"))
        self.assertEqual({r[0] for r in rows[1:]}, {"192.0.2.11"})
        rows = _rows(_export("?redundancy=stack,ha_pair&columns=ip"))
        self.assertEqual({r[0] for r in rows[1:]}, {"192.0.2.10", "192.0.2.12"})

    def test_an_empty_filter_means_all(self):
        rows = _rows(_export("?groups=&vendors=&columns=ip"))
        self.assertEqual(len(rows) - 1, len(DEVICES))

    def test_the_tenant_scope_still_wins_over_the_query(self):
        # A viewer confined to sede-a asking for sede-b must get nothing, not
        # the other tenant's devices: a filter narrows the scope, never widens it.
        viewer = {"sub": "viewer", "role": "viewer", "groups": ["sede-a"]}
        with patch("routers.inventory.user_group_scope", return_value={"sede-a"}):
            rows = _rows(_export("?groups=sede-b&columns=ip", user=viewer))
        self.assertEqual(len(rows), 1)


class TestPerMemberRows(unittest.TestCase):
    def test_a_stack_gets_one_row_per_physical_unit(self):
        rows = _rows(_export("?groups=sede-a&columns=hostname,member_index,member_serial"))
        stack = [r for r in rows[1:] if r[0] == "switch-01"]
        self.assertEqual([r[1] for r in stack], ["1", "2"])
        self.assertEqual([r[2] for r in stack], ["AAA0000A0AA", "AAA0000A0AB"])

    def test_an_ha_pair_exports_both_node_serials(self):
        rows = _rows(_export("?groups=sede-a&columns=hostname,member_role,member_serial"))
        ha = [r for r in rows[1:] if r[0] == "fw-01"]
        self.assertEqual([r[1] for r in ha], ["active", "standby"])
        self.assertEqual([r[2] for r in ha], ["BBB0000B0BB", "BBB0000B0BC"])

    def test_a_standalone_device_keeps_one_row_with_empty_member_cells(self):
        rows = _rows(_export("?columns=hostname,member_serial"))
        self.assertEqual([r for r in rows[1:] if r[0] == "switch-02"],
                         [["switch-02", ""]])

    def test_without_member_columns_a_stack_stays_on_one_row(self):
        rows = _rows(_export("?columns=hostname,redundancy_type,member_count"))
        self.assertIn(["switch-01", "stack", "2"], rows)
        self.assertEqual(len(rows) - 1, len(DEVICES))

    def test_a_standalone_device_is_labelled_as_such(self):
        rows = _rows(_export("?columns=hostname,redundancy_type"))
        self.assertIn(["switch-02", "standalone"], rows)


class TestFormulaInjectionSurvivedTheRewrite(unittest.TestCase):
    """The device writes hostname, model and member serial: all three reach a
    spreadsheet, and all three must stay inert there."""

    def test_every_column_is_neutralised(self):
        devices = [dict(DEVICES[0], Hostname="=cmd|' /c calc'!A1")]
        versions = {"192.0.2.10": {"version": "@SUM(A1:A9)", "status": "ok",
                                   "serial": "-1+1"}}
        badges = {"192.0.2.10": dict(BADGES["192.0.2.10"], members=[
            {"index": 1, "role": "master", "serial": "+1+1",
             "model": "\t=1+1", "state": "ready"}])}
        res = _export("?columns=hostname,version,serial,member_serial,member_model",
                      devices=devices, versions=versions, badges=badges)
        for row in _rows(res)[1:]:
            for cell in row:
                self.assertNotIn(cell[:1], ("=", "+", "-", "@", "\t", "\r"),
                                 f"cell executable in Excel: {cell!r}")


class _FakeConn:
    def __init__(self, out):
        self.out = out

    def send_command(self, cmd):
        return self.out


class TestDriverSerialParsing(unittest.TestCase):
    """Serials for standalone devices come from a command the triage already
    runs, so a device outside any stack or HA pair also gets one."""

    def test_cisco_catalyst(self):
        from drivers.cisco_ios import CiscoIosDriver
        out = ("Model Number                       : C9200-24P\n"
               "System Serial Number               : AAA0000A0AA\n")
        self.assertEqual(CiscoIosDriver(_FakeConn(out)).get_serial(), "AAA0000A0AA")

    def test_cisco_older_ios_without_the_catalyst_line(self):
        from drivers.cisco_ios import CiscoIosDriver
        out = "Processor board ID AAA0000A0AA\n"
        self.assertEqual(CiscoIosDriver(_FakeConn(out)).get_serial(), "AAA0000A0AA")

    def test_fortigate(self):
        from drivers.fortinet import FortinetDriver
        out = ("Version: FortiGate-60F v7.4.12,build2902,240101 (GA)\n"
               "Serial-Number: BBB0000B0BB\n")
        self.assertEqual(FortinetDriver(_FakeConn(out)).get_serial(), "BBB0000B0BB")

    def test_hp_procurve(self):
        from drivers.hp_procurve import HpProcurveDriver
        out = " Serial Number      : CCC0000C0CC\n Firmware revision  : WB.16.10\n"
        self.assertEqual(HpProcurveDriver(_FakeConn(out)).get_serial(), "CCC0000C0CC")

    def test_palo_alto(self):
        from drivers.paloalto_panos import PaloAltoDriver
        out = "hostname: fw-01\nserial: 000000000000\nsw-version: 10.2.9\n"
        self.assertEqual(PaloAltoDriver(_FakeConn(out)).get_serial(), "000000000000")

    def test_a_platform_without_a_serial_command_says_nothing(self):
        from drivers.base_driver import BaseDriver
        self.assertEqual(BaseDriver(_FakeConn("")).get_serial(), "")

    def test_a_failed_triage_does_not_erase_the_known_serial(self):
        # Unreachable is not "no chassis": overwriting the serial with an empty
        # one would silently blank the column on every offline device.
        from services import inventory_manager
        stored = {}
        with patch.object(inventory_manager, "get_detected_versions",
                          side_effect=lambda: dict(stored)), \
             patch.object(inventory_manager, "safe_json_write",
                          side_effect=lambda _p, data: stored.update(data)):
            inventory_manager.update_version_inventory(
                "192.0.2.10", "cisco", "17.9.4", "online", serial="AAA0000A0AA")
            inventory_manager.update_version_inventory(
                "192.0.2.10", "cisco", "Non Rilevata", "offline")
        self.assertEqual(stored["192.0.2.10"]["serial"], "AAA0000A0AA")


if __name__ == "__main__":
    unittest.main()
