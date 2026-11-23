# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Live FortiGate advisor on a multi-VDOM unit (mocked REST).

Synthetic data only: RFC 5737 / private addresses, invented names.
"""

import os
import tempfile
import unittest
from unittest import mock

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_advvdom_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
from core import db  # noqa: E402
from security import user_manager  # noqa: E402
from services import fortigate_service as fgs  # noqa: E402

DEVICE = {"IP": "192.0.2.1", "Vendor": "fortinet", "Profile": "custom", "Hostname": "switch-01"}
PASS = "PasswordSicura1!"


def _pol(pid, name, src, dst, svc, srcintf, dstintf):
    return {"policyid": pid, "name": name, "action": "accept", "status": "enable",
            "srcintf": [{"name": srcintf}], "dstintf": [{"name": dstintf}],
            "srcaddr": [{"name": src}], "dstaddr": [{"name": dst}],
            "service": [{"name": svc}], "inspection-mode": "flow",
            "auto-asic-offload": "enable", "utm-status": "disable"}


POLICIES = {
    # internal -> wan1 is internet-bound in root; port5 is WAN only in vd-b.
    "root": [_pol(1, "lan-out", "all", "all", "HTTPS", "internal", "wan1"),
             _pol(2, "to-port5", "all", "all", "HTTPS", "internal", "port5")],
    "vd-b": [_pol(1, "vip-in", "all", "VIP_B", "HTTPS", "port5", "port6")],
}
VIPS = {"root": [], "vd-b": [{"name": "VIP_B"}]}
IFACES = [{"name": "wan1", "role": "wan", "vdom": "root"},
          {"name": "internal", "role": "lan", "vdom": "root"},
          {"name": "port5", "role": "wan", "vdom": "vd-b"},
          {"name": "port6", "role": "lan", "vdom": "vd-b"}]


class _Unit:
    """Mocked REST of one unit; ``fgs._VDOM`` tells which VDOM is asked."""

    def __init__(self, mode="multi-vdom", denied=(), global_fails=False):
        self.mode, self.denied, self.global_fails = mode, set(denied), global_fails
        self.calls = []

    def _vd(self):
        vd = fgs._VDOM.get()
        if vd in self.denied:
            raise fgs.FortiGateError(f"REST API {DEVICE['IP']}: accesso negato (403)")
        return vd or "root"

    def cmdb(self, _ip, path, *a, **k):
        self.calls.append((path, fgs._VDOM.get(), k.get("fmt")))
        if path == "cmdb/system/global":
            if self.global_fails:
                raise fgs.FortiGateError("403")
            return {"results": {"vdom-mode": self.mode}}
        if path == "cmdb/system/vdom":
            return {"results": [{"name": "root"}, {"name": "vd-b"}]}
        if path == "cmdb/system/interface":
            return {"results": IFACES}
        self._vd()
        return {"results": []}

    def policies(self, _device):
        return {"data": POLICIES[self._vd()]}

    def vips(self, _device):
        return {"data": VIPS[self._vd()]}

    def profiles(self, _device):
        self._vd()
        return {"data": {}, "errors": {}}

    def run(self):
        with mock.patch.object(fgs, "api_get_cmdb", side_effect=self.cmdb), \
             mock.patch.object(fgs, "get_system_status",
                               return_value={"data": {"model": "FGT100F", "version": "7.4.5"}}), \
             mock.patch.object(fgs, "get_policies_with_stats", side_effect=self.policies), \
             mock.patch.object(fgs, "get_vips", side_effect=self.vips), \
             mock.patch.object(fgs, "get_security_profiles", side_effect=self.profiles):
            return fgs.get_firewall_advisor(DEVICE, lang="en")


class TestLiveMultiVdom(unittest.TestCase):
    def test_recs_from_both_vdoms(self):
        data = _Unit().run()["data"]
        by_id = {r["id"]: r for r in data["recommendations"]}
        self.assertEqual(len(by_id), len(data["recommendations"]))
        self.assertEqual(by_id["root:ADV-AV-1"]["vdom"], "root")
        self.assertEqual(by_id["vd-b:ADV-VIP-L7-1"]["vdom"], "vd-b")
        self.assertEqual(data["source"], {"kind": "api", "vdoms": ["root", "vd-b"]})
        self.assertEqual(data["summary"]["policies_analyzed"], 3)
        self.assertEqual(data["summary"]["total"], len(data["recommendations"]))
        cli = by_id["vd-b:ADV-VIP-L7-1"]["cli"]
        self.assertTrue(cli.startswith("config vdom\n    edit vd-b\n        config "))
        self.assertTrue(cli.endswith("\n    next\nend"))

    def test_ui_fields_survive_the_merge(self):
        by_id = {r["id"]: r for r in _Unit().run()["data"]["recommendations"]}
        av = by_id["root:ADV-AV-1"]
        self.assertEqual(av["policy"]["dstintf"], ["wan1"])
        self.assertTrue(av["policy"]["dst_is_wan"])
        self.assertEqual({c["field"] for c in av["changes"]}, {"utm-status", "av-profile"})
        self.assertIn("av-profile", av["highlight"])
        self.assertFalse(all(c["ok"] for c in av["checks"]))

    def test_wan_is_per_vdom(self):
        ids = {r["id"] for r in _Unit().run()["data"]["recommendations"]}
        self.assertIn("root:ADV-BYPASS-2", ids)
        self.assertNotIn("root:ADV-AV-2", ids)

    def test_requests_scoped_per_vdom(self):
        unit = _Unit()
        unit.run()
        scoped = {vd for path, vd, _f in unit.calls if path == "cmdb/ips/sensor"}
        self.assertEqual(scoped, {"root", "vd-b"})
        self.assertIn(("cmdb/system/interface", None, "name|role|vdom"), unit.calls)

    def test_denied_vdom_reported_other_analysed(self):
        data = _Unit(denied={"vd-b"}).run()["data"]
        ids = {r["id"] for r in data["recommendations"]}
        self.assertIn("root:ADV-AV-1", ids)
        self.assertFalse(any(i.startswith("vd-b:") for i in ids))
        self.assertIn("vd-b:policies", data["errors"])
        self.assertIn("403", data["errors"]["vd-b:policies"])


class TestSingleScopeUnchanged(unittest.TestCase):
    def _baseline(self):
        with mock.patch.object(fgs, "_advisor_vdoms", return_value=[]):
            return _Unit(mode="no-vdom").run()

    def test_no_vdom_unit(self):
        unit = _Unit(mode="no-vdom")
        res = unit.run()
        self.assertEqual(res, self._baseline())
        self.assertNotIn("source", res["data"])
        self.assertFalse(any(r.get("vdom") for r in res["data"]["recommendations"]))
        # One detection call, then exactly the old requests, none VDOM-scoped.
        self.assertEqual(unit.calls[0][0], "cmdb/system/global")
        self.assertNotIn("cmdb/system/vdom", [c[0] for c in unit.calls])
        self.assertTrue(all(vd is None for _p, vd, _f in unit.calls))
        self.assertIn(("cmdb/system/interface", None, "name|role"), unit.calls)

    def test_detection_failure_falls_back(self):
        res = _Unit(global_fails=True).run()
        self.assertEqual(res, self._baseline())

    def test_vdom_context_does_not_leak(self):
        _Unit().run()
        self.assertIsNone(fgs._VDOM.get())

    def test_api_get_adds_vdom_only_in_scope(self):
        with mock.patch.object(fgs, "api_request", return_value={}) as req:
            fgs.api_get(DEVICE["IP"], "cmdb/firewall/policy")
            token = fgs._VDOM.set("vd-b")
            try:
                fgs.api_get(DEVICE["IP"], "cmdb/firewall/policy", params={"format": "name"})
            finally:
                fgs._VDOM.reset(token)
        self.assertIsNone(req.call_args_list[0].kwargs["params"])
        self.assertEqual(req.call_args_list[1].kwargs["params"], {"format": "name", "vdom": "vd-b"})


class TestAdvisorRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()
        try:
            user_manager.create_user("adm_advvdom", PASS, role="admin", groups=None)
        except Exception:
            pass

    def test_route_returns_merged_vdoms(self):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": "adm_advvdom", "password": PASS})
        self.assertEqual(r.status_code, 200, r.text)
        unit = _Unit()
        with mock.patch("routers.fortigate.assert_device_allowed", return_value=DEVICE), \
             mock.patch.object(fgs, "api_get_cmdb", side_effect=unit.cmdb), \
             mock.patch.object(fgs, "get_system_status",
                               return_value={"data": {"model": "FGT100F", "version": "7.4.5"}}), \
             mock.patch.object(fgs, "get_policies_with_stats", side_effect=unit.policies), \
             mock.patch.object(fgs, "get_vips", side_effect=unit.vips), \
             mock.patch.object(fgs, "get_security_profiles", side_effect=unit.profiles):
            r = c.get(f"/api/fortigate/{DEVICE['IP']}/firewall/advisor?lang=en")
        self.assertEqual(r.status_code, 200, r.text)
        data = r.json()["data"]
        self.assertEqual(data["source"]["vdoms"], ["root", "vd-b"])
        self.assertIn("vd-b:ADV-VIP-L7-1", {x["id"] for x in data["recommendations"]})


if __name__ == "__main__":
    unittest.main()
