# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Network segments (plan 2026-11-03 network-segments): manager and API."""

import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import app_server
from core import data_config
from security import security_manager, user_manager
from services import inventory_manager, probe_manager, segment_manager


class _Isolated(unittest.TestCase):
    PW = "PasswordSicura1!"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="seg_")
        self._patches = [
            patch.object(data_config, "DATA_DIR", self.tmp),
            patch.object(user_manager, "USERS_JSON", os.path.join(self.tmp, "users.json")),
            patch.object(inventory_manager, "HOSTS_CSV", os.path.join(self.tmp, "network_hosts.csv")),
            patch.object(probe_manager, "PROBES_JSON", os.path.join(self.tmp, "probes.json")),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(self._patches)])
        security_manager._failed_attempts.clear()
        inventory_manager.save_groups({"acme": {"description": ""}, "beta": {"description": ""}})


class TestSegmentManager(_Isolated):

    def test_save_and_list(self):
        s = segment_manager.save_segment("acme", None, "OT Produzione", "amber",
                                         subnets=["10.20.0.7/24"], members=["switch-01"])
        self.assertEqual(s["subnets"], ["10.20.0.0/24"])
        out = segment_manager.list_segments("acme")
        self.assertEqual([x["name"] for x in out["segments"]], ["OT Produzione"])
        self.assertEqual(segment_manager.list_segments("beta")["segments"], [])

    def test_update_keeps_id(self):
        s = segment_manager.save_segment("acme", None, "OT", "amber")
        u = segment_manager.save_segment("acme", s["id"], "OT linea", "teal")
        self.assertEqual(u["id"], s["id"])
        self.assertEqual(len(segment_manager.list_segments("acme")["segments"]), 1)

    def test_member_moves_out_of_other_segment(self):
        a = segment_manager.save_segment("acme", None, "A", "amber", members=["switch-01", "switch-02"])
        segment_manager.save_segment("acme", None, "B", "teal", members=["switch-02"])
        segs = {s["id"]: s for s in segment_manager.list_segments("acme")["segments"]}
        self.assertEqual(segs[a["id"]]["members"], ["switch-01"])

    def test_validation(self):
        with self.assertRaises(ValueError):
            segment_manager.save_segment("acme", None, "  ", "amber")
        with self.assertRaises(ValueError):
            segment_manager.save_segment("acme", None, "X", "black")
        with self.assertRaises(ValueError):
            segment_manager.save_segment("acme", None, "X", "amber", subnets=["not-a-net"])
        with self.assertRaises(ValueError):
            segment_manager.save_segment("nope", None, "X", "amber")
        other = segment_manager.save_segment("beta", None, "B", "amber")
        with self.assertRaises(ValueError):  # id of another tenant
            segment_manager.save_segment("acme", other["id"], "X", "amber")

    def test_delete(self):
        s = segment_manager.save_segment("acme", None, "A", "amber")
        segment_manager.delete_segment("acme", s["id"])
        self.assertEqual(segment_manager.list_segments("acme")["segments"], [])
        with self.assertRaises(ValueError):
            segment_manager.delete_segment("acme", s["id"])

    def test_link_decision_is_unordered_and_clearable(self):
        segment_manager.set_link_decision("acme", "switch-02", "switch-01", "allowed")
        links = segment_manager.list_segments("acme")["links"]
        self.assertEqual(links, [{"a": "switch-01", "b": "switch-02", "decision": "allowed"}])
        segment_manager.set_link_decision("acme", "switch-01", "switch-02", "gateway")
        self.assertEqual(segment_manager.list_segments("acme")["links"][0]["decision"], "gateway")
        segment_manager.set_link_decision("acme", "switch-01", "switch-02", None)
        self.assertEqual(segment_manager.list_segments("acme")["links"], [])
        with self.assertRaises(ValueError):
            segment_manager.set_link_decision("acme", "switch-01", "switch-02", "maybe")
        with self.assertRaises(ValueError):
            segment_manager.set_link_decision("acme", "switch-01", "switch-01", "allowed")


class TestSegmentsApi(_Isolated):

    def setUp(self):
        super().setUp()
        user_manager.create_user("adm", self.PW, role="super_admin")
        user_manager.create_user("op", self.PW, role="operator", groups=["acme"])
        user_manager.create_user("view", self.PW, role="viewer", groups=["acme"])
        self.client = TestClient(app_server.app, raise_server_exceptions=False)

    def _h(self, user):
        r = self.client.post("/api/auth/login", json={"username": user, "password": self.PW})
        self.assertEqual(r.status_code, 200, r.text)
        return {"Authorization": f"Bearer {r.json()['access_token']}", "X-Requested-With": "1"}

    def test_crud_roundtrip(self):
        h = self._h("op")
        r = self.client.post("/api/segments", headers=h, json={
            "org": "acme", "name": "OT", "color": "amber", "subnets": ["10.20.0.0/24"], "members": ["switch-01"]})
        self.assertEqual(r.status_code, 200, r.text)
        sid = r.json()["segment"]["id"]
        r = self.client.get("/api/segments", params={"org": "acme"}, headers=h)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["segments"][0]["id"], sid)
        r = self.client.post("/api/segments/link", headers=h,
                             json={"org": "acme", "a": "switch-01", "b": "switch-02", "decision": "allowed"})
        self.assertEqual(r.status_code, 200, r.text)
        r = self.client.post("/api/segments/delete", headers=h, json={"org": "acme", "id": sid})
        self.assertEqual(r.status_code, 200, r.text)

    def test_bad_input_is_400(self):
        r = self.client.post("/api/segments", headers=self._h("op"),
                             json={"org": "acme", "name": "X", "color": "black"})
        self.assertEqual(r.status_code, 400)

    def test_scope_and_role(self):
        h = self._h("op")
        self.assertEqual(self.client.get("/api/segments", params={"org": "beta"}, headers=h).status_code, 403)
        self.assertEqual(self.client.post("/api/segments", headers=h,
                                          json={"org": "beta", "name": "X", "color": "amber"}).status_code, 403)
        hv = self._h("view")
        self.assertEqual(self.client.get("/api/segments", params={"org": "acme"}, headers=hv).status_code, 200)
        self.assertEqual(self.client.post("/api/segments", headers=hv,
                                          json={"org": "acme", "name": "X", "color": "amber"}).status_code, 403)
        anon = TestClient(app_server.app, raise_server_exceptions=False)  # no login cookie
        self.assertEqual(anon.get("/api/segments", params={"org": "acme"}).status_code, 401)


if __name__ == "__main__":
    unittest.main()
