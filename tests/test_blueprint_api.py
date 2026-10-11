# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""/api/blueprint: drafts, apply, revisions, restore (spec 2026-10-11)."""
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from routers.deps import CSRF_HEADER
from security import security_manager, user_manager
from services import blueprint_observe, blueprint_store, inventory_manager, location_manager, probe_manager
from tests.conftest import seed_inventory

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"
LOCS = {"milano": {"org": "acme", "name": "Milano", "role": "hq", "subnets": ["10.10.0.0/16"], "probe": "central"},
        "roma": {"org": "acme", "name": "Roma", "role": "branch", "subnets": ["10.20.0.0/16"], "probe": "central"}}
EMPTY_OBS = {"devices": [], "arp": [], "routes": {}, "tunnels": {}, "observed_at": None}


class _Api(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="bp_api_")
        for p in (patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv")),
                  patch.object(probe_manager, "PROBES_JSON", os.path.join(tmp, "probes.json")),
                  patch.object(user_manager, "USERS_JSON", os.path.join(tmp, "users.json")),
                  patch.object(blueprint_observe, "gather", return_value=EMPTY_OBS)):
            p.start()
            self.addCleanup(p.stop)
        security_manager._failed_attempts.clear()
        seed_inventory(orgs=["acme", "beta"], locations=LOCS)
        with inventory_manager._db() as conn, conn:
            blueprint_store.record_revisions(conn, "", "migration")
        user_manager.create_user("adm", PW, role="admin")
        user_manager.create_user("admbeta", PW, role="admin", groups=["beta"])
        user_manager.create_user("view", PW, role="viewer")
        self.c = self._as("adm")

    def _as(self, name):
        c = TestClient(app_server.app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", json={"username": name, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        c.headers.update(H)
        return c

    def draft(self, body):
        return self.c.post("/api/blueprint/acme/draft", json=body)


class TestAccess(_Api):
    def test_state_checks_and_gates(self):
        r = self.c.get("/api/blueprint/acme")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((sorted(r.json()["locations"]), r.json()["rev"], r.json()["draft"]),
                         (["milano", "roma"], 1, None))
        self.assertEqual(self.c.get("/api/blueprint/acme/checks").status_code, 200)
        self.assertEqual(self._as("admbeta").get("/api/blueprint/acme").status_code, 403)
        self.assertEqual(self._as("view").post("/api/blueprint/acme/draft", json={"ops": []}).status_code, 403)
        self.assertEqual(self.c.get("/api/blueprint/nobody").status_code, 404)

    def test_scoped_admin_cannot_write_another_org(self):
        beta = self._as("admbeta")
        for method, path, body in (("post", "/draft", {"ops": []}), ("put", "/draft", {"ops": []}),
                                   ("post", "/draft/apply", {}), ("post", "/draft/discard", None),
                                   ("post", "/draft/align", None), ("post", "/observe", None)):
            with self.subTest(path=path, method=method):
                r = getattr(beta, method)(f"/api/blueprint/acme{path}", json=body)
                self.assertEqual(r.status_code, 403, r.text)


class TestDraftFlow(_Api):
    def test_preset_apply_revisions_diff(self):
        r = self.draft({"preset": "hub_spoke", "n": 2})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(len(r.json()["draft"]["ops"]), 4)                    # 2 branches + 2 links
        self.assertIn("filiale-3", r.json()["preview"]["locations"])
        r = self.c.post("/api/blueprint/acme/draft/apply", json={"note": "prime filiali"})
        self.assertEqual(r.json(), {"rev": 2, "renamed": {}})
        revs = self.c.get("/api/blueprint/acme/revisions").json()["revisions"]
        self.assertEqual((revs[0]["rev"], revs[0]["source"], revs[0]["note"]), (2, "blueprint", "prime filiali"))
        d = self.c.get("/api/blueprint/acme/diff", params={"a": 1, "b": 2}).json()
        self.assertEqual([x["id"] for x in d["locations"]["added"]], ["filiale-2", "filiale-3"])
        self.assertIsNone(self.c.get("/api/blueprint/acme").json()["draft"])

    def test_invalid_op_is_422_with_its_index(self):
        r = self.draft({"ops": [{"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"},
                                {"op": "add_link", "a": "roma", "b": "roma", "kind": "vpn"}]})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.json()["detail"]["index"], 1)
        self.assertIsNone(self.c.get("/api/blueprint/acme").json()["draft"])

    def test_malformed_op_is_422_not_500(self):
        r = self.draft({"ops": [{"op": "add_link", "a": ["x"], "b": "roma", "kind": "vpn"}]})
        self.assertEqual(r.status_code, 422, r.text)
        self.assertEqual(r.json()["detail"]["index"], 0)

    def test_replace_and_discard(self):
        self.draft({"ops": [{"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"},
                            {"op": "add_subnet", "id": "roma", "subnet": "10.21.0.0/24"}]})
        r = self.c.put("/api/blueprint/acme/draft", json={"ops": [{"op": "set_gateway", "id": "roma", "ip": "10.20.0.2"}]})
        self.assertEqual(len(r.json()["draft"]["ops"]), 1)
        self.assertEqual(self.c.post("/api/blueprint/acme/draft/discard").status_code, 200)
        self.assertIsNone(self.c.get("/api/blueprint/acme").json()["draft"])

    def test_stale_draft_is_409_until_aligned(self):
        self.draft({"ops": [{"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"}]})
        location_manager.update_location("milano", name="Milano HQ", by="anna")
        r = self.c.post("/api/blueprint/acme/draft/apply", json={})
        self.assertEqual(r.status_code, 409)
        self.assertEqual(location_manager.get_location("roma")["gateway"], "")
        self.assertEqual(self.c.post("/api/blueprint/acme/draft/align").status_code, 200)
        r = self.c.post("/api/blueprint/acme/draft/apply", json={})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(location_manager.get_location("roma")["gateway"], "10.20.0.1")

    def test_delete_with_devices_refused_with_count(self):
        seed_inventory(hosts=[{"IP": "10.20.0.5", "Group": "acme", "Location": "roma"}], locations=LOCS)
        self.draft({"ops": [{"op": "delete_location", "id": "roma"}]})
        r = self.c.post("/api/blueprint/acme/draft/apply", json={})
        self.assertEqual(r.status_code, 422)
        self.assertIn("1 apparati", r.json()["detail"]["message"])
        self.assertIsNotNone(location_manager.get_location("roma"))

    def test_restore_round_trip_and_renamed_id(self):
        self.draft({"ops": [{"op": "delete_location", "id": "roma"},
                            {"op": "update_location", "id": "milano", "fields": {"name": "HQ"}}]})
        self.c.post("/api/blueprint/acme/draft/apply", json={})
        location_manager.create_location("beta", "Roma", by="x")         # takes the id «roma»
        r = self.draft({"restore": 1})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["draft"]["source"], "restore")
        r = self.c.post("/api/blueprint/acme/draft/apply", json={})
        self.assertEqual(r.json()["renamed"], {"roma": "roma-2"})
        state = self.c.get("/api/blueprint/acme").json()
        self.assertEqual(sorted(l["name"] for l in state["locations"].values()), ["Milano", "Roma"])
        revs = self.c.get("/api/blueprint/acme/revisions").json()["revisions"]
        self.assertEqual(revs[0]["source"], "restore")

    def test_observe_runs_the_live_collection(self):
        with patch.object(blueprint_observe, "observe", return_value={"at": "now", "gateways": {}}) as obs:
            r = self.c.post("/api/blueprint/acme/observe")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(obs.call_args.args[0], "acme")

    def test_observe_collects_from_the_draft_gateways(self):
        self.draft({"ops": [{"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"}]})
        with patch.object(blueprint_observe, "observe", return_value={"at": "now", "gateways": {}}) as obs:
            self.c.post("/api/blueprint/acme/observe")
        self.assertEqual(obs.call_args.args[1]["locations"]["roma"]["gateway"], "10.20.0.1")
