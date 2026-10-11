# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""/api/blueprint assistant routes (spec 2026-10-11 blueprint-assistant)."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from ai import config_analyzer
from routers.deps import CSRF_HEADER
from security import security_manager, user_manager
from services import blueprint_observe, blueprint_store, inventory_manager, probe_manager
from tests.conftest import seed_inventory

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"
LOCS = {"milano": {"org": "acme", "name": "Milano", "role": "hq", "subnets": ["10.10.0.0/16"], "probe": "central"},
        "roma": {"org": "acme", "name": "Roma", "role": "branch", "subnets": [], "probe": "central"}}
EMPTY_OBS = {"devices": [], "arp": [], "routes": {}, "tunnels": {}, "observed_at": None}
SUBNET = [{"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"}]


class _Api(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="bp_assist_api_")
        self.tmp = tmp
        for p in (patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv")),
                  patch.object(probe_manager, "PROBES_JSON", os.path.join(tmp, "probes.json")),
                  patch.object(user_manager, "USERS_JSON", os.path.join(tmp, "users.json")),
                  patch.object(blueprint_observe, "gather", return_value=EMPTY_OBS),
                  patch("routers.ai._get_active_ai_profile", return_value={"provider": "ollama"})):
            p.start()
            self.addCleanup(p.stop)
        security_manager._failed_attempts.clear()
        seed_inventory(orgs=["acme", "beta"], hosts=[{"IP": "10.20.0.1", "Group": "acme", "Location": "roma"}],
                       locations=LOCS)
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


def fake_chat(*replies):
    return patch("routers.ai.chat_with_active_profile", side_effect=[(r, {"provider": "ollama"}) for r in replies])


class TestDescribe(_Api):
    def test_admin_gets_a_draft(self):
        with fake_chat(json.dumps({"ops": SUBNET, "notes": "ok"})):
            r = self.c.post("/api/blueprint/acme/assistant/describe", json={"text": "Roma usa 10.20.1.0/24"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((r.json()["added"], r.json()["notes"]), (1, "ok"))
        self.assertEqual(r.json()["state"]["draft"]["ops"][0]["source"], "assistant")

    def test_gates(self):
        with fake_chat() as chat:
            for who in ("view", "admbeta"):
                with self.subTest(who=who):
                    r = self._as(who).post("/api/blueprint/acme/assistant/describe", json={"text": "x"})
                    self.assertEqual(r.status_code, 403)
        chat.assert_not_called()

    def test_invalid_twice_and_empty_text_are_422(self):
        with fake_chat("boh", "boh"):
            r = self.c.post("/api/blueprint/acme/assistant/describe", json={"text": "Roma usa 10.20.1.0/24"})
        self.assertEqual(r.status_code, 422)
        self.assertIn("bozza valida", r.json()["detail"]["message"])
        self.assertEqual(self.c.post("/api/blueprint/acme/assistant/describe", json={"text": " "}).status_code, 422)

    def test_no_active_profile_keeps_the_ai_tab_error(self):
        with patch("routers.ai._get_active_ai_profile", return_value=None):
            r = self.c.post("/api/blueprint/acme/assistant/describe", json={"text": "Roma usa 10.20.1.0/24"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("profilo AI", r.json()["detail"])


class TestDerive(_Api):
    def test_nothing_derived_is_422_with_the_notes(self):
        with patch.object(config_analyzer, "analyze_device", return_value=None):
            r = self.c.post("/api/blueprint/acme/assistant/derive", json={})
        self.assertEqual(r.status_code, 422)
        self.assertIn("senza backup", r.json()["detail"]["message"])

    def test_derived_ops_reach_the_draft(self):
        backup = {"interfaces": [{"name": "internal", "ip": "10.20.1.1/24"}], "routing": {"static": []}, "vpn": []}
        with patch.object(config_analyzer, "analyze_device", return_value=backup):
            r = self.c.post("/api/blueprint/acme/assistant/derive", json={"use_ai": False})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["added"], 1)
        self.assertEqual(self._as("view").post("/api/blueprint/acme/assistant/derive", json={}).status_code, 403)


class TestInstructions(_Api):
    def test_round_trip_limit_and_gates(self):
        r = self.c.put("/api/blueprint/acme/instructions", json={"text": "  Sedi col nome della città.  "})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {"instructions": "Sedi col nome della città."})
        st = self.c.get("/api/blueprint/acme").json()
        self.assertEqual((st["instructions"], st["ai_available"]), ("Sedi col nome della città.", True))
        self.assertEqual(self.c.put("/api/blueprint/acme/instructions", json={"text": "x" * 4001}).status_code, 422)
        self.assertEqual(self._as("view").put("/api/blueprint/acme/instructions", json={"text": "y"}).status_code, 403)
        self.assertEqual(self._as("admbeta").put("/api/blueprint/acme/instructions", json={"text": "y"}).status_code, 403)
