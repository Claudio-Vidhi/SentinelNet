# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""/api/blueprint assistant routes (spec 2026-10-11 blueprint-assistant)."""
import json
import os
import pathlib
import tempfile
import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from ai import config_analyzer
from routers.deps import CSRF_HEADER
from security import mcp_grants, security_manager, user_manager
from security.security_manager import verify_access_token
from services import blueprint_observe, blueprint_store, inventory_manager, probe_manager
from tests.conftest import seed_inventory

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"
LOCS = {"milano": {"org": "acme", "name": "Milano", "role": "hq", "subnets": ["10.10.0.0/16"], "probe": "central"},
        "roma": {"org": "acme", "name": "Roma", "role": "branch", "subnets": [], "probe": "central"}}
EMPTY_OBS = {"devices": [], "arp": [], "routes": {}, "tunnels": {}, "observed_at": None}
SUBNET = [{"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"}]
ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFIER = "v" * 64
CHALLENGE = mcp_grants.challenge_for(VERIFIER)


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


class _Mcp(_Api):
    def setUp(self):
        super().setUp()
        p = patch.object(mcp_grants, "_path", return_value=os.path.join(self.tmp, "mcp_grants.json"))
        p.start()
        self.addCleanup(p.stop)
        user_manager.create_user("oper", PW, role="operator")

    def grant(self, client, **extra):
        r = client.post("/api/mcp/authorize", json={"port": 38461, "state": "state-123", "challenge": CHALLENGE,
                                                    "client": "Claude Desktop", **extra})
        self.assertEqual(r.status_code, 200, r.text)
        code = parse_qs(urlparse(r.json()["redirect"]).query)["code"][0]
        r = TestClient(app_server.app).post("/api/mcp/token", json={"code": code, "verifier": VERIFIER})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["token"]

    def session(self, grant):
        r = TestClient(app_server.app).post("/api/mcp/session", json={"token": grant})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["access_token"]

    def claims(self, client, **extra):
        return verify_access_token(self.session(self.grant(client, **extra)))

    def bearer(self, client, **extra):
        c = TestClient(app_server.app, raise_server_exceptions=False)
        c.headers["Authorization"] = "Bearer " + self.session(self.grant(client, **extra))
        return c

    def propose(self, c, org="acme", ops=SUBNET):
        return c.post(f"/api/blueprint/{org}/assistant-draft", json={"ops": ops, "note": "da\nClaude"})


class TestGrantPermission(_Mcp):
    def test_bpd_only_for_read_only_admin_grants(self):
        claims = self.claims(self.c, read_only=True, bp_draft=True)
        self.assertEqual((claims.get("ro"), claims.get("bpd")), (True, True))
        self.assertNotIn("bpd", self.claims(self.c, read_only=True))
        self.assertNotIn("bpd", self.claims(self.c, read_only=False, bp_draft=True))   # full grant: not needed
        self.assertNotIn("bpd", self.claims(self._as("oper"), read_only=True, bp_draft=True))
        oper_grants = mcp_grants.list_grants("oper")
        self.assertTrue(oper_grants)
        self.assertFalse(any(mcp_grants._load()[g["id"]].get("bp_draft") for g in oper_grants))

    def test_user_demoted_before_the_session_gets_no_bpd(self):
        grant = self.grant(self.c, read_only=True, bp_draft=True)
        user_manager.set_role("adm", "operator")
        claims = verify_access_token(self.session(grant))
        self.assertTrue(claims["ro"])
        self.assertNotIn("bpd", claims)

    def test_consent_offers_it_to_admins_only(self):
        self.assertTrue(self.c.get("/api/mcp/authorize/info").json()["can_bp_draft"])
        self.assertFalse(self._as("oper").get("/api/mcp/authorize/info").json()["can_bp_draft"])
        html = (ROOT / "templates/mcp_authorize.html").read_text(encoding="utf-8")
        js = (ROOT / "static/js/mcp-authorize.js").read_text(encoding="utf-8")
        self.assertIn('id="mcpcBpDraft"', html)
        self.assertIn('id="mcpcBpBox"', html)
        self.assertIn("bp_draft:", js)


class TestAssistantDraft(_Mcp):
    def test_admin_session_appends_with_source_assistant(self):
        with patch("routers.blueprint.log_audit") as audit:
            r = self.propose(self.c)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["draft"]["ops"][0]["source"], "assistant")
        self.assertIn("da Claude", audit.call_args.args[0])
        self.assertIn("1 modifiche", audit.call_args.args[0])

    def test_read_only_grant_with_bp_draft_appends_and_nothing_else(self):
        c = self.bearer(self.c, read_only=True, bp_draft=True)
        self.assertEqual(self.propose(c).status_code, 200)
        self.assertEqual(c.get("/api/auth/me").json()["role"], "viewer")
        self.assertEqual(c.post("/api/blueprint/acme/draft", json={"ops": SUBNET}).status_code, 403)
        self.assertEqual(c.post("/api/blueprint/acme/draft/apply", json={}).status_code, 403)
        self.assertEqual(c.post("/api/blueprint/acme/assistant/describe", json={"text": "x"}).status_code, 403)

    def test_read_only_grant_without_bp_draft_is_refused(self):
        self.assertEqual(self.propose(self.bearer(self.c, read_only=True)).status_code, 403)

    def test_demoted_user_loses_it_at_once(self):
        c = self.bearer(self.c, read_only=True, bp_draft=True)
        user_manager.set_role("adm", "operator")
        self.assertEqual(self.propose(c).status_code, 403)

    def test_other_tenant_viewer_and_operator_are_refused(self):
        for who in ("admbeta", "view", "oper"):
            with self.subTest(who=who):
                self.assertEqual(self.propose(self._as(who)).status_code, 403)

    def test_invalid_op_is_422_with_its_index(self):
        r = self.propose(self.c, ops=[{"op": "add_link", "a": "roma", "b": "roma", "kind": "vpn"}])
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.json()["detail"]["index"], 0)

    def test_too_many_ops_is_422(self):
        self.assertEqual(self.propose(self.c, ops=SUBNET * 201).status_code, 422)

    def test_error_index_counts_only_the_posted_ops(self):
        self.assertEqual(self.propose(self.c).status_code, 200)
        r = self.propose(self.c, ops=[{"op": "add_link", "a": "roma", "b": "roma", "kind": "vpn"}])
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.json()["detail"]["index"], 0)
        self.assertIn("Modifica 1:", r.json()["detail"]["message"])
