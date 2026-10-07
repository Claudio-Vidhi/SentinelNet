# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""MCP bridge sign-in through the browser (security/mcp_grants.py).

Server side: approve -> one-time code -> PKCE-checked grant -> short JWT, and
every way a grant must die (revoke, sign out everywhere, reused or forged
code). Bridge side: the fallbacks for clients that ignore list_changed (the
lone login tool) and the loopback callback that only takes its own state.
"""

import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_mcplogin_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from ai import mcp_server  # noqa: E402
from security import mcp_grants, user_manager  # noqa: E402

USER, PASS = "mcp_login_viewer", "PasswordSicura1!"
OPER, OPASS = "mcp_login_operator", "PasswordSicura1!"
CSRF = {"X-Requested-With": "XMLHttpRequest"}
VERIFIER = "v" * 64
CHALLENGE = mcp_grants.challenge_for(VERIFIER)


class TestServerFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        user_manager.create_user(USER, PASS, role="viewer")
        user_manager.create_user(OPER, OPASS, role="operator")
        cls.client = TestClient(app_server.app)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def setUp(self):
        r = self.client.post("/api/auth/login", json={"username": USER, "password": PASS})
        self.assertEqual(r.status_code, 200, r.text)

    def _code(self, port=38461, client=None, **extra):
        r = (client or self.client).post(
            "/api/mcp/authorize", headers=CSRF,
            json={"port": port, "state": "state-123", "challenge": CHALLENGE,
                  "client": "Claude Desktop", "host": "pc-01", **extra})
        self.assertEqual(r.status_code, 200, r.text)
        url = urlparse(r.json()["redirect"])
        self.assertEqual((url.scheme, url.hostname, url.port), ("http", "127.0.0.1", port))
        q = parse_qs(url.query)
        self.assertEqual(q["state"], ["state-123"])
        return q["code"][0]

    def _grant(self, client=None, **extra):
        r = self.client.post("/api/mcp/token",
                             json={"code": self._code(client=client, **extra), "verifier": VERIFIER})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["token"]

    def _operator(self):
        c = TestClient(app_server.app)
        self.assertEqual(c.post("/api/auth/login", json={"username": OPER, "password": OPASS}).status_code, 200)
        return c

    def _bearer(self, grant):
        r = self._session(grant)
        self.assertEqual(r.status_code, 200, r.text)
        return {"Authorization": "Bearer " + r.json()["access_token"]}

    def _session(self, grant):
        return self.client.post("/api/mcp/session", json={"token": grant})

    def test_grant_opens_a_session_as_the_approving_user(self):
        r = self._session(self._grant())
        self.assertEqual(r.status_code, 200, r.text)
        me = TestClient(app_server.app).get(
            "/api/auth/me", headers={"Authorization": "Bearer " + r.json()["access_token"]})
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["username"], USER)

    def test_only_the_hash_is_stored(self):
        grant = self._grant()
        with open(mcp_grants._path(), encoding="utf-8") as f:
            self.assertNotIn(grant, f.read())

    def test_wrong_verifier_is_refused_and_burns_the_code(self):
        code = self._code()
        bad = self.client.post("/api/mcp/token", json={"code": code, "verifier": "w" * 64})
        self.assertEqual(bad.status_code, 400)
        again = self.client.post("/api/mcp/token", json={"code": code, "verifier": VERIFIER})
        self.assertEqual(again.status_code, 400)

    def test_code_is_single_use(self):
        code = self._code()
        ok = self.client.post("/api/mcp/token", json={"code": code, "verifier": VERIFIER})
        self.assertEqual(ok.status_code, 200)
        reuse = self.client.post("/api/mcp/token", json={"code": code, "verifier": VERIFIER})
        self.assertEqual(reuse.status_code, 400)

    def test_forged_token_is_refused(self):
        self.assertEqual(self._session("snmcp_forged").status_code, 401)
        self.assertEqual(self._session("not-a-grant").status_code, 401)

    def test_privileged_or_odd_ports_are_rejected(self):
        for port in (80, 0, 70000):
            r = self.client.post("/api/mcp/authorize", headers=CSRF,
                                 json={"port": port, "state": "state-123", "challenge": CHALLENGE})
            self.assertEqual(r.status_code, 422, port)

    def test_authorize_needs_a_session(self):
        r = TestClient(app_server.app).post(
            "/api/mcp/authorize", headers=CSRF,
            json={"port": 38461, "state": "state-123", "challenge": CHALLENGE})
        self.assertEqual(r.status_code, 401)

    def test_revoked_grant_stops_working(self):
        grant = self._grant()
        gid = mcp_grants.list_grants()[-1]["id"]
        self.assertEqual(mcp_grants.revoke(gid), USER)
        self.assertEqual(self._session(grant).status_code, 401)

    def test_sign_out_everywhere_ends_grants(self):
        grant = self._grant()
        self.assertEqual(self._session(grant).status_code, 200)
        r = self.client.post("/api/auth/logout-all", headers=CSRF)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self._session(grant).status_code, 401)

    def test_grant_list_is_admin_only(self):
        self.assertEqual(self.client.get("/api/mcp/grants").status_code, 403)

    def test_users_see_and_revoke_only_their_own_grants(self):
        mine = self._grant()
        self._grant(client=self._operator())
        theirs_id = mcp_grants.list_grants(OPER)[-1]["id"]
        listed = self.client.get("/api/mcp/my-grants").json()["grants"]
        self.assertTrue(listed)
        self.assertTrue(all(g["user"] == USER for g in listed))
        r = self.client.post("/api/mcp/my-grants/revoke", headers=CSRF, json={"id": theirs_id})
        self.assertEqual(r.status_code, 404)
        self.assertTrue(any(g["id"] == theirs_id for g in mcp_grants.list_grants(OPER)))
        own_id = listed[-1]["id"]
        r = self.client.post("/api/mcp/my-grants/revoke", headers=CSRF, json={"id": own_id})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(own_id, [g["id"] for g in mcp_grants.list_grants(USER)])
        del mine

    def test_grant_remembers_client_and_host(self):
        self._grant()
        self.assertEqual(mcp_grants.list_grants()[-1]["label"], "Claude Desktop · pc-01")

    def test_read_only_operator_grant_acts_as_viewer(self):
        h = self._bearer(self._grant(client=self._operator(), read_only=True))
        me = TestClient(app_server.app).get("/api/auth/me", headers=h)
        self.assertEqual(me.json()["role"], "viewer")
        # The web terminal needs an operator: a read-only grant cannot open it.
        ws = TestClient(app_server.app).post("/api/ws-token", headers={**h, **CSRF})
        self.assertEqual(ws.status_code, 403)

    def test_full_operator_grant_keeps_the_role(self):
        h = self._bearer(self._grant(client=self._operator(), read_only=False))
        me = TestClient(app_server.app).get("/api/auth/me", headers=h)
        self.assertEqual(me.json()["role"], "operator")

    def test_viewer_cannot_ask_for_more_than_read_only(self):
        self._grant(read_only=False)
        self.assertTrue(mcp_grants.list_grants()[-1]["read_only"])

    def test_read_only_token_is_never_renewed_into_a_cookie(self):
        h = self._bearer(self._grant(client=self._operator(), read_only=True))
        c = TestClient(app_server.app)
        c.cookies.set("net_session", h["Authorization"][7:])
        r = c.get("/api/auth/me", headers={"X-SentinelNet-Active": "1"})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("net_session", r.cookies)

    def test_consent_info_follows_role_and_read_only(self):
        v = {p["key"]: p for p in self.client.get("/api/mcp/authorize/info").json()["permissions"]}
        self.assertTrue(v["read"]["full"])
        self.assertFalse(v["actions"]["full"])
        info = self._operator().get("/api/mcp/authorize/info").json()
        self.assertTrue(info["can_choose"])
        o = {p["key"]: p for p in info["permissions"]}
        self.assertTrue(o["actions"]["full"])
        self.assertFalse(o["actions"]["read_only"])

    def test_consent_page_is_served(self):
        r = TestClient(app_server.app).get("/mcp/authorize?port=38461")
        self.assertEqual(r.status_code, 200)
        self.assertIn("mcp-authorize.js", r.text)

    def test_control_characters_in_client_name_are_rejected(self):
        r = self.client.post("/api/mcp/authorize", headers=CSRF,
                             json={"port": 38461, "state": "state-123", "challenge": CHALLENGE,
                                   "client": "evil\nline"})
        self.assertEqual(r.status_code, 422)


class TestSsoReturn(unittest.TestCase):
    def test_only_the_consent_page_is_a_valid_return(self):
        from routers.auth import _sso_next_ok
        self.assertTrue(_sso_next_ok("/mcp/authorize?port=38461&state=x"))
        for bad in ("/", "https://evil.example/", "//evil.example/mcp/authorize?",
                    "/mcp/authorize", "/mcp/authorize?\\evil"):
            self.assertFalse(_sso_next_ok(bad), bad)


class TestBridgeFallbacks(unittest.TestCase):
    def test_unsigned_client_sees_only_the_login_tool(self):
        with patch.object(mcp_server, "PASSWORD", ""), \
             patch.object(mcp_server, "_grant", None), \
             patch.object(mcp_server, "_stored_grant", return_value=None), \
             patch.object(mcp_server, "_authorize_in_background") as auth:
            names = [t["name"] for t in mcp_server._tool_list()["tools"]]
            self.assertEqual(names, [mcp_server.LOGIN_TOOL])
            out = mcp_server._tool_call({"name": mcp_server.LOGIN_TOOL})
            self.assertFalse(out.get("isError"))
            auth.assert_called_once()

    def test_password_config_still_lists_the_tools(self):
        with patch.object(mcp_server, "PASSWORD", "x"), \
             patch.object(mcp_server, "disabled_tools", return_value=set()):
            names = [t["name"] for t in mcp_server._tool_list()["tools"]]
        self.assertNotIn(mcp_server.LOGIN_TOOL, names)
        self.assertIn("list_devices", names)


class TestCallback(unittest.TestCase):
    def setUp(self):
        self.srv = mcp_server._CallbackServer(("127.0.0.1", 0), mcp_server._CallbackHandler)
        self.srv.state = "good-state"
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def _get(self, query):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        try:
            return opener.open(f"http://127.0.0.1:{self.port}/callback?{query}", timeout=5)
        except urllib.error.HTTPError as e:
            return e

    def test_wrong_state_is_ignored(self):
        self.assertEqual(self._get("code=abc&state=evil").status, 400)
        self.assertIsNone(self.srv.code)

    def test_right_state_takes_the_code_and_shows_the_outcome(self):
        r = self._get("code=abc&state=good-state")
        self.assertEqual(r.status, 302)
        self.assertTrue(r.headers["Location"].startswith(
            f"{mcp_server.BASE_URL}/mcp/authorize?result=done"))
        self.assertEqual(self.srv.code, "abc")

    def test_cancel_stops_the_wait(self):
        r = self._get("error=access_denied&state=good-state")
        self.assertEqual(r.status, 302)
        self.assertIn("result=denied", r.headers["Location"])
        self.assertTrue(self.srv.denied)
        self.assertIsNone(self.srv.code)

    def test_cancel_with_a_foreign_state_is_ignored(self):
        self.assertEqual(self._get("error=access_denied&state=evil").status, 400)
        self.assertFalse(self.srv.denied)


if __name__ == "__main__":
    unittest.main()
