# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Test fase 5: gate frontend (niente sessionStorage/Bearer nel percorso
Traffico)."""

import os
import re
import shutil
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_obsui_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
from core import db  # noqa: E402
from security import user_manager  # noqa: E402
from tests.test_helpers_frontend import frontend_source  # noqa: E402

PASS = "PasswordSicura1!"


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        db.migrate()
        for user, role, groups in (("adm", "admin", None),
                                   ("op_a", "operator", ["sede-a"]),
                                   ("viewer_a", "viewer", ["sede-a"])):
            try:
                user_manager.create_user(user, PASS, role=role, groups=groups)
            except Exception:
                pass

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200
        return c


class TestObsSettingsNestedKeys(unittest.TestCase):
    """renderObsSettings deve leggere le chiavi annidate restituite da
    obs_config() (d[l].enabled / d[l].port), non le chiavi piatte."""

    def test_render_reads_nested_listener_keys(self):
        html = frontend_source()
        block = html[html.index("function renderObsSettings"):
                     html.index("async function saveObsSettings")]
        self.assertNotIn("d[`${l}_enabled`]", block)
        self.assertNotIn("d[`${l}_port`]", block)
        self.assertIn("d[l]", block)


class TestFrontendGates(_Base):
    HTML = frontend_source()

    def test_no_sessionstorage_anywhere(self):
        self.assertEqual(len(re.findall(r"sessionStorage\.(get|set)Item", self.HTML)), 0)

    def test_traffic_path_uses_apifetch_not_bearer(self):
        # The Traffic tab block of static/js/observability.js: cookie auth
        # through apiFetch, never a bearer token in JS.
        obs_js = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                    "static", "js", "observability.js"),
                       encoding="utf-8").read()
        block = obs_js[obs_js.index("TRAFFIC TAB"):]
        self.assertNotIn("Authorization", block)
        self.assertNotIn("Bearer", block)
        self.assertIn("apiFetch(", block)

    def test_flows_tab_registered(self):
        self.assertIn('id="tab-flows"', self.HTML)
        # Concedibile a un non-admin: la lista non e' piu' scritta a mano in
        # settings.js, si deriva dal pulsante di navigazione (che non deve
        # quindi essere requires-admin). Vedi tests/test_assignable_tabs.py.
        self.assertIn('data-tab="tab-flows"', self.HTML)
        self.assertIn("visibilitychange", self.HTML)


if __name__ == "__main__":
    unittest.main()
