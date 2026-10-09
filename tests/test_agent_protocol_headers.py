# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Agents authenticate with X-Probe-*; the old headers are refused with a
message that says what to do (reinstall), not a bare 401."""
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from services import probe_manager


class TestAgentHeaders(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp(prefix="probe_hdr_")
        p = patch.object(probe_manager, "PROBES_JSON", os.path.join(d, "probes.json"))
        p.start()
        self.addCleanup(p.stop)
        self.probe, self.token = probe_manager.create_probe("Lab", "agent")
        self.c = TestClient(app_server.app, raise_server_exceptions=False)

    def test_new_headers_accepted(self):
        r = self.c.post("/api/agent/heartbeat", json={},
                        headers={"X-Probe-Id": self.probe["id"], "X-Probe-Token": self.token})
        self.assertNotEqual(r.status_code, 401, r.text)

    def test_old_headers_refused_with_reinstall_hint(self):
        r = self.c.post("/api/agent/heartbeat", json={},
                        headers={"X-Site-Id": self.probe["id"],  # check-site-name: ok
                                 "X-Site-Token": self.token})  # check-site-name: ok
        self.assertEqual(r.status_code, 401)
        self.assertIn("reinstall", r.json()["detail"].lower())


if __name__ == "__main__":
    unittest.main()
