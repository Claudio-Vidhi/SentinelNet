# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Every MCP tool must reach a real route of the central server.

The bridge builds paths by hand: a typo is a tool that always answers 404 and
that no unit test of the lambda would notice. Each tool is called with sample
arguments and its request is sent, unauthenticated, through the actual app:
401/403/422 prove that a handler matched, 404/405 that none did.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_mcproutes_"))

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from ai import mcp_server  # noqa: E402

_SAMPLE = {"string": "192.0.2.1", "integer": 1, "boolean": True, "array": [], "object": {}}


def _sample_args(schema: dict) -> dict:
    return {k: _SAMPLE[p.get("type", "string")]
            for k, p in schema.get("properties", {}).items()}


class TestEveryToolHitsARoute(unittest.TestCase):
    def test_each_tool_matches_a_handler(self):
        client = TestClient(app_server.app)
        sent = []

        def fake_api(method, path, params=None, body=None):
            r = client.request(method, path, params=params, json=body)
            sent.append((method, path, r.status_code))
            return {}

        with patch.object(mcp_server, "api", side_effect=fake_api):
            for name, (_desc, schema, fn) in mcp_server.TOOLS.items():
                with self.subTest(tool=name):
                    sent.clear()
                    fn(_sample_args(schema))
                    self.assertTrue(sent, f"{name} sent no request")
                    method, path, status = sent[-1]
                    self.assertNotIn(status, (404, 405), f"{name}: {method} {path} -> {status}")


if __name__ == "__main__":
    unittest.main()
