# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The MCP tab's client snippet and the bridge's two entry points.

A snippet with a bare "python" failed on Windows (Store alias), running
ai/mcp_server.py as a script failed on `import security`, and `exe --mcp`
died on the data-dir writability check. Each regression is one test here.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_mcplaunch_"))

from routers import mcp as mcp_router  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_INIT = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}) + "\n"
_ENV = {**os.environ, "SENTINELNET_USERNAME": "x", "SENTINELNET_PASSWORD": "y"}


class TestClientLaunch(unittest.TestCase):
    def test_source_points_at_interpreter_and_script(self):
        launch = mcp_router._mcp_client_launch()
        self.assertEqual(launch["command"], sys.executable)
        self.assertEqual(launch["args"],
                         [os.path.join(REPO, "ai", "mcp_server.py")])

    def test_frozen_uses_exe_flag(self):
        with patch.object(sys, "frozen", True, create=True):
            launch = mcp_router._mcp_client_launch()
        self.assertEqual(launch, {"command": sys.executable, "args": ["--mcp"]})


class TestBridgeStarts(unittest.TestCase):
    def _initialize(self, args):
        # cwd outside the repo, as an LLM client launches it.
        out = subprocess.run([sys.executable, *args], input=_INIT, capture_output=True,
                             text=True, timeout=60, cwd=tempfile.gettempdir(), env=_ENV)
        reply = json.loads(out.stdout.splitlines()[0])
        self.assertEqual(reply["id"], 0, out.stderr)
        self.assertIn("protocolVersion", reply["result"])

    def test_script_path(self):
        self._initialize([os.path.join(REPO, "ai", "mcp_server.py")])

    def test_app_server_flag(self):
        self._initialize([os.path.join(REPO, "app_server.py"), "--mcp"])


if __name__ == "__main__":
    unittest.main()
