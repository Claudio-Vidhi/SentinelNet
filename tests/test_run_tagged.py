# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""_run_tagged: the triage accessory-command loop every vendor shares."""
import unittest
from unittest.mock import MagicMock

from core.core_engine import _run_tagged


class RunTagged(unittest.TestCase):
    def test_a_failing_command_drops_only_its_section(self):
        conn = MagicMock()
        conn.send_command.side_effect = ["a-out", RuntimeError("unknown command"), "c-out"]
        out = _run_tagged(conn, [("a", "--- A ---"), ("b", "--- B ---"), ("c", "--- C ---")])
        self.assertEqual(out, "\n--- A ---\na-out\n--- C ---\nc-out")

    def test_read_timeout_is_passed_only_when_set(self):
        conn = MagicMock(); conn.send_command.return_value = "x"
        _run_tagged(conn, [("a", "--- A ---")])
        self.assertEqual(conn.send_command.call_args.kwargs, {})
        _run_tagged(conn, [("a", "--- A ---")], read_timeout=30)
        self.assertEqual(conn.send_command.call_args.kwargs, {"read_timeout": 30})

    def test_hostname_prefix_is_opt_in(self):
        conn = MagicMock(); conn.send_command.return_value = "switch-01\n"
        cmds = [("hostname", "--- HOSTNAME ---")]
        self.assertEqual(_run_tagged(conn, cmds, prefix_hostname=True),
                         "\n--- HOSTNAME ---\nhostname switch-01")
        # Windows builds its own hostname line: it must pass through untouched.
        self.assertEqual(_run_tagged(conn, cmds), "\n--- HOSTNAME ---\nswitch-01\n")


if __name__ == "__main__":
    unittest.main()
