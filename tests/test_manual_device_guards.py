# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""A manual device has no credentials: any session would go out with the
defaults. Every per-device session path refuses it before connecting."""
import os
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_manualguard_"))

from core import core_engine  # noqa: E402

MANUAL = {"IP": "192.0.2.40", "Vendor": "cisco", "Group": "Generale",
          "Site": "central", "Transports": '{"manual":null}'}


class SessionGuards(unittest.TestCase):
    def test_cli_transport_refuses(self):
        with self.assertRaises(ValueError):
            core_engine.get_cli_transport(MANUAL)

    def test_triage_refuses_before_credentials(self):
        with mock.patch.object(core_engine, "get_device_credentials") as creds:
            out = core_engine._run_backup_and_triage(dict(MANUAL))
        self.assertEqual(out["status"], "error")
        creds.assert_not_called()

    def test_fortigate_manual_never_dispatched(self):
        fgt = dict(MANUAL, Vendor="fortinet")
        with mock.patch.object(core_engine, "_fortigate_backup_and_triage") as fg:
            out = core_engine._run_backup_and_triage(fgt)
        self.assertEqual(out["status"], "error")
        fg.assert_not_called()

    def test_custom_command_bulk_and_probe_refuse(self):
        with mock.patch.object(core_engine, "ConnectHandler") as conn:
            self.assertEqual(core_engine.send_custom_command(dict(MANUAL), "show clock")["status"], "error")
            self.assertEqual(core_engine.run_bulk_command(dict(MANUAL), ["show clock"])["status"], "error")
            self.assertEqual(core_engine.probe_device(dict(MANUAL))["status"], "error")
        conn.assert_not_called()

    def test_route_table_reads_only_the_backup(self):
        from services import route_table
        out = route_table._collect_live(dict(MANUAL))
        self.assertIn("error", out)
        self.assertNotIn("rows", out)


if __name__ == "__main__":
    unittest.main()
