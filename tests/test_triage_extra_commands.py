# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The triage's accessory commands, read by the triage and the manual guide."""
import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_extras_"))

from core import core_engine as ce  # noqa: E402


class Extras(unittest.TestCase):
    def test_cisco(self):
        cmds = ce.triage_extra_commands("cisco")
        self.assertEqual(cmds[0], ("show cdp neighbors", "--- SHOW CDP NEIGHBORS ---"))
        self.assertEqual(cmds[-1], ("show inventory", "--- SHOW INVENTORY ---"))
        self.assertEqual(len(cmds), 6)

    def test_linux_privileged_tier(self):
        base = ce.triage_extra_commands("linux")
        full = ce.triage_extra_commands("linux", privileged=True)
        self.assertIn(("sshd -T", "--- SSHD EFFECTIVE CONFIG ---"), full)
        self.assertNotIn(("sshd -T", "--- SSHD EFFECTIVE CONFIG ---"), base)
        self.assertEqual(full[:len(base)], base)

    def test_windows_comes_from_the_driver(self):
        from drivers.windows import TRIAGE_COMMANDS
        self.assertEqual(ce.triage_extra_commands("windows"), list(TRIAGE_COMMANDS))

    def test_fortinet_and_unknown_have_none(self):
        self.assertEqual(ce.triage_extra_commands("fortinet"), [])
        self.assertEqual(ce.triage_extra_commands("juniper"), [])

    def test_timeouts_match_the_old_branches(self):
        self.assertEqual(ce.TRIAGE_EXTRA_TIMEOUT,
                         {"cisco_9800": 30, "cisco_wlc": 30, "paloalto": 30, "windows": 45})

    def test_returned_list_is_a_copy(self):
        ce.triage_extra_commands("cisco").clear()
        self.assertEqual(len(ce.triage_extra_commands("cisco")), 6)


if __name__ == "__main__":
    unittest.main()
