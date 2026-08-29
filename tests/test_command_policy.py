# -*- coding: utf-8 -*-
"""Politica comandi pericolosi in UN solo modulo (WP5,
docs/app-review-fix-plan.md): i tre tier vivono in security/command_policy,
i vecchi call site delegano, le semantiche di bypass restano esplicite."""

import unittest
from unittest import mock

from security import command_policy
from routers import commands as commands_router
from core import core_engine


class TestSingleSourceOfTruth(unittest.TestCase):

    def test_old_names_are_aliases_of_the_policy_lists(self):
        self.assertIs(commands_router.COMMAND_BLACKLIST,
                      command_policy.INTERACTIVE_PATTERNS)
        self.assertIs(commands_router.BULK_DESTRUCTIVE_BLACKLIST,
                      command_policy.BULK_ALWAYS_PATTERNS)
        self.assertIs(core_engine.DANGEROUS_COMMANDS,
                      command_policy.SYSTEM_SUBSTRINGS)

    def test_tiers_are_distinct(self):
        self.assertNotEqual(command_policy.INTERACTIVE_PATTERNS,
                            command_policy.BULK_ALWAYS_PATTERNS)
        self.assertTrue(command_policy.INTERACTIVE_PATTERNS)
        self.assertTrue(command_policy.BULK_ALWAYS_PATTERNS)
        self.assertTrue(command_policy.SYSTEM_SUBSTRINGS)


class TestInteractiveTier(unittest.TestCase):

    def test_destructive_commands_are_blocked(self):
        for cmd in ("reload", "reload in 5", "write erase", "conf t",
                    "configure terminal", "rollback 3", "request system zeroize",
                    "delete flash:/old.bin"):
            self.assertFalse(commands_router.is_command_safe(cmd), cmd)

    def test_operational_commands_pass(self):
        for cmd in ("show version", "show ip interface brief",
                    "get system status", "display version",
                    "show running-config"):
            self.assertTrue(commands_router.is_command_safe(cmd), cmd)

    def test_admin_bypasses_interactive_tier(self):
        admin = {"role": "admin", "sub": "capo"}
        with mock.patch.object(commands_router, "get_app_settings",
                               return_value={"cli_blacklist_operators": True}):
            self.assertTrue(commands_router.command_allowed("reload", admin))

    def test_operator_subject_when_setting_on(self):
        op = {"role": "operator", "sub": "op1"}
        with mock.patch.object(commands_router, "get_app_settings",
                               return_value={"cli_blacklist_operators": True}):
            self.assertFalse(commands_router.command_allowed("reload", op))
            self.assertTrue(commands_router.command_allowed("show version", op))

    def test_operator_free_when_setting_off(self):
        op = {"role": "operator", "sub": "op1"}
        with mock.patch.object(commands_router, "get_app_settings",
                               return_value={"cli_blacklist_operators": False}):
            self.assertTrue(commands_router.command_allowed("reload", op))


class TestBulkTier(unittest.TestCase):

    def test_bulk_destructive_blocked_for_everyone(self):
        # Nessun bypass per ruolo: il bulk lega anche gli admin.
        for cmd in ("reload", "reboot", "erase startup-config",
                    "format disk0", "write erase"):
            self.assertFalse(commands_router.is_bulk_command_allowed(cmd), cmd)

    def test_bulk_operational_allowed(self):
        for cmd in ("show version", "show clock", "get system performance"):
            self.assertTrue(commands_router.is_bulk_command_allowed(cmd), cmd)


class TestSystemTier(unittest.TestCase):

    def test_substring_net(self):
        self.assertEqual(command_policy.matches_system("sudo rm -rf /var"), "rm -rf")
        self.assertEqual(command_policy.matches_system("dd if=/dev/zero of=/dev/sda"), "dd if=")
        self.assertEqual(command_policy.matches_system("mkfs.ext4 /dev/sdb1"), "mkfs")
        self.assertIsNone(command_policy.matches_system("show ip route"))

    def test_shutdown_is_not_blocked(self):
        # Su Cisco 'shutdown' spegne una porta: e' lavoro quotidiano.
        self.assertIsNone(command_policy.matches_system("shutdown"))


if __name__ == "__main__":
    unittest.main()
