# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""FortiGate config file identity: hostname and management IP candidates."""
import unittest

from core.core_engine import extract_hostname_from_config

HEADER = "#config-version=FGT60F-7.4.4-FW-build2662-240514:opmode=0\n"

SYSTEM_GLOBAL = (
    "config system global\n"
    "    set admintimeout 30\n"
    '    set hostname "fw-01"\n'
    "end\n"
)


class TestFortiosHostname(unittest.TestCase):
    def test_hostname_ignores_webfilter_before_global(self):
        cfg = HEADER + (
            "config webfilter ftgd-local-rating\n"
            '    edit "1"\n'
            r'        set hostname ".*\.example\..*"' "\n"
            "    next\n"
            "end\n"
        ) + SYSTEM_GLOBAL
        self.assertEqual(extract_hostname_from_config(cfg), "fw-01")

    def test_hostname_ignores_multiline_script_line(self):
        cfg = HEADER + (
            "config system auto-script\n"
            '    edit "s1"\n'
            '        set script "hostname evil-01\n'
            'end\n'
            'set hostname "evil-02"\n'
            'show"\n'
            "    next\n"
            "end\n"
        ) + SYSTEM_GLOBAL
        self.assertEqual(extract_hostname_from_config(cfg), "fw-01")

    def test_hostname_multivdom_global(self):
        cfg = HEADER + (
            "config vdom\n"
            "edit root\n"
            "next\n"
            "end\n"
            "config global\n"
            "    config system global\n"
            '        set hostname "fw-01"\n'
            "    end\n"
            "end\n"
        )
        self.assertEqual(extract_hostname_from_config(cfg), "fw-01")

    def test_hostname_global_without_hostname(self):
        cfg = HEADER + (
            "config system global\n"
            "    set admintimeout 30\n"
            "end\n"
            "config webfilter ftgd-local-rating\n"
            '    edit "1"\n'
            '        set hostname ".*x.*"\n'
            "    next\n"
            "end\n"
        )
        self.assertIsNone(extract_hostname_from_config(cfg))

    def test_cisco_unchanged(self):
        self.assertEqual(extract_hostname_from_config("hostname switch-01\n"), "switch-01")


if __name__ == "__main__":
    unittest.main()
