# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""FortiGate config file identity: hostname and management IP candidates."""
import unittest

import os
import tempfile

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_fortiid_"))

from core.core_engine import extract_hostname_from_config  # noqa: E402
from services.manual_config import ip_candidates  # noqa: E402

HEADER = "#config-version=FGT-7.4.1-FW-build2463-230314:opmode=0\n"

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


def _interfaces(body):
    return HEADER + "config system interface\n" + body + "end\n"


class TestFortiosIpCandidates(unittest.TestCase):
    def test_candidates_gui_public_first(self):
        cfg = _interfaces(
            '    edit "port1"\n'
            "        set ip 10.0.0.1 255.255.255.0\n"
            "        set allowaccess ping\n"
            "    next\n"
            '    edit "internal"\n'
            "        set ip 192.168.1.99 255.255.255.0\n"
            "        set allowaccess ping https ssh\n"
            "    next\n"
            '    edit "wan1"\n'
            "        set ip 203.0.113.10 255.255.255.248\n"
            "        set allowaccess ping https\n"
            "    next\n"
        )
        self.assertEqual(ip_candidates(cfg), ["203.0.113.10", "192.168.1.99", "10.0.0.1"])

    def test_candidates_secondaryip(self):
        cfg = _interfaces(
            '    edit "wan1"\n'
            "        set ip 198.51.100.2 255.255.255.0\n"
            "        set secondary-IP enable\n"
            "        config secondaryip\n"
            "            edit 1\n"
            "                set ip 203.0.113.20 255.255.255.255\n"
            "                set allowaccess https\n"
            "            next\n"
            "        end\n"
            "    next\n"
        )
        self.assertEqual(ip_candidates(cfg)[0], "203.0.113.20")

    def test_candidates_dhcp_interface_skipped(self):
        cfg = _interfaces(
            '    edit "wan2"\n'
            "        set mode dhcp\n"
            "        set allowaccess https\n"
            "    next\n"
            '    edit "internal"\n'
            "        set ip 192.168.1.99 255.255.255.0\n"
            "    next\n"
        )
        self.assertEqual(ip_candidates(cfg), ["192.168.1.99"])

    def test_candidates_partial_paste_falls_back_to_generic(self):
        # FortiOS detected, but the paste has no `config system interface`
        # block: the generic `set ip` regex still proposes the address.
        cfg = HEADER + (
            "        set ip 192.0.2.10 255.255.255.0\n"
            "        set allowaccess https\n"
        )
        self.assertEqual(ip_candidates(cfg), ["192.0.2.10"])

    def test_candidates_ios_unchanged(self):
        cfg = (
            "hostname switch-01\n"
            "interface Vlan1\n"
            " ip address 192.168.1.10 255.255.255.0\n"
            "interface GigabitEthernet0/0\n"
            " ip address 10.0.0.1 255.255.255.0\n"
        )
        self.assertEqual(ip_candidates(cfg), ["192.168.1.10", "10.0.0.1"])


if __name__ == "__main__":
    unittest.main()
