# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Manual config upload: the guide, and a session log turned into the
backup layout the triage writes."""
import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_manualcfg_"))

from services import manual_config as mc  # noqa: E402
from services.config_drift.normalize import TRIAGE_MARKER  # noqa: E402

IOS_LOG = (
    "=~=~=~=~=~=~=~=~=~=~=~= PuTTY log 2026.10.08 10:00:00 =~=~=~=~=~=~=~=~=~=~=~=\r\n"
    "switch-01#terminal length 0\r\n"
    "switch-01#show running-config\r\n"
    "Building configuration...\r\n"
    "hostname switch-01\r\n"
    "interface Vlan10\r\n"
    " ip address 192.0.2.10 255.255.255.0\r\n"
    "interface Vlan20\r\n"
    " ip address 198.51.100.1 255.255.255.0\r\n"
    "end\r\n"
    "switch-01#show version\r\n"
    "Cisco IOS Software, C2960X Software, Version 15.2(7)E2, RELEASE SOFTWARE (fc3)\r\n"
    "Model Number                       : WS-C2960X-24TS-L\r\n"
    "System Serial Number               : FOC0000X0XX\r\n"
    "switch-01#show cdp neighbors detail\r\n"
    "Device ID: switch-02\r\n"
    "switch-01#\r\n"
)

FORTI_GUI = (
    "#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0\n"
    "config system global\n"
    "    set hostname \"FGT-01\"\n"
    "end\n"
    "config system interface\n"
    "    edit \"port1\"\n"
    "        set ip 192.0.2.1 255.255.255.0\n"
    "    next\n"
    "end\n"
)

PANOS = ("set deviceconfig system hostname PA-01\n"
         "set deviceconfig system ip-address 203.0.113.5\n")

JUNOS = ("set system host-name router-01\n"
         "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.2/24\n")


class Guide(unittest.TestCase):
    def test_every_vendor_resolves_and_has_its_backup_command(self):
        rows = {g["vendor"]: g for g in mc.guide()}
        self.assertEqual(set(rows), set(mc.GUIDE_VENDORS))
        self.assertEqual(rows["cisco"]["commands"][0], "show running-config")
        self.assertIn("show version", rows["cisco"]["commands"])
        self.assertIn("show cdp neighbors detail", rows["cisco"]["commands"])
        self.assertEqual(rows["cisco"]["paging"], "terminal length 0")
        self.assertEqual(rows["fortinet"]["commands"][0], "show full-configuration")
        self.assertIn("get system status", rows["fortinet"]["commands"])

    def test_commands_are_not_repeated(self):
        for g in mc.guide():
            self.assertEqual(len(g["commands"]), len(set(g["commands"])), g["vendor"])


class SessionLog(unittest.TestCase):
    """Review focus 1: CRLF and a PuTTY header line."""

    def test_ios_log_becomes_triage_layout(self):
        out = mc.to_backup("cisco", IOS_LOG)
        self.assertTrue(out["structured"])
        config, _, rest = out["backup"].partition(f"\n\n{TRIAGE_MARKER}\n")
        self.assertIn("hostname switch-01", config)
        self.assertNotIn("show version", config)
        self.assertNotIn("PuTTY log", out["backup"])
        self.assertIn("--- SHOW CDP NEIGHBORS DETAIL ---\nDevice ID: switch-02", rest)
        self.assertNotIn("Cisco IOS Software", out["backup"])  # read, not stored
        self.assertEqual(out["version"], "15.2(7)E2")
        self.assertEqual(out["model"], "WS-C2960X-24TS-L")
        self.assertEqual(out["serial"], "FOC0000X0XX")
        self.assertEqual(out["hostname"], "switch-01")

    def test_abbreviated_command_is_a_plain_file(self):
        """Review focus 3."""
        out = mc.to_backup("cisco", "switch-01#sh run\nhostname switch-01\nend\n")
        self.assertFalse(out["structured"])
        self.assertEqual(out["backup"], "switch-01#sh run\nhostname switch-01\nend\n")

    def test_fortios_prompt_change_mid_log(self):
        log = (
            "FGT-01 # show full-configuration\n"
            "config system global\n"
            "    set hostname \"FGT-01\"\n"
            "end\n"
            "FGT-01 (global) # get system status\n"
            "Version: FortiGate-60F v7.2.5,build1517,230606 (GA)\n"
            "FGT-01 (global) # \n"
        )
        out = mc.to_backup("fortinet", log)
        self.assertTrue(out["structured"])
        self.assertEqual(out["version"], "7.2.5")
        self.assertNotIn("(global) #", out["backup"])
        self.assertIn('set hostname "FGT-01"', out["backup"])

    def test_cisco_user_exec_then_enable(self):
        log = (
            "R1>show version\n"
            "Cisco IOS Software, Version 15.2(7)E2, RELEASE SOFTWARE\n"
            "R1>enable\n"
            "R1#show running-config\n"
            "hostname R1\n"
            "end\n"
            "R1#\n"
        )
        out = mc.to_backup("cisco", log)
        self.assertTrue(out["structured"])
        self.assertIn("hostname R1", out["backup"].partition(TRIAGE_MARKER)[0])
        self.assertNotIn("R1#", out["backup"])
        self.assertEqual(out["version"], "15.2(7)E2")

    def test_linux_hostname_section_is_prefixed(self):
        backup_cmd, _, extras = mc._commands("linux")
        host_cmd, host_tag = extras[0]
        self.assertEqual((host_cmd, host_tag), ("hostname", "--- HOSTNAME ---"))
        log = (
            f"root@srv-01:~# {backup_cmd}\n"
            "--- /etc/hosts ---\n"
            "127.0.0.1 localhost\n"
            f"root@srv-01:~# {host_cmd}\n"
            "srv-01\n"
            "root@srv-01:~#\n"
        )
        out = mc.to_backup("linux", log)
        self.assertTrue(out["structured"])
        self.assertIn(f"\n{host_tag}\nhostname srv-01", out["backup"])
        self.assertEqual(out["hostname"], "srv-01")


    def test_linux_colour_codes_and_bracketed_paste_are_stripped(self):
        backup_cmd, _, extras = mc._commands("linux")
        host_cmd = extras[0][0]
        ps = "\x1b[0;32mroot@srv-01\x1b[0m:\x1b[1;34m~\x1b[0m# "
        log = (
            f"{ps}\x1b[?2004l{backup_cmd}\r\n"
            "\x1b]8003;start=abc\x1b\x5c--- /etc/hosts ---\r\n"
            "127.0.0.1 localhost\r\n"
            f"{ps}\x1b[?2004l{host_cmd}\r\n"
            "srv-01\r\n"
            f"{ps}\x1b[?2004l\r\n"
        )
        out = mc.to_backup("linux", log)
        self.assertTrue(out["structured"])
        self.assertNotIn("\x1b", out["backup"])
        self.assertIn("127.0.0.1 localhost", out["backup"])
        self.assertEqual(out["hostname"], "srv-01")

    def test_linux_wrapped_command_echo_is_rejoined(self):
        backup_cmd, _, extras = mc._commands("linux")
        host_cmd = extras[0][0]
        cut = len(backup_cmd) // 2
        log = (
            f"root@srv-01:~# {backup_cmd[:cut]} \r{backup_cmd[cut:]}\r\n"
            "--- /etc/hosts ---\r\n"
            "127.0.0.1 localhost\r\n"
            f"root@srv-01:~# {host_cmd}\r\n"
            "srv-01\r\n"
            "root@srv-01:~#\r\n"
        )
        out = mc.to_backup("linux", log)
        self.assertTrue(out["structured"])
        self.assertIn("127.0.0.1 localhost", out["backup"])
        self.assertEqual(out["hostname"], "srv-01")


class PlainFiles(unittest.TestCase):
    def test_fortigate_gui_backup_is_stored_as_is(self):
        """Review focus 2."""
        out = mc.to_backup("fortinet", FORTI_GUI)
        self.assertFalse(out["structured"])
        self.assertEqual(out["backup"], FORTI_GUI)
        self.assertEqual((out["model"], out["version"]), ("FGT60F", "7.2.5"))
        self.assertEqual(out["hostname"], "FGT-01")

    def test_hostnames_of_other_vendors(self):
        self.assertEqual(mc.to_backup("paloalto", PANOS)["hostname"], "PA-01")
        self.assertEqual(mc.to_backup("juniper", JUNOS)["hostname"], "router-01")


class Candidates(unittest.TestCase):
    def test_ip_candidates(self):
        self.assertEqual(mc.ip_candidates(IOS_LOG), ["192.0.2.10", "198.51.100.1"])
        self.assertEqual(mc.ip_candidates(FORTI_GUI), ["192.0.2.1"])
        self.assertEqual(mc.ip_candidates(PANOS), ["203.0.113.5"])
        self.assertEqual(mc.ip_candidates(JUNOS), ["192.0.2.2"])

    def test_invalid_octet_is_excluded(self):
        text = " ip address 999.1.1.1 255.255.255.0\n ip address 192.0.2.7 255.255.255.0\n"
        self.assertEqual(mc.ip_candidates(text), ["192.0.2.7"])


class Preview(unittest.TestCase):
    def test_vendor_is_suggested_and_analyses_listed(self):
        p = mc.preview(FORTI_GUI)
        self.assertEqual(p["vendor"], "fortinet")
        self.assertEqual(p["config_type"], "fortios")
        self.assertEqual(p["analyses"], ["analyzer", "audit", "policy", "drift", "routes", "cve"])
        self.assertNotIn("backup", p)

    def test_junos_gets_drift_only(self):
        p = mc.preview(JUNOS)
        self.assertEqual(p["vendor"], "juniper")
        self.assertEqual(p["analyses"], ["drift"])

    def test_given_vendor_wins(self):
        self.assertEqual(mc.preview(IOS_LOG, "cisco")["vendor"], "cisco")

    def test_sniffed_vendor_ignores_the_given_one(self):
        p = mc.preview(FORTI_GUI, "cisco")
        self.assertEqual((p["vendor"], p["sniffed_vendor"]), ("cisco", "fortinet"))
        self.assertEqual(mc.preview(FORTI_GUI)["sniffed_vendor"], "fortinet")


if __name__ == "__main__":
    unittest.main()
