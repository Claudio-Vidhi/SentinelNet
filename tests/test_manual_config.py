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

    def test_fortinet_section_commands(self):
        rows = {g["vendor"]: g for g in mc.guide()}
        sections = rows["fortinet"]["sections"]
        self.assertTrue(sections)
        self.assertTrue(all(c.startswith("show ") for c in sections))
        self.assertNotIn("show full-configuration", sections)
        self.assertFalse([c for c in sections if "user local" in c])
        self.assertEqual(len(sections), len(set(sections)))
        for vendor, g in rows.items():
            if vendor != "fortinet":
                self.assertEqual(g["sections"], [], vendor)

    def test_single_vdom_sections_unchanged(self):
        """The scope tags must not reorder or change the single-VDOM list."""
        expected = [f"show {s}" for s in (
            'system global', 'system interface', 'system password-policy', 'system ha',
            'system dns', 'system snmp community', 'system snmp user', 'system admin',
            'system session-helper', 'system auto-install', 'system ntp', 'system zone',
            'log disk setting', 'log fortianalyzer setting', 'log syslogd setting',
            'log eventfilter', 'log fortiguard setting', 'firewall address', 'firewall addrgrp',
            'firewall service custom', 'firewall service group', 'firewall schedule recurring',
            'firewall schedule onetime', 'ips sensor', 'user radius', 'user tacacs+', 'user ldap',
            'user fsso', 'user group', 'vpn ssl web portal', 'vpn ssl settings',
            'antivirus profile', 'webfilter profile', 'dnsfilter profile', 'application list',
            'dlp profile', 'emailfilter profile', 'firewall ssl-ssh-profile',
            'vpn ipsec phase1-interface', 'vpn ipsec phase2-interface', 'vpn ipsec phase1',
            'vpn ipsec phase2', 'firewall vip', 'firewall vipgrp', 'firewall ippool',
            'firewall policy', 'firewall local-in-policy', 'firewall DoS-policy',
            'firewall central-snat-map', 'router static', 'router policy', 'router ospf',
            'router bgp')]
        rows = {g["vendor"]: g for g in mc.guide()}
        self.assertEqual(rows["fortinet"]["sections"], expected)

    def test_fortinet_multi_vdom_split(self):
        rows = {g["vendor"]: g for g in mc.guide()}
        split = rows["fortinet"]["sections_vdom"]
        glob, vdom = split["global"], split["vdom"]
        for c in ("show system global", "show system interface", "show system admin",
                  "show log syslogd setting"):
            self.assertIn(c, glob)
        for c in ("show firewall policy", "show system zone", "show log eventfilter",
                  "show router static", "show user group", "show ips sensor"):
            self.assertIn(c, vdom)
        self.assertFalse(set(glob) & set(vdom))
        self.assertEqual(sorted(glob + vdom), sorted(rows["fortinet"]["sections"]))
        # Each scope keeps the single-VDOM order.
        order = rows["fortinet"]["sections"]
        for part in (glob, vdom):
            self.assertEqual(part, [c for c in order if c in part])
        for vendor, g in rows.items():
            if vendor != "fortinet":
                self.assertEqual(g["sections_vdom"], {}, vendor)

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
        # Read into the fields and, like the live triage, stored under its tag.
        self.assertIn("--- SHOW VERSION ---\nCisco IOS Software", rest)
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


FORTI_SECTIONS_LOG = (
    "fw-01 # show system global\r\n"
    "config system global\r\n"
    "    set hostname \"fw-01\"\r\n"
    "end\r\n"
    "\r\n"
    "fw-01 # show system interface\r\n"
    "config system interface\r\n"
    "    edit \"port1\"\r\n"
    "        set ip 192.0.2.1 255.255.255.0\r\n"
    "        set allowaccess ping https\r\n"
    "    next\r\n"
    "    edit \"port2\"\r\n"
    "        set ip 198.51.100.1 255.255.255.0\r\n"
    "    next\r\n"
    "end\r\n"
    "\r\n"
    "fw-01 # show firewall policy\r\n"
    "config firewall policy\r\n"
    "    edit 1\r\n"
    "        set srcintf \"port1\"\r\n"
    "        set dstintf \"port2\"\r\n"
    "        set srcaddr \"all\"\r\n"
    "        set dstaddr \"all\"\r\n"
    "        set action accept\r\n"
    "        set service \"ALL\"\r\n"
    "    next\r\n"
    "end\r\n"
    "\r\n"
    "fw-01 # get system status\r\n"
    "Version: FortiGate-60F v7.2.5,build1517,230606 (GA)\r\n"
    "Serial-Number: FGT60FTK00000000\r\n"
    "fw-01 # \r\n"
)


class SectionLog(unittest.TestCase):
    """GUI console without SSH: one `show <section>` per command, no header."""

    def test_sections_become_one_config(self):
        out = mc.to_backup("fortinet", FORTI_SECTIONS_LOG)
        self.assertTrue(out["structured"])
        config, marker, _ = out["backup"].partition(f"\n\n{TRIAGE_MARKER}\n")
        self.assertTrue(marker)
        self.assertTrue(config.startswith("config system global\n"))
        starts = [config.index(f"config {s}\n") for s in
                  ("system global", "system interface", "firewall policy")]
        self.assertEqual(starts, sorted(starts))
        self.assertNotIn("fw-01 #", out["backup"])
        self.assertNotIn("Version:", out["backup"])
        self.assertEqual(out["hostname"], "fw-01")
        self.assertEqual(out["version"], "7.2.5")
        self.assertEqual(out["model"], "FortiGate-60F")
        self.assertEqual(out["serial"], "FGT60FTK00000000")

    def test_out_of_order_sections_follow_the_guide(self):
        head, _, tail = FORTI_SECTIONS_LOG.partition("fw-01 # show system interface")
        iface, _, rest = tail.partition("fw-01 # show firewall policy")
        policy, _, status = rest.partition("fw-01 # get system status")
        log = ("fw-01 # show firewall policy" + policy + head
               + "fw-01 # show system interface" + iface + "fw-01 # get system status" + status)
        config = mc.to_backup("fortinet", log)["backup"]
        self.assertLess(config.index("config system interface"), config.index("config firewall policy"))

    def test_stored_backup_reads_as_fortios(self):
        from ai.config_analyzer import analyze_fortios_config, detect_config_type
        backup = mc.to_backup("fortinet", FORTI_SECTIONS_LOG)["backup"]
        self.assertEqual(detect_config_type(backup, {"Vendor": "fortinet"}), "fortios")
        self.assertEqual(detect_config_type(backup), "fortios")
        parsed = analyze_fortios_config(backup)
        self.assertEqual([i["name"] for i in parsed["interfaces"]], ["port1", "port2"])
        self.assertEqual(len(parsed["policies"]), 1)
        self.assertEqual(parsed["hostname"], "fw-01")
        p = mc.preview(FORTI_SECTIONS_LOG, "fortinet")
        self.assertEqual(p["config_type"], "fortios")
        self.assertEqual(p["ip_candidates"][0], "192.0.2.1")
        self.assertEqual(p["warnings"], [])

    def test_truncated_fortios_text_is_flagged(self):
        truncated = ("config firewall policy\n    edit 1\n        set action accept\n"
                     "    next\nend\n")
        self.assertEqual(mc.preview(truncated, "fortinet")["warnings"], ["mcWarnFortiPartial"])
        self.assertEqual(mc.preview(FORTI_GUI)["warnings"], [])
        self.assertEqual(mc.preview(IOS_LOG, "cisco")["warnings"], [])


FORTI_VDOM_LOG = (
    "fw-01 # config global\r\n"
    "\r\n"
    "fw-01 (global) # config system console\r\n"
    "fw-01 (console) # set output standard\r\n"
    "fw-01 (console) # end\r\n"
    "fw-01 (global) # show system global\r\n"
    "config system global\r\n"
    "    set hostname \"fw-01\"\r\n"
    "    set vdom-mode multi-vdom\r\n"
    "end\r\n"
    "\r\n"
    "fw-01 (global) # show system interface\r\n"
    "config system interface\r\n"
    "    edit \"port1\"\r\n"
    "        set vdom \"root\"\r\n"
    "        set ip 192.0.2.1 255.255.255.0\r\n"
    "        set allowaccess ping https\r\n"
    "    next\r\n"
    "    edit \"port2\"\r\n"
    "        set vdom \"root\"\r\n"
    "        set ip 198.51.100.1 255.255.255.0\r\n"
    "    next\r\n"
    "end\r\n"
    "\r\n"
    "fw-01 (global) # get system status\r\n"
    "Version: FortiGate-100F v7.4.3,build2573,240201 (GA.F)\r\n"
    "Serial-Number: FG100FTK00000000\r\n"
    "Virtual domain configuration: multiple\r\n"
    "fw-01 (global) # end\r\n"
    "\r\n"
    "fw-01 # config vdom\r\n"
    "\r\n"
    "fw-01 (vdom) # edit root\r\n"
    "current vf=root:0\r\n"
    "\r\n"
    "fw-01 (root) # show firewall policy\r\n"
    "config firewall policy\r\n"
    "    edit 1\r\n"
    "        set srcintf \"port1\"\r\n"
    "        set dstintf \"port2\"\r\n"
    "        set srcaddr \"all\"\r\n"
    "        set dstaddr \"all\"\r\n"
    "        set action accept\r\n"
    "        set service \"ALL\"\r\n"
    "    next\r\n"
    "end\r\n"
    "\r\n"
    "fw-01 (root) # show system zone\r\n"
    "config system zone\r\n"
    "end\r\n"
    "\r\n"
    "fw-01 (root) # end\r\n"
    "fw-01 # \r\n"
)


class VdomLog(unittest.TestCase):
    """Multi-VDOM GUI console: global sections under config global, the rest
    under config vdom / edit <name>; stored as one flat config."""

    def test_global_and_vdom_sections_become_one_config(self):
        out = mc.to_backup("fortinet", FORTI_VDOM_LOG)
        self.assertTrue(out["structured"])
        config, marker, _ = out["backup"].partition(f"\n\n{TRIAGE_MARKER}\n")
        self.assertTrue(marker)
        self.assertTrue(config.startswith("#vdom=root\nconfig system global\n"))
        # Global first, then the VDOM, each in guide order (zone before policy).
        starts = [config.index(f"config {s}\n") for s in
                  ("system global", "system interface", "system zone", "firewall policy")]
        self.assertEqual(starts, sorted(starts))
        for echo in ("fw-01 ", "current vf", "config global", "config vdom", "edit root",
                     "Version:", "config system console"):
            self.assertNotIn(echo, out["backup"])
        self.assertEqual(out["hostname"], "fw-01")
        self.assertEqual(out["version"], "7.4.3")
        self.assertEqual(out["model"], "FortiGate-100F")
        self.assertEqual(out["serial"], "FG100FTK00000000")

    def test_vdom_name_other_than_root(self):
        log = FORTI_VDOM_LOG.replace("edit root", "edit dmz-vdom").replace("(root)", "(dmz-vdom)")
        backup = mc.to_backup("fortinet", log)["backup"]
        self.assertTrue(backup.startswith("#vdom=dmz-vdom\n"))

    def test_stored_backup_reads_as_fortios(self):
        from ai.config_analyzer import analyze_fortios_config, detect_config_type
        backup = mc.to_backup("fortinet", FORTI_VDOM_LOG)["backup"]
        self.assertEqual(detect_config_type(backup), "fortios")
        parsed = analyze_fortios_config(backup)
        self.assertEqual([i["name"] for i in parsed["interfaces"]], ["port1", "port2"])
        self.assertEqual(len(parsed["policies"]), 1)
        self.assertEqual(parsed["hostname"], "fw-01")
        p = mc.preview(FORTI_VDOM_LOG, "fortinet")
        self.assertEqual(p["warnings"], [])
        self.assertEqual(p["ip_candidates"][0], "192.0.2.1")

    def test_single_vdom_log_gets_no_vdom_comment(self):
        self.assertNotIn("#vdom=", mc.to_backup("fortinet", FORTI_SECTIONS_LOG)["backup"])


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

    def test_securecrt_timestamps_read_like_a_plain_log(self):
        # SecureCRT "timestamp each line": 'HHMMSS.mmm: ' before every line, blank ones included.
        stamped = "".join(f"150701.{i:03d}: {line}\r\n" for i, line in enumerate(IOS_LOG.splitlines()))
        plain, p = mc.preview(IOS_LOG, "cisco"), mc.preview(stamped, "cisco")
        for key in ("hostname", "version", "model", "ip_candidates", "structured"):
            self.assertEqual(p[key], plain[key], key)
        self.assertEqual(p["hostname"], "switch-01")

    def test_unrecognised_content_sniffs_nothing(self):
        # An HPE/Aruba/CBS log falls into the IOS fallback: no vendor claim, no false warning.
        p = mc.preview(IOS_LOG, "hpe")
        self.assertEqual((p["vendor"], p["sniffed_vendor"]), ("hpe", ""))


class GuideUi(unittest.TestCase):
    def test_section_block_is_rendered_and_copied(self):
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        js = (root / "static/js/manual-config.js").read_text(encoding="utf-8")
        html = (root / "templates/dashboard.html").read_text(encoding="utf-8")
        i18n = (root / "static/js/i18n.js").read_text(encoding="utf-8")
        self.assertTrue("v.sections" in js and "'mc-copy-sections'" in js)
        self.assertTrue("r.warnings" in js)
        self.assertEqual(i18n.count("mcWarnFortiPartial:"), 2)  # it + en
        self.assertIn('id="mcSectionsBlock"', html)
        self.assertIn('id="mcSections"', html)
        self.assertIn('data-action="mc-copy-sections"', html)

    def test_vdom_block_is_rendered_and_copied(self):
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        js = (root / "static/js/manual-config.js").read_text(encoding="utf-8")
        html = (root / "templates/dashboard.html").read_text(encoding="utf-8")
        i18n = (root / "static/js/i18n.js").read_text(encoding="utf-8")
        self.assertTrue("v.sections_vdom" in js and "'mc-copy-vdom'" in js)
        for key in ("mcLblVdom:", "mcVdomHint:", "mcLblVdomName:", "mcCopyVdomAria:"):
            self.assertEqual(i18n.count(key), 2, key)  # it + en
        for frag in ('id="mcVdomBlock"', 'id="mcVdomCommands"', 'data-action="mc-copy-vdom"',
                     '<label for="mcVdomName"', 'id="mcVdomName"', 'value="root"'):
            self.assertIn(frag, html)
        self.assertIn("$('mcVdomName')?.addEventListener('input'", js)


if __name__ == "__main__":
    unittest.main()
