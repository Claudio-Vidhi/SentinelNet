# -*- coding: utf-8 -*-
"""Test del parser FortiOS con tracciamento di riga usato dal motore di audit."""

import unittest

from services.netsec_audit.parser import (
    parse_with_lines, section_entries, section_present, setting)

SAMPLE = """\
#config-version=FGT
config system global
    set admintimeout 5
    set strong-crypto enable
end
config system interface
    edit "port1"
        set allowaccess ping https telnet
    next
    edit "port2"
        set allowaccess ping https
    next
end
config system snmp community
end
"""


class TestParser(unittest.TestCase):
    def test_records_carry_path_key_values_and_line(self):
        cfg = parse_with_lines(SAMPLE)
        rec = setting(cfg, "system global", "admintimeout")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.path, ("system global",))
        self.assertEqual(rec.key, "admintimeout")
        self.assertEqual(rec.values, ["5"])
        self.assertEqual(rec.line, 3)
        self.assertIn("admintimeout 5", rec.raw)

    def test_edit_blocks_are_grouped_by_key(self):
        cfg = parse_with_lines(SAMPLE)
        ifaces = section_entries(cfg, "system interface")
        self.assertEqual(set(ifaces), {"port1", "port2"})
        port1 = [r for r in ifaces["port1"] if r.key == "allowaccess"][0]
        self.assertEqual(port1.values, ["ping", "https", "telnet"])
        self.assertEqual(port1.line, 8)

    def test_empty_section_is_still_reported_present(self):
        """Un blocco senza 'set' non produce record ma esiste: serve a
        distinguere 'assente' (UNKNOWN) da 'presente e conforme' (PASS)."""
        cfg = parse_with_lines(SAMPLE)
        self.assertTrue(section_present(cfg, "system snmp community"))
        self.assertEqual(section_entries(cfg, "system snmp community"), {})
        self.assertFalse(section_present(cfg, "log syslogd setting"))

    def test_comments_and_blank_lines_ignored(self):
        cfg = parse_with_lines(SAMPLE)
        self.assertTrue(all(not r.raw.strip().startswith("#") for r in cfg.records))

    def test_quoted_values_are_unquoted(self):
        cfg = parse_with_lines(
            'config firewall policy\n'
            '    edit 1\n'
            '        set srcaddr "all"\n'
            '    next\n'
            'end\n')
        pol = section_entries(cfg, "firewall policy")["1"]
        self.assertEqual([r for r in pol if r.key == "srcaddr"][0].values, ["all"])

    def test_none_and_empty_input_are_safe(self):
        for bad in (None, "", "   \n\n"):
            cfg = parse_with_lines(bad)
            self.assertEqual(cfg.records, [])
            self.assertEqual(cfg.sections, set())

    def test_unclosed_blocks_do_not_raise(self):
        cfg = parse_with_lines(
            'config system global\n    set admintimeout 5\n')
        self.assertIsNotNone(setting(cfg, "system global", "admintimeout"))

    def test_stray_end_does_not_raise(self):
        cfg = parse_with_lines('end\nend\nconfig system global\n set a b\nend\n')
        self.assertIsNotNone(setting(cfg, "system global", "a"))


if __name__ == "__main__":
    unittest.main()
