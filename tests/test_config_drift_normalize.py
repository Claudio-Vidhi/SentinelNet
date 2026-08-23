# -*- coding: utf-8 -*-
"""Volatile lines must not read as configuration changes.

Every one of these appears in a real backup and changes without anyone
touching the device. If they survive normalisation, the archive grows a new
version on every collection run and the whole feature becomes noise.
"""
import unittest

from services.config_drift import normalize


class VolatileLinesAreStripped(unittest.TestCase):
    def test_ios_byte_count_and_timestamps_are_ignored(self):
        first = (
            "Building configuration...\n"
            "Current configuration : 48210 bytes\n"
            "! Last configuration change at 10:02:11 UTC Mon Aug 19 2026\n"
            "hostname switch-01\n"
            "ntp clock-period 17179860\n"
        )
        second = (
            "Building configuration...\n"
            "Current configuration : 48244 bytes\n"
            "! Last configuration change at 03:14:07 UTC Fri Aug 22 2026\n"
            "hostname switch-01\n"
            "ntp clock-period 17179902\n"
        )
        self.assertEqual(normalize.normalize("cisco", first),
                         normalize.normalize("cisco", second))

    def test_a_real_ios_change_survives(self):
        base = "hostname switch-01\nip http server\n"
        changed = "hostname switch-01\nno ip http server\n"
        self.assertNotEqual(normalize.normalize("cisco", base),
                            normalize.normalize("cisco", changed))

    def test_fortios_config_header_is_ignored(self):
        first = "#config-version=FGT-7.4.1-FW-build2463-230314:opmode=0\nconfig system global\n"
        second = "#config-version=FGT-7.4.1-FW-build2470-230501:opmode=0\nconfig system global\n"
        self.assertEqual(normalize.normalize("fortinet", first),
                         normalize.normalize("fortinet", second))

    def test_a_real_fortios_change_survives(self):
        base = 'config system global\n    set hostname "fw-01"\nend\n'
        changed = 'config system global\n    set hostname "fw-02"\nend\n'
        self.assertNotEqual(normalize.normalize("fortinet", base),
                            normalize.normalize("fortinet", changed))

    def test_an_unknown_vendor_still_normalises_whitespace(self):
        self.assertEqual(normalize.normalize("", "hostname switch-01   \n\n\n"),
                         normalize.normalize("weird-os", "hostname switch-01\n"))

    def test_normalisation_is_idempotent(self):
        text = "Current configuration : 10 bytes\nhostname switch-01\n"
        once = normalize.normalize("cisco", text)
        self.assertEqual(once, normalize.normalize("cisco", once))


if __name__ == "__main__":
    unittest.main()
