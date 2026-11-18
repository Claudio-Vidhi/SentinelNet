# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for industrial networking drivers, registry aliases, triage, drift, and CLI counters."""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_ind_drv_"))

from collectors import iface_counters_cli
from core import core_engine
from drivers.cisco_ie import CISCO_IE_OIDS, CiscoIeDriver
from drivers.hirschmann import HirschmannDriver
from drivers.moxa import MoxaDriver
from drivers.phoenix_contact import PhoenixContactDriver
from drivers.registry import (
    DRIVER_REGISTRY,
    arp_command_for,
    cpe_match_string,
    driver_name_for,
    resolve_driver,
    services_enabled,
)
from drivers.siemens_scalance import SiemensScalanceDriver
from drivers.westermo import WestermoDriver
from services import inventory_manager, manual_config as mc
from services.config_drift import normalize as drift_normalize


class _FakeConn:
    def __init__(self, responses: dict[str, str]):
        self._responses = responses
        self.commands: list[str] = []

    def send_command(self, cmd: str, *args, **kwargs) -> str:
        self.commands.append(cmd)
        return self._responses.get(cmd, "")


class TestIndustrialDriverParsers(unittest.TestCase):
    def test_siemens_scalance_driver(self):
        conn = _FakeConn({
            "show versions": (
                "Device Type      : SCALANCE XC208\n"
                "Order No.        : 6GK5208-0BA00-2AC2\n"
                "Firmware Version : V04.04.00\n"
                "Serial Number    : S C-P1A2B3C4\n"
            ),
        })
        drv = SiemensScalanceDriver(conn)
        self.assertEqual(drv.get_version(), "04.04.00")
        self.assertEqual(drv.get_model(), "6GK5208-0BA00-2AC2")
        self.assertEqual(drv.get_serial(), "S C-P1A2B3C4")
        self.assertEqual(drv.get_backup_command(), "show running-config")

    def test_hirschmann_driver(self):
        conn = _FakeConn({
            "show sysinfo": (
                "System Name          : switch-01\n"
                "Hardware Description : BRS40-0012OOOO-S\n"
                "Running Release      : HiOS-2S-09.0.00\n"
                "Serial Number        : 94217000100001\n"
            ),
        })
        drv = HirschmannDriver(conn)
        self.assertEqual(drv.get_version(), "09.0.00")
        self.assertEqual(drv.get_model(), "BRS40-0012OOOO-S")
        self.assertEqual(drv.get_serial(), "94217000100001")
        self.assertEqual(drv.get_backup_command(), "show running-config script")

    def test_moxa_driver(self):
        conn = _FakeConn({
            "show system": (
                "Model Name       : EDS-510E\n"
                "Firmware Version : V2.3\n"
                "Serial Number    : TABC00001234\n"
            ),
        })
        drv = MoxaDriver(conn)
        self.assertEqual(drv.get_version(), "2.3")
        self.assertEqual(drv.get_model(), "EDS-510E")
        self.assertEqual(drv.get_serial(), "TABC00001234")
        self.assertEqual(drv.get_backup_command(), "show running-config")

    def test_westermo_driver(self):
        conn = _FakeConn({
            "show system": (
                "Product          : Lynx-3510-E-F2G-T8G-LV\n"
                "WeOS Version     : 5.21.1\n"
                "Serial Number    : WES0009988\n"
            ),
        })
        drv = WestermoDriver(conn)
        self.assertEqual(drv.get_version(), "5.21.1")
        self.assertEqual(drv.get_model(), "Lynx-3510-E-F2G-T8G-LV")
        self.assertEqual(drv.get_serial(), "WES0009988")
        self.assertEqual(drv.get_backup_command(), "show running-config")

    def test_phoenix_contact_driver(self):
        conn = _FakeConn({
            "show version": (
                "Device Type      : FL SWITCH 3008\n"
                "Firmware Version : 1.40.2\n"
                "Serial Number    : PCX00012345\n"
            ),
        })
        drv = PhoenixContactDriver(conn)
        self.assertEqual(drv.get_version(), "1.40.2")
        self.assertEqual(drv.get_model(), "FL SWITCH 3008")
        self.assertEqual(drv.get_serial(), "PCX00012345")
        self.assertEqual(drv.get_backup_command(), "show running-config")

    def test_cisco_ie_driver_and_oids(self):
        conn = _FakeConn({
            "show version": (
                "Cisco IOS Software [Bengaluru], IE3x00 Switch Software (IE3x00-UNIVERSALK9-M), "
                "Version 17.9.4a, RELEASE SOFTWARE (fc3)\n"
                "cisco IE-3300-8T2S (ARM64) processor with 1024K bytes of memory.\n"
                "System Serial Number            : FDO0000A0AA\n"
            ),
        })
        drv = CiscoIeDriver(conn)
        self.assertEqual(drv.get_version(), "17.9.4a")
        self.assertEqual(drv.get_model(), "IE-3300-8T2S")
        self.assertEqual(drv.get_serial(), "FDO0000A0AA")
        self.assertEqual(drv.get_backup_command(), "show running-config")
        self.assertIn("dlr_ring_state", CISCO_IE_OIDS)
        self.assertIn("envmon_temp_value", CISCO_IE_OIDS)


class TestIndustrialRegistryAndEngineIntegration(unittest.TestCase):
    def test_all_industrial_vendors_resolve_and_have_no_windows_generic(self):
        cases = [
            ("siemens", SiemensScalanceDriver, "generic_termserver", "show arp"),
            ("scalance", SiemensScalanceDriver, "generic_termserver", "show arp"),
            ("hirschmann", HirschmannDriver, "hirschmann_hios", "show arp"),
            ("belden", HirschmannDriver, "hirschmann_hios", "show arp"),
            ("moxa", MoxaDriver, "moxa_nos", "show arp"),
            ("westermo", WestermoDriver, "generic_termserver", "show arp"),
            ("phoenix_contact", PhoenixContactDriver, "generic_termserver", "show arp"),
            ("cisco_ie", CiscoIeDriver, "cisco_ios", "show ip arp"),
        ]
        for raw_vendor, expected_cls, expected_netmiko, expected_arp in cases:
            cls, ntype = resolve_driver(raw_vendor)
            self.assertIs(cls, expected_cls)
            self.assertEqual(ntype, expected_netmiko)
            drv_key = driver_name_for(raw_vendor)
            self.assertIn(drv_key, DRIVER_REGISTRY)
            self.assertEqual(arp_command_for(drv_key), expected_arp)

    def test_generic_termserver_never_triggers_windows_prep_or_blind_enable(self):
        conn = MagicMock()
        core_engine.maybe_enable(conn, "generic_termserver", "")
        conn.enable.assert_not_called()

        core_engine.maybe_enable(conn, "generic_termserver", "enable-secret")
        conn.enable.assert_called_once()

        # Verify triage path with generic_termserver never calls prepare_windows_session
        with patch.object(core_engine, "probe_manager") as pm, \
             patch.object(core_engine, "is_reachable", return_value=True), \
             patch.object(core_engine, "get_device_credentials", return_value=("u", "p", "")), \
             patch.object(core_engine, "prepare_windows_session") as prep_win, \
             patch.object(core_engine, "ConnectHandler") as ch, \
             patch.object(core_engine, "update_version_inventory"), \
             patch.object(core_engine, "update_device_hostname"), \
             patch.object(core_engine, "save_backup", return_value="/tmp/b.txt"):
            pm.is_agent_probe.return_value = False
            pm.has_direct_path.return_value = True
            fake_ssh = MagicMock()
            fake_ssh.find_prompt.return_value = "switch-01#"
            fake_ssh.send_command.return_value = "hostname switch-01\nFirmware Version: V04.04.00\n"
            ch.return_value.__enter__.return_value = fake_ssh

            res = core_engine._run_backup_and_triage({
                "IP": "192.0.2.50",
                "Vendor": "siemens_scalance",
                "Group": "OT",
                "Probe": "central",
            })
            self.assertEqual(res["status"], "success")
            prep_win.assert_not_called()

    def test_nvd_cpe_and_service_extractor(self):
        self.assertEqual(inventory_manager.resolve_euvd_term("siemens_scalance"), "siemens")
        self.assertEqual(inventory_manager.resolve_euvd_term("hirschmann"), "hirschmann")
        self.assertEqual(inventory_manager.resolve_euvd_term("moxa"), "moxa")
        self.assertEqual(inventory_manager.resolve_euvd_term("westermo"), "westermo")
        self.assertEqual(inventory_manager.resolve_euvd_term("phoenix_contact"), "phoenix contact")
        self.assertEqual(inventory_manager.resolve_euvd_term("cisco_ie"), "cisco")

        self.assertEqual(cpe_match_string("cisco_ie", "17.9.4a"), "cpe:2.3:o:cisco:ios_xe:17.9.4a")
        self.assertEqual(cpe_match_string("cisco_ie", "15.2(4)EA9"), r"cpe:2.3:o:cisco:ios:15.2\(4\)ea9")
        self.assertEqual(services_enabled("cisco_ie", "ip http server\nsnmp-server community public RO\n"), {"http": True, "snmp": True})

    def test_triage_extras_drift_hostname_and_manual_guide(self):
        for v in ("cisco_ie", "siemens_scalance", "hirschmann", "moxa", "westermo", "phoenix_contact"):
            self.assertGreater(len(core_engine.triage_extra_commands(v)), 0, v)
            self.assertIn(v, mc.GUIDE_VENDORS)

        self.assertEqual(core_engine.extract_hostname_from_config("sysname plc-ring-sw01\n"), "plc-ring-sw01")
        self.assertEqual(core_engine.guess_vendor(platform="SCALANCE XC208"), "siemens_scalance")
        self.assertEqual(core_engine.guess_vendor(description="Hirschmann HiOS BRS40"), "hirschmann")
        self.assertEqual(core_engine.guess_vendor(platform="Moxa EDS-510E"), "moxa")
        self.assertEqual(core_engine.guess_vendor(platform="Westermo Lynx"), "westermo")
        self.assertEqual(core_engine.guess_vendor(platform="Phoenix Contact FL SWITCH 3008"), "phoenix_contact")
        self.assertEqual(core_engine.guess_vendor(platform="cisco IE-3300-8T2S"), "cisco_ie")

        raw_cfg = "! Configuration generated 2026-11-18 10:00:00\nhostname switch-01\nvlan 10\n"
        self.assertEqual(drift_normalize.normalize("hirschmann", raw_cfg), "hostname switch-01\nvlan 10\n")

    def test_industrial_cli_iface_counters(self):
        for drv in ("cisco_ie", "siemens_scalance", "hirschmann_hios", "moxa_nos", "westermo_weos", "phoenix_contact"):
            self.assertIn(drv, iface_counters_cli.COMMANDS)

        block_out = (
            "Port Gi1/1\n"
            "  Rx Errors: 3\n"
            "  Tx Errors: 1\n"
            "  CRC Errors: 2\n"
            "  Rx Drops: 4\n"
        )
        parsed = iface_counters_cli.parse_industrial_counters(block_out)
        self.assertEqual(parsed["Gi1/1"], {"in_errors": 3, "out_errors": 1, "crc": 2, "in_discards": 4})

        table_out = (
            "Port    RxErrors  TxErrors  CRC  Drops\n"
            "1/1     5         0         2    1\n"
            "1/2     0         0         0    0\n"
        )
        parsed_tbl = iface_counters_cli.parse_industrial_counters(table_out)
        self.assertEqual(parsed_tbl["1/1"], {"in_errors": 5, "out_errors": 0, "crc": 2, "in_discards": 1})


if __name__ == "__main__":
    unittest.main()
