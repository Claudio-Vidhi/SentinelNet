# -*- coding: utf-8 -*-
"""Report Port-channel: due sorgenti, ciascuna per ciò che sa davvero.

La configurazione (backup) dice chi è MEMBRO e chi è spento da comando; lo
stato SNMP dice chi è SU adesso. Prima il report si reggeva solo sul backup, e
il badge di stato veniva da una sezione presente solo in alcuni backup vecchi:
una porta caduta dopo l'ultimo salvataggio non compariva affatto.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_po_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import core_engine  # noqa: E402

CONFIG = """hostname SW2
!
interface Ethernet0/0
 switchport mode trunk
 shutdown
 channel-group 10 mode active
!
interface Ethernet0/2
 switchport mode trunk
 channel-group 10 mode active
!
interface Ethernet0/3
 description libera
!
"""


class TestShutdownParsing(unittest.TestCase):

    def test_a_shut_member_is_recognised(self):
        self.assertEqual(core_engine.parse_shutdown_interfaces(CONFIG),
                         {"Ethernet0/0"})

    def test_an_interface_without_shutdown_is_not_included(self):
        shut = core_engine.parse_shutdown_interfaces(CONFIG)
        self.assertNotIn("Ethernet0/2", shut)
        self.assertNotIn("Ethernet0/3", shut)

    def test_the_word_shutdown_elsewhere_is_not_a_shut_interface(self):
        # 'no shutdown' e le descrizioni non devono spegnere nulla.
        config = ("interface Ethernet0/1\n"
                  " description da non shutdown mai\n"
                  " no shutdown\n")
        self.assertEqual(core_engine.parse_shutdown_interfaces(config), set())


class TestReport(unittest.TestCase):

    def setUp(self):
        self.backup_dir = tempfile.mkdtemp(prefix="po_backup_")
        cisco = os.path.join(self.backup_dir, "test_cml", "cisco")
        os.makedirs(cisco)
        for name in ("SW2-192.168.31.7.txt", "SW2-172.20.31.5.txt"):
            with open(os.path.join(cisco, name), "w", encoding="utf-8") as f:
                f.write(CONFIG)

    def _report(self, devices):
        with patch.object(core_engine, "BACKUP_FOLDER", self.backup_dir), \
             patch.object(core_engine, "get_all_devices", return_value=devices):
            return core_engine.get_portchannel_report()

    def test_shut_members_are_reported_apart(self):
        report = self._report([{"IP": "192.168.31.7", "Group": "test_cml"}])
        po = report[0]["portchannels"][0]
        self.assertEqual(po["members"], ["Ethernet0/0", "Ethernet0/2"])
        self.assertEqual(po["shut_members"], ["Ethernet0/0"])

    def test_a_backup_of_a_device_no_longer_in_inventory_is_dropped(self):
        """Il doppione fantasma: lo stesso switch compariva due volte, a un IP
        vecchio e con dati di settimane prima, sotto il tenant 'Generale' —
        quindi nemmeno nascondibile con il filtro per tenant."""
        report = self._report([{"IP": "192.168.31.7", "Group": "test_cml"}])
        self.assertEqual([r["ip"] for r in report], ["192.168.31.7"])

    def test_both_are_kept_when_both_are_in_inventory(self):
        # Il filtro guarda l'inventario, non indovina quale IP sia "vecchio".
        report = self._report([{"IP": "192.168.31.7", "Group": "test_cml"},
                               {"IP": "172.20.31.5", "Group": "test_cml"}])
        self.assertEqual(sorted(r["ip"] for r in report),
                         ["172.20.31.5", "192.168.31.7"])

    def test_the_backup_age_is_exposed(self):
        report = self._report([{"IP": "192.168.31.7", "Group": "test_cml"}])
        self.assertIsInstance(report[0]["backup_ts"], int)


if __name__ == "__main__":
    unittest.main()
