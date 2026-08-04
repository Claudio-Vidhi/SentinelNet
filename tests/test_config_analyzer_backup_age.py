# -*- coding: utf-8 -*-
"""Il Config Analyzer dichiara l'eta' del dato che sta mostrando.

Mostra config PARSATA DA UN BACKUP, non dall'apparato: senza il timestamp una
scheda di due settimane fa e una di tre minuti fa si leggono identiche. E' anche
cio' che rende il bottone di triage una decisione invece di un rituale.
"""

import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_caage_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from ai import config_analyzer  # noqa: E402
from core import core_engine  # noqa: E402

IOS_BACKUP = """\
hostname switch-01
!
interface Vlan10
 ip address 192.0.2.10 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 192.0.2.1
"""


class TestBackupAgeExposed(unittest.TestCase):

    def setUp(self):
        self.ip = "192.0.2.10"
        folder = os.path.join(core_engine.BACKUP_FOLDER, "tenant-a")
        os.makedirs(folder, exist_ok=True)
        self.path = os.path.join(folder, f"switch-01-{self.ip}.txt")
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(IOS_BACKUP)

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_the_analysis_carries_the_backup_timestamp(self):
        result = config_analyzer.analyze_device(self.ip)
        self.assertIsNotNone(result)
        self.assertIsInstance(result["backup_ts"], int)
        # Stesso nome di campo del report Port-Channel: e' lo stesso fatto.
        self.assertAlmostEqual(result["backup_ts"], int(time.time()), delta=120)

    def test_the_timestamp_follows_the_file_not_the_request(self):
        # Un backup vecchio deve dichiararsi vecchio: se il campo raccontasse
        # "adesso" a ogni apertura della scheda, non direbbe niente.
        old = time.time() - 9 * 24 * 3600
        os.utime(self.path, (old, old))
        result = config_analyzer.analyze_device(self.ip)
        self.assertAlmostEqual(result["backup_ts"], int(old), delta=2)

    def test_no_backup_no_analysis(self):
        self.assertIsNone(config_analyzer.analyze_device("198.51.100.99"))


class TestAnalyzeDeviceCache(unittest.TestCase):
    """Ogni salto della catena dei trunk rilegge e ri-parsa un file. Il memo
    serve alla derivazione del gateway, che scansiona un tenant intero, e
    intanto ripaga il percorso che gia' esiste."""

    def setUp(self):
        config_analyzer._analyze_device_at.cache_clear()

    def test_second_call_does_not_reparse(self):
        calls = []

        def _fake(ip):
            calls.append(ip)
            return {"ip": ip, "vlans": []}

        with patch.object(config_analyzer, "analyze_device", _fake), \
             patch.object(config_analyzer, "_backup_mtime", lambda ip: 111):
            config_analyzer.analyze_device_cached("192.0.2.20")
            config_analyzer.analyze_device_cached("192.0.2.20")
        self.assertEqual(len(calls), 1)

    def test_a_newer_backup_invalidates(self):
        calls = []

        def _fake(ip):
            calls.append(ip)
            return {"ip": ip, "vlans": []}

        mtime = {"v": 111}
        with patch.object(config_analyzer, "analyze_device", _fake), \
             patch.object(config_analyzer, "_backup_mtime", lambda ip: mtime["v"]):
            config_analyzer.analyze_device_cached("192.0.2.20")
            mtime["v"] = 222
            config_analyzer.analyze_device_cached("192.0.2.20")
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
