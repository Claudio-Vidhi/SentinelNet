# -*- coding: utf-8 -*-
"""Poller di salute Linux: parsing, selezione degli host, e la pipeline intera.

Il punto non è leggere ``/proc``: è che uno snapshot Linux entri nella STESSA
pipeline degli snapshot REST e SNMP. Se ci riesce, regole, evidenze e incidenti
funzionano senza sapere da dove arriva la misura.
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_linuxpoll_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import correlator, normalize  # noqa: E402
from observability.ingesters import linux_poller  # noqa: E402

NOW = int(time.time())
DEVICE = "192.0.2.10"

# Output di PROBE_COMMAND su un host che al secondo campione ha consumato
# 800 jiffies su 1000, di cui 200 inattivi -> 80% di CPU.
PROBE_OUTPUT = """\
--- CPU ---
cpu  1000 0 500 8000 500 0 0 0 0 0
cpu  1600 0 700 8100 600 0 0 0 0 0
--- MEM ---
               total        used        free      shared  buff/cache   available
Mem:      8000000000  5000000000   500000000    10000000  2500000000  2000000000
Swap:     2000000000           0  2000000000
--- DISK ---
Filesystem     1024-blocks     Used Available Capacity Mounted on
/dev/sda1         51475068 44268516   4560428      92% /
--- UPTIME ---
987654.32 3812345.67
--- KERNEL ---
6.8.0-59-generic
--- FAILED ---
  nginx.service loaded failed failed A high performance web server
  cron.service  loaded failed failed Regular background program processing daemon
"""


class TestParsing(unittest.TestCase):

    def test_cpu_is_a_delta_between_the_two_samples(self):
        # Un solo campione darebbe la media dall'accensione, non il carico ora.
        self.assertEqual(linux_poller._cpu_pct(PROBE_OUTPUT), 80.0)

    def test_cpu_needs_two_samples(self):
        single = '--- CPU ---\ncpu  1000 0 500 8000 500 0 0 0\n--- MEM ---\n'
        self.assertIsNone(linux_poller._cpu_pct(single))

    def test_memory_uses_available_not_used(self):
        # buff/cache è memoria riutilizzabile: contarla come occupata farebbe
        # sembrare saturo qualunque host che abbia letto un file grosso.
        self.assertEqual(linux_poller._memory_pct(PROBE_OUTPUT), 75.0)

    def test_disk_percentage_of_the_root_filesystem(self):
        self.assertEqual(linux_poller._disk_pct(PROBE_OUTPUT), 92)

    def test_state_and_measures_are_separated(self):
        results, metrics = linux_poller.parse_health(PROBE_OUTPUT)
        self.assertEqual(results["kernel"], "6.8.0-59-generic")
        self.assertEqual(results["uptime_s"], 987654)
        self.assertEqual(results["failed_units"], 2)
        self.assertEqual(metrics, {"cpu_pct": 80.0, "memory_pct": 75.0,
                                   "disk_pct": 92})

    def test_a_missing_section_is_omitted_not_invented(self):
        results, metrics = linux_poller.parse_health("--- KERNEL ---\n6.1.0\n")
        self.assertEqual(results, {"failed_units": 0, "kernel": "6.1.0"})
        self.assertEqual(metrics, {})

    def test_garbage_does_not_raise(self):
        self.assertEqual(linux_poller.parse_health(""), ({"failed_units": 0}, {}))
        self.assertEqual(linux_poller.parse_health("bash: no"),
                         ({"failed_units": 0}, {}))


class TestDeviceSelection(unittest.TestCase):

    def test_only_linux_hosts_are_polled(self):
        rows = [
            {"IP": "192.0.2.10", "Group": "sede-a", "Vendor": "linux"},
            {"IP": "192.0.2.11", "Group": "sede-a", "Vendor": "Ubuntu"},
            {"IP": "192.0.2.12", "Group": "sede-a", "Vendor": "cisco"},
            {"IP": "192.0.2.13", "Vendor": "fortinet"},
        ]
        with patch("services.inventory_manager.get_all_devices",
                   return_value=rows):
            selected = linux_poller._linux_devices()
        self.assertEqual([d["ip"] for d in selected],
                         ["192.0.2.10", "192.0.2.11"])
        self.assertEqual(selected[0]["tenant"], "sede-a")


class TestSnapshotsReachTheEngine(unittest.TestCase):
    """La prova che conta: uno snapshot Linux percorre tutta la pipeline."""

    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()

    def setUp(self):
        conn = db.get_observability_connection()
        for table in ("events", "normalize_cursors", "evidence", "incidents",
                      "incident_conclusions", "api_observations"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def _observe(self, ts, output):
        results, metrics = linux_poller.parse_health(output)
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO api_observations (ts, tenant, device_ip, kind, summary_json) "
            "VALUES (?, 'sede-a', ?, 'linux_health', ?)",
            (ts, DEVICE, json.dumps({"results": results, "metrics": metrics})))
        conn.commit()
        conn.close()

    def _rows(self, sql, params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params)]
        finally:
            conn.close()

    def _correlate(self):
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            return correlator.correlate_once(NOW)

    def test_measures_land_in_the_event_and_provenance_says_linux(self):
        self._observe(NOW - 60, PROBE_OUTPUT)
        normalize.normalize_once(NOW)
        ev = self._rows("SELECT * FROM events WHERE event_type = 'device.state'")[0]
        self.assertEqual(ev["source"], "linux")
        self.assertEqual(json.loads(ev["metrics_json"]),
                         {"cpu_pct": 80.0, "memory_pct": 75.0, "disk_pct": 92})

    def test_uptime_does_not_invent_a_change_every_poll(self):
        # uptime cresce a ogni giro per costruzione: se entrasse nel confronto,
        # ogni host avrebbe un "cambiamento" a ogni intervallo.
        self._observe(NOW - 300, PROBE_OUTPUT)
        self._observe(NOW - 60, PROBE_OUTPUT.replace("987654.32", "987954.32"))
        normalize.normalize_once(NOW)
        self.assertEqual(
            self._rows("SELECT * FROM events WHERE event_type = 'device.change'"),
            [])

    def test_a_new_failed_unit_is_a_real_change(self):
        self._observe(NOW - 300, PROBE_OUTPUT.replace(
            "  cron.service  loaded failed failed Regular background program processing daemon\n", ""))
        self._observe(NOW - 60, PROBE_OUTPUT)
        normalize.normalize_once(NOW)
        changes = self._rows(
            "SELECT * FROM events WHERE event_type = 'device.change'")
        self.assertEqual(len(changes), 1)
        self.assertEqual(json.loads(changes[0]["attrs_json"])["field"],
                         "results.failed_units")

    def test_disk_over_threshold_is_a_symptom(self):
        self._observe(NOW - 60, PROBE_OUTPUT)
        self._correlate()
        rows = self._rows("SELECT * FROM evidence WHERE rule_id = 'DEVICE_LOAD_001' "
                          "ORDER BY id")
        metrics = [json.loads(r["attrs_json"])["metric"] for r in rows]
        self.assertIn("disk_pct", metrics)
        disk = rows[metrics.index("disk_pct")]
        self.assertEqual(disk["role"], "symptom")
        self.assertIn("Disco al 92%", disk["summary"])
        self.assertEqual(disk["entity_key"], f"ip:{DEVICE}")

    def test_disk_below_threshold_says_nothing(self):
        self._observe(NOW - 60, PROBE_OUTPUT.replace("92%", "42%"))
        self._correlate()
        self.assertEqual(
            self._rows("SELECT * FROM evidence WHERE rule_id = 'DEVICE_LOAD_001'"),
            [])


if __name__ == "__main__":
    unittest.main()
