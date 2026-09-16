# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Windows health poller: parsing, host selection, and DEVICE_LOAD_001 firing
on a Windows snapshot through the same pipeline as Linux."""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_winpoll_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import correlator, normalize  # noqa: E402
from observability.ingesters import linux_poller, windows_poller  # noqa: E402

NOW = int(time.time())
DEVICE = "192.0.2.20"

# PROBE_COMMAND output captured on a real Windows 11 host through cmd.exe
# (loads | memory KB total | free KB | system drive bytes | free bytes).
CAPTURED = "LOAD|55|33085724|7736412|510915506176|177062785024\n"


class TestParsing(unittest.TestCase):

    def test_captured_line(self):
        self.assertEqual(windows_poller.parse_health(CAPTURED),
                         {"cpu_pct": 55.0, "memory_pct": 76.6, "disk_pct": 65.3})

    def test_cpu_is_the_average_across_sockets(self):
        out = windows_poller.parse_health("LOAD|40,60|100|50|100|25")
        self.assertEqual(out["cpu_pct"], 50.0)

    def test_a_missing_field_is_absent_not_zero(self):
        # LoadPercentage comes back empty on some hypervisors.
        out = windows_poller.parse_health("LOAD||100|50||")
        self.assertEqual(out, {"memory_pct": 50.0})

    def test_banner_and_garbage_do_not_raise(self):
        self.assertEqual(windows_poller.parse_health(""), {})
        self.assertEqual(windows_poller.parse_health("'powershell' non e' riconosciuto"), {})
        self.assertEqual(
            windows_poller.parse_health("Microsoft Windows\r\n" + CAPTURED + "C:\\>"),
            {"cpu_pct": 55.0, "memory_pct": 76.6, "disk_pct": 65.3})

    def test_command_has_no_nested_double_quote(self):
        # ps() wraps the script in double quotes; one inside would break it.
        script = windows_poller.PROBE_COMMAND.split('"', 1)[1].rstrip('"')
        self.assertNotIn('"', script)


class TestSelection(unittest.TestCase):

    def test_windows_hosts_ride_the_linux_loop(self):
        rows = [
            {"IP": "192.0.2.10", "Vendor": "linux"},
            {"IP": "192.0.2.20", "Vendor": "windows"},
            {"IP": "192.0.2.30", "Vendor": "cisco"},
        ]
        with patch("services.inventory_manager.get_all_devices", return_value=rows):
            selected = linux_poller._linux_devices()
        self.assertEqual([d["ip"] for d in selected], ["192.0.2.10", "192.0.2.20"])

    def test_windows_device_dispatches_to_windows_poller(self):
        with patch.object(windows_poller, "poll_device", return_value=["x"]) as poll:
            out = linux_poller._poll_device({"IP": DEVICE, "Vendor": "windows"})
        self.assertEqual(out, ["x"])
        poll.assert_called_once()


class TestSnapshotReachesTheEngine(unittest.TestCase):

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

    def _observe(self, ts, metrics):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO api_observations (ts, tenant, device_ip, kind, summary_json) "
            "VALUES (?, 'sede-a', ?, 'windows_health', ?)",
            (ts, DEVICE, json.dumps({"results": {}, "metrics": metrics})))
        conn.commit()
        conn.close()

    def _rows(self, sql):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql)]
        finally:
            conn.close()

    def test_provenance_says_windows(self):
        self._observe(NOW - 60, windows_poller.parse_health(CAPTURED))
        normalize.normalize_once(NOW)
        ev = self._rows("SELECT * FROM events WHERE event_type = 'device.state'")[0]
        self.assertEqual(ev["source"], "windows")

    def test_disk_over_threshold_fires_device_load(self):
        self._observe(NOW - 60, windows_poller.parse_health(
            "LOAD|10|100|50|1000|50"))
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        rows = self._rows("SELECT * FROM evidence WHERE rule_id = 'DEVICE_LOAD_001'")
        metrics = [json.loads(r["attrs_json"])["metric"] for r in rows]
        self.assertIn("disk_pct", metrics)
        self.assertEqual(rows[metrics.index("disk_pct")]["entity_key"], f"ip:{DEVICE}")


if __name__ == "__main__":
    unittest.main()
