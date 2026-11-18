# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for ring/redundancy monitoring (MRP, DLR, PRP/HSR, RSTP) and immediate alarms."""

import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import patch

_TMP = tempfile.mkdtemp(prefix="sentinelnet_ring_test_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from core import data_config, db  # noqa: E402
data_config.DATA_DIR = _TMP

from observability import fieldmap, normalize  # noqa: E402
from observability.ingesters import ring_monitor, snmp_poller, syslog, udp_server  # noqa: E402
from services import inventory_manager  # noqa: E402


class TestRingSnmpEvaluation(unittest.TestCase):
    def setUp(self):
        ring_monitor.clear_state_cache()

    def test_evaluate_mrp_dlr_prp_and_rstp(self):
        results, metrics = ring_monitor.evaluate_ring_snmp({
            "mrp": {
                "domain_name": {"1": "PlantRing1"},
                "admin_role": {"1": 3},
                "oper_role": {"1": 3},
                "state": {"1": 3},  # ringOpen
                "ring_open_count": {"1": 4},
            },
            "dlr": {
                "state": {"1": 4},  # partialFault -> redundancy_lost
                "node_state": {"1": 2},  # active_supervisor
                "supervisor": {"1": "192.0.2.10"},
                "faults": {"1": 2},
            },
            "prp_hsr": {
                "dup_mode": {"1": 2},
                "link_a": {"1": 1},  # up
                "link_b": {"1": 2},  # down -> redundancy_lost
                "err_wrong_lan_a": {"1": 0},
            },
            "rstp": {
                "designated_root": "8000001122334455",
                "top_changes": 7,
                "port_states": {"1": 5, "2": 6},  # 6 -> broken
            },
        })

        self.assertEqual(results["mrp"]["1"]["state"], "ring_open")
        self.assertEqual(results["mrp"]["1"]["oper_role"], "manager")
        self.assertEqual(metrics["mrp.1.ring_open_count"], 4)

        self.assertEqual(results["dlr"]["1"]["state"], "redundancy_lost")
        self.assertEqual(results["dlr"]["1"]["node_state"], "active_supervisor")
        self.assertEqual(metrics["dlr.1.faults"], 2)

        self.assertEqual(results["prp_hsr"]["1"]["state"], "redundancy_lost")
        self.assertEqual(results["prp_hsr"]["1"]["link_b"], "down")

        self.assertEqual(results["rstp"]["0"]["state"], "redundancy_lost")
        self.assertEqual(results["rstp"]["0"]["broken_ports"], ["2"])
        self.assertEqual(metrics["rstp.0.top_changes"], 7)

    def test_diff_ring_states_detects_open_redundancy_loss_and_manager_change(self):
        prev = {
            "mrp": {"1": {"domain": "Ring1", "state": "ring_closed", "oper_role": "client"}},
            "dlr": {"1": {"state": "ring_closed", "node_state": "ring_node", "supervisor": "192.0.2.10"}},
            "prp_hsr": {"1": {"mode": "prp", "state": "redundant", "link_a": "up", "link_b": "up"}},
            "rstp": {"0": {"state": "normal", "designated_root": "8000001122334455"}},
        }
        curr = {
            "mrp": {"1": {"domain": "Ring1", "state": "ring_open", "oper_role": "manager"}},
            "dlr": {"1": {"state": "ring_open", "node_state": "active_supervisor", "supervisor": "192.0.2.11"}},
            "prp_hsr": {"1": {"mode": "prp", "state": "redundancy_lost", "link_a": "up", "link_b": "down"}},
            "rstp": {"0": {"state": "normal", "designated_root": "800000AABBCCDDEE"}},
        }
        alerts = ring_monitor.diff_ring_states(
            prev, curr,
            prev_metrics={"rstp.0.top_changes": 1},
            curr_metrics={"rstp.0.top_changes": 2},
        )
        pairs = {(a["protocol"], a["condition"]) for a in alerts}
        self.assertIn(("mrp", "ring_open"), pairs)
        self.assertIn(("dlr", "ring_open"), pairs)
        self.assertIn(("dlr", "ring_manager_changed"), pairs)
        self.assertIn(("prp_hsr", "redundancy_lost"), pairs)
        self.assertIn(("rstp", "ring_manager_changed"), pairs)

    def test_process_snmp_ring_emits_immediate_notification_on_transition(self):
        with patch("services.notifications.emit", return_value=1) as mock_emit:
            ring_monitor.process_snmp_ring(
                "192.0.2.20",
                "OT_Plant",
                {"mrp": {"1": {"domain": "R1", "state": "ring_closed", "oper_role": "client"}}},
                {},
                ts=1000,
            )
            mock_emit.assert_not_called()

            alerts = ring_monitor.process_snmp_ring(
                "192.0.2.20",
                "OT_Plant",
                {"mrp": {"1": {"domain": "R1", "state": "ring_open", "oper_role": "client"}}},
                {},
                ts=1060,
            )
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["condition"], "ring_open")
            self.assertEqual(alerts[0]["severity"], "critical")
            mock_emit.assert_called_once()
            kwargs = mock_emit.call_args.kwargs
            self.assertEqual(kwargs["device_ip"], "192.0.2.20")
            self.assertEqual(kwargs["tenant"], "OT_Plant")
            self.assertEqual(kwargs["severity"], "critical")
            self.assertIn("ring:192.0.2.20:mrp:1:ring_open", kwargs["dedup_key"])

    def test_snmp_poller_poll_once_processes_snmp_ring(self):
        devices = [{"ip": "192.0.2.21", "tenant": "OT_Plant", "community": "public"}]
        ring_snap = json.dumps({
            "results": {"dlr": {"1": {"state": "ring_open", "node_state": "active_supervisor"}}},
            "metrics": {"dlr.1.faults": 1},
        })
        with patch("observability.ingesters.snmp_poller._snmp_devices", return_value=devices), \
             patch("observability.ingesters.snmp_poller._poll_device",
                   return_value=[("snmp_system", '{"results": {}, "metrics": {}}'), ("snmp_ring", ring_snap)]), \
             patch("core.db.enqueue_write") as mock_enq, \
             patch("services.notifications.emit", return_value=1) as mock_emit:
            written = asyncio.run(snmp_poller.poll_once())
            self.assertEqual(written, 2)
            self.assertEqual(mock_enq.call_count, 2)
            mock_emit.assert_called_once()
            self.assertEqual(mock_emit.call_args.kwargs["ctx"]["protocol"], "dlr")
            self.assertEqual(mock_emit.call_args.kwargs["ctx"]["condition"], "ring_open")


class TestRingSyslogTrapAndNormalize(unittest.TestCase):
    def setUp(self):
        ring_monitor.clear_state_cache()
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()
        inventory_manager.invalidate_device_ip_cache()

    def tearDown(self):
        db.stop_writer()

    def test_syslog_ring_rules(self):
        cases = [
            ("<131>Nov 18 10:00:00 switch-01 %MRP-3-RING_OPEN: MRP domain 1 ring is open",
             "mrp", "ring_open", "critical"),
            ("<132>Nov 18 10:00:00 switch-01 MRP ring manager role changed to MRM",
             "mrp", "ring_manager_changed", "high"),
            ("<131>Nov 18 10:00:00 ie-sw01 %DLR-3-RING_FAULT: DLR ring fault detected on ring 1",
             "dlr", "ring_open", "critical"),
            ("<132>Nov 18 10:00:00 ie-sw01 DLR active supervisor changed to 192.0.2.15",
             "dlr", "ring_manager_changed", "high"),
            ("<131>Nov 18 10:00:00 prp-01 PRP LAN B link down - redundancy lost",
             "prp_hsr", "redundancy_lost", "critical"),
            ("<132>Nov 18 10:00:00 sw-01 RSTP root bridge changed on VLAN 10",
             "rstp", "ring_manager_changed", "high"),
        ]
        for raw, proto, cond, sev in cases:
            ev = syslog.parse(raw.encode("utf-8"), "192.0.2.30")[0]
            self.assertIsNotNone(ev["ring_event"], raw)
            self.assertEqual(ev["ring_event"]["protocol"], proto, raw)
            self.assertEqual(ev["ring_event"]["condition"], cond, raw)
            self.assertEqual(ev["ring_event"]["severity"], sev, raw)
            self.assertEqual(fieldmap.extract(raw)["ring_event"]["condition"], cond)

    def test_udp_ingest_emits_immediate_alarm_and_normalizes_event(self):
        devices = [{"IP": "192.0.2.30", "Hostname": "scalance-01", "Vendor": "siemens_scalance", "Group": "PlantA"}]
        msg = b"<131>Nov 18 10:00:00 scalance-01 %MRP-3-RING_OPEN: MRP ring open on domain 1"
        with patch("services.inventory_manager.get_all_devices", return_value=devices), \
             patch("services.notifications.emit", return_value=1) as mock_emit:
            inventory_manager.invalidate_device_ip_cache()
            recs = syslog.parse(msg, "192.0.2.30")
            db.start_writer()
            udp_server._handle_records(recs, 1_700_000_000.0)
            mock_emit.assert_called_once()
            self.assertEqual(mock_emit.call_args.kwargs["tenant"], "PlantA")
            self.assertEqual(mock_emit.call_args.kwargs["severity"], "critical")

        import time
        time.sleep(0.6)
        db.stop_writer()

        # Verify normalize projects ring.alert from both syslog_events and snmp_ring api_observations
        conn = db.get_observability_connection()
        try:
            conn.execute(
                "INSERT INTO api_observations(ts, tenant, device_ip, kind, summary_json) VALUES (?, ?, ?, ?, ?)",
                (1_700_000_000, "PlantA", "192.0.2.31", "snmp_ring",
                 json.dumps({"results": {"dlr": {"1": {"state": "ring_closed"}}}, "metrics": {}})),
            )
            conn.execute(
                "INSERT INTO api_observations(ts, tenant, device_ip, kind, summary_json) VALUES (?, ?, ?, ?, ?)",
                (1_700_000_060, "PlantA", "192.0.2.31", "snmp_ring",
                 json.dumps({"results": {"dlr": {"1": {"state": "ring_open"}}}, "metrics": {}})),
            )
            conn.commit()
        finally:
            conn.close()

        normalize.normalize_once(now=1_700_000_100)

        conn = db.get_observability_connection()
        try:
            ring_rows = conn.execute(
                "SELECT source, device_ip, event_type, severity, attrs_json FROM events WHERE event_type = 'ring.alert' ORDER BY id ASC"
            ).fetchall()
            self.assertEqual(len(ring_rows), 2)
            self.assertEqual(ring_rows[0]["source"], "syslog")
            self.assertEqual(ring_rows[0]["device_ip"], "192.0.2.30")
            self.assertEqual(ring_rows[1]["source"], "snmp")
            self.assertEqual(ring_rows[1]["device_ip"], "192.0.2.31")
            attrs = json.loads(ring_rows[1]["attrs_json"])
            self.assertEqual(attrs["protocol"], "dlr")
            self.assertEqual(attrs["condition"], "ring_open")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
