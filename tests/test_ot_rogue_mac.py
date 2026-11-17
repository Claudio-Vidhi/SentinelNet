# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import os
import tempfile
import unittest
from unittest.mock import patch

from collectors import mac_history
from core import data_config
from services import inventory_manager, notifications, segment_manager


class TestOtRogueMac(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ot_rogue_")
        mac_history._init_done = False
        self._patches = [
            patch.object(data_config, "DATA_DIR", self.tmp),
            patch.object(inventory_manager, "HOSTS_CSV", os.path.join(self.tmp, "network_hosts.csv")),
            patch.object(mac_history, "DB_PATH", os.path.join(self.tmp, "mac_history.db")),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: setattr(mac_history, "_init_done", False))
        self.addCleanup(lambda: [p.stop() for p in reversed(self._patches)])
        inventory_manager.save_groups({"acme": {"description": ""}})

    def test_rogue_mac_emits_only_on_ot_segment_after_baseline(self):
        segment_manager.save_segment(
            "acme", None, "Linea-1", "amber",
            subnets=["198.51.100.0/24"], purdue_level="L1", is_ot=True,
        )
        with patch.object(notifications, "emit") as emit_mock:
            # First scan establishes baseline: no rogue alert
            s1 = mac_history.record_sightings(
                [{"mac": "AA:BB:CC:DD:EE:01", "vlan": "10", "interface": "Gi1/0/1"}],
                switch_ip="198.51.100.10", switch_name="sw-ot-01", tenant="acme",
            )
            self.assertEqual(s1["rogue_macs"], 0)
            emit_mock.assert_not_called()

            # Uplink new MAC does not alert
            s2 = mac_history.record_sightings(
                [{"mac": "AA:BB:CC:DD:EE:02", "vlan": "10", "interface": "Gi1/0/24", "is_uplink": True}],
                switch_ip="198.51.100.10", switch_name="sw-ot-01", tenant="acme",
            )
            self.assertEqual(s2["rogue_macs"], 0)
            emit_mock.assert_not_called()

            # New non-uplink MAC on OT switch emits critical alert
            s3 = mac_history.record_sightings(
                [{"mac": "AA:BB:CC:DD:EE:99", "vlan": "10", "interface": "Gi1/0/5"}],
                switch_ip="198.51.100.10", switch_name="sw-ot-01", tenant="acme",
            )
            self.assertEqual(s3["rogue_macs"], 1)
            emit_mock.assert_called_once()
            kwargs = emit_mock.call_args.kwargs
            self.assertEqual(kwargs["severity"], "critical")
            self.assertEqual(kwargs["tenant"], "acme")
            self.assertTrue(kwargs["ctx"]["ot_rogue_mac"])

    def test_it_segment_never_emits_rogue_mac(self):
        segment_manager.save_segment(
            "acme", None, "Uffici", "sky",
            subnets=["203.0.113.0/24"], purdue_level="L4", is_ot=False,
        )
        with patch.object(notifications, "emit") as emit_mock:
            mac_history.record_sightings(
                [{"mac": "AA:BB:CC:DD:EE:01", "vlan": "20", "interface": "Gi1/0/1"}],
                switch_ip="203.0.113.10", switch_name="sw-it-01", tenant="acme",
            )
            s2 = mac_history.record_sightings(
                [{"mac": "AA:BB:CC:DD:EE:99", "vlan": "20", "interface": "Gi1/0/5"}],
                switch_ip="203.0.113.10", switch_name="sw-it-01", tenant="acme",
            )
            self.assertEqual(s2["rogue_macs"], 0)
            emit_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
