# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Firewall Hygiene & Rule Delta Tracker tests (unit + API + tenant isolation)."""

import json
import os
import tempfile
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app_server
from core import db
from security import user_manager
from services import firewall_traffic

PASS = "PasswordSicura1!"

FGT_DEV = {"IP": "192.0.2.40", "Hostname": "fw-dmz-01", "Vendor": "fortinet", "Group": "tenant-a"}
FGT_OTHER = {"IP": "198.51.100.40", "Hostname": "fw-other", "Vendor": "fortinet", "Group": "tenant-b"}
PA_DEV = {"IP": "203.0.113.10", "Hostname": "fw-pa-01", "Vendor": "paloalto", "Group": "tenant-a"}

FORTI_CFG = """config firewall address
    edit "OT-NET"
        set subnet 192.0.2.0 255.255.255.0
    next
    edit "DEAD-NET"
        set subnet 10.99.0.0 255.255.255.0
    next
    edit "UNUSED-OBJ"
        set subnet 198.51.100.88 255.255.255.255
    next
end
config firewall service custom
    edit "MODBUS"
        set tcp-portrange 502
    next
    edit "UNUSED-SVC"
        set tcp-portrange 2323
    next
end
config firewall policy
    edit 10
        set name "Broad-Any"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
    edit 99
        set name "Dead-Rule"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "DEAD-NET"
        set dstaddr "OT-NET"
        set action accept
        set service "MODBUS"
    next
end
"""


class TestFirewallHygieneUnit(unittest.TestCase):
    def setUp(self):
        db.migrate()

    def test_unused_objects_extraction_across_vendors(self):
        fgt_unused = firewall_traffic.extract_unused_objects(FORTI_CFG, "fortios")
        self.assertEqual({u["name"] for u in fgt_unused}, {"UNUSED-OBJ", "UNUSED-SVC"})
        self.assertIn("delete", fgt_unused[0]["cli_dry_run"])
        self.assertIn("edit", fgt_unused[0]["cli_rollback"])

        pan_cfg = (
            "set address USED ip-netmask 10.0.0.0/24\n"
            "set address GHOST-ADDR ip-netmask 198.51.100.9/32\n"
            "set rulebase security rules R1 source USED\n"
        )
        pan_unused = firewall_traffic.extract_unused_objects(pan_cfg, "panos")
        self.assertEqual([u["name"] for u in pan_unused], ["GHOST-ADDR"])

        junos_cfg = (
            "set security address-book global address USED 10.0.0.0/24\n"
            "set security address-book global address ORPHAN 198.51.100.12/32\n"
            "set security policies from-zone u to-zone t policy P1 match source-address USED\n"
        )
        junos_unused = firewall_traffic.extract_unused_objects(junos_cfg, "junos")
        self.assertEqual([u["name"] for u in junos_unused], ["ORPHAN"])

        ios_cfg = (
            "object-group network USED-GRP\n host 10.0.0.1\n!\n"
            "object-group network ORPHAN-GRP\n host 198.51.100.15\n!\n"
            "ip access-list extended ACL-1\n permit ip object-group USED-GRP any\n!\n"
            "interface Vlan10\n ip access-group ACL-1 in\n"
        )
        ios_unused = firewall_traffic.extract_unused_objects(ios_cfg, "ios")
        self.assertEqual([u["name"] for u in ios_unused], ["ORPHAN-GRP"])

    def test_snapshots_deltas_and_counter_reset_handling(self):
        now = int(time.time())
        dev_ip = "192.0.2.244"
        dev_obj = {"IP": dev_ip, "Group": "tenant-a"}
        firewall_traffic.record_policy_snapshots(dev_obj, [
            {"policyid": 1, "name": "R1", "hit_count": 100, "bytes": 1000},
            {"policyid": 2, "name": "Dead", "hit_count": 50, "bytes": 500},
            {"policyid": 3, "name": "ResetRule", "hit_count": 900, "bytes": 9000},
        ], ts=now - 30 * 86400)
        firewall_traffic.record_policy_snapshots(dev_obj, [
            {"policyid": 1, "name": "R1", "hit_count": 200, "bytes": 2000},
            {"policyid": 2, "name": "Dead", "hit_count": 50, "bytes": 500},
            {"policyid": 3, "name": "ResetRule", "hit_count": 900, "bytes": 9000},
        ], ts=now - 7 * 86400)

        current_rows = [
            {"policyid": 1, "name": "R1", "hit_count": 250, "bytes": 2500},
            {"policyid": 2, "name": "Dead", "hit_count": 50, "bytes": 500},
            # Counter reset (lower than baseline 900): delta equals current value (12)
            {"policyid": 3, "name": "ResetRule", "hit_count": 12, "bytes": 120},
        ]
        enriched = firewall_traffic.compute_policy_deltas(dev_ip, "tenant-a", current_rows, now_ts=now)
        by_id = {r["policyid"]: r for r in enriched}
        self.assertEqual(by_id[1]["delta_hits_7d"], 50)
        self.assertEqual(by_id[1]["delta_hits_30d"], 150)
        self.assertEqual(by_id[2]["delta_hits_30d"], 0)
        self.assertEqual(by_id[3]["delta_hits_30d"], 12)

    def test_snapshot_history_is_keyed_by_tenant(self):
        # Two customers, same private firewall IP: counters must not mix.
        now = int(time.time())
        dev_ip = "192.0.2.245"
        firewall_traffic.record_policy_snapshots({"IP": dev_ip, "Group": "tenant-a"}, [
            {"policyid": 1, "name": "R1", "hit_count": 100, "bytes": 1000},
        ], ts=now - 8 * 86400)
        firewall_traffic.record_policy_snapshots({"IP": dev_ip, "Group": "tenant-b"}, [
            {"policyid": 1, "name": "R1", "hit_count": 5, "bytes": 50},
        ], ts=now - 8 * 86400)
        rows = [{"policyid": 1, "name": "R1", "hit_count": 160, "bytes": 1600}]
        a = firewall_traffic.compute_policy_deltas(dev_ip, "tenant-a", rows, now_ts=now)
        self.assertEqual(a[0]["delta_hits_7d"], 60)
        self.assertEqual({h["tenant"] for h in firewall_traffic.get_policy_snapshot_history(dev_ip, "tenant-b")},
                         {"tenant-b"})
        c = firewall_traffic.compute_policy_deltas(dev_ip, "tenant-c", rows, now_ts=now)
        self.assertIsNone(c[0]["delta_hits_7d"])

    def test_snapshots_pruned_after_history_window(self):
        from observability import rollup
        dev = {"IP": "192.0.2.246", "Group": "tenant-a"}
        now = int(time.time())
        days = firewall_traffic.SNAPSHOT_HISTORY_DAYS
        firewall_traffic.record_policy_snapshots(dev, [{"policyid": 1, "hit_count": 1}],
                                                 ts=now - (days + 1) * 86400)
        firewall_traffic.record_policy_snapshots(dev, [{"policyid": 1, "hit_count": 2}], ts=now - 86400)
        rollup.prune_once({"policy_hit_snapshots": days})
        hist = firewall_traffic.get_policy_snapshot_history(dev["IP"], "tenant-a")
        self.assertEqual([h["hit_count"] for h in hist], [2])

    def test_analyze_hygiene_dead_unused_and_tightening(self):
        now = int(time.time())
        firewall_traffic.record_policy_snapshots(FGT_DEV, [
            {"policyid": "10", "name": "Broad-Any", "hit_count": 10, "bytes": 1000},
            {"policyid": "99", "name": "Dead-Rule", "hit_count": 0, "bytes": 0},
        ], ts=now - 31 * 86400)
        firewall_traffic.record_policy_snapshots(FGT_DEV, [
            {"policyid": "10", "name": "Broad-Any", "hit_count": 25, "bytes": 2500},
            {"policyid": "99", "name": "Dead-Rule", "hit_count": 0, "bytes": 0},
        ], ts=now - 60)

        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = os.path.join(tmp, "fw-dmz-01.cfg")
            with open(cfg_path, "w", encoding="utf-8") as fh:
                fh.write(FORTI_CFG)
            conn = db.get_observability_connection()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO events "
                    "(ts, ingested_ts, tenant, source, event_type, entity_type, entity_id, severity, "
                    "device_ip, interface, src_ip, dst_ip, dst_port, protocol, attrs_json, dedup_key) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (now - 100, now, "tenant-a", "syslog", "flow", "flow", "10.20.0.5>192.0.2.10", 6,
                     FGT_DEV["IP"], "", "10.20.0.5", "192.0.2.10", 502, "tcp", "{}", "hyg-test-flow"),
                )
                conn.commit()
            finally:
                conn.close()

            with mock.patch("ai.config_analyzer._find_freshest_backup", return_value=(cfg_path, "tenant-a")):
                res = firewall_traffic.analyze_hygiene([FGT_DEV], window_days=30, now_ts=now)

        self.assertEqual([d["policyid"] for d in res["dead_policies"]], ["99"])
        self.assertEqual({u["name"] for u in res["unused_objects"]}, {"UNUSED-OBJ", "UNUSED-SVC"})
        self.assertEqual([t["policyid"] for t in res["tightenable_rules"]], ["10"])
        self.assertEqual(res["tightenable_rules"][0]["suggested_src"], ["10.20.0.5/32"])
        self.assertEqual(res["tightenable_rules"][0]["suggested_services"], ["MODBUS-TCP"])

    def test_window_days_is_the_second_positional_argument(self):
        # The router calls analyze_hygiene(scoped, days) through to_thread.
        with mock.patch("ai.config_analyzer._find_freshest_backup", return_value=(None, None)):
            res = firewall_traffic.analyze_hygiene([FGT_DEV], 7)
        self.assertEqual(res["window_days"], 7)


class TestFirewallHygieneApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for u, role, grps in (("adm_hyg", "admin", None), ("op_hyg", "operator", ["tenant-a"])):
            try:
                user_manager.create_user(u, PASS, role=role, groups=grps)
            except Exception:
                pass

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200
        return c

    def test_hygiene_api_respects_tenant_scope_and_snapshot_post(self):
        with mock.patch("services.inventory_manager.get_all_devices", return_value=[FGT_DEV, FGT_OTHER, PA_DEV]), \
             mock.patch("ai.config_analyzer._find_freshest_backup", return_value=(None, None)):
            r = self._client("op_hyg").get("/api/firewall-traffic/hygiene")
            self.assertEqual(r.status_code, 200, r.text)
            body = r.json()
            ips = {d["ip"] for d in body["eligible_devices"]}
            self.assertEqual(ips, {FGT_DEV["IP"], PA_DEV["IP"]})

            # Snapshot endpoint targets FGT_DEV + PA_DEV in tenant-a (excludes tenant-b) and runs live collect_for for FortiGate
            with mock.patch.object(firewall_traffic, "collect_for",
                                   return_value={"rows": [{"policyid": 1, "name": "P1", "hit_count": 7, "bytes": 70}]}) as m_collect:
                snap_res = self._client("op_hyg").post(
                    "/api/firewall-traffic/snapshot",
                    json={"device": ""},
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )
            self.assertEqual(snap_res.status_code, 200, snap_res.text)
            self.assertEqual(snap_res.json()["devices_snapshotted"], 2)
            self.assertEqual(snap_res.json()["snapshots_saved"], 1)
            called_ips = {call.args[0]["IP"] for call in m_collect.call_args_list}
            self.assertEqual(called_ips, {FGT_DEV["IP"]})


if __name__ == "__main__":
    unittest.main()
