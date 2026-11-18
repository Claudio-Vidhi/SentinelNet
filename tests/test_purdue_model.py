# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for IEC 62443 Purdue Model, Zone/Conduit checks, and Rogue OT MAC detection."""

import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from collectors import mac_history
from core import data_config, db
from observability.ingesters import syslog
from routers import topology as topology_router
from security import security_manager, user_manager
from services import blueprint_checks, inventory_manager, inventory_store, notifications, purdue_model, segment_manager


def _sync_enqueue(sql: str, params: tuple = ()) -> bool:
    conn = db.get_observability_connection()
    conn.execute(sql, params)
    conn.commit()
    return True


class _PurdueBase(unittest.TestCase):
    PW = "PasswordSicura1!"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="purdue_")
        purdue_model._SYSLOG_CTX_CACHE.clear()
        self._patches = [
            patch.object(data_config, "DATA_DIR", self.tmp),
            patch.object(user_manager, "USERS_JSON", os.path.join(self.tmp, "users.json")),
            patch.object(inventory_manager, "HOSTS_CSV", os.path.join(self.tmp, "network_hosts.csv")),
            patch.object(mac_history, "DB_PATH", os.path.join(self.tmp, "mac_history.db")),
            patch.object(mac_history, "_init_done", False),
            patch.object(db, "enqueue_write", side_effect=_sync_enqueue),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._cleanup)
        security_manager._failed_attempts.clear()
        db.migrate()
        inventory_manager.save_groups({"plant": {"description": "Plant OT"}})
        with inventory_manager._db() as conn:
            inventory_store.write_locations(conn, {
                "loc-ot": {
                    "org": "plant",
                    "name": "Linea 1",
                    "role": "branch",
                    "subnets": ["10.10.1.0/24"],
                    "gateway": "",
                    "probe": "central",
                }
            })

    def _cleanup(self):
        purdue_model._SYSLOG_CTX_CACHE.clear()
        for p in reversed(self._patches):
            p.stop()


class TestPurdueInventoryAndSegments(_PurdueBase):
    def test_device_purdue_level_persistence_and_preserve(self):
        inventory_manager.add_or_update_device(
            ip="10.10.1.11",
            vendor="siemens",
            profile="default",
            username="",
            password="",
            enable_secret="",
            group="plant",
            location="loc-ot",
            purdue_level="1",
        )
        dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "10.10.1.11")
        self.assertEqual(dev["Purdue Level"], "L1")

        # Updating other attributes with purdue_level=None preserves L1
        inventory_manager.add_or_update_device(
            ip="10.10.1.11",
            vendor="siemens",
            profile="default",
            username="",
            password="",
            enable_secret="",
            group="plant",
            location="loc-ot",
            purdue_level=None,
        )
        dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "10.10.1.11")
        self.assertEqual(dev["Purdue Level"], "L1")

        # Explicit empty string clears Purdue Level
        inventory_manager.add_or_update_device(
            ip="10.10.1.11",
            vendor="siemens",
            profile="default",
            username="",
            password="",
            enable_secret="",
            group="plant",
            location="loc-ot",
            purdue_level="",
        )
        dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "10.10.1.11")
        self.assertEqual(dev["Purdue Level"], "")

        with self.assertRaises(ValueError):
            inventory_manager.add_or_update_device(
                ip="10.10.1.12",
                vendor="cisco",
                profile="default",
                username="",
                password="",
                enable_secret="",
                group="plant",
                location="loc-ot",
                purdue_level="L9",
            )

    def test_segment_purdue_and_ot_vlans_validation(self):
        v0 = segment_manager.segment_version()
        seg = segment_manager.save_segment(
            "plant", None, "Cella PLC", "amber",
            subnets=["10.10.1.0/24"],
            purdue_level="L1",
            ot_vlans=["100", "20", "100"],
        )
        self.assertEqual(seg["purdue_level"], "L1")
        self.assertEqual(seg["ot_vlans"], ["20", "100"])
        self.assertGreater(segment_manager.segment_version(), v0)

        with self.assertRaises(ValueError):
            segment_manager.save_segment("plant", None, "Bad", "teal", purdue_level="L99")
        with self.assertRaises(ValueError):
            segment_manager.save_segment("plant", None, "BadVlan", "teal", ot_vlans=["5000"])

    def test_inventory_store_migrates_legacy_db_columns(self):
        legacy_path = os.path.join(self.tmp, "legacy.db")
        import sqlite3
        c = sqlite3.connect(legacy_path)
        c.execute("CREATE TABLE hosts (ip TEXT PRIMARY KEY, hostname TEXT DEFAULT '')")
        c.execute("CREATE TABLE decommissioned_hosts (ip TEXT PRIMARY KEY, hostname TEXT DEFAULT '')")
        c.execute("CREATE TABLE segments (id TEXT PRIMARY KEY, org TEXT NOT NULL, name TEXT NOT NULL)")
        c.commit()
        c.close()

        conn = inventory_store.connect(legacy_path)
        try:
            host_cols = {r[1] for r in conn.execute("PRAGMA table_info(hosts)")}
            decom_cols = {r[1] for r in conn.execute("PRAGMA table_info(decommissioned_hosts)")}
            seg_cols = {r[1] for r in conn.execute("PRAGMA table_info(segments)")}
            self.assertIn("Purdue Level", host_cols)
            self.assertIn("Purdue Level", decom_cols)
            self.assertIn("purdue_level", seg_cols)
            self.assertIn("ot_vlans", seg_cols)
        finally:
            conn.close()

    def test_api_device_segments_topology_and_ot_findings(self):
        user_manager.create_user("op", self.PW, role="operator", groups=["plant"])
        client = TestClient(app_server.app, raise_server_exceptions=False)
        r = client.post("/api/auth/login", json={"username": "op", "password": self.PW})
        self.assertEqual(r.status_code, 200, r.text)
        headers = {"Authorization": f"Bearer {r.json()['access_token']}", "X-Requested-With": "1"}

        r_dev = client.post("/api/add-device", headers=headers, json={
            "ip": "10.10.1.20",
            "vendor": "siemens",
            "profile": "default",
            "group": "plant",
            "location": "loc-ot",
            "purdue_level": "L1",
        })
        self.assertEqual(r_dev.status_code, 200, r_dev.text)

        r_seg = client.post("/api/segments", headers=headers, json={
            "org": "plant",
            "name": "Controllo PLC",
            "color": "amber",
            "subnets": ["10.10.1.0/24"],
            "purdue_level": "L1",
            "ot_vlans": ["100", "110"],
        })
        self.assertEqual(r_seg.status_code, 200, r_seg.text)
        self.assertEqual(r_seg.json()["segment"]["purdue_level"], "L1")
        self.assertEqual(r_seg.json()["segment"]["ot_vlans"], ["100", "110"])

        # enrich_map_nodes attaches purdue_level from inventory
        enriched = topology_router.enrich_map_nodes({"nodes": [{"id": "10.10.1.20", "label": "PLC-01"}]})
        self.assertEqual(enriched["nodes"][0]["purdue_level"], "L1")

        # CSV export supports purdue_level column
        r_csv = client.get("/api/export/devices?columns=ip,purdue_level", headers=headers)
        self.assertEqual(r_csv.status_code, 200)
        self.assertIn("10.10.1.20,L1", r_csv.text)

        # OT findings summary endpoint works
        r_ot = client.get("/api/segments/ot-findings?org=plant", headers=headers)
        self.assertEqual(r_ot.status_code, 200, r_ot.text)
        body = r_ot.json()
        self.assertEqual(body["org"], "plant")
        self.assertIn("conduit_violations", body)
        self.assertIn("traffic_violations", body)
        self.assertIn("rogue_ot_devices", body)


class TestPurdueConduitAndBoundaryChecks(_PurdueBase):
    def test_blueprint_checks_detect_dmz_bypass_layer_skip_and_overlap(self):
        devices = [
            {"IP": "10.10.1.10", "Group": "plant", "Purdue Level": "L1"},
            {"IP": "10.10.3.10", "Group": "plant", "Purdue Level": "L3"},
            {"IP": "10.10.35.10", "Group": "plant", "Purdue Level": "L3.5"},
            {"IP": "10.10.4.10", "Group": "plant", "Purdue Level": "L4"},
        ]
        segments = [
            {"id": "s1", "name": "Cella OT", "purdue_level": "L1", "subnets": ["10.10.1.0/24"], "members": [], "excluded": []},
            {"id": "s4", "name": "Enterprise IT", "purdue_level": "L4", "subnets": ["10.10.1.0/25"], "members": [], "excluded": []},
        ]
        links = [
            {"a": "10.10.1.10", "b": "10.10.4.10", "decision": None},   # L1 <-> L4 DMZ bypass
            {"a": "10.10.1.10", "b": "10.10.3.10", "decision": None},   # L1 <-> L3 layer skip
            {"a": "10.10.1.10", "b": "10.10.35.10", "decision": None},  # L1 <-> L3.5 valid
            {"a": "10.10.35.10", "b": "10.10.4.10", "decision": None},  # L3.5 <-> L4 valid
        ]

        findings = purdue_model.check_purdue_blueprint(devices, segments, links)
        codes = [f["code"] for f in findings]
        self.assertIn("purdue_dmz_bypass", codes)
        self.assertIn("purdue_layer_skip", codes)
        self.assertIn("purdue_subnet_overlap", codes)
        self.assertEqual(len(codes), 3)

        # Integrated in blueprint_checks.run()
        bp = {
            "org": "plant",
            "locations": {"loc-ot": {"id": "loc-ot", "name": "Linea 1", "role": "branch", "subnets": ["10.10.1.0/24"], "gateway": ""}},
            "links": {},
        }
        observed = {
            "devices": devices,
            "locations_meta": {},
            "gateways": {},
            "segments": segments,
            "segment_links": links,
        }
        all_findings = blueprint_checks.run(bp, observed)
        self.assertIn("purdue_dmz_bypass", {f["code"] for f in all_findings})

    def test_firewall_policy_violations(self):
        devices = [
            {"IP": "10.10.1.20", "Group": "plant", "Purdue Level": "L1"},
            {"IP": "10.10.4.20", "Group": "plant", "Purdue Level": "L4"},
            {"IP": "10.10.35.20", "Group": "plant", "Purdue Level": "L3.5"},
        ]
        segments = []
        policies = [
            {"policyid": 1, "name": "Direct_IT_OT", "action": "accept", "status": "enable",
             "srcaddr": "10.10.4.20", "dstaddr": "10.10.1.20", "device": "fw-01", "device_ip": "10.10.35.1"},
            {"policyid": 2, "name": "OT_Internet", "action": "accept", "status": "enable",
             "srcaddr": "10.10.1.20", "dstaddr": "all", "device": "fw-01", "device_ip": "10.10.35.1"},
            {"policyid": 3, "name": "Blocked_Direct", "action": "deny", "status": "enable",
             "srcaddr": "10.10.4.20", "dstaddr": "10.10.1.20", "device": "fw-01", "device_ip": "10.10.35.1"},
            {"policyid": 4, "name": "Disabled_Direct", "action": "accept", "status": "disable",
             "srcaddr": "10.10.4.20", "dstaddr": "10.10.1.20", "device": "fw-01", "device_ip": "10.10.35.1"},
            {"policyid": 5, "name": "DMZ_Proxy", "action": "accept", "status": "enable",
             "srcaddr": "10.10.4.20", "dstaddr": "10.10.35.20", "device": "fw-01", "device_ip": "10.10.35.1"},
        ]

        out = purdue_model.check_policy_violations(policies, devices, segments)
        self.assertEqual(len(out), 2)
        self.assertEqual({v["policy_id"]: v["code"] for v in out}, {
            1: "it_ot_dmz_bypass",
            2: "ot_external_communication",
        })

    def test_syslog_parse_and_live_it_ot_violation_emits_alert(self):
        inventory_manager.add_or_update_device(
            ip="10.10.1.50", vendor="siemens", profile="default",
            username="", password="", enable_secret="",
            group="plant", location="loc-ot", purdue_level="L1",
        )
        segment_manager.save_segment(
            "plant", None, "Corporate IT", "sky",
            subnets=["10.40.0.0/24"], purdue_level="L4",
        )

        # Syslog with accepted PLC -> Enterprise L4 triggers critical violation & event
        raw_bad = (
            b'<134>date=2026-11-18 time=10:00:00 devname="fw-01" logid="0000000013" type="traffic" '
            b'srcip=10.10.1.50 dstip=10.40.0.25 dstport=502 proto=6 action="accept"'
        )
        rec_bad = syslog.parse(raw_bad, "10.10.35.1")[0]
        self.assertEqual(rec_bad["src_ip"], "10.10.1.50")
        self.assertEqual(rec_bad["dst_ip"], "10.40.0.25")
        self.assertEqual(rec_bad["action"], "accept")

        emitted = []
        with patch.object(notifications, "emit", side_effect=lambda **kw: emitted.append(kw)):
            v = purdue_model.inspect_syslog_it_ot("10.10.35.1", "plant", rec_bad, action=rec_bad["action"])
            self.assertIsNotNone(v)
            self.assertEqual(v["code"], "it_ot_dmz_bypass")

            # Denied traffic must NOT trigger
            raw_deny = (
                b'<134>date=2026-11-18 time=10:00:01 devname="fw-01" logid="0000000013" type="traffic" '
                b'srcip=10.10.1.50 dstip=203.0.113.10 dstport=443 proto=6 action="deny"'
            )
            rec_deny = syslog.parse(raw_deny, "10.10.35.1")[0]
            self.assertEqual(rec_deny["action"], "deny")
            self.assertIsNone(
                purdue_model.inspect_syslog_it_ot("10.10.35.1", "plant", rec_deny, action=rec_deny["action"])
            )

            # Accepted traffic to external TEST-NET IP triggers ot_external_communication
            raw_ext = (
                b'<134>date=2026-11-18 time=10:00:02 devname="fw-01" logid="0000000013" type="traffic" '
                b'srcip=10.10.1.50 dstip=203.0.113.10 dstport=443 proto=6 action="accept"'
            )
            rec_ext = syslog.parse(raw_ext, "10.10.35.1")[0]
            v_ext = purdue_model.inspect_syslog_it_ot("10.10.35.1", "plant", rec_ext, action=rec_ext["action"])
            self.assertIsNotNone(v_ext)
            self.assertEqual(v_ext["code"], "ot_external_communication")

        self.assertEqual(len(emitted), 2)
        self.assertTrue(all(e["kind"] == "siem.alert" and e["severity"] == "critical" for e in emitted))

        rows = db.get_observability_connection().execute(
            "SELECT event_type, src_ip, dst_ip FROM events WHERE event_type='ot.it_ot_violation' ORDER BY src_ip, dst_ip"
        ).fetchall()
        self.assertEqual(len(rows), 2)


class TestRogueOtDeviceDetection(_PurdueBase):
    def test_rogue_mac_on_ot_vlan_fires_after_baseline_and_ignores_uplinks(self):
        # Register L1 industrial switch in plant
        inventory_manager.add_or_update_device(
            ip="10.10.1.2", vendor="cisco_ie", profile="default",
            username="", password="", enable_secret="",
            group="plant", location="loc-ot", purdue_level="L1",
        )
        # Mark switch's own MAC as infrastructure
        mac_history.record_switch_if_macs(
            [{"interface": "GigabitEthernet1/1", "mac": "02:00:00:00:00:01"}],
            switch_ip="10.10.1.2", switch_name="ie-sw-01",
        )

        emitted = []
        with patch.object(notifications, "emit", side_effect=lambda **kw: emitted.append(kw)):
            # Scan 1: establish baseline on VLAN 100 — zero rogue alerts
            mac_history.record_sightings(
                [{"mac": "02:00:00:00:00:10", "vlan": "100", "interface": "FastEthernet1/1", "is_uplink": False}],
                switch_ip="10.10.1.2", switch_name="ie-sw-01", tenant="plant",
            )
            self.assertEqual(emitted, [])

            # Scan 2: repeat baseline MAC, add uplink MAC, add switch interface MAC, and inject 1 rogue MAC
            mac_history.record_sightings(
                [
                    {"mac": "02:00:00:00:00:10", "vlan": "100", "interface": "FastEthernet1/1", "is_uplink": False},
                    {"mac": "02:00:00:00:00:02", "vlan": "100", "interface": "GigabitEthernet1/1", "is_uplink": True},
                    {"mac": "02:00:00:00:00:01", "vlan": "100", "interface": "FastEthernet1/2", "is_uplink": False},
                    {"mac": "02:00:00:00:00:99", "vlan": "100", "interface": "FastEthernet1/3", "is_uplink": False},
                ],
                switch_ip="10.10.1.2", switch_name="ie-sw-01", tenant="plant",
            )

        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["kind"], "siem.alert")
        self.assertEqual(emitted[0]["severity"], "critical")
        self.assertEqual(emitted[0]["ctx"]["mac"], "02:00:00:00:00:99")

        rogue_list = purdue_model.list_rogue_ot_events("plant")
        self.assertEqual(len(rogue_list), 1)
        self.assertEqual(rogue_list[0]["mac"], "02:00:00:00:00:99")
        self.assertEqual(rogue_list[0]["vlan"], "100")

    def test_segment_ot_vlans_protects_vlan_and_ignores_it_vlan(self):
        # Core switch with NO Purdue level of its own
        inventory_manager.add_or_update_device(
            ip="10.10.99.2", vendor="cisco", profile="default",
            username="", password="", enable_secret="",
            group="plant", location="loc-ot", purdue_level="",
        )
        # Segment declares VLAN 250 as protected OT VLAN
        segment_manager.save_segment(
            "plant", None, "Confezionamento", "teal", ot_vlans=["250"],
        )

        emitted = []
        with patch.object(notifications, "emit", side_effect=lambda **kw: emitted.append(kw)):
            # Establish baselines on both VLAN 250 (OT) and VLAN 99 (IT office)
            mac_history.record_sightings(
                [
                    {"mac": "02:00:00:00:00:21", "vlan": "250", "interface": "Gi1/0/5", "is_uplink": False},
                    {"mac": "02:00:00:00:00:31", "vlan": "99", "interface": "Gi1/0/6", "is_uplink": False},
                ],
                switch_ip="10.10.99.2", switch_name="core-01", tenant="plant",
            )
            self.assertEqual(emitted, [])

            # Inject new MAC on both VLANs
            mac_history.record_sightings(
                [
                    {"mac": "02:00:00:00:00:22", "vlan": "250", "interface": "Gi1/0/7", "is_uplink": False},
                    {"mac": "02:00:00:00:00:32", "vlan": "99", "interface": "Gi1/0/8", "is_uplink": False},
                ],
                switch_ip="10.10.99.2", switch_name="core-01", tenant="plant",
            )

        # Only VLAN 250 fires a rogue OT alert
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["ctx"]["vlan"], "250")
        self.assertEqual(emitted[0]["ctx"]["mac"], "02:00:00:00:00:22")


class TestPurdueFrontendPresence(unittest.TestCase):
    def test_dashboard_and_js_contain_purdue_ui_hooks(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "templates", "dashboard.html"), encoding="utf-8") as fh:
            html = fh.read()
        with open(os.path.join(root, "static", "js", "topology.js"), encoding="utf-8") as fh:
            topo_js = fh.read()
        with open(os.path.join(root, "static", "js", "devices.js"), encoding="utf-8") as fh:
            dev_js = fh.read()

        for control_id in ("mapViewPurdueBtn", "mapSegPurdue", "mapSegOtVlans", "mapSegOtSection", "devPurdueLevel"):
            self.assertIn(control_id, html)
        for token in ("'purdue'", "drawPurdueBands", "purdueConduitState", "loadMapSegments"):
            self.assertIn(token, topo_js)
        self.assertIn("devPurdueLevel", dev_js)
