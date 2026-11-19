# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for §5 OT Backup Vault & IEC 62443 / NIS2 automatic compliance checks."""

import base64
import hashlib
import io
import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from docx import Document
from fastapi.testclient import TestClient

import app_server
from core import backup_store, core_engine, data_config, db
from security import security_manager, user_manager
from services import (
    inventory_manager,
    inventory_store,
    ot_compliance,
    probe_manager,
    segment_manager,
)
from services.cloud_backup import sync as cb_sync
from services.status_report import evidence


PASS = "PasswordSicura1!"
CSRF = {"X-Requested-With": "SentinelNet"}


class _OtVaultBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ot_vault_")
        self.backup_dir = os.path.join(self.tmp, "backup-config")
        os.makedirs(self.backup_dir, exist_ok=True)
        self._patches = [
            patch.object(data_config, "DATA_DIR", self.tmp),
            patch.object(backup_store, "BACKUP_FOLDER", self.backup_dir),
            patch.object(core_engine, "BACKUP_FOLDER", self.backup_dir),
            patch.object(user_manager, "USERS_JSON", os.path.join(self.tmp, "users.json")),
            patch.object(inventory_manager, "HOSTS_CSV", os.path.join(self.tmp, "network_hosts.csv")),
            patch.object(probe_manager, "PROBES_JSON", os.path.join(self.tmp, "probes.json")),
            patch.object(probe_manager, "JOBS_DB", os.path.join(self.tmp, "probe_jobs.db")),
            patch.dict(os.environ, {"SENTINELNET_DATA_DIR": self.tmp}, clear=False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._cleanup)
        security_manager._failed_attempts.clear()
        inventory_manager._rows_cache.clear()
        inventory_manager.invalidate_device_ip_cache()
        db.migrate()

        inventory_manager.save_groups({
            "plant-a": {"description": "Plant A"},
            "plant-b": {"description": "Plant B"},
        })
        with inventory_manager._db() as conn:
            inventory_store.write_locations(conn, {
                "loc-a": {
                    "org": "plant-a",
                    "name": "Cell A",
                    "role": "branch",
                    "subnets": ["192.0.2.0/24"],
                    "gateway": "",
                    "probe": "central",
                },
                "loc-b": {
                    "org": "plant-b",
                    "name": "Cell B",
                    "role": "branch",
                    "subnets": ["198.51.100.0/24"],
                    "gateway": "",
                    "probe": "central",
                },
            })

    def _cleanup(self):
        inventory_manager._rows_cache.clear()
        inventory_manager.invalidate_device_ip_cache()
        for p in reversed(self._patches):
            p.stop()

    def _seed_device(
        self,
        ip: str,
        *,
        hostname: str = "plc-01",
        vendor: str = "siemens",
        group: str = "plant-a",
        location: str = "loc-a",
        transports: dict | None = None,
        snmp_community: str = "",
        snmp_disabled: bool = False,
        purdue_level: str = "",
        probe: str = "central",
    ) -> dict:
        inventory_manager.add_or_update_device(
            ip=ip,
            hostname=hostname,
            vendor=vendor,
            profile="default",
            username="",
            password="",
            enable_secret="",
            group=group,
            location=location,
            transports=transports,
            snmp_community=snmp_community,
            snmp_disabled=snmp_disabled,
            purdue_level=purdue_level,
            probe=probe,
        )
        return next(d for d in inventory_manager.get_all_devices() if d["IP"] == ip and d["Group"] == group)


class TestOtVaultCore(_OtVaultBase):
    def test_upload_dedupe_multiversion_verify_tamper_delete_and_walk_exclusion(self):
        dev = self._seed_device("192.0.2.10", hostname="plc-line1", purdue_level="L1")

        # 1. Valid project uploads across types + auto-classification
        r1 = backup_store.save_ot_artifact(
            dev,
            filename="line1_plc.zap18",
            data=b"TIA-ARCHIVE-V1",
            uploaded_by="admin",
            project_version="v1.0",
            notes="Commissioning baseline",
        )
        self.assertTrue(r1["ok"])
        self.assertFalse(r1["deduplicated"])
        self.assertEqual(r1["version"]["artifact_type"], "tia_portal")
        self.assertEqual(
            r1["version"]["sha256"],
            "sha256:" + hashlib.sha256(b"TIA-ARCHIVE-V1").hexdigest(),
        )

        # 2. Deduplication when identical filename + digest is uploaded consecutively
        r_dup = backup_store.save_ot_artifact(
            dev, filename="line1_plc.zap18", data=b"TIA-ARCHIVE-V1", uploaded_by="admin"
        )
        self.assertTrue(r_dup["deduplicated"])
        self.assertEqual(r_dup["count"], 1)

        # 3. Multi-versioning when bytes or filename differ
        for fname, blob, expected_type in (
            ("station_ctrl.acd", b"STUDIO5000-V2", "studio_5000"),
            ("substation.scd", b"<SCL/>", "iec_61850"),
            ("ied_bay01.icd", b"<ICD/>", "iec_61850"),
            ("panel_op1.hmi", b"HMI-BIN", "hmi_backup"),
            ("s7_legacy.s7p", b"STEP7-V5", "plc_project"),
            ("bundle.zip", b"PK-ZIP", "config_archive"),
        ):
            res = backup_store.save_ot_artifact(dev, filename=fname, data=blob, uploaded_by="admin")
            self.assertFalse(res["deduplicated"])
            self.assertEqual(res["version"]["artifact_type"], expected_type)

        versions = backup_store.list_ot_artifacts(dev)
        self.assertEqual(len(versions), 7)

        # Verify passes for all 7
        chk = backup_store.verify_ot_artifact(dev)
        self.assertTrue(chk["ok"])
        self.assertEqual(chk["checked"], 7)
        self.assertEqual(chk["corrupted"], [])
        self.assertEqual(chk["missing"], [])

        # .ot-vault excluded from CLI backup_times() and remove_stale_backups(),
        # while cloud_backup walk_local mirrors it.
        backup_store.save_backup(dev, "plc-line1", "cli config")
        times = backup_store.backup_times()
        self.assertIn(("plant-a", "192.0.2.10"), times)
        self.assertEqual(len(times), 1)
        backup_store.remove_stale_backups("192.0.2.10", tenant="plant-a")
        self.assertEqual(len(backup_store.list_ot_artifacts(dev)), 7)

        mirrored = cb_sync.walk_local(self.backup_dir)
        self.assertTrue(any(".ot-vault/192.0.2.10/" in rel for rel in mirrored))

        # 4. SHA-256 tamper detection
        tamper_vid = r1["version"]["version_id"]
        tamper_path = os.path.join(
            self.backup_dir, "plant-a", ".ot-vault", "192.0.2.10", r1["version"]["stored_file"]
        )
        with open(tamper_path, "wb") as fh:
            fh.write(b"TAMPERED-PAYLOAD")
        bad = backup_store.verify_ot_artifact(dev)
        self.assertFalse(bad["ok"])
        self.assertEqual(bad["corrupted"], [tamper_vid])
        with self.assertRaises(ValueError):
            backup_store.read_ot_artifact(dev, tamper_vid, verify=True)

        # 5. Missing file detection
        os.remove(tamper_path)
        miss = backup_store.verify_ot_artifact(dev, version_id=tamper_vid)
        self.assertFalse(miss["ok"])
        self.assertEqual(miss["missing"], [tamper_vid])

        # 6. Delete removes index entry and disk blob
        self.assertTrue(backup_store.delete_ot_artifact(dev, tamper_vid))
        self.assertFalse(backup_store.delete_ot_artifact(dev, tamper_vid))
        self.assertEqual(len(backup_store.list_ot_artifacts(dev)), 6)

        # 7. Validation errors (path traversal stripped safely / disallowed extensions / empty)
        with self.assertRaises(ValueError):
            backup_store.save_ot_artifact(dev, filename="payload.exe", data=b"MZ")
        with self.assertRaises(ValueError):
            backup_store.save_ot_artifact(dev, filename="script.sh", data=b"#!/bin/sh")
        with self.assertRaises(ValueError):
            backup_store.save_ot_artifact(dev, filename="empty.zap18", data=b"")
        with self.assertRaises(ValueError):
            backup_store.save_ot_artifact(dev, filename="..", data=b"data")
        # Traversal prefix in basename collapses cleanly to basename and saves inside vault
        trav = backup_store.save_ot_artifact(dev, filename="../../etc/safe.scd", data=b"<SCL>ok</SCL>")
        self.assertEqual(trav["version"]["filename"], "safe.scd")


class TestOtVaultApi(_OtVaultBase):
    def _login(self, username: str) -> TestClient:
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": username, "password": PASS})
        self.assertEqual(r.status_code, 200, r.text)
        return c

    def test_auth_rbac_csrf_scoping_tamper_and_validation(self):
        self._seed_device("192.0.2.10", hostname="plc-a", group="plant-a", location="loc-a", purdue_level="L1")
        self._seed_device("198.51.100.10", hostname="plc-b", group="plant-b", location="loc-b", purdue_level="L1")

        user_manager.create_user("vault_admin", PASS, role="admin", groups=None)
        user_manager.create_user("vault_op", PASS, role="operator", groups=["plant-a"])
        user_manager.create_user("vault_view", PASS, role="viewer", groups=["plant-a"])
        user_manager.create_user("vault_other_admin", PASS, role="admin", groups=["plant-b"])

        # Unauthenticated -> 401
        anon = TestClient(app_server.app)
        self.assertEqual(anon.get("/api/ot-vault/summary").status_code, 401)
        self.assertEqual(anon.get("/api/ot-vault/192.0.2.10").status_code, 401)

        # Viewer -> 403 on operator-gated vault routes
        viewer = self._login("vault_view")
        self.assertEqual(viewer.get("/api/ot-vault/summary").status_code, 403)
        self.assertEqual(viewer.get("/api/ot-vault/192.0.2.10").status_code, 403)

        admin = self._login("vault_admin")
        op = self._login("vault_op")
        other_admin = self._login("vault_other_admin")

        payload = {
            "filename": "cell_a.zap18",
            "content_b64": base64.b64encode(b"PROJECT-BYTES-V1").decode("ascii"),
            "project_version": "rev-1",
            "notes": "FAT approved",
        }

        # CSRF check on cookie auth without X-Requested-With header
        no_csrf = admin.post("/api/ot-vault/192.0.2.10", json=payload)
        self.assertEqual(no_csrf.status_code, 403)

        # Operator cannot upload or delete (admin-only)
        self.assertEqual(
            op.post("/api/ot-vault/192.0.2.10", json=payload, headers=CSRF).status_code,
            403,
        )

        # Admin uploads invalid base64 / disallowed ext -> 400
        self.assertEqual(
            admin.post(
                "/api/ot-vault/192.0.2.10",
                json={"filename": "bad.zap18", "content_b64": "%%%not-b64%%%"},
                headers=CSRF,
            ).status_code,
            400,
        )
        self.assertEqual(
            admin.post(
                "/api/ot-vault/192.0.2.10",
                json={"filename": "malware.exe", "content_b64": payload["content_b64"]},
                headers=CSRF,
            ).status_code,
            400,
        )

        # Valid upload by admin succeeds
        up = admin.post("/api/ot-vault/192.0.2.10", json=payload, headers=CSRF)
        self.assertEqual(up.status_code, 200, up.text)
        vid = up.json()["version"]["version_id"]

        # Operator in plant-a can list, verify, download; blocked on plant-b -> 403
        lst = op.get("/api/ot-vault/192.0.2.10")
        self.assertEqual(lst.status_code, 200)
        self.assertEqual(len(lst.json()["versions"]), 1)
        self.assertEqual(op.get("/api/ot-vault/198.51.100.10").status_code, 403)

        ver = op.post("/api/ot-vault/192.0.2.10/verify", headers=CSRF)
        self.assertEqual(ver.status_code, 200)
        self.assertTrue(ver.json()["ok"])

        dl = op.get(f"/api/ot-vault/192.0.2.10/download/{vid}")
        self.assertEqual(dl.status_code, 200)
        self.assertEqual(dl.content, b"PROJECT-BYTES-V1")
        self.assertTrue(dl.headers["X-Artifact-SHA256"].startswith("sha256:"))

        # Tenant isolation in summary
        self.assertIn("192.0.2.10", op.get("/api/ot-vault/summary").json()["by_ip"])
        self.assertNotIn("192.0.2.10", other_admin.get("/api/ot-vault/summary").json()["by_ip"])
        self.assertEqual(other_admin.post("/api/ot-vault/192.0.2.10", json=payload, headers=CSRF).status_code, 403)

        # Tampered artifact -> download returns HTTP 409 Conflict
        stored = up.json()["version"]["stored_file"]
        with open(os.path.join(self.backup_dir, "plant-a", ".ot-vault", "192.0.2.10", stored), "wb") as fh:
            fh.write(b"CORRUPTED")
        self.assertEqual(op.get(f"/api/ot-vault/192.0.2.10/download/{vid}").status_code, 409)

        # Operator cannot delete (403); CSRF missing -> 403; Admin deletes -> 200
        self.assertEqual(op.delete(f"/api/ot-vault/192.0.2.10/{vid}", headers=CSRF).status_code, 403)
        self.assertEqual(admin.delete(f"/api/ot-vault/192.0.2.10/{vid}").status_code, 403)
        self.assertEqual(admin.delete(f"/api/ot-vault/192.0.2.10/{vid}", headers=CSRF).status_code, 200)


class TestOtComplianceAndReport(_OtVaultBase):
    def _insert_event(
        self,
        tenant: str,
        ts: int,
        event_type: str,
        *,
        device_ip: str = "",
        src_ip: str = "",
        dst_ip: str = "",
        dst_port: int | None = None,
        protocol: str = "",
        interface: str = "",
        entity_id: str = "",
        attrs: dict | None = None,
    ):
        conn = db.get_observability_connection()
        try:
            conn.execute(
                "INSERT INTO events (ts, ingested_ts, tenant, source, event_type, entity_type, entity_id, severity, "
                "device_ip, src_ip, dst_ip, dst_port, protocol, interface, attrs_json) "
                "VALUES (?, ?, ?, 'test', ?, ?, ?, 4, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ts,
                    ts,
                    tenant,
                    event_type,
                    "interface" if event_type == "interface.state" else "flow",
                    entity_id or f"{device_ip}:{interface}",
                    device_ip,
                    src_ip,
                    dst_ip,
                    dst_port,
                    protocol,
                    interface,
                    json.dumps(attrs or {}),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def test_insecure_protocols_segregated_vs_unsegregated_and_cli_flags(self):
        # Healthy segmented OT cell (same L1 segment, SSH-only, no SNMPv1/v2c)
        plc_ok = self._seed_device(
            "192.0.2.21", hostname="plc-ok", vendor="siemens", group="plant-a",
            location="loc-a", transports={"ssh": 22}, snmp_disabled=True, purdue_level="L1",
        )
        hmi_ok = self._seed_device(
            "192.0.2.22", hostname="hmi-ok", vendor="siemens", group="plant-a",
            location="loc-a", transports={"restconf": 443}, snmp_disabled=True, purdue_level="L1",
        )
        segment_manager.save_segment(
            "plant-a", None, "Cell L1", "sky",
            subnets=["192.0.2.0/24"], purdue_level="L1",
            members=["192.0.2.21", "192.0.2.22"],
        )
        now = int(time.time())
        # Segregated Modbus inside the same L1 cell is OK
        self._insert_event(
            "plant-a", now, "flow",
            src_ip="192.0.2.22", dst_ip="192.0.2.21", dst_port=502, protocol="tcp",
            attrs={"ot_protocol": "modbus_tcp"},
        )
        res_ok = ot_compliance.evaluate_insecure_protocols("plant-a", [plc_ok, hmi_ok], 30)
        self.assertTrue(res_ok["available"])
        self.assertEqual(res_ok["metrics"]["total_findings"], 0)

        # Insecure tenant: Telnet inventory + HTTP config + SNMPv2c + unsegregated S7comm from unassigned/IT IP
        sw_bad = self._seed_device(
            "198.51.100.20", hostname="sw-bad", vendor="cisco_ios", group="plant-b",
            location="loc-b", transports={"telnet": 23, "ssh": 22}, snmp_community="public", purdue_level="L1",
        )
        backup_store.save_backup(sw_bad, "sw-bad", "ip http server\nsnmp-server community public RO\n")
        self._insert_event(
            "plant-b", now, "flow",
            src_ip="203.0.113.50", dst_ip="198.51.100.20", dst_port=102, protocol="tcp",
            attrs={"ot_protocol": "s7comm"},
        )
        res_bad = ot_compliance.evaluate_insecure_protocols("plant-b", [sw_bad], 30)
        self.assertEqual(res_bad["metrics"]["telnet_devices"], 1)
        self.assertEqual(res_bad["metrics"]["http_devices"], 1)
        self.assertEqual(res_bad["metrics"]["snmp_v1_v2c_devices"], 1)
        self.assertEqual(res_bad["metrics"]["unsegregated_ot_flows"], 1)
        self.assertEqual(res_bad["metrics"]["total_findings"], 4)

    def test_unused_physical_switch_ports_ignores_virtual_interfaces(self):
        sw = self._seed_device(
            "192.0.2.30", hostname="field-sw-01", vendor="siemens_scalance",
            group="plant-a", location="loc-a", purdue_level="L2",
        )
        fw = self._seed_device(
            "192.0.2.1", hostname="fw-edge", vendor="fortigate",
            group="plant-a", location="loc-a", purdue_level="L3.5",
        )
        now = int(time.time())
        # Physical port active + virtual Vlan10 down must both be OK
        self._insert_event(
            "plant-a", now, "interface.state", device_ip="192.0.2.30", interface="Gi1/0/1",
            entity_id="192.0.2.30:Gi1/0/1", attrs={"admin_status": "up", "link": "up"},
        )
        self._insert_event(
            "plant-a", now, "interface.state", device_ip="192.0.2.30", interface="Vlan10",
            entity_id="192.0.2.30:Vlan10", attrs={"admin_status": "up", "link": "down"},
        )
        # Unused port on firewall must be ignored
        self._insert_event(
            "plant-a", now, "interface.state", device_ip="192.0.2.1", interface="port4",
            entity_id="192.0.2.1:port4", attrs={"admin_status": "up", "link": "down"},
        )
        clean = ot_compliance.evaluate_unused_ports("plant-a", [sw, fw], 30)
        self.assertTrue(clean["available"])
        self.assertEqual(clean["metrics"]["physical_ports_checked"], 1)
        self.assertEqual(clean["metrics"]["unused_admin_up"], 0)

        # Now add an unused physical port left admin_up on the field switch -> flagged
        self._insert_event(
            "plant-a", now, "interface.state", device_ip="192.0.2.30", interface="Gi1/0/8",
            entity_id="192.0.2.30:Gi1/0/8", attrs={"admin_status": "up", "link": "down"},
        )
        flagged = ot_compliance.evaluate_unused_ports("plant-a", [sw, fw], 30)
        self.assertEqual(flagged["metrics"]["physical_ports_checked"], 2)
        self.assertEqual(flagged["metrics"]["unused_admin_up"], 1)
        self.assertEqual(flagged["metrics"]["field_switches_affected"], 1)
        self.assertEqual(flagged["rows"][0]["interface"], "Gi1/0/8")

    def test_remote_access_jump_dmz_and_bypass_detection(self):
        jump, _ = probe_manager.create_probe(
            name="ot-jump", mode="jump", jump_host="10.10.0.5", jump_port=22, jump_identity="ot-bastion",
        )
        plc = self._seed_device(
            "192.0.2.40", hostname="plc-jump", vendor="siemens", group="plant-a",
            location="loc-a", purdue_level="L1", probe=jump["id"],
        )
        # Jump probe -> ok
        ok_res = ot_compliance.evaluate_remote_access("plant-a", [plc], 30)
        self.assertTrue(ok_res["available"])
        self.assertEqual(ok_res["metrics"]["mediated_ot_devices"], 1)
        self.assertEqual(ok_res["metrics"]["unmediated_ot_devices"], 0)
        self.assertEqual(ok_res["metrics"]["direct_remote_bypasses"], 0)

        # Denied remote flow does NOT count as bypass; allowed RDP from L4 to L1 DOES count as bypass
        seg_ot = segment_manager.save_segment(
            "plant-a", None, "OT Cell", "sky", subnets=["192.0.2.0/24"], purdue_level="L1"
        )
        seg_it = segment_manager.save_segment(
            "plant-a", None, "Corp IT", "amber", subnets=["203.0.113.0/24"], purdue_level="L4"
        )
        now = int(time.time())
        self._insert_event(
            "plant-a", now, "flow",
            src_ip="203.0.113.15", dst_ip="192.0.2.40", dst_port=3389, protocol="rdp",
            attrs={"action": "deny"},
        )
        still_ok = ot_compliance.evaluate_remote_access("plant-a", [plc], 30)
        self.assertEqual(still_ok["metrics"]["direct_remote_bypasses"], 0)

        # Allowed L4 -> L1 RDP flow + allowed Purdue link bypassing L3.5 DMZ -> bypasses detected
        self._insert_event(
            "plant-a", now, "flow",
            src_ip="203.0.113.20", dst_ip="192.0.2.40", dst_port=3389, protocol="rdp",
            attrs={"action": "accept"},
        )
        segment_manager.set_link_decision("plant-a", "203.0.113.20", "192.0.2.40", "allowed")
        bad_res = ot_compliance.evaluate_remote_access("plant-a", [plc], 30)
        self.assertGreaterEqual(bad_res["metrics"]["direct_remote_bypasses"], 2)

        # Central probe on OT without DMZ in plant-b -> unmediated
        plc_b = self._seed_device(
            "198.51.100.40", hostname="plc-direct", vendor="rockwell", group="plant-b",
            location="loc-b", purdue_level="L1", probe="central",
        )
        unmed = ot_compliance.evaluate_remote_access("plant-b", [plc_b], 30)
        self.assertEqual(unmed["metrics"]["unmediated_ot_devices"], 1)

    def test_status_report_snapshot_isolation_and_docx_rendering(self):
        # plant-a fully healthy for all 4 OT sections; plant-b fails them; verify strict isolation & DOCX render
        jump, _ = probe_manager.create_probe(
            name="ot-jump-a", mode="jump", jump_host="10.20.0.5", jump_port=22, jump_identity="ot-bastion-a",
        )
        plc_a = self._seed_device(
            "192.0.2.50", hostname="plc-a50", vendor="siemens", group="plant-a",
            location="loc-a", transports={"ssh": 22}, snmp_disabled=True, purdue_level="L1", probe=jump["id"],
        )
        sw_a = self._seed_device(
            "192.0.2.51", hostname="sw-a51", vendor="siemens_scalance", group="plant-a",
            location="loc-a", transports={"ssh": 22}, snmp_disabled=True, purdue_level="L2", probe=jump["id"],
        )
        art_a = backup_store.save_ot_artifact(plc_a, "plc_a50.zap18", b"PLC-A-PROJECT", uploaded_by="admin")
        backup_store.save_ot_artifact(sw_a, "sw_a51.zip", b"SW-A-ARCHIVE", uploaded_by="admin")

        now = int(time.time())
        self._insert_event(
            "plant-a", now, "interface.state", device_ip="192.0.2.51", interface="Gi1/0/1",
            entity_id="192.0.2.51:Gi1/0/1", attrs={"admin_status": "up", "link": "up"},
        )

        # plant-b has Telnet, unused port, missing vault artifact, central OT without DMZ
        sw_b = self._seed_device(
            "198.51.100.51", hostname="sw-b51", vendor="moxa", group="plant-b",
            location="loc-b", transports={"telnet": 23}, snmp_disabled=True, purdue_level="L1", probe="central",
        )
        self._insert_event(
            "plant-b", now, "interface.state", device_ip="198.51.100.51", interface="Fa0/2",
            entity_id="198.51.100.51:Fa0/2", attrs={"admin_status": "up", "link": "down"},
        )

        snap_a = evidence.build_snapshot("plant-a", "tester")["evidence"]
        self.assertEqual(snap_a["ot_vault"]["status"], "ok")
        self.assertEqual(snap_a["ot_insecure_protocols"]["status"], "ok")
        self.assertEqual(snap_a["ot_unused_ports"]["status"], "ok")
        self.assertEqual(snap_a["ot_remote_access"]["status"], "ok")
        self.assertNotIn("198.51.100.51", str(snap_a))

        snap_b = evidence.build_snapshot("plant-b", "tester")["evidence"]
        self.assertEqual(snap_b["ot_vault"]["status"], "partial")
        self.assertEqual(snap_b["ot_insecure_protocols"]["status"], "gap")
        self.assertEqual(snap_b["ot_unused_ports"]["status"], "gap")
        self.assertEqual(snap_b["ot_remote_access"]["status"], "partial")
        self.assertNotIn("192.0.2.50", str(snap_b))

        # Verify DOCX generation via API route succeeds cleanly
        user_manager.create_user("rpt_ot_admin", PASS, role="admin", groups=None)
        client = TestClient(app_server.app)
        r_login = client.post("/api/auth/login", json={"username": "rpt_ot_admin", "password": PASS})
        self.assertEqual(r_login.status_code, 200)
        r_docx = client.get("/api/reports/network-status", params={"tenant": "plant-a", "lang": "en"}, headers=CSRF)
        self.assertEqual(r_docx.status_code, 200, r_docx.text)
        doc = Document(io.BytesIO(r_docx.content))
        full_text = "\n".join(p.text for p in doc.paragraphs) + "\n" + "\n".join(
            cell.text for t in doc.tables for row in t.rows for cell in row.cells
        )
        self.assertIn("IEC 62443", full_text)
        self.assertIn("OT Project Vault", full_text)
        self.assertNotIn("198.51.100.51", full_text)

        # Corrupt one vault blob -> ot_vault status becomes gap
        blob_path = os.path.join(
            self.backup_dir, "plant-a", ".ot-vault", "192.0.2.50", art_a["version"]["stored_file"]
        )
        with open(blob_path, "wb") as fh:
            fh.write(b"CORRUPT")
        snap_a_bad = evidence.build_snapshot("plant-a", "tester")["evidence"]
        self.assertEqual(snap_a_bad["ot_vault"]["status"], "gap")


if __name__ == "__main__":
    unittest.main()
