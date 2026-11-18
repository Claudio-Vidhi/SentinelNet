# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for §4 OT Vulnerability Intelligence:
- CISA KEV + CISA ICS Advisories ingestion & matching
- Air-gapped offline mode (outbound NVD/EPSS/CISA kill-switch + local cache)
- Ed25519 + SHA-256 signed offline bundle export & verified import
- Asset Process Criticality & Maintenance Window persistence and surfacing
"""

import csv
import io
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from core import data_config, db
from routers import backup as backup_router
from security import security_manager, user_manager
from services import cve_intel, inventory_manager, inventory_store, nvd, ot_vuln_intel
from services.status_report import evidence


class _OtVulnBase(unittest.TestCase):
    PW = "PasswordSicura1!"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ot_vuln_")
        ot_vuln_intel.invalidate_cache()
        nvd._cache.clear()
        self._patches = [
            patch.object(data_config, "DATA_DIR", self.tmp),
            patch.object(user_manager, "USERS_JSON", os.path.join(self.tmp, "users.json")),
            patch.object(inventory_manager, "HOSTS_CSV", os.path.join(self.tmp, "network_hosts.csv")),
            patch.dict(os.environ, {"SENTINELNET_AIRGAP_MODE": "", "SENTINELNET_DATA_DIR": self.tmp}, clear=False),
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
                    "subnets": ["192.0.2.0/24"],
                    "gateway": "",
                    "probe": "central",
                }
            })

    def _cleanup(self):
        ot_vuln_intel.invalidate_cache()
        nvd._cache.clear()
        for p in reversed(self._patches):
            p.stop()


class TestProcessCriticalityAndMaintenanceWindow(_OtVulnBase):
    def test_persistence_preserve_clear_and_validation(self):
        inventory_manager.add_or_update_device(
            ip="192.0.2.21",
            vendor="siemens",
            profile="default",
            username="",
            password="",
            enable_secret="",
            group="plant",
            location="loc-ot",
            process_criticality="scheduled_shutdown",
            maintenance_window="Sun 02:00-06:00",
        )
        dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "192.0.2.21")
        self.assertEqual(dev["Process Criticality"], "scheduled_shutdown")
        self.assertEqual(dev["Maintenance Window"], "Sun 02:00-06:00")

        # None preserves existing attributes
        inventory_manager.add_or_update_device(
            ip="192.0.2.21",
            vendor="siemens",
            profile="default",
            username="",
            password="",
            enable_secret="",
            group="plant",
            location="loc-ot",
            process_criticality=None,
            maintenance_window=None,
        )
        dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "192.0.2.21")
        self.assertEqual(dev["Process Criticality"], "scheduled_shutdown")
        self.assertEqual(dev["Maintenance Window"], "Sun 02:00-06:00")

        # Empty string clears
        inventory_manager.add_or_update_device(
            ip="192.0.2.21",
            vendor="siemens",
            profile="default",
            username="",
            password="",
            enable_secret="",
            group="plant",
            location="loc-ot",
            process_criticality="",
            maintenance_window="",
        )
        dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "192.0.2.21")
        self.assertEqual(dev["Process Criticality"], "")
        self.assertEqual(dev["Maintenance Window"], "")

        with self.assertRaises(ValueError):
            ot_vuln_intel.normalize_process_criticality("invalid_tier")
        with self.assertRaises(ValueError):
            ot_vuln_intel.normalize_maintenance_window("x" * 129)

    def test_legacy_sqlite_migration_adds_columns(self):
        legacy_db = os.path.join(self.tmp, "legacy_inv.db")
        conn = sqlite3.connect(legacy_db)
        conn.execute(
            "CREATE TABLE hosts (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE NOT NULL, "
            "vendor TEXT DEFAULT '', profile TEXT DEFAULT '', username TEXT DEFAULT '', "
            "password TEXT DEFAULT '', enable_secret TEXT DEFAULT '', grp TEXT DEFAULT '', "
            "location TEXT DEFAULT '', probe TEXT DEFAULT 'central', hostname TEXT DEFAULT '', "
            "model TEXT DEFAULT '', \"group\" TEXT)"
        )
        conn.commit()
        conn.close()

        migrated = inventory_store.connect(legacy_db)
        cols = {row[1] for row in migrated.execute("PRAGMA table_info(hosts)")}
        migrated.close()
        self.assertIn("Process Criticality", cols)
        self.assertIn("Maintenance Window", cols)

    def test_csv_export_includes_ot_criticality_columns(self):
        user_manager.create_user("admin1", self.PW, "admin")
        inventory_manager.add_or_update_device(
            ip="192.0.2.22",
            vendor="rockwell",
            profile="default",
            username="",
            password="",
            enable_secret="",
            group="plant",
            location="loc-ot",
            process_criticality="mission_critical",
            maintenance_window="Annual Shutdown August",
        )
        client = TestClient(app_server.app)
        res_login = client.post("/api/auth/login", json={"username": "admin1", "password": self.PW})
        self.assertEqual(res_login.status_code, 200)
        res = client.get("/api/export/devices", params={"columns": "ip,process_criticality,maintenance_window"})
        self.assertEqual(res.status_code, 200)
        rows = list(csv.DictReader(io.StringIO(res.text)))
        row = next(r for r in rows if r["IP"] == "192.0.2.22")
        self.assertEqual(row["Process Criticality"], "mission_critical")
        self.assertEqual(row["Maintenance Window"], "Annual Shutdown August")


class TestKevAndIcsEnrichment(_OtVulnBase):
    def _seed_catalogs(self):
        ot_vuln_intel.ingest_kev_catalog({
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-90001",
                    "vendorProject": "Siemens",
                    "product": "SIMATIC S7-1500",
                    "vulnerabilityName": "Siemens S7 Improper Authentication",
                    "dateAdded": "2024-02-01",
                    "dueDate": "2024-02-22",
                    "requiredAction": "Apply firmware update",
                    "knownRansomwareCampaignUse": "Known",
                }
            ]
        })
        ot_vuln_intel.ingest_ics_advisories({
            "advisories": [
                {
                    "id": "ICSA-24-045-01",
                    "title": "Siemens SCALANCE / SIMATIC S7 Advisory",
                    "vendor": "Siemens",
                    "product": "SIMATIC S7-1500",
                    "cves": ["CVE-2024-90001", "CVE-2024-90002"],
                    "published": "2024-02-14",
                    "cvss": 9.8,
                    "url": "https://www.cisa.gov/news-events/ics-advisories/icsa-24-045-01",
                    "summary": "Critical vulnerability affecting PLC control traffic.",
                }
            ]
        })

    def test_kev_and_ics_enrich_nvd_score_rows_and_evidence_without_altering_score_math(self):
        self._seed_catalogs()
        raw_cve = {
            "id": "CVE-2024-90001",
            "published": "2024-01-10T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Synthetic PLC flaw in SNMP."}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH"},
                }]
            },
            "references": [],
        }
        norm = nvd.normalize_item(raw_cve, model="S7-1500")
        self.assertTrue(norm["exploited"])
        self.assertIsNotNone(norm["kev"])
        self.assertEqual(norm["kev"]["cve_id"], "CVE-2024-90001")
        self.assertEqual([a["id"] for a in norm["icsAdvisories"]], ["ICSA-24-045-01"])

        inventory_manager.add_or_update_device(
            ip="192.0.2.30",
            vendor="siemens",
            profile="default",
            username="",
            password="",
            enable_secret="",
            group="plant",
            location="loc-ot",
            process_criticality="scheduled_shutdown",
            maintenance_window="Monthly Maint Window",
        )
        dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "192.0.2.30")
        snapshot = {
            "device": "192.0.2.30",
            "fetched_at": "20261117T000000.000000Z",
            "version_seen_at": "20261117T000000.000000Z",
            "query": {"kind": "cpe", "value": "cpe:2.3:o:siemens:simatic:1.0", "confidence": "exact"},
            "cves": [{
                "id": "CVE-2024-90001",
                "cvss": 8.0,
                "severity": "HIGH",
                "published": "2024-01-10T00:00:00.000",
                "summary": "Synthetic PLC flaw.",
                "exploited": False,
                "services": [],
            }],
        }
        rows = cve_intel.score_rows(snapshot, {}, device=dev)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        # Score math untouched: 8.0 * 1.0 (exact) * 1.0 (unknown) == 8.0
        self.assertEqual(row["score"], 8.0)
        self.assertTrue(row["exploited"])
        self.assertEqual(row["ics_advisories"], ["ICSA-24-045-01"])
        self.assertEqual(row["process_criticality"], "scheduled_shutdown")
        self.assertEqual(row["maintenance_window"], "Monthly Maint Window")
        self.assertTrue(row["maintenance_deferrable"])

        # Summary + status report evidence surface ICS advisories & deferrable devices
        cve_intel._save(dev, snapshot)
        summary = cve_intel.summary([dev])
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["deferrable_devices"], 1)
        self.assertEqual(summary[0]["ics_advisories_count"], 1)
        self.assertEqual(summary[0]["devices_detail"][0]["exploited"], 1)
        self.assertEqual(summary[0]["devices_detail"][0]["ics_advisories"], ["ICSA-24-045-01"])

        ev = evidence.collect_vulnerabilities("plant", [dev], period_days=30)
        self.assertEqual(ev["metrics"]["ics_advisories"], 1)
        self.assertEqual(ev["metrics"]["deferrable_devices"], 1)
        self.assertEqual(ev["rows"][0]["process_criticality"], "scheduled_shutdown")


class TestAirgapModeAndSignedBundles(_OtVulnBase):
    def test_airgap_blocks_outbound_nvd_and_epss_and_serves_cached_nvd(self):
        # Record online NVD query response first
        sample_resp = {
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-88888",
                    "published": "2024-05-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Cached OT NVD item."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}]},
                    "references": [],
                }
            }],
        }
        ot_vuln_intel.record_nvd_response(
            {"virtualMatchString": "cpe:2.3:o:siemens:scalance:4.3"},
            sample_resp,
        )
        ot_vuln_intel.set_airgap_mode(True)
        nvd._cache.clear()

        with patch("services.nvd.requests.get", side_effect=AssertionError("outbound NVD call in airgap")) as mock_nvd_get:
            # Exact probe hit in offline store
            status, payload = nvd.get({"virtualMatchString": "cpe:2.3:o:siemens:scalance:4.3", "resultsPerPage": "20"}, fresh=True)
            self.assertEqual(status, 200)
            self.assertTrue(payload.get("offline"))
            self.assertEqual(payload["vulnerabilities"][0]["cve"]["id"], "CVE-2024-88888")

            # Prefix probe hit (unversioned CPE)
            status_prefix, payload_prefix = nvd.get({"virtualMatchString": "cpe:2.3:o:siemens:scalance"}, fresh=True)
            self.assertEqual(status_prefix, 200)
            self.assertEqual(len(payload_prefix["vulnerabilities"]), 1)

            # Uncached query fails cleanly with 503 airgap_offline without touching network
            status_miss, payload_miss = nvd.get({"keywordSearch": "unknown-vendor-offline"}, fresh=True)
            self.assertEqual(status_miss, 503)
            self.assertTrue(payload_miss.get("airgap_offline"))
            mock_nvd_get.assert_not_called()

        with patch("routers.backup.requests.get", side_effect=AssertionError("outbound EPSS call in airgap")) as mock_epss:
            self.assertEqual(backup_router._epss_scores(["CVE-2024-88888"]), {})
            mock_epss.assert_not_called()

    def test_signed_bundle_export_verify_tamper_and_trust(self):
        ot_vuln_intel.ingest_kev_catalog({
            "vulnerabilities": [{"cveID": "CVE-2024-77777", "vendorProject": "Moxa", "product": "EDS"}]
        })
        ot_vuln_intel.ingest_ics_advisories({
            "advisories": [{"id": "ICSA-24-100-01", "title": "Moxa Switch", "vendor": "Moxa", "cves": ["CVE-2024-77777"]}]
        })
        ot_vuln_intel.record_nvd_response(
            {"keywordSearch": "moxa"},
            {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2024-77777", "published": "2024-03-01", "descriptions": [], "metrics": {}, "references": []}}]},
        )

        bundle = ot_vuln_intel.export_signed_bundle(include_nvd_cache=True)
        self.assertEqual(bundle["format"], ot_vuln_intel.BUNDLE_FORMAT)
        self.assertEqual(bundle["version"], ot_vuln_intel.BUNDLE_VERSION)

        # Simulate transferring bundle to a completely separate air-gapped DATA_DIR
        target_dir = tempfile.mkdtemp(prefix="ot_airgap_target_")
        with patch.object(data_config, "DATA_DIR", target_dir), patch.dict(os.environ, {"SENTINELNET_DATA_DIR": target_dir}, clear=False):
            ot_vuln_intel.invalidate_cache()
            ot_vuln_intel.set_airgap_mode(True)

            # 1. Untrusted key fails by default
            with self.assertRaises(ot_vuln_intel.BundleVerificationError):
                ot_vuln_intel.verify_and_import_bundle(bundle, trust_bundle_key=False)

            # 2. Tampered payload fails SHA-256 verification even with trust_bundle_key=True
            tampered_payload = json.loads(json.dumps(bundle))
            tampered_payload["payload"]["kev"]["CVE-2024-77777"]["product"] = "Tampered"
            with self.assertRaises(ot_vuln_intel.BundleVerificationError):
                ot_vuln_intel.verify_and_import_bundle(tampered_payload, trust_bundle_key=True)

            # 3. Tampered signature fails Ed25519 verification
            tampered_sig = json.loads(json.dumps(bundle))
            tampered_sig["signature"] = "AAAA" + tampered_sig["signature"][4:]
            with self.assertRaises(ot_vuln_intel.BundleVerificationError):
                ot_vuln_intel.verify_and_import_bundle(tampered_sig, trust_bundle_key=True)

            # 4. Pre-registering signer's public key allows trusted import without trust_bundle_key=True
            ot_vuln_intel.add_trusted_key(bundle["public_key"], label="Online Collector")
            res = ot_vuln_intel.verify_and_import_bundle(bundle, trust_bundle_key=False)
            self.assertEqual(res["kev_imported"], 1)
            self.assertEqual(res["ics_imported"], 1)
            self.assertEqual(res["nvd_imported"], 1)
            self.assertIsNotNone(ot_vuln_intel.lookup_kev("CVE-2024-77777"))
            self.assertEqual(len(ot_vuln_intel.list_ics_advisories(vendor="moxa")), 1)
            self.assertIsNotNone(ot_vuln_intel.lookup_nvd_response({"keywordSearch": "moxa"}))


class TestOtVulnApiAndUiHooks(_OtVulnBase):
    def test_api_rbac_sync_airgap_bundle_and_keys(self):
        user_manager.create_user("admin1", self.PW, "admin")
        user_manager.create_user("op1", self.PW, "operator", groups=["plant"])
        user_manager.create_user("view1", self.PW, "viewer", groups=["plant"])

        client = TestClient(app_server.app)

        def _login_headers(username: str) -> dict:
            c = TestClient(app_server.app)
            r = c.post("/api/auth/login", json={"username": username, "password": self.PW})
            self.assertEqual(r.status_code, 200)
            return {"Authorization": f"Bearer {r.json()['access_token']}", "X-Requested-With": "1"}

        op_headers = _login_headers("op1")
        view_headers = _login_headers("view1")
        admin_headers = _login_headers("admin1")

        # Operator cannot toggle air-gap or manage trusted keys or trust new bundle keys
        self.assertEqual(client.post("/api/cve/ot/airgap", json={"enabled": True}, headers=op_headers).status_code, 403)
        self.assertEqual(client.get("/api/cve/ot/trusted-keys", headers=op_headers).status_code, 403)

        # Viewer can read status and ICS advisories, cannot export/sync
        self.assertEqual(client.get("/api/cve/ot/status", headers=view_headers).status_code, 200)
        self.assertEqual(client.get("/api/cve/ot/ics-advisories", headers=view_headers).status_code, 200)
        self.assertEqual(client.get("/api/cve/ot/bundle/export", headers=view_headers).status_code, 403)

        mock_kev = {"vulnerabilities": [{"cveID": "CVE-2024-60001", "vendorProject": "Schneider", "product": "Modicon"}]}
        mock_ics = {"advisories": [{"id": "ICSA-24-200-01", "title": "Modicon M340", "vendor": "Schneider", "cves": ["CVE-2024-60001"]}]}

        class _FakeResp:
            def __init__(self, data):
                self._data = data
            def raise_for_status(self):
                return None
            def json(self):
                return self._data

        def _fake_cisa_get(url, headers=None, timeout=20):
            if "known_exploited" in url:
                return _FakeResp(mock_kev)
            return _FakeResp(mock_ics)

        with patch("services.ot_vuln_intel.requests.get", side_effect=_fake_cisa_get):
            sync_res = client.post("/api/cve/ot/sync", json={"fetch_kev": True, "fetch_ics": True}, headers=admin_headers)
            self.assertEqual(sync_res.status_code, 200)
            self.assertEqual(sync_res.json()["kev_count"], 1)
            self.assertEqual(sync_res.json()["ics_count"], 1)

        # Export signed bundle via API
        exp_res = client.get("/api/cve/ot/bundle/export", headers=admin_headers)
        self.assertEqual(exp_res.status_code, 200)
        exported_bundle = json.loads(exp_res.text)

        # Enable air-gap via API -> sync refuses with 409
        ag_res = client.post("/api/cve/ot/airgap", json={"enabled": True}, headers=admin_headers)
        self.assertEqual(ag_res.status_code, 200)
        self.assertTrue(ag_res.json()["airgap_mode"])
        self.assertEqual(client.post("/api/cve/ot/sync", json={}, headers=admin_headers).status_code, 409)

        # Trusted keys CRUD
        keys_res = client.get("/api/cve/ot/trusted-keys", headers=admin_headers)
        self.assertEqual(keys_res.status_code, 200)
        local_pub = keys_res.json()["local_signing_key"]["public_key"]
        local_kid = keys_res.json()["local_signing_key"]["key_id"]
        add_res = client.post("/api/cve/ot/trusted-keys", json={"public_key": local_pub, "label": "Plant Hub"}, headers=admin_headers)
        self.assertEqual(add_res.status_code, 200)
        self.assertEqual(add_res.json()["key"]["key_id"], local_kid)

        # Import valid bundle via API (operator succeeds when key is trusted, fails when trust_bundle_key=True)
        self.assertEqual(
            client.post("/api/cve/ot/bundle/import", json={"bundle": exported_bundle, "trust_bundle_key": True}, headers=op_headers).status_code,
            403,
        )
        imp_res = client.post("/api/cve/ot/bundle/import", json={"bundle": exported_bundle, "trust_bundle_key": False}, headers=op_headers)
        self.assertEqual(imp_res.status_code, 200)
        self.assertEqual(imp_res.json()["kev_imported"], 1)

        del_res = client.delete(f"/api/cve/ot/trusted-keys/{local_kid}", headers=admin_headers)
        self.assertEqual(del_res.status_code, 200)

        # ICS advisories query endpoint filters properly
        adv_res = client.get("/api/cve/ot/ics-advisories", params={"vendor": "schneider"}, headers=view_headers)
        self.assertEqual(adv_res.status_code, 200)
        self.assertEqual(adv_res.json()["advisories"][0]["id"], "ICSA-24-200-01")

    def test_frontend_hooks_present(self):
        root = os.path.dirname(os.path.dirname(__file__))
        with open(os.path.join(root, "templates", "dashboard.html"), encoding="utf-8") as fh:
            html = fh.read()
        with open(os.path.join(root, "static", "js", "devices.js"), encoding="utf-8") as fh:
            devices_js = fh.read()
        with open(os.path.join(root, "static", "js", "threat-intel.js"), encoding="utf-8") as fh:
            ti_js = fh.read()

        for hook in ("tiTabOt", "tiViewOt", "otAirgapToggle", "otSyncFeedsBtn",
                     "otExportBundleBtn", "otImportBundleBtn", "otIcsBody",
                     "cvePrioHideDeferrable", "devProcessCriticality", "devMaintenanceWindow"):
            self.assertIn(hook, html)
        self.assertIn("devProcessCriticality", devices_js)
        self.assertIn("devMaintenanceWindow", devices_js)
        self.assertIn("cvePrioHideDeferrable", ti_js)
        self.assertIn("/api/cve/ot/status", ti_js)
