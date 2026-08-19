# -*- coding: utf-8 -*-
"""Test device site selection in GUI and /api/add-device endpoint."""
import os
import pathlib
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="sentinelnet_dev_site_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP
os.environ.setdefault("SENTINELNET_JWT_SECRET", "test-secret-dev-site-gui")

from fastapi.testclient import TestClient
import app_server
from services import inventory_manager, site_manager
from security import user_manager
import bcrypt

ADMIN = "admin_dev_site"
ADMIN_PW = "adminpw12345"
OPERATOR = "op_dev_site"
OPERATOR_PW = "oppw12345"
ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestDeviceSiteGui(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app_server.app)
        users = user_manager.get_users()
        h_adm = bcrypt.hashpw(ADMIN_PW.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        h_op = bcrypt.hashpw(OPERATOR_PW.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        users[ADMIN] = {"hashed_password": h_adm, "role": "admin", "disabled": False}
        users[OPERATOR] = {"hashed_password": h_op, "role": "operator", "disabled": False}
        user_manager._save_users(users)

        r_adm = cls.client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PW})
        cls.admin_h = {"Authorization": "Bearer " + r_adm.json()["access_token"]}

        r_op = cls.client.post("/api/auth/login", json={"username": OPERATOR, "password": OPERATOR_PW})
        cls.op_h = {"Authorization": "Bearer " + r_op.json()["access_token"]}

    @classmethod
    def tearDownClass(cls):
        try:
            site_manager.delete_site("branch-site")
        except Exception:
            pass

    def test_list_sites_accessible_by_operator(self):
        r = self.client.get("/api/sites", headers=self.op_h)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("sites", data)
        site_ids = [s["id"] for s in data["sites"]]
        self.assertIn("central", site_ids)

    def test_operator_does_not_see_bastion_details(self):
        """A dropdown needs id/name/mode; it does not need the bastion address."""
        r = self.client.get("/api/sites", headers=self.op_h)
        self.assertEqual(r.status_code, 200)
        for site in r.json()["sites"]:
            self.assertEqual(set(site), {"id", "name", "mode"})

    def test_admin_still_sees_the_full_site_record(self):
        r = self.client.get("/api/sites", headers=self.admin_h)
        self.assertEqual(r.status_code, 200)
        central = next(s for s in r.json()["sites"] if s["id"] == "central")
        self.assertIn("subnets", central)
        self.assertNotIn("token_hash", central)

    def test_add_device_with_site(self):
        # Create a jump site
        site_manager.create_site(
            name="Branch Site",
            mode="jump",
            subnets=["198.51.100.0/24"],
            jump_host="198.51.100.10",
            jump_port=22,
            jump_identity="id-fake",
        )
        sid = "branch-site"

        # Add device targeting this site
        payload = {
            "ip": "203.0.113.55",
            "vendor": "cisco",
            "profile": "default",
            "group": "Generale",
            "site": sid,
            "ssh_port": 22,
        }
        r = self.client.post("/api/add-device", headers=self.op_h, json=payload)
        self.assertEqual(r.status_code, 200)

        # Verify device record has site
        dev = next((d for d in inventory_manager.get_all_devices() if d["IP"] == "203.0.113.55"), None)
        self.assertIsNotNone(dev)
        self.assertEqual(dev.get("Site"), sid)

    def test_add_device_rejects_invalid_site(self):
        payload = {
            "ip": "192.0.2.56",
            "vendor": "cisco",
            "profile": "default",
            "group": "Generale",
            "site": "nonexistent-site-id",
            "ssh_port": 22,
        }
        r = self.client.post("/api/add-device", headers=self.op_h, json=payload)
        self.assertEqual(r.status_code, 400)
        self.assertIn("inesistente", r.json()["detail"])

    def test_gui_template_has_dev_site_select(self):
        html = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
        self.assertIn('id="devSiteSelect"', html)
        self.assertIn('data-i18n="lblDeviceSite"', html)

    def test_js_has_populate_site_options(self):
        js = (ROOT / "static/js/provisioning.js").read_text(encoding="utf-8")
        self.assertIn("populateSiteOptions", js)
        self.assertIn("devSiteSelect", js)


if __name__ == "__main__":
    unittest.main()
