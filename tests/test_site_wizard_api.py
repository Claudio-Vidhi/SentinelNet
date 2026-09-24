# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Site wizard API: test an unsaved bastion, save with a confirmed key.

net_ssh is mocked at the function boundary: the dial itself is covered by
tests/test_bastion_fingerprint.py.
"""
import os
import shutil
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="sentinelnet_test_sitewizard_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP
os.environ.setdefault("SENTINELNET_JWT_SECRET", "test-secret-site-wizard")

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from core import net_ssh  # noqa: E402

ADMIN, SCOPED, PW = "sitewiz_admin", "sitewiz_scoped", "PasswordSicura1!"
DRAFT = {"jump_host": "198.51.100.70", "jump_port": 22, "jump_identity": "id-hk"}
FP = "SHA256:" + "A" * 43


def _login(client, user):
    r = client.post("/api/auth/login", json={"username": user, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


class SiteWizardApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from security import user_manager
        user_manager.create_user(ADMIN, PW, role="admin")
        user_manager.create_user(SCOPED, PW, role="admin", groups=["tenant-a"])
        cls.client = TestClient(app_server.app)
        cls.h = _login(cls.client, ADMIN)
        cls.hs = _login(cls.client, SCOPED)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP, ignore_errors=True)

    def _site(self, sid):
        sites = self.client.get("/api/sites", headers=self.h).json()["sites"]
        return next(s for s in sites if s["id"] == sid)

    def _draft(self, **patch):
        with mock.patch.object(net_ssh, "probe_bastion_draft", **patch):
            return self.client.post("/api/sites/test-bastion/draft", headers=self.h, json=DRAFT)

    def test_draft_statuses(self):
        ok = self._draft(return_value={"fingerprint": FP, "key_type": "ssh-ed25519", "known": False})
        self.assertEqual(ok.json(), {"status": "success", "fingerprint": FP,
                                     "key_type": "ssh-ed25519", "known": False})
        cases = ((net_ssh.BastionAuthError("refused"), "auth_failed"),
                 (net_ssh.BastionHostKeyError("changed"), "host_key_mismatch"),
                 (OSError("timed out"), "unreachable"))
        for exc, status in cases:
            with self.subTest(status=status):
                r = self._draft(side_effect=exc)
                self.assertEqual(r.status_code, 200, r.text)
                self.assertEqual(r.json()["status"], status)
                self.assertIn(str(exc), r.json()["message"])

    def test_draft_rejects_a_bad_port(self):
        r = self.client.post("/api/sites/test-bastion/draft", headers=self.h,
                             json={**DRAFT, "jump_port": 70000})
        self.assertEqual(r.status_code, 400)

    def test_draft_with_a_missing_identity_is_400_not_unreachable(self):
        # _dial raises ValueError when the identity is gone: that is a form
        # error, not a network one.
        r = self._draft(side_effect=ValueError("Identita' id-hk non trovata."))
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("non trovata", r.json()["detail"])

    def test_resaving_an_unchanged_bastion_is_not_audited_as_a_change(self):
        # The wizard sends the jump fields on every save of a jump site.
        r = self.client.post("/api/sites", headers=self.h, json={
            "name": "wiz-rename", "mode": "jump", **DRAFT})
        sid = r.json()["site"]["id"]
        with mock.patch("routers.sites.log_audit") as audit:
            r = self.client.post("/api/sites/update", headers=self.h,
                                 json={"id": sid, "name": "wiz-renamed", **DRAFT})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(any("senza verifica" in c.args[0] for c in audit.call_args_list))

    def test_scoped_admin_is_refused(self):
        r = self.client.post("/api/sites/test-bastion/draft", headers=self.hs, json=DRAFT)
        self.assertEqual(r.status_code, 403)

    def test_confirmed_fingerprint_pins_and_verifies(self):
        with mock.patch.object(net_ssh, "pin_confirmed", return_value=True) as pin, \
             mock.patch("routers.sites.log_audit") as audit:
            r = self.client.post("/api/sites", headers=self.h, json={
                "name": "wiz-verified", "mode": "jump", **DRAFT,
                "confirmed_fingerprint": FP})
        self.assertEqual(r.status_code, 200, r.text)
        pin.assert_called_once_with("198.51.100.70", 22, FP)
        self.assertIsNotNone(self._site(r.json()["site"]["id"])["bastion_verified_ts"])
        self.assertTrue(any("impronta" in c.args[0] for c in audit.call_args_list))

    def test_stale_fingerprint_is_409(self):
        with mock.patch.object(net_ssh, "pin_confirmed", return_value=False):
            r = self.client.post("/api/sites", headers=self.h, json={
                "name": "wiz-stale", "mode": "jump", **DRAFT,
                "confirmed_fingerprint": FP})
        self.assertEqual(r.status_code, 409)
        sites = self.client.get("/api/sites", headers=self.h).json()["sites"]
        self.assertFalse(any(s["name"] == "wiz-stale" for s in sites))

    def test_unverified_save_is_allowed_and_audited(self):
        with mock.patch("routers.sites.log_audit") as audit:
            r = self.client.post("/api/sites", headers=self.h, json={
                "name": "wiz-unverified", "mode": "jump", **DRAFT})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(self._site(r.json()["site"]["id"])["bastion_verified_ts"])
        self.assertTrue(any("non verificato" in c.args[0] for c in audit.call_args_list))

    def test_update_with_new_host_needs_a_confirmation_to_stay_verified(self):
        r = self.client.post("/api/sites", headers=self.h, json={
            "name": "wiz-move", "mode": "jump", **DRAFT})
        sid = r.json()["site"]["id"]
        from services import site_manager
        site_manager.mark_bastion_verified(sid)
        r = self.client.post("/api/sites/update", headers=self.h,
                             json={"id": sid, "jump_host": "198.51.100.71"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(self._site(sid)["bastion_verified_ts"])
        with mock.patch.object(net_ssh, "pin_confirmed", return_value=True) as pin:
            r = self.client.post("/api/sites/update", headers=self.h, json={
                "id": sid, "jump_host": "198.51.100.72", "confirmed_fingerprint": FP})
        self.assertEqual(r.status_code, 200, r.text)
        pin.assert_called_once_with("198.51.100.72", 22, FP)
        self.assertIsNotNone(self._site(sid)["bastion_verified_ts"])

    def test_saved_site_test_marks_verified_and_returns_fingerprint(self):
        r = self.client.post("/api/sites", headers=self.h, json={
            "name": "wiz-table", "mode": "jump", **DRAFT})
        sid = r.json()["site"]["id"]
        with mock.patch.object(net_ssh, "probe_bastion", return_value=FP):
            r = self.client.post("/api/sites/test-bastion", headers=self.h, json={"id": sid})
        self.assertEqual(r.json(), {"status": "success", "fingerprint": FP})
        self.assertIsNotNone(self._site(sid)["bastion_verified_ts"])
        with mock.patch.object(net_ssh, "probe_bastion",
                               side_effect=net_ssh.BastionHostKeyError("changed")):
            r = self.client.post("/api/sites/test-bastion", headers=self.h, json={"id": sid})
        self.assertEqual(r.json()["status"], "host_key_mismatch")


if __name__ == "__main__":
    unittest.main()
