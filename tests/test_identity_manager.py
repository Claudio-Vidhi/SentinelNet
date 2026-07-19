# -*- coding: utf-8 -*-
"""Test per identity_manager: CRUD, cifratura, blocco delete-in-uso,
risoluzione credenziali 'identity:<id>' in core_engine."""
import os
import tempfile
import unittest
from unittest import mock


class TestIdentityManager(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.json_path = os.path.join(self.tmp.name, "identities.json")
        import identity_manager
        self.im = identity_manager
        self._orig = self.im.IDENTITIES_JSON
        self.im.IDENTITIES_JSON = self.json_path

    def tearDown(self):
        self.im.IDENTITIES_JSON = self._orig
        self.tmp.cleanup()

    def test_add_and_list_no_secrets(self):
        ident = self.im.add_identity("noc-admin", "Tenant_Torino", "admin", "pw1", "sec1")
        self.assertTrue(ident["id"])
        rows = self.im.get_identities()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "noc-admin")
        self.assertEqual(rows[0]["tenant"], "Tenant_Torino")
        self.assertNotIn("password_enc", rows[0])
        self.assertNotIn("secret_enc", rows[0])

    def test_tenant_filter(self):
        self.im.add_identity("a", "T1", "u", "p", "s")
        self.im.add_identity("b", "T2", "u", "p", "s")
        self.assertEqual(len(self.im.get_identities(tenant="T1")), 1)

    def test_credentials_roundtrip(self):
        ident = self.im.add_identity("x", "T", "user1", "pw!", "sec!")
        u, p, s = self.im.get_identity_credentials(ident["id"])
        self.assertEqual((u, p, s), ("user1", "pw!", "sec!"))
        # su disco NON in chiaro
        with open(self.json_path, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("pw!", raw)
        self.assertNotIn("sec!", raw)

    def test_update(self):
        ident = self.im.add_identity("x", "T", "u1", "p1", "s1")
        self.im.update_identity(ident["id"], name="y", tenant="T", username="u2",
                                password="p2", secret="s2")
        u, p, s = self.im.get_identity_credentials(ident["id"])
        self.assertEqual((u, p, s), ("u2", "p2", "s2"))
        self.assertEqual(self.im.get_identities()[0]["name"], "y")

    def test_delete_blocked_when_in_use(self):
        ident = self.im.add_identity("x", "T", "u", "p", "s")
        with mock.patch("inventory_manager.get_all_devices", return_value=[
                {"IP": "10.0.0.1", "Profile": f"identity:{ident['id']}"}]):
            ok, devices = self.im.delete_identity(ident["id"])
        self.assertFalse(ok)
        self.assertEqual(devices, ["10.0.0.1"])
        self.assertEqual(len(self.im.get_identities()), 1)

    def test_delete_free(self):
        ident = self.im.add_identity("x", "T", "u", "p", "s")
        with mock.patch("inventory_manager.get_all_devices", return_value=[]):
            ok, devices = self.im.delete_identity(ident["id"])
        self.assertTrue(ok)
        self.assertEqual(self.im.get_identities(), [])


class TestCoreEngineIdentityResolution(unittest.TestCase):
    def test_identity_profile_resolved(self):
        import core_engine
        with mock.patch("identity_manager.get_identity_credentials",
                        return_value=("iu", "ip", "is")):
            u, p, s = core_engine.get_device_credentials(
                {"Profile": "identity:abc123"})
        self.assertEqual((u, p, s), ("iu", "ip", "is"))

    def test_identity_missing_falls_back_to_default(self):
        import core_engine
        with mock.patch("identity_manager.get_identity_credentials",
                        return_value=None):
            u, p, s = core_engine.get_device_credentials(
                {"Profile": "identity:gone"})
        self.assertEqual(u, core_engine.DEFAULT_USERNAME)


if __name__ == "__main__":
    unittest.main()
