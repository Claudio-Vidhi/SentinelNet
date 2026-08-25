# -*- coding: utf-8 -*-
"""cloud_backup.settings: secrets never leave the vault in clear."""
import unittest
from unittest import mock

from services.cloud_backup import settings as cb_settings


class TestCloudBackupSettings(unittest.TestCase):

    def setUp(self):
        self.store = {}
        patcher_get = mock.patch("core.app_settings.get_app_settings",
                                 side_effect=lambda: dict(self.store))
        patcher_save = mock.patch("core.app_settings.save_app_settings",
                                  side_effect=self.store.update)
        patcher_get.start(); patcher_save.start()
        self.addCleanup(patcher_get.stop); self.addCleanup(patcher_save.stop)

    def _sample(self, **over):
        cfg = {"enabled": True, "kind": "sftp", "host": "backup.example.net",
               "port": 22, "username": "sentinelnet", "auth": "password",
               "password": "s3cret", "remote_root": "/srv/backups"}
        cfg.update(over)
        return cfg

    def test_password_is_stored_encrypted_and_read_back(self):
        cb_settings.save(self._sample())
        raw = self.store["cloud_backup"]
        self.assertNotIn("password", raw)
        self.assertNotEqual("s3cret", raw["password_enc"])
        self.assertEqual("s3cret", cb_settings.read()["password"])

    def test_redacted_never_exposes_a_secret(self):
        cb_settings.save(self._sample())
        red = cb_settings.redacted()
        self.assertEqual("", red["password"])
        self.assertNotIn("password_enc", red)
        self.assertTrue(red["has_password"])

    def test_saving_without_a_new_secret_keeps_the_stored_one(self):
        cb_settings.save(self._sample())
        cb_settings.save(self._sample(password=""))
        self.assertEqual("s3cret", cb_settings.read()["password"])

    def test_validate_rejects_an_unusable_config(self):
        errors = cb_settings.validate({"enabled": True, "kind": "sftp", "host": "",
                                       "port": 0, "username": "", "auth": "key",
                                       "key_path": "", "remote_root": ""})
        joined = " ".join(errors)
        for expected in ("host", "port", "username", "remote_root", "key_path"):
            self.assertIn(expected, joined)

    def test_validate_accepts_a_complete_config(self):
        self.assertEqual([], cb_settings.validate(self._sample()))

    def test_disabled_by_default(self):
        self.assertFalse(cb_settings.is_enabled())


if __name__ == "__main__":
    unittest.main()
