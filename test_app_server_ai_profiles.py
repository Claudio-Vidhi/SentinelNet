# -*- coding: utf-8 -*-
"""Unit test per la gestione dei profili di connessione AI in app_server.py
(storage in app_settings.json, migrazione dal vecchio formato a profilo
singolo, mascheramento della API key). Uso una data dir temporanea dedicata
(SENTINELNET_DATA_DIR) cosi' non tocca lo stato reale dell'app."""

import os
import shutil
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_ai_profiles_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

import app_server  # noqa: E402  (import dopo aver impostato la data dir)


class TestAiProfiles(unittest.TestCase):
    def setUp(self):
        # Ripulisce lo stato tra un test e l'altro sovrascrivendo app_settings.json.
        app_server.save_app_settings({"ai_profiles": [], "ai_active_profile": None})
        # save_app_settings fa un merge, non un reset: azzero esplicitamente le chiavi.
        settings_path = app_server.data_config.get_path("app_settings.json")
        if os.path.exists(settings_path):
            os.remove(settings_path)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def test_no_profiles_initially(self):
        profiles, active = app_server._get_ai_profiles_raw()
        self.assertEqual(profiles, [])
        self.assertIsNone(active)

    def test_migration_from_legacy_ai_settings(self):
        app_server.save_app_settings({
            "ai": {
                "provider": "gemini",
                "model": "gemini-3-flash",
                "base_url": "",
                "api_key_enc": app_server.crypto_vault.encrypt_password("AIza-legacy"),
                "rate_limit_rpm": 5,
            }
        })
        profiles, active = app_server._get_ai_profiles_raw()
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["name"], "Default")
        self.assertEqual(profiles[0]["provider"], "gemini")
        self.assertEqual(active, profiles[0]["id"])
        # La migrazione è persistita: una seconda lettura non duplica il profilo.
        profiles2, active2 = app_server._get_ai_profiles_raw()
        self.assertEqual(len(profiles2), 1)
        self.assertEqual(active2, active)

    def test_mask_ai_profile_never_exposes_plaintext_key(self):
        profile = {
            "id": "abc123",
            "name": "Test",
            "provider": "openai",
            "model": "gpt-4o-mini",
            "base_url": "",
            "api_key_enc": app_server.crypto_vault.encrypt_password("sk-secret"),
            "rate_limit_rpm": 0,
        }
        masked = app_server._mask_ai_profile(profile)
        self.assertNotIn("api_key_enc", masked)
        self.assertNotIn("sk-secret", str(masked))
        self.assertTrue(masked["api_key_set"])

    def test_find_ai_profile(self):
        profiles = [{"id": "a"}, {"id": "b"}]
        self.assertEqual(app_server._find_ai_profile(profiles, "b"), {"id": "b"})
        self.assertIsNone(app_server._find_ai_profile(profiles, "missing"))
        self.assertIsNone(app_server._find_ai_profile(profiles, None))

    def test_create_update_delete_profile_roundtrip(self):
        profiles, active = app_server._get_ai_profiles_raw()
        self.assertEqual(profiles, [])
        new_profile = {
            "id": "p1",
            "name": "Claude",
            "provider": "anthropic",
            "model": "claude-3-5-sonnet-latest",
            "base_url": "",
            "api_key_enc": app_server.crypto_vault.encrypt_password("sk-ant-x"),
            "rate_limit_rpm": 10,
        }
        app_server.save_app_settings({"ai_profiles": [new_profile], "ai_active_profile": "p1"})

        profiles, active = app_server._get_ai_profiles_raw()
        self.assertEqual(len(profiles), 1)
        self.assertEqual(active, "p1")

        active_profile = app_server._get_active_ai_profile()
        self.assertEqual(active_profile["provider"], "anthropic")
        decrypted = app_server.crypto_vault.decrypt_password(active_profile["api_key_enc"])
        self.assertEqual(decrypted, "sk-ant-x")

        # Elimina il profilo -> nessun profilo attivo rimasto.
        app_server.save_app_settings({"ai_profiles": [], "ai_active_profile": None})
        profiles, active = app_server._get_ai_profiles_raw()
        self.assertEqual(profiles, [])
        self.assertIsNone(app_server._get_active_ai_profile())


if __name__ == "__main__":
    unittest.main()
