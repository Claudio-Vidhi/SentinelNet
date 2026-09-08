# -*- coding: utf-8 -*-
"""Test per data_config.resolve_tls_config (finding H-1): entrambe le
variabili → percorsi risolti; nessuna → HTTP invariato; parziale o file
mancante → fail-closed con TlsConfigError."""

import os
import tempfile
import unittest
from unittest.mock import patch

from core import data_config
from core.data_config import resolve_tls_config, TlsConfigError


class TestTlsConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cert = os.path.join(self.tmp.name, "server.crt")
        self.key = os.path.join(self.tmp.name, "server.key")
        for p in (self.cert, self.key):
            with open(p, "w") as f:
                f.write("dummy pem")

    def tearDown(self):
        self.tmp.cleanup()

    def _env(self, cert=None, key=None):
        env = {}
        if cert is not None:
            env["SENTINELNET_SSL_CERTFILE"] = cert
        if key is not None:
            env["SENTINELNET_SSL_KEYFILE"] = key
        return patch.dict(os.environ, env, clear=False)

    def test_none_set_returns_http(self):
        # Nessuna delle DUE sorgenti: ne' le variabili d'ambiente ne' le
        # impostazioni app. _app_adv va neutralizzato esplicitamente, non
        # lasciato al caso: da quando generare un certificato scrive
        # ssl_certfile, un altro modulo della suite puo' averlo gia' messo
        # nell'app_settings.json della sua SENTINELNET_DATA_DIR temporanea, e
        # questo test leggerebbe quello invece di misurare il caso "niente
        # configurato".
        with patch.dict(os.environ, {}, clear=False),              patch.object(data_config, "_app_adv", return_value=None):
            os.environ.pop("SENTINELNET_SSL_CERTFILE", None)
            os.environ.pop("SENTINELNET_SSL_KEYFILE", None)
            self.assertEqual(resolve_tls_config(), (None, None))

    def test_app_settings_are_used_when_the_environment_is_silent(self):
        # Il ripiego che rende utile il pulsante "genera certificato": senza
        # variabili d'ambiente decidono le impostazioni salvate.
        with patch.dict(os.environ, {}, clear=False),              patch.object(data_config, "DATA_DIR", self.tmp.name),              patch.object(data_config, "_app_adv",
                          side_effect=lambda k, d=None: {
                              "ssl_certfile": "server.crt",
                              "ssl_keyfile": "server.key"}.get(k, d)):
            os.environ.pop("SENTINELNET_SSL_CERTFILE", None)
            os.environ.pop("SENTINELNET_SSL_KEYFILE", None)
            self.assertEqual(resolve_tls_config(), (self.cert, self.key))

    def test_both_absolute_paths(self):
        with self._env(self.cert, self.key):
            self.assertEqual(resolve_tls_config(), (self.cert, self.key))

    def test_relative_paths_resolve_against_data_dir(self):
        with self._env("server.crt", "server.key"), \
             patch.object(data_config, "DATA_DIR", self.tmp.name):
            self.assertEqual(resolve_tls_config(), (self.cert, self.key))

    def test_only_cert_fails_closed(self):
        with self._env(cert=self.cert, key=""):
            with self.assertRaises(TlsConfigError) as ctx:
                resolve_tls_config()
            self.assertIn("SENTINELNET_SSL_KEYFILE", str(ctx.exception))

    def test_only_key_fails_closed(self):
        with self._env(cert="", key=self.key):
            with self.assertRaises(TlsConfigError) as ctx:
                resolve_tls_config()
            self.assertIn("SENTINELNET_SSL_CERTFILE", str(ctx.exception))

    def test_missing_file_fails_closed(self):
        with self._env(self.cert, os.path.join(self.tmp.name, "nope.key")):
            with self.assertRaises(TlsConfigError) as ctx:
                resolve_tls_config()
            self.assertIn("non esiste", str(ctx.exception))


class TestGeneratedCertIsApplied(unittest.TestCase):
    """Generare il certificato deve anche accenderlo.

    Prima i file venivano scritti e lasciati scollegati: il pannello restava
    in HTTP finche' qualcuno non impostava a mano le due variabili
    d'ambiente, e nulla lo diceva. L'ambiente, se c'e', resta piu' forte.
    """

    def _client(self):
        from fastapi.testclient import TestClient
        import app_server
        return TestClient(app_server.app)

    def test_settings_point_at_the_generated_files(self):
        saved = {}

        def fake_generate(host):
            return {"certfile": "/x/certs/server.crt", "keyfile": "/x/certs/server.key",
                    "days": 825, "not_after": "2027-01-01T00:00:00+00:00"}

        from routers import settings as settings_router
        with patch.object(settings_router.cert_manager, "generate_self_signed",
                          side_effect=fake_generate), \
             patch.object(settings_router, "save_app_settings",
                          side_effect=lambda d: saved.update(d)), \
             patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SENTINELNET_SSL_CERTFILE", None)
            os.environ.pop("SENTINELNET_SSL_KEYFILE", None)
            settings_router.generate_self_signed_cert(
                settings_router.SelfSignedCertSchema(host="192.0.2.10"),
                current_user={"sub": "admin"})

        self.assertEqual(saved.get("app", {}).get("ssl_certfile"),
                         os.path.join("certs", "server.crt"))
        self.assertEqual(saved.get("app", {}).get("ssl_keyfile"),
                         os.path.join("certs", "server.key"))

    def test_environment_wins_and_settings_are_left_alone(self):
        saved = {}
        from routers import settings as settings_router
        with patch.object(settings_router.cert_manager, "generate_self_signed",
                          return_value={"certfile": "c", "keyfile": "k",
                                        "days": 825, "not_after": "x"}), \
             patch.object(settings_router, "save_app_settings",
                          side_effect=lambda d: saved.update(d)), \
             patch.dict(os.environ,
                        {"SENTINELNET_SSL_CERTFILE": "/etc/ssl/a.crt",
                         "SENTINELNET_SSL_KEYFILE": "/etc/ssl/a.key"}):
            out = settings_router.generate_self_signed_cert(
                settings_router.SelfSignedCertSchema(host="192.0.2.10"),
                current_user={"sub": "admin"})

        self.assertEqual(saved, {}, "l'ambiente decide: non si scrivono impostazioni")
        self.assertFalse(out["applied"])


if __name__ == "__main__":
    unittest.main()
