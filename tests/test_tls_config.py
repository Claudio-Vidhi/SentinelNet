# -*- coding: utf-8 -*-
"""Test per data_config.resolve_tls_config (finding H-1): entrambe le
variabili → percorsi risolti; nessuna → HTTP invariato; parziale o file
mancante → fail-closed con TlsConfigError."""

import os
import tempfile
import unittest
from unittest.mock import patch

import data_config
from data_config import resolve_tls_config, TlsConfigError


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
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SENTINELNET_SSL_CERTFILE", None)
            os.environ.pop("SENTINELNET_SSL_KEYFILE", None)
            self.assertEqual(resolve_tls_config(), (None, None))

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


if __name__ == "__main__":
    unittest.main()
